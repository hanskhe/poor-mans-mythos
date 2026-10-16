"""Phases 2c-3: merge the agents' findings, cluster them for validation, join the verdicts."""
import math
import posixpath
import re

import numpy as np
import pandas as pd

from . import CONFIG, W, load, read_tsv

FIELDS = ["id", "file", "lines", "title", "severity", "confidence", "owasp", "cwe", "source",
          "excerpt", "detail", "dataflow", "references"]
VERDICT = ["id", "status", "severity", "duplicate_of", "reasoning", "fix", "excerpt"]


def agent_outputs():
    """One row per Phase 2a/2b output file. `findings` is None when the file is not valid YAML."""
    assigned = read_tsv("phase2a-files.tsv", ["file", "output"]).set_index("output").file
    rows = []
    for path in sorted((W / "findings").glob("2[ab]-*.yaml")):
        data = load(path)
        data = data if isinstance(data, dict) and isinstance(data.get("findings"), list) else {"findings": None}
        scenario = re.match(r"2b-(S\d+)", path.name)
        rows.append({"path": str(path), "scenario": scenario[1] if scenario else "", "notes": data.get("notes") or "",
                     "source": f"2b:{scenario[1]}" if scenario else f"2a:{assigned.get(str(path), path.stem)}",
                     "findings": data["findings"]})
    return pd.DataFrame(rows, columns=["path", "scenario", "source", "notes", "findings"])


def rank(values, levels):
    """Index into levels by the first three letters ("crit" -> Critical); 0 when unknown."""
    return values.str.strip().str.lower().str[:3].map({l[:3].lower(): i for i, l in enumerate(levels)}).fillna(0).astype(int)


def category(owasp, cwe, n):
    """Merge key: A05, API1, NA:CWE-89, or NA:#<n>, which never merges."""
    if m := re.search(r"(API|A)(\d+)", owasp.upper()):
        return f"API{int(m[2])}" if m[1] == "API" else f"A{int(m[2]):02d}"
    m = re.search(r"CWE-?(\d+)", cwe.upper())
    return f"NA:CWE-{int(m[1])}" if m else f"NA:#{n}"


def prepare(records, columns=FIELDS):
    """Findings as a table of strings, plus the line range, category and ranks used downstream."""
    df = pd.DataFrame(list(records)).reindex(columns=columns).fillna("")
    df["references"] = df.references.map(lambda r: ", ".join(r) if isinstance(r, list) else r)
    df = df.astype(str)
    df["file"] = df.file.str.strip("` ").str.removeprefix("./")
    lines = df.lines.str.extractall(r"(\d+)")[0].astype(int).groupby(level=0)
    df["lo"], df["hi"] = lines.min(), lines.max()
    df["key"] = [category(o, c, n) for n, (o, c) in enumerate(zip(df.owasp, df.cwe), 1)]
    df["sev"], df["conf"] = rank(df.severity, CONFIG["severities"]), rank(df.confidence, CONFIG["confidences"])
    return df


def raw(outputs):
    """Every finding the agents wrote, tagged with the agent that wrote it."""
    return prepare({**f, "source": source} for source, found in zip(outputs.source, outputs.findings)
                   for f in found or [] if isinstance(f, dict))


def merge(df):
    """Same file, same category, overlapping lines: one finding. The most severe, then most
    confident, then most detailed is kept, with the sources and references of all."""
    df = df.assign(span=df.lines.where(df.lo.isna(), ""), lo=df.lo.fillna(0), hi=df.hi.fillna(0))
    df = df.sort_values(["file", "key", "span", "lo"], kind="stable")
    reach = df.groupby(["file", "key", "span"]).hi.transform(lambda hi: hi.cummax().shift())
    df["group"] = (reach.isna() | (df.lo > reach)).cumsum()
    df = df.assign(length=df.detail.str.len()).sort_values(
        ["group", "sev", "conf", "length"], ascending=[True, False, False, False], kind="stable")
    kept = df.drop_duplicates("group").set_index("group")
    kept.update(df.groupby("group")[["source", "references"]].agg(union))
    kept = kept.sort_values(["sev", "file", "lo"], ascending=[False, True, True], kind="stable")
    return kept.assign(id=[f"F{i:03d}" for i in range(1, len(kept) + 1)])


def clusters(df):
    """Same category and file: one cluster. Leftover singletons sharing category and directory:
    one cluster. Clusters over 10 are split into chunks of at most 8."""
    df = df.assign(dir=df.file.map(lambda f: posixpath.dirname(f) or "."))
    same_file = df.groupby(["key", "file"]).id.transform("size") > 1
    same_dir = df[~same_file].groupby(["key", "dir"]).id.transform("size").reindex(df.index, fill_value=0) > 1
    df["label"] = df.key + " " + np.where(same_dir, df.dir + "/*", df.file)
    rows = []
    for (_, label), ids in df.groupby([np.where(same_file | same_dir, df.label, df.id), "label"], sort=False).id:
        parts = math.ceil(len(ids) / 8) if len(ids) > 10 else 1
        for k, chunk in enumerate(np.array_split(ids.tolist(), parts), 1):
            rows.append((",".join(chunk), label + (f" (part {k}/{parts})" if parts > 1 else "")))
    found = pd.DataFrame(rows, columns=["ids", "label"])
    return found.assign(cluster=[f"C{i:02d}" for i in range(1, len(found) + 1)])[["cluster", "ids", "label"]]


def judge(f):
    """Each merged finding with its verdict (the last one, if a validator wrote several)."""
    verdicts = prepare_verdicts()
    f = f.merge(verdicts.drop_duplicates("id", keep="last"), on="id", how="left", suffixes=("", "_verdict"), indicator=True)
    validated = f.pop("_merge") == "both"
    f = f.fillna("")
    letters = f.status.str.lower().str.replace("[^a-z]", "", regex=True)
    status = letters.str.extract(f"^({'|'.join(CONFIG['statuses'])})")[0].map(CONFIG["statuses"]).fillna(letters)
    selected = read_tsv("clusters.tsv", ["cluster", "ids", "label"]).ids.str.split(",").explode()
    f["status"] = status.where(validated, np.where(f.id.isin(selected), "missing", "not selected"))
    f["adjusted"] = rank(f.severity_verdict, CONFIG["severities"]).replace(0, np.nan).fillna(f.sev).astype(int)
    f["real"] = f.status.isin(CONFIG["real_statuses"])
    f["rerated"] = f.real & (f.adjusted != f.sev)
    f["unclear"] = validated & ~f.real & ~f.status.isin(["false positive", "duplicate"])
    f["pending"] = ~validated
    f["excerpt"] = f.excerpt_verdict.mask(f.excerpt_verdict == "", f.excerpt)
    sources = f.source.str.split(r",\s*")
    f["scenarios"] = sources.map(lambda s: [x[3:] for x in s if x.startswith("2b:")])
    f["found_by"] = sources.map(lambda s: " + ".join(sorted({x[:2] for x in s})))
    f["group"] = f.key.mask(f.key.str.startswith("NA"), "NA")
    return f, verdicts.id[verdicts.id.duplicated()].tolist(), selected.nunique()


def prepare_verdicts():
    found = [v for path in sorted((W / "validated").glob("*.yaml")) for v in load(path) or [] if isinstance(v, dict)]
    verdicts = pd.DataFrame(found).reindex(columns=VERDICT).fillna("").astype(str)
    return verdicts.assign(id=verdicts.id.str.strip().str.upper())


def union(lists):
    """Union of comma-separated lists, order kept."""
    return ", ".join(dict.fromkeys(item.strip() for text in lists for item in text.split(",") if item.strip()))
