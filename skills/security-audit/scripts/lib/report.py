"""Phase 4: gather what report.md.j2 needs."""
import re
import subprocess
from datetime import date
from pathlib import Path

import pandas as pd

from . import A, W, load, read_tsv
from .findings import agent_outputs, judge, prepare, raw, union


def scenarios(f, outputs):
    """Each scenario with its agent's output (if any) and how many of its findings were confirmed."""
    s = read_tsv("refs/scenarios/index.tsv", ["id", "name", "covers"])
    out = outputs[outputs.scenario != ""].set_index("scenario")
    return s.assign(ran=s.id.isin(out.index), notes=s.id.map(out.notes).fillna(""),
                    raised=s.id.map(out.findings.map(
                        lambda found: len(found or []))).fillna(0).astype(int),
                    confirmed=s.id.map(f[f.real].scenarios.explode().value_counts()).fillna(0).astype(int))


def owasp(f, s):
    """Both OWASP lists, named from the staged references, with counts and the scenarios
    designed for each category or raising findings in it."""
    refs = "".join((W / "refs" / name).read_text()
                   for name in ("owasp-top10.md", "owasp-api-top10.md"))
    c = pd.DataFrame(re.findall(r"^# (.+?) \((\d+)\)|^## ((?:API|A)\d+):\d+ — (.+?)(?: \(.*\))?$", refs, re.M),
                     columns=["list", "year", "key", "name"])
    c[["list", "year"]] = c[["list", "year"]].replace("", None).ffill()
    c = c[c.key != ""]
    designed = s.assign(key=s.covers.str.split(
        r",\s*")).explode("key").groupby("key").id.agg(list)
    raised_in = f.explode("scenarios").dropna(
        subset="scenarios").groupby("group").scenarios.agg(list)
    return c.assign(scenarios=[union(designed.get(k, []) + raised_in.get(k, [])) or "—" for k in c.key],
                    raised=c.key.map(f.group.value_counts()
                                     ).fillna(0).astype(int),
                    confirmed=c.key.map(f[f.real].group.value_counts()).fillna(0).astype(int))


def out_of_scope(recon):
    if not (m := re.search(r"^(#+) [^\n]*[Oo]ut.of.[Ss]cope[^\n]*\n", recon, re.M)):
        return ""
    end = re.search(rf"^#{{1,{len(m[1])}}} ", recon[m.end():], re.M)
    return recon[m.end():][:end.start() if end else None]


def context(stack):
    f, repeated, selected = judge(prepare(load(W / "findings.yaml") or []))
    outputs = agent_outputs()
    s = scenarios(f, outputs)
    classes = read_tsv("file-classes.tsv",
                       ["bucket", "priority", "path", "reason"])
    phase2a = read_tsv("phase2a-files.tsv", ["path", "output"])
    usage = read_tsv("usage.tsv", ["phase", "label", "tokens", "tools"])
    usage[["tokens", "tools"]] = usage[["tokens", "tools"]].apply(
        pd.to_numeric, errors="coerce")
    recon = (A / "recon.md").read_text() if (A / "recon.md").exists() else ""
    top = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True).stdout.strip()
    return dict(
        f=f, raw=raw(outputs), repeated=repeated, selected=selected, scenarios=s, owasp=owasp(f, s),
        classes=classes, phase2a=phase2a, out_of_scope=out_of_scope(recon), stack=stack,
        uncovered=classes[(classes.bucket == "review") & ~
                          classes.path.isin(phase2a.path)],
        no_output=phase2a[~phase2a.output.map(lambda p: Path(p).exists())],
        usage=usage.groupby("phase", sort=False).agg(agents=("label", "size"), total=("tokens", "sum"),
                                                     average=("tokens", "mean"), tools=("tools", "sum")),
        repo=Path(top or ".").resolve().name, date=date.today().isoformat())
