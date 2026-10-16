"""Phase 1: sort the repository's files into review, skim and skip."""
import re
import subprocess
from pathlib import Path

import pandas as pd
from pathspec import PathSpec

from . import CONFIG, W

CLASS = ["bucket", "priority", "reason"]
RULES = pd.DataFrame([r[:3] for r in CONFIG["rules"]] +
                     [CONFIG["scripted"]["undecided"]], columns=CLASS)
SPECS = [PathSpec.from_lines("gitwildmatch", r[3]) for r in CONFIG["rules"]]
SIGNALS = re.compile("|".join(CONFIG["signals"]), re.I)
RISKY_MIGRATION = re.compile("|".join(CONFIG["risky_migration"]), re.I)
SCRIPTED = CONFIG["scripted"]


def repository_files():
    git = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard", "-z"], capture_output=True, text=True)
    paths = git.stdout.split("\0") if git.returncode == 0 else map(
        str, Path().rglob("*"))
    return sorted(p for p in set(paths) if p and Path(p).is_file() and not Path(p).is_symlink())


def read(path, size=-1):
    try:
        with open(path, "rb") as f:
            return f.read(size)
    except OSError:
        return None  # unreadable (e.g. sandboxed): classify by path only


def text(path):
    return (read(path) or b"").decode(errors="replace")


def signals(path):
    """The six most frequent risky primitives in a file, e.g. "exec((3) token(1)"."""
    hits = pd.Series(SIGNALS.findall(text(path)),
                     dtype=str).str.lower().value_counts()
    top = hits.sort_index(ascending=False).sort_values(
        ascending=False, kind="stable").head(6)
    return " ".join(f"{hit}({n})" for hit, n in top.items())


def scan():
    """Path rules first, then the checks that need the file's contents."""
    df = pd.DataFrame({"path": repository_files()})
    df = df.join(RULES, on=df.path.map(lambda p: next(
        (i for i, s in enumerate(SPECS) if s.match_file(p.lower())), len(SPECS))))
    binary = df.path.map(lambda p: (head := read(p, 8192))
                         is not None and (not head or b"\0" in head))
    df.loc[(df.bucket != "skip") & binary, CLASS] = SCRIPTED["binary"]
    df.loc[(df.reason == "migration") & df.path.map(lambda p: bool(
        RISKY_MIGRATION.search(text(p)))), CLASS] = SCRIPTED["migration"]
    seen = df.path[df.bucket == "decide"].map(signals)
    df.loc[seen.index, "reason"] = "signals: " + seen
    df.loc[seen.index[seen == ""], CLASS] = SCRIPTED["no_signals"]
    return df[["bucket", "priority", "path", "reason"]]


def finalize(df, overrides, recon):
    """Overrides win; files recon.md mentions (outside Out of scope) are promoted; the rest of
    the undecided files default up to review."""
    overrides = (overrides[overrides.bucket.isin(CONFIG["override_priority"])]
                 .assign(path=lambda o: o.path.str.removeprefix("./"),
                         reason=lambda o: o.reason.mask(
                             o.reason == "", "override"),
                         priority=lambda o: o.bucket.map(CONFIG["override_priority"]))
                 .drop_duplicates("path", keep="last").set_index("path"))
    recon = re.sub(
        r"^#+ [^\n]*[Oo]ut.of.[Ss]cope.*?(?=^#+ |\Z)", "", recon, flags=re.M | re.S)
    df = df.astype({"priority": int})
    overridden = df.path.isin(overrides.index)
    mentioned = ~overridden & df.path.map(lambda p: bool(
        re.search(r"(?<![\w./-])" + re.escape(p), recon)))
    tagged, promoted = mentioned & (
        df.bucket == "review"), mentioned & df.bucket.isin(["skim", "decide"])
    defaulted = ~overridden & ~mentioned & (df.bucket == "decide")

    df.loc[tagged, "priority"] = 1
    df.loc[tagged, "reason"] += "; referenced in recon.md"
    df.loc[promoted, CLASS] = SCRIPTED["in_recon"]
    df.loc[defaulted,
           "reason"] = "undecided, defaulted up (" + df.reason[defaulted] + ")"
    df.loc[defaulted, CLASS[:2]] = SCRIPTED["defaulted"]
    if overridden.any():
        df.loc[overridden, CLASS] = overrides.loc[df.path[overridden], CLASS].values
    counts = dict(promoted=promoted.sum(),
                  overrides=overridden.sum(), defaulted=defaulted.sum())
    return df.sort_values(["priority", "path"]), counts


def select(df, n):
    """The top n review files (or all), each with the file its Phase 2a agent writes."""
    review = df[df.bucket == "review"].path
    review = review if n == "all" else review.head(int(n))
    slug = review.str.replace(
        "/", "__").str.replace(r"[^\w.-]", "_", regex=True)
    return pd.DataFrame({"path": review, "output": [f"{W}/findings/2a-{i:03d}-{s}.yaml" for i, s in enumerate(slug, 1)]})
