#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.9"
# dependencies = ["pandas>=2", "jinja2>=3", "pyyaml>=6", "pathspec>=0.11", "typer>=0.12"]
# ///
"""The scripted steps of the security audit. Run them from the root of the audited repository."""
import sys
sys.dont_write_bytecode = True  # keep the plugin directory clean

from lib import A, CONFIG, LIB, W, classify, dump, findings, load, read_tsv, render, report as reporting, say, write_tsv
import typer
import pandas as pd
from typing import List
from pathlib import Path
from datetime import datetime, timezone
import re
import shutil


REFS = LIB.parent.parent / "references"
app = typer.Typer(add_completion=False, help=__doc__)


@app.command()
def init():
    """Phase 0: create .security-audit/, clear the previous run's working state, stage what subagents read."""
    A.mkdir(exist_ok=True)
    # findings quote secrets: the workspace is never committed
    (A / ".gitignore").write_text("*\n")
    # earlier reports stay; only the unfinished or uncleaned state of the last run goes
    cleared = W.exists()
    shutil.rmtree(W, ignore_errors=True)
    for sub in ("refs/scenarios", "findings", "clusters", "validated"):
        (W / sub).mkdir(parents=True, exist_ok=True)
    for name in CONFIG["staged_refs"]:
        shutil.copy(REFS / name, W / "refs")
    sections = re.findall(r"^(## (S\d+)\.[ \t]*(.*)\n(?s:.*?)^\*\*Covers:\*\*(.*)\n(?s:.*?))(?=^## |\Z)",
                          (REFS / "scenarios.md").read_text(), re.M)
    scenarios = pd.DataFrame(
        sections, columns=["text", "id", "name", "covers"])
    for s in scenarios.itertuples():
        (W / "refs/scenarios" / f"{s.id}.md").write_text(s.text)
    write_tsv(scenarios[["id", "name", "covers"]].apply(
        lambda c: c.str.strip()), "refs/scenarios/index.tsv")
    say("init", cleared=cleared, scenarios=scenarios)


@app.command()
def scan():
    """Phase 1.1: classify every file by path and list those that need a decision."""
    df = classify.scan()
    write_tsv(df, "file-classes.base.tsv")
    say("scan", df=df)


@app.command()
def finalize():
    """Phase 1.3: apply class-overrides.tsv and recon.md; write file-classes.tsv and file-rankings.md."""
    columns = ["bucket", "priority", "path", "reason"]
    df, counts = classify.finalize(read_tsv("file-classes.base.tsv", columns),
                                   read_tsv("class-overrides.tsv",
                                            ["bucket", "path", "reason"]),
                                   (A / "recon.md").read_text())
    write_tsv(df, "file-classes.tsv")
    groups = {bucket: df[df.bucket == bucket]
              for bucket in ("review", "skim", "skip")}
    render("file-rankings.md.j2", A / "file-rankings.md",
           groups=groups, generated=datetime.now(timezone.utc))
    say("finalize", groups=groups, **counts)


@app.command()
def select(n: str = typer.Argument("all", help="How many Review files, or 'all'.")):
    """Phase 1.4: pick the Review files for the per-file pass; write phase2a-files.tsv."""
    chosen = classify.select(
        read_tsv("file-classes.tsv", ["bucket", "priority", "path", "reason"]), n)
    write_tsv(chosen, "phase2a-files.tsv")
    say("select", chosen=chosen)


@app.command()
def collect():
    """Phase 2c: merge the agents' findings into findings.yaml."""
    outputs = findings.agent_outputs()
    raw = findings.raw(outputs)
    kept = findings.merge(raw)
    dump(kept[findings.FIELDS].to_dict("records"), W / "findings.yaml")
    expected = [*read_tsv("phase2a-files.tsv", ["path", "output"]).output,
                *(f"{W}/findings/2b-{s}.yaml" for s in read_tsv("refs/scenarios/index.tsv", ["id", "name", "covers"]).id)]
    say("collect", raw=raw, kept=kept, invalid=outputs[outputs.findings.isna()].path,
        missing=[path for path in expected if not Path(path).exists()])


@app.command()
def cluster(n: str = typer.Argument("all", help="How many merged findings to validate, or 'all'.")):
    """Phase 3.1: group the top merged findings into validation clusters."""
    merged = load(W / "findings.yaml") or []
    merged = merged if n == "all" else merged[:int(n)]
    found = findings.clusters(findings.prepare(merged))
    write_tsv(found, "clusters.tsv")
    for old in (W / "clusters").glob("C*.yaml"):
        old.unlink()
    by_id = {f["id"]: f for f in merged}
    for c in found.itertuples():
        dump([by_id[i] for i in c.ids.split(",")],
             W / "clusters" / f"{c.cluster}.yaml")
    say("cluster", found=found)


@app.command()
def report(stack: str = typer.Argument("Unknown", help="One-line stack summary.")):
    """Phase 4: write coverage.md and report-<date>.md; print the closing summary."""
    context = reporting.context(stack)
    path = A / f"report-{context['date']}.md"
    render("report.md.j2", path, **context)
    render("coverage.md.j2", A / "coverage.md", **context)
    say("report", path=path, **{k: context[k]
        for k in ("f", "raw", "repeated")})


@app.command()
def clean(force: bool = typer.Option(False, "--force", help="Clean even if no report has been written.")):
    """After Phase 4: delete the working state, keeping the .md files at the top level."""
    if not force and not any(A.glob("report-*.md")):
        sys.exit(f"No report in {A} yet: run audit.py report first, or pass --force.")
    shutil.rmtree(W, ignore_errors=True)
    say("clean", kept=sorted(p.name for p in A.iterdir() if p.name != ".gitignore"))


@app.command()
def usage(groups: List[str] = typer.Argument(..., help="<phase> <label> <total_tokens> <tool_uses> ...")):
    """Record subagent token usage in usage.tsv ('-' for an unknown value)."""
    if len(groups) % 4:
        sys.exit(
            "Arguments come in groups of four: <phase> <label> <total_tokens> <tool_uses>")
    rows = pd.DataFrame([groups[i:i + 4] for i in range(0, len(groups), 4)])
    rows[2] = rows[2].str.replace(r"[,_ ]", "", regex=True)
    rows.to_csv(W / "usage.tsv", sep="\t", index=False, header=False, mode="a")


if __name__ == "__main__":
    app()
