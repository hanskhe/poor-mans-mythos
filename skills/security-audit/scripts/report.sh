#!/usr/bin/env bash
# Phase 4 + final report. Run from the root of the audited repository.
#   report.sh "<one-line stack summary>"
# Writes .security-audit/coverage.md and .security-audit/report-<date>.md and
# prints the closing summary. The orchestrator only adds "Auditor Notes".
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
A=.security-audit
STACK=${1:-see recon.md}
DATE=$(date +%Y-%m-%d)
REPO=$(basename "$(git rev-parse --show-toplevel 2>/dev/null || pwd)")

for f in stats.tsv findings-index.tsv findings-merged.md; do
  [ -f "$A/$f" ] || { echo "Missing $A/$f. Run collect.sh first." >&2; exit 1; }
done

set -- "$A/stats.tsv" "$A/refs/scenarios/index.tsv" "$A/findings-index.tsv" "$A/findings-merged.md"
for f in clusters.tsv coverage-2b.tsv file-classes.tsv phase2a-files.tsv usage.tsv recon.md; do
  [ -f "$A/$f" ] && set -- "$@" "$A/$f"
done
for f in "$A"/validated/*.md; do
  [ -f "$f" ] && set -- "$@" "$f"
done

awk -v OUT_COV="$A/coverage.md" -v OUT_REP="$A/report-$DATE.md" \
    -v REPO="$REPO" -v DATE="$DATE" -v STACK="$STACK" \
    -f "$HERE/lib.awk" -f "$HERE/report.awk" "$@"
