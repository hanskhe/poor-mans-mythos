#!/usr/bin/env bash
# Phase 2c: merge and deduplicate the Phase 2a/2b findings written by the
# reviewer and scenario agents. Run from the root of the audited repository.
# Writes findings-merged.md, findings-index.tsv, coverage-2b.tsv, stats.tsv and
# prints the summary to show the user.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
A=.security-audit

missing=""
if [ -f "$A/phase2a-files.tsv" ]; then
  while IFS="$(printf '\t')" read -r path outfile; do
    [ -f "$outfile" ] || missing="$missing
  2a $path -> $outfile"
  done < "$A/phase2a-files.tsv"
fi
for s in $(cut -f1 "$A/refs/scenarios/index.tsv"); do
  [ -f "$A/findings/2b-$s.md" ] || missing="$missing
  2b $s -> $A/findings/2b-$s.md"
done

set -- "$A"/findings/2[ab]-*.md
[ -f "$1" ] || { echo "No findings files in $A/findings/." >&2; exit 1; }
sel=""; [ -f "$A/phase2a-files.tsv" ] && sel="$A/phase2a-files.tsv"

awk -v OUT_MERGED="$A/findings-merged.md" -v OUT_INDEX="$A/findings-index.tsv" \
    -v OUT_COV="$A/coverage-2b.tsv" -v OUT_STATS="$A/stats.tsv" \
    -f "$HERE/lib.awk" -f "$HERE/collect.awk" $sel "$@"

if [ -n "$missing" ]; then
  echo "MISSING agent output (agent failed or never wrote its file):$missing"
fi
