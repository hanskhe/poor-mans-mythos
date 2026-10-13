#!/usr/bin/env bash
# Record subagent token usage so each audit leaves a cost baseline behind.
#   usage.sh <phase> <label> <total_tokens> <tool_uses> [<phase> <label> <total_tokens> <tool_uses> ...]
# Pass "-" for an unknown value. report.sh summarizes .security-audit/usage.tsv.
set -eu
[ $# -ge 4 ] && [ $(($# % 4)) -eq 0 ] || { echo "usage: usage.sh <phase> <label> <total_tokens> <tool_uses> [...] (groups of four)" >&2; exit 1; }
while [ $# -gt 0 ]; do
  tokens=$(printf '%s' "$3" | tr -d ',_ ')
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$tokens" "$4" >> .security-audit/usage.tsv
  shift 4
done
