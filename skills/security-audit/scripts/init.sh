#!/usr/bin/env bash
# Phase 0 setup. Run from the root of the repository being audited.
# Creates .security-audit/, archives any previous run, writes the .gitignore,
# and stages the reference files that subagents read (they run with the audited
# repo as cwd and cannot see the plugin's install directory).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REFS="$HERE/../references"
A=.security-audit

mkdir -p "$A"
printf '*\n' > "$A/.gitignore"

# Move a previous run aside so stale findings are never collected into this one.
old=$(ls -A "$A" | grep -v -e '^\.gitignore$' -e '^archive$' || true)
if [ -n "$old" ]; then
  stamp="$A/archive/$(date -u +%Y%m%dT%H%M%SZ)"
  dest=$stamp; i=1
  while [ -e "$dest" ]; do dest="$stamp-$i"; i=$((i + 1)); done
  mkdir -p "$dest"
  printf '%s\n' "$old" | while IFS= read -r f; do mv "$A/$f" "$dest/"; done
  echo "Previous run archived to $dest"
fi

mkdir -p "$A/refs/scenarios" "$A/findings" "$A/clusters" "$A/validated"

for f in owasp-top10 owasp-api-top10 severity-rubric finding-format; do
  cp "$REFS/$f.md" "$A/refs/$f.md"
done

# One file per scenario so each scenario agent reads only its own section.
awk -v dir="$A/refs/scenarios" '
  /^## S[0-9]+\./ {
    if (out != "") close(out)
    id = $2; sub(/\.$/, "", id)
    name = $0; sub(/^## S[0-9]+\.[ \t]*/, "", name)
    out = dir "/" id ".md"
    printf "%s\t%s\n", id, name > (dir "/index.tsv")
    print > out
    next
  }
  /^## / { if (out != "") close(out); out = ""; next }
  out != "" { print > out }
' "$REFS/scenarios.md"

fail=0
for f in owasp-top10 owasp-api-top10 severity-rubric finding-format; do
  [ -s "$A/refs/$f.md" ] || { echo "STAGING FAILED: refs/$f.md missing" >&2; fail=1; }
done
n=$(ls "$A/refs/scenarios"/S*.md 2>/dev/null | wc -l | tr -d ' ')
[ "$n" -gt 0 ] || { echo "STAGING FAILED: no scenarios split from scenarios.md" >&2; fail=1; }
[ "$fail" -eq 0 ] || exit 1

echo "Workspace ready: $A (refs staged, $n scenarios)"
cut -f1,2 "$A/refs/scenarios/index.tsv"
