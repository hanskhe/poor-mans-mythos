#!/usr/bin/env bash
# Phase 3.1: select the top N merged findings (or "all") and group them into
# validation clusters. Run from the root of the audited repository.
#   - same (category, file)            -> one cluster
#   - leftover singletons sharing (category, directory) -> one cluster
#   - clusters larger than 10 are split into chunks of 8
# Writes clusters/Cnn.md (the raw finding blocks a validator reads),
# clusters.tsv (cluster <TAB> IDs <TAB> label) and prints the spawn list.
set -eu

A=.security-audit
[ -f "$A/findings-index.tsv" ] || { echo "Run collect.sh first." >&2; exit 1; }
n=${1:-all}

rm -f "$A"/clusters/C*.md
awk -F'\t' -v n="$n" '
  function dirname(p) { if (p !~ /\//) return "."; sub(/\/[^\/]*$/, "", p); return p }
  { if (n != "all" && NR > n + 0) exit
    m++; ID[m] = $1; K1[m] = $4 "|" $5; K2[m] = $4 "|" dirname($5); CAT[m] = $4; F[m] = $5; D[m] = dirname($5)
    c1[K1[m]]++ }
  END {
    for (i = 1; i <= m; i++) if (c1[K1[i]] == 1) c2[K2[i]]++
    nc = 0
    for (i = 1; i <= m; i++) {
      if (c1[K1[i]] > 1)      { key = "f:" K1[i]; lab = CAT[i] " " F[i] }
      else if (c2[K2[i]] > 1) { key = "d:" K2[i]; lab = CAT[i] " " D[i] "/*" }
      else                    { key = "s:" ID[i]; lab = CAT[i] " " F[i] }
      if (!(key in CI)) { nc++; CI[key] = nc; LAB[nc] = lab; CNT[nc] = 0 }
      c = CI[key]; CNT[c]++; MEM[c, CNT[c]] = ID[i]
    }
    out = 0
    for (c = 1; c <= nc; c++) {
      chunks = (CNT[c] > 10) ? int((CNT[c] + 7) / 8) : 1
      per = int((CNT[c] + chunks - 1) / chunks)
      for (k = 0; k < chunks; k++) {
        ids = ""
        for (j = k * per + 1; j <= CNT[c] && j <= (k + 1) * per; j++) ids = ids (ids == "" ? "" : ",") MEM[c, j]
        if (ids == "") continue
        out++
        printf "C%02d\t%s\t%s\n", out, ids, LAB[c] (chunks > 1 ? " (part " (k + 1) "/" chunks ")" : "")
      }
    }
  }' "$A/findings-index.tsv" > "$A/clusters.tsv"

# Copy each cluster's finding blocks out of findings-merged.md verbatim.
awk -v dir="$A/clusters" '
  FILENAME ~ /clusters\.tsv$/ {
    split($0, x, "\t"); nid = split(x[2], ids, ",")
    for (i = 1; i <= nid; i++) WHERE[ids[i]] = x[1]
    LABEL[x[1]] = x[3]; next
  }
  /^---FINDING---[ \t]*$/ { inb = 1; buf = $0 "\n"; id = ""; next }
  inb {
    buf = buf $0 "\n"
    if ($0 ~ /^ID: /) { id = $0; sub(/^ID: /, "", id); sub(/[ \t\r]+$/, "", id) }
    if ($0 ~ /^---END FINDING---[ \t]*$/) {
      inb = 0
      if (id in WHERE) {
        c = WHERE[id]; f = dir "/" c ".md"
        # Files were removed above; append and close so BWK awk never runs out of descriptors.
        if (!(c in started)) { started[c] = 1; printf "# Validation cluster %s — %s\n\n", c, LABEL[c] >> f }
        printf "%s\n", buf >> f
        close(f)
      }
    }
  }' "$A/clusters.tsv" "$A/findings-merged.md"

nf=$(awk -F'\t' '{ n += split($2, a, ",") } END { print n + 0 }' "$A/clusters.tsv")
echo "Validating $nf findings in $(wc -l < "$A/clusters.tsv" | tr -d ' ') clusters (cluster <TAB> input <TAB> output <TAB> label):"
awk -F'\t' -v A="$A" '{ printf "%s\t%s/clusters/%s.md\t%s/validated/%s.md\t%s [%s]\n", $1, A, $1, A, $1, $3, $2 }' "$A/clusters.tsv"
