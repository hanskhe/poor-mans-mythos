# Phase 2c: parse every findings/2a-*.md and findings/2b-*.md file, deduplicate
# mechanically, assign IDs, and write the merged set.
# Inputs: [phase2a-files.tsv] findings/*.md
# Vars:   OUT_MERGED, OUT_INDEX, OUT_COV, OUT_STATS

BEGIN { init_known(); FS = "\n" }

FNR == 1 {
  parse_reset(); cur = FILENAME; is_sel = (cur ~ /phase2a-files\.tsv$/)
  if (!is_sel) { nf++; FL[nf] = cur; nblk[cur] = 0 }
  notes_on = 0
}

is_sel { split($0, sx, "\t"); assigned[sx[2]] = sx[1]; next }

{
  before = NREC
  if (parse_line($0, cur)) { if (NREC > before) nblk[cur]++; next }
  t = trim($0)
  if (t == "NO FINDINGS")  { nofind[cur] = 1; next }
  if (t ~ /^Scenario:/)    { scname[cur] = trim(substr(t, 10)); notes_on = 0; next }
  if (t ~ /^Findings:/)    { sccount[cur] = trim(substr(t, 10)); notes_on = 0; next }
  if (t ~ /^Notes:/)       { scnotes[cur] = trim(substr(t, 7)); notes_on = 1; next }
  if (notes_on && t != "") scnotes[cur] = scnotes[cur] " " t
}

function phase_of(f,   b) { b = basename(f); return b ~ /^2b-/ ? "2b" : b ~ /^2a-/ ? "2a" : "?" }
function find(x) { while (UF[x] != x) x = UF[x]; return x }
function better(a, b) {   # is record a a better keeper than b?
  if (SV[a] != SV[b]) return SV[a] > SV[b]
  if (CF[a] != CF[b]) return CF[a] > CF[b]
  return length(R[a, "Detail"]) > length(R[b, "Detail"])
}
function gless(a, b) {    # group ordering: severity desc, file, first line
  if (SV[a] != SV[b]) return SV[a] > SV[b]
  if (FN[a] != FN[b]) return FN[a] < FN[b]
  return LO[a] + 0 < LO[b] + 0
}

END {
  n = 0
  for (i = 1; i <= NREC; i++) {
    if (RTYPE[i] != "F") continue
    n++; I[n] = i
    ph = phase_of(RSRC[i]); raw[ph]++
    if (R[i, "Source"] == "") {
      b = RSRC[i]; sub(/^.*\//, "", b); sub(/\.md$/, "", b)
      R[i, "Source"] = (ph == "2a" && (RSRC[i] in assigned)) ? "2a:" assigned[RSRC[i]] : (ph == "2b" ? "2b:" substr(b, 4) : ph ":" b)
    }
    FN[i] = normfile(R[i, "File"]); if (FN[i] == "") FN[i] = "(unknown file)"
    R[i, "File"] = FN[i]
    LO[i] = linelo(R[i, "Lines"]); HI[i] = linehi(R[i, "Lines"])
    OK[i] = owaspkey(R[i, "OWASP"], R[i, "CWE"], i)
    SV[i] = sevrank(R[i, "Severity"]); CF[i] = confrank(R[i, "Confidence"])
    UF[i] = i
    if (R[i, "Title"] == "") warn = warn "\n  finding without Title in " RSRC[i]
  }

  # Duplicates: same file, overlapping line ranges, same category key.
  for (a = 1; a <= n; a++) for (b = a + 1; b <= n; b++) {
    x = I[a]; y = I[b]
    if (FN[x] != FN[y] || OK[x] != OK[y]) continue
    if (LO[x] == "" || LO[y] == "") { if (R[x, "Lines"] != R[y, "Lines"]) continue }
    else if (HI[x] < LO[y] || HI[y] < LO[x]) continue
    rx = find(x); ry = find(y); if (rx != ry) UF[ry] = rx
  }

  ng = 0
  for (a = 1; a <= n; a++) {
    x = I[a]; r = find(x)
    if (!(r in KEEP)) { ng++; G[ng] = r; KEEP[r] = x; SIZE[r] = 0 }
    SIZE[r]++
    if (better(x, KEEP[r])) KEEP[r] = x
  }
  for (a = 1; a <= n; a++) {
    x = I[a]; k = KEEP[find(x)]
    if (x == k) continue
    MSRC[k] = listunion(MSRC[k], R[x, "Source"])
    MREF[k] = listunion(MREF[k], R[x, "References"])
  }
  for (g = 1; g <= ng; g++) {
    k = KEEP[G[g]]; H[g] = k
    R[k, "Source"] = listunion(R[k, "Source"], MSRC[k])
    R[k, "References"] = listunion(R[k, "References"], MREF[k])
  }
  for (g = 2; g <= ng; g++) {   # insertion sort of kept records
    v = H[g]; j = g - 1
    while (j >= 1 && gless(v, H[j])) { H[j + 1] = H[j]; j-- }
    H[j + 1] = v
  }

  printf "# Merged findings\n\n%d raw findings (2a: %d, 2b: %d) merged to %d. IDs are ordered by severity, then file.\n\n", n, raw["2a"], raw["2b"], ng > OUT_MERGED
  printf "" > OUT_INDEX
  for (g = 1; g <= ng; g++) {
    k = H[g]; id = sprintf("F%03d", g)
    printf "%s\n", render_finding(k, id) > OUT_MERGED
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", id, sevname(SV[k]), R[k, "Confidence"], OK[k], FN[k], R[k, "Lines"], cell(R[k, "Title"]), R[k, "Source"] > OUT_INDEX
    bysev[SV[k]]++
  }

  printf "" > OUT_COV
  for (f = 1; f <= nf; f++) {
    p = FL[f]; b = basename(p)
    if (b ~ /^2b-S[0-9]+\.md$/) {
      s = b; sub(/^2b-/, "", s); sub(/\.md$/, "", s)
      printf "%s\t%s\t%s\t%d\t%s\n", s, cell(scname[p]), sccount[p], nblk[p], cell(scnotes[p]) > OUT_COV
    }
    if (nblk[p] == 0 && !nofind[p] && sccount[p] == "") warn = warn "\n  no finding blocks, no NO FINDINGS marker: " p
  }

  printf "raw_2a\t%d\nraw_2b\t%d\nraw_total\t%d\nmerged\t%d\n", raw["2a"], raw["2b"], n, ng > OUT_STATS

  printf "Phase 2 complete. Per-file pass: %d findings. Scenario pass: %d findings. After dedup: %d.\n", raw["2a"], raw["2b"], ng
  printf "Severity breakdown: Critical %d, High %d, Medium %d, Low %d", bysev[4], bysev[3], bysev[2], bysev[1]
  if (bysev[0]) printf ", Unrated %d", bysev[0]
  printf "\n"
  if (warn != "") printf "WARNINGS:%s\n", warn
}
