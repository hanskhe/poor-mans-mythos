# Phase 4 + final report. Joins merged findings with validator verdicts and
# writes coverage.md and the report. Inputs are recognized by file name.
# Vars: OUT_COV, OUT_REP, REPO, DATE, STACK

BEGIN {
  init_known(); FS = "\t"
  split("Broken Access Control|Security Misconfiguration|Software Supply Chain Failures|Cryptographic Failures|Injection|Insecure Design|Authentication Failures|Software or Data Integrity Failures|Security Logging and Alerting Failures|Mishandling of Exceptional Conditions", WEBN, "|")
  split("Broken Object Level Authorization|Broken Authentication|Broken Object Property Level Authorization|Unrestricted Resource Consumption|Broken Function Level Authorization|Unrestricted Access to Sensitive Business Flows|Server-Side Request Forgery|Security Misconfiguration|Improper Inventory Management|Unsafe Consumption of APIs", APIN, "|")
  # Categories each scenario is designed to probe (scenarios.md).
  nm = split("S1:A05;S2:A01,API1,API3;S3:A01,API5;S4:A01,API7;S5:A01,A02,A07,API2,API8;S6:A04,A07;S7:A08;S8:A06,A10,API4,API6;S9:A09,A02;S10:A10", m, ";")
  for (i = 1; i <= nm; i++) {
    split(m[i], kv, ":"); nc = split(kv[2], cs, ",")
    for (j = 1; j <= nc; j++) TOUCH[cs[j]] = listunion(TOUCH[cs[j]], kv[1])
  }
}

FNR == 1 {
  parse_reset(); f = FILENAME
  kind = f ~ /stats\.tsv$/ ? "stats" : f ~ /scenarios\/index\.tsv$/ ? "scidx" : f ~ /findings-index\.tsv$/ ? "idx" \
       : f ~ /findings-merged\.md$/ ? "merged" : f ~ /clusters\.tsv$/ ? "clu" : f ~ /validated\/[^\/]*\.md$/ ? "val" \
       : f ~ /coverage-2b\.tsv$/ ? "cov" : f ~ /file-classes\.tsv$/ ? "cls" : f ~ /phase2a-files\.tsv$/ ? "sel" \
       : f ~ /usage\.tsv$/ ? "use" : f ~ /recon\.md$/ ? "recon" : "other"
  insec = 0
}

kind == "stats" { ST[$1] = $2; next }
kind == "scidx" { NSC++; SCID[NSC] = $1; SCNAME[$1] = $2; next }
kind == "idx"   { NID++; IDS[NID] = $1; XSEV[$1] = sevrank($2); XCONF[$1] = $3; XOK[$1] = $4; XFILE[$1] = $5; XLINES[$1] = $6; XTITLE[$1] = $7; XSRC[$1] = $8; next }
kind == "merged" || kind == "val" { parse_line($0, f); next }
kind == "clu"   { n = split($2, a, ","); for (i = 1; i <= n; i++) SELECTED[a[i]] = $1; next }
kind == "cov"   { COVH[$1] = 1; COVN[$1] = $2; COVD[$1] = $3; COVB[$1] = $4; COVNOTE[$1] = $5; next }
kind == "cls"   { CNT[$1]++; TOT++; if ($1 == "review") { NREV++; REV[NREV] = $3; REVWHY[$3] = $4 }; next }
kind == "sel"   { NSEL++; IN2A[$1] = 1; OUT2A[NSEL] = $2; next }
kind == "use"   { p = $1; UN[p]++; if ($3 ~ /^[0-9]+$/) { UT[p] += $3; UTN[p]++ }; if ($4 ~ /^[0-9]+$/) UTL[p] += $4; if (!(p in UORD)) { NUP++; UORD[p] = NUP; UP[NUP] = p }; next }
kind == "recon" {
  if ($0 ~ /^#+ /) {
    lvl = $0; sub(/ .*/, "", lvl); lvl = length(lvl)
    if (insec && lvl <= seclvl) insec = 0
    if ($0 ~ /[Oo]ut.of.[Ss]cope/) { insec = 1; seclvl = lvl; next }
  }
  if (insec) OOS = OOS $0 "\n"
  next
}

function normid(s,   u) { u = toupper(trim(s)); if (match(u, /F[0-9]+/)) return sprintf("F%03d", substr(u, RSTART + 1, RLENGTH - 1) + 0); return u }
function isreal(st) { return st == "confirmed" || st == "upgraded" || st == "downgraded" }
function hasphase(src, ph,   n, a, i) { n = split(src, a, ","); for (i = 1; i <= n; i++) if (index(trim(a[i]), ph ":") == 1) return 1; return 0 }
function hastag(src, tag,   n, a, i) { n = split(src, a, ","); for (i = 1; i <= n; i++) if (trim(a[i]) == tag) return 1; return 0 }
function fence(x) { if (x == "") return "_(no excerpt)_\n"; if (x !~ /^[ \t]*```/) x = "```\n" x (x ~ /\n$/ ? "" : "\n") "```\n"; return x (x ~ /\n$/ ? "" : "\n") }
function loc(id) { return "`" XFILE[id] (XLINES[id] != "" ? ":" XLINES[id] : "") "`" }
function fmt(n) { return n == "" ? 0 : n }
function thousands(n,   s, out) { s = sprintf("%d", n); out = ""; while (length(s) > 3) { out = "," substr(s, length(s) - 2) out; s = substr(s, 1, length(s) - 3) }; return s out }

function coverage(h,   s, k, sid, raised, conf, note, i, id, c, key, name, nf, nr, t, ocount, oreal) {
  s = h " Scenarios\n\n| Scenario | Findings raised | Confirmed | Notes |\n|---|---|---|---|\n"
  for (k = 1; k <= NSC; k++) {
    sid = SCID[k]
    if (!(sid in COVH)) { s = s "| " sid " " cell(SCNAME[sid]) " | — | — | **No output: the scenario agent did not complete.** |\n"; continue }
    conf = 0
    for (i = 1; i <= NID; i++) { id = IDS[i]; if (isreal(STATUS[id]) && hastag(XSRC[id], "2b:" sid)) conf++ }
    note = COVNOTE[sid]; if (COVD[sid] != "" && COVD[sid] + 0 != COVB[sid] + 0) note = note " _(agent declared " COVD[sid] ", " COVB[sid] " parsed)_"
    s = s "| " sid " " cell(SCNAME[sid]) " | " COVB[sid] " | " conf " | " note " |\n"
  }

  s = s "\n" h " Which pass found what\n\n| Found by | Confirmed | All merged findings |\n|---|---|---|\n"
  s = s "| Per-file pass (2a) only | " fmt(PROV_R["2a"]) " | " fmt(PROV_A["2a"]) " |\n"
  s = s "| Scenario pass (2b) only | " fmt(PROV_R["2b"]) " | " fmt(PROV_A["2b"]) " |\n"
  s = s "| Both | " fmt(PROV_R["both"]) " | " fmt(PROV_A["both"]) " |\n"
  s = s "\nThe two passes overlap on purpose. These counts show, over time, how much each pass adds on its own.\n"

  s = s "\n" h " OWASP Top 10 (2025)\n\n| Category | Findings | Confirmed | Scenarios (designed for / raised here) |\n|---|---|---|---|\n"
  for (c = 1; c <= 10; c++) { key = sprintf("A%02d", c); s = s "| " key " " WEBN[c] " | " fmt(OCNT[key]) " | " fmt(OREAL[key]) " | " (TOUCH[key] == "" ? "—" : TOUCH[key]) " |\n" }
  s = s "\n" h " OWASP API Security Top 10 (2023)\n\n| Category | Findings | Confirmed | Scenarios (designed for / raised here) |\n|---|---|---|---|\n"
  for (c = 1; c <= 10; c++) { key = "API" c; s = s "| " key " " APIN[c] " | " fmt(OCNT[key]) " | " fmt(OREAL[key]) " | " (TOUCH[key] == "" ? "—" : TOUCH[key]) " |\n" }
  s = s "\nFindings outside both lists: " fmt(OCNT["NA"]) " (" fmt(OREAL["NA"]) " confirmed).\n"

  s = s "\n" h " Coverage gaps\n\n"
  t = ""
  for (i = 1; i <= NREV; i++) if (!(REV[i] in IN2A)) { nf++; t = t "  - `" REV[i] "` — " REVWHY[REV[i]] "\n" }
  if (nf) s = s "- **Review files not covered by the per-file pass** (user chose to review the top " NSEL "): " nf ". Scenario agents still searched across them.\n" t
  t = ""; nr = 0
  for (i = 1; i <= NSEL; i++) if ((getline line < OUT2A[i]) < 0) { nr++; t = t "  - `" OUT2A[i] "`\n" } else close(OUT2A[i])
  if (nr) s = s "- **Per-file agents that produced no output:** " nr "\n" t
  if (MISSINGV != "") s = s "- **Selected for validation but no verdict returned:** " MISSINGV "\n"
  if (UNCLEAR != "") s = s "- **Unrecognized validation status:** " UNCLEAR "\n"
  if (NUNVAL) s = s "- **Not validated (user truncation):** " NUNVAL ". See Not Validated.\n"
  t = ""
  for (k = 1; k <= NSC; k++) { sid = SCID[k]; if ((sid in COVH) && COVB[sid] + 0 == 0) t = t "  - " sid " " SCNAME[sid] ": " (COVNOTE[sid] == "" ? "_no notes_" : COVNOTE[sid]) "\n" }
  if (t != "") s = s "- **Scenarios with zero findings.** Judge from the notes whether the zero is a confident one:\n" t
  s = s "- **Skim (" fmt(CNT["skim"]) ") and Skip (" fmt(CNT["skip"]) ") files** got no dedicated reviewer. See `.security-audit/file-rankings.md`.\n"

  s = s "\n" h " Out of scope\n\n" (OOS == "" ? "_Not recorded in recon.md._\n" : OOS)
  s = s "\n" h " Known limitations\n\n"
  s = s "- Static reading only. Behavior that emerges only at runtime (config pulled from a secret store, feature flags) is not exercised.\n"
  s = s "- No dependency CVE matching; manifests are only checked for risky patterns (unpinned versions, suspicious packages).\n"
  s = s "- No dynamic analysis, fuzzing, or live exploitation.\n"
  s = s "- Physical attacks and social engineering are out of scope for this audit.\n"
  return s
}

function finding_section(id, v, m,   s, sv, os, ex) {
  sv = ADJ[id]; os = XSEV[id]
  s = "#### [" id "] " XTITLE[id] "\n"
  s = s "- **File:** " loc(id) "\n"
  s = s "- **OWASP:** " (m ? R[m, "OWASP"] : XOK[id]) " · **CWE:** " (m ? R[m, "CWE"] : "N/A") "\n"
  s = s "- **Severity:** " sevname(sv) (sv != os ? " (was: " sevname(os) ")" : "") " · **Confidence:** " XCONF[id] " · **Status:** " R[v, "Status"] "\n"
  s = s "- **Found by:** " XSRC[id] "\n\n"
  ex = RX[v]; if (ex == "" || tolower(trim(ex)) ~ /^unchanged/) ex = (m ? RX[m] : "")
  s = s fence(ex) "\n"
  if (m) s = s "**Detail:** " R[m, "Detail"] "\n\n**Data flow:** " R[m, "DataFlow"] "\n\n"
  s = s "**Validation:** " R[v, "Reasoning"] "\n\n**Fix:** " R[v, "Fix"] "\n\n"
  return s
}

END {
  for (i = 1; i <= NREC; i++) {
    id = normid(R[i, "ID"])
    if (RTYPE[i] == "F") MREC[id] = i
    else if (RTYPE[i] == "V") { if (id in VREC) DUPV = DUPV " " id; VREC[id] = i }
  }

  for (i = 1; i <= NID; i++) {
    id = IDS[i]; os = XSEV[id]
    ok = XOK[id]; if (ok ~ /^NA/) ok = "NA"
    OCNT[ok]++
    nsrc = split(XSRC[id], srcs, ",")
    for (j = 1; j <= nsrc; j++) { tg = trim(srcs[j]); if (tg ~ /^2b:S[0-9]+$/) TOUCH[ok] = listunion(TOUCH[ok], substr(tg, 4)) }
    prov = hasphase(XSRC[id], "2a") ? (hasphase(XSRC[id], "2b") ? "both" : "2a") : "2b"
    PROV_A[prov]++
    if (id in VREC) {
      v = VREC[id]; st = normstatus(R[v, "Status"]); STATUS[id] = st
      adj = sevrank(R[v, "AdjustedSeverity"]); ADJ[id] = (adj ? adj : os)
      if (isreal(st)) { NREAL++; REAL[ADJ[id]]++; OREAL[ok]++; PROV_R[prov]++; if (ADJ[id] != os) CHG[ADJ[id]]++ }
      else if (st == "falsepositive") { NFP++; FP[os]++ }
      else if (st == "duplicate") { NDUP++; DUP[os]++ }
      else { UNCLEAR = UNCLEAR " " id " (" R[v, "Status"] ")" }
      NVAL++
    } else if (id in SELECTED) { MISSINGV = MISSINGV " " id; NMISS++; UNV[os]++; STATUS[id] = "missing" }
    else { NUNVAL++; UNV[os]++; STATUS[id] = "unvalidated" }
  }
  nselv = 0; for (id in SELECTED) nselv++

  COV = coverage("##")
  printf "# Audit Coverage\n\n%s", COV > OUT_COV

  o = "# Security Audit Report\n\n"
  o = o "**Repository:** " REPO "  \n**Date:** " DATE "  \n**Stack:** " STACK "  \n"
  o = o "**Files classified:** " fmt(TOT) " (Review " fmt(CNT["review"]) " · Skim " fmt(CNT["skim"]) " · Skip " fmt(CNT["skip"]) ")  \n"
  o = o "**Files reviewed in Phase 2a:** " fmt(NSEL) " of " fmt(NREV) " Review files  \n"
  o = o "**Findings raised:** " fmt(ST["raw_total"]) " (2a: " fmt(ST["raw_2a"]) ", 2b: " fmt(ST["raw_2b"]) "), " fmt(NID) " after deduplication  \n"
  o = o "**Findings validated:** " fmt(NVAL) " of " nselv " selected  \n"
  o = o "**Findings confirmed:** " fmt(NREAL) "\n\n---\n\n"

  o = o "## Executive Summary\n\n| Severity | Confirmed | of which re-rated | False positives | Duplicates | Not validated |\n|---|---|---|---|---|---|\n"
  for (s = 4; s >= 1; s--) o = o "| " sevname(s) " | " fmt(REAL[s]) " | " fmt(CHG[s]) " | " fmt(FP[s]) " | " fmt(DUP[s]) " | " fmt(UNV[s]) " |\n"
  tchg = 0; for (s = 1; s <= 4; s++) tchg += CHG[s]
  o = o "| **Total** | **" fmt(NREAL) "** | **" tchg "** | **" fmt(NFP) "** | **" fmt(NDUP) "** | **" (NUNVAL + NMISS) "** |\n\n"
  o = o "Confirmed findings are counted at their validated severity. False positives, duplicates and unvalidated findings are counted at the severity they were raised with.\n"
  crit = ""
  for (i = 1; i <= NID; i++) { id = IDS[i]; if (isreal(STATUS[id]) && ADJ[id] == 4) crit = crit "- [" id "] " XTITLE[id] " — " loc(id) "\n" }
  if (crit != "") o = o "\n**Critical findings:**\n\n" crit
  o = o "\n---\n\n## Confirmed Findings\n"
  for (s = 4; s >= 0; s--) {
    if (s == 0 && !REAL[0]) continue
    o = o "\n### " sevname(s) "\n\n"; any = 0
    for (i = 1; i <= NID; i++) { id = IDS[i]; if (isreal(STATUS[id]) && ADJ[id] == s) { any = 1; o = o finding_section(id, VREC[id], MREC[id]) } }
    if (!any) o = o "_None._\n"
  }

  o = o "\n---\n\n## Adjusted Findings (severity changed during validation)\n\n"
  t = ""; for (i = 1; i <= NID; i++) { id = IDS[i]; if (isreal(STATUS[id]) && ADJ[id] != XSEV[id]) t = t "| " id " | " cell(XTITLE[id]) " | " loc(id) " | " sevname(XSEV[id]) " → " sevname(ADJ[id]) " | " cell(R[VREC[id], "Reasoning"]) " |\n" }
  o = o (t == "" ? "_None._\n" : "| ID | Title | File | Original → Adjusted | Why |\n|---|---|---|---|---|\n" t)

  o = o "\n## False Positives\n\n"
  t = ""; for (i = 1; i <= NID; i++) { id = IDS[i]; if (STATUS[id] == "falsepositive") t = t "| " id " | " loc(id) " | " cell(XTITLE[id]) " | " cell(R[VREC[id], "Reasoning"]) " |\n" }
  o = o (t == "" ? "_None._\n" : "| ID | File | Issue | Reason dismissed |\n|---|---|---|---|\n" t)

  o = o "\n## Duplicates found during validation\n\n"
  t = ""; for (i = 1; i <= NID; i++) { id = IDS[i]; if (STATUS[id] == "duplicate") t = t "| " id " | " cell(XTITLE[id]) " | " normid(R[VREC[id], "DuplicateOf"]) " |\n" }
  o = o (t == "" ? "_None._\n" : "| ID | Title | Duplicate of |\n|---|---|---|\n" t)

  o = o "\n## Not Validated\n\n"
  t = ""; for (i = 1; i <= NID; i++) { id = IDS[i]; if (STATUS[id] == "unvalidated" || STATUS[id] == "missing") t = t "| " id " | " sevname(XSEV[id]) " | " cell(XTITLE[id]) " | " loc(id) " | " (STATUS[id] == "missing" ? "validator returned no verdict" : "not selected for validation") " |\n" }
  o = o (t == "" ? "_None._\n" : "| ID | Raised severity | Title | File | Why |\n|---|---|---|---|---|\n" t)
  if (t != "") o = o "\nFull details of these findings are in `.security-audit/findings-merged.md`.\n"

  o = o "\n---\n\n## Auditor Notes\n\n_None._\n"
  o = o "\n---\n\n## Coverage\n\n" coverage("###")

  o = o "\n---\n\n## Token Usage (subagents)\n\n"
  if (NUP == 0) o = o "_Not recorded._\n"
  else {
    o = o "| Phase | Agents | Total tokens | Avg per agent | Tool uses |\n|---|---|---|---|---|\n"
    gt = 0; ga = 0
    for (k = 1; k <= NUP; k++) { p = UP[k]; gt += UT[p]; ga += UN[p]; o = o "| " p " | " UN[p] " | " thousands(UT[p]) " | " (UTN[p] ? thousands(UT[p] / UTN[p]) : "—") " | " fmt(UTL[p]) " |\n" }
    o = o "| **Total** | **" ga "** | **" thousands(gt) "** | | |\n\nThe orchestrating session's own usage is not included (see `/cost`).\n"
  }
  printf "%s", o > OUT_REP

  printf "Security audit complete. Report saved to %s.\n", OUT_REP
  printf "Confirmed: %d Critical, %d High, %d Medium, %d Low.\n", REAL[4], REAL[3], REAL[2], REAL[1]
  printf "%d dismissed as false positives. %d marked duplicate during validation (%d raw findings were merged before validation). %d not validated.\n", NFP, NDUP, ST["raw_total"] - NID, NUNVAL + NMISS
  if (crit != "") printf "\nCRITICAL:\n%s", crit
  if (MISSINGV != "") printf "\nWARNING: no verdict for:%s\n", MISSINGV
  if (UNCLEAR != "") printf "WARNING: unrecognized status for:%s\n", UNCLEAR
  if (DUPV != "") printf "WARNING: more than one verdict for:%s (last one used)\n", DUPV
}
