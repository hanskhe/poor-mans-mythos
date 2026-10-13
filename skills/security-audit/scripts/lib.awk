# Shared helpers for the security-audit scripts. POSIX awk only (tested with
# mawk and BWK awk, the awk shipped with macOS).
#
# parse_line() turns ---FINDING--- / ---VALIDATED--- blocks (see
# references/finding-format.md) into records:
#   NREC              number of records parsed so far
#   RTYPE[i]          "F" (raw/merged finding) or "V" (validated verdict)
#   RSRC[i]           file the record came from
#   R[i, label]       single-line field values (wrapped lines are joined with spaces)
#   RX[i]             Excerpt, verbatim, fences included ("unchanged" is allowed for V)
# Callers must reset parser state at the start of every input file:
#   FNR == 1 { parse_reset() }

function init_known(   n, a, i) {
  n = split("ID File Lines Title Severity Confidence OWASP CWE Source Excerpt Detail DataFlow References Status AdjustedSeverity DuplicateOf Reasoning Fix", a, " ")
  for (i = 1; i <= n; i++) KNOWN[a[i]] = 1
}

function trim(s) { sub(/^[ \t\r]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }

function parse_reset() { P_in = 0; P_mode = ""; P_field = "" }

function parse_open(type, src) {
  P_n = ++NREC; RTYPE[P_n] = type; RSRC[P_n] = src; RX[P_n] = ""
  P_in = 1; P_mode = ""; P_field = ""
}

# Returns 1 if the line belonged to a block (or opened/closed one), 0 otherwise.
function parse_line(line, src,   t, lbl, val) {
  t = trim(line)
  if (t == "---FINDING---")   { parse_open("F", src); return 1 }
  if (t == "---VALIDATED---") { parse_open("V", src); return 1 }
  if (!P_in) return 0
  if (t == "---END FINDING---" || t == "---END VALIDATED---") { P_in = 0; P_mode = ""; return 1 }

  if (P_mode == "code") {
    RX[P_n] = RX[P_n] line "\n"
    if (t ~ /^```[ \t]*$/) P_mode = ""
    return 1
  }
  if (P_mode == "exc") {
    if (t ~ /^```/) { RX[P_n] = RX[P_n] line "\n"; P_mode = "code"; return 1 }
    if (t == "") return 1
  }
  if (match(line, /^[ \t]*[*_]*[A-Za-z]+[*_]*:/)) {
    lbl = substr(line, RSTART, RLENGTH - 1); gsub(/[ \t*_]/, "", lbl)
    if (lbl in KNOWN) {
      val = substr(line, RSTART + RLENGTH); sub(/^[*_]+/, "", val); val = trim(val)
      if (lbl == "Excerpt") {
        P_field = ""
        if (val == "") P_mode = "exc"; else { RX[P_n] = val; P_mode = "" }
        return 1
      }
      R[P_n, lbl] = val; P_field = lbl; P_mode = ""
      return 1
    }
  }
  if (P_mode == "exc") { RX[P_n] = RX[P_n] line "\n"; return 1 }
  if (P_field != "" && t != "") R[P_n, P_field] = (R[P_n, P_field] == "" ? t : R[P_n, P_field] " " t)
  return 1
}

function sevrank(s) {
  s = tolower(trim(s))
  if (s ~ /^crit/) return 4; if (s ~ /^high/) return 3
  if (s ~ /^med/) return 2;  if (s ~ /^low/) return 1
  return 0
}
function sevname(r) { return r == 4 ? "Critical" : r == 3 ? "High" : r == 2 ? "Medium" : r == 1 ? "Low" : "Unrated" }
function confrank(s) {
  s = tolower(trim(s))
  if (s ~ /^high/) return 3; if (s ~ /^med/) return 2; if (s ~ /^low/) return 1
  return 0
}

function cwekey(c,   u) {
  u = toupper(c)
  if (match(u, /CWE-?[0-9]+/)) { u = substr(u, RSTART, RLENGTH); sub(/CWE-?/, "", u); return "CWE-" (u + 0) }
  return ""
}

# Normalized category key: A05, API1, or NA:<cwe>. A finding outside both lists
# and without a CWE gets a unique key so it is never merged mechanically.
function owaspkey(o, cwe, uniq,   u, c) {
  u = toupper(o)
  if (match(u, /API[0-9]+/)) return "API" (substr(u, RSTART + 3, RLENGTH - 3) + 0)
  if (match(u, /A[0-9]+/))   return sprintf("A%02d", substr(u, RSTART + 1, RLENGTH - 1) + 0)
  c = cwekey(cwe)
  return c != "" ? "NA:" c : "NA:#" uniq
}

function normfile(f) {
  f = trim(f); gsub(/`/, "", f)
  sub(/^\.\//, "", f); sub(/:[0-9][0-9 ,–-]*$/, "", f)
  return f
}

# Line range helpers: "42", "38-51", "38–51", "12, 40-44" -> min / max.
function linelo(s,   n, a, i, v) {
  gsub(/[^0-9]+/, " ", s); n = split(s, a, " "); v = ""
  for (i = 1; i <= n; i++) if (v == "" || a[i] + 0 < v) v = a[i] + 0
  return v
}
function linehi(s,   n, a, i, v) {
  gsub(/[^0-9]+/, " ", s); n = split(s, a, " "); v = ""
  for (i = 1; i <= n; i++) if (v == "" || a[i] + 0 > v) v = a[i] + 0
  return v
}

function normstatus(s) {
  s = tolower(s); gsub(/[^a-z]/, "", s)
  if (s ~ /^confirm/) return "confirmed"
  if (s ~ /^false/)   return "falsepositive"
  if (s ~ /^down/)    return "downgraded"
  if (s ~ /^up/)      return "upgraded"
  if (s ~ /^dup/)     return "duplicate"
  return s
}

# Union of comma-separated lists, order preserved, duplicates dropped.
function listunion(a, b,   n, x, i, seen, out, v) {
  out = ""
  n = split(a "," b, x, ",")
  for (i = 1; i <= n; i++) {
    v = trim(x[i])
    if (v == "" || v in seen) continue
    seen[v] = 1; out = (out == "" ? v : out ", " v)
  }
  return out
}

function cell(s) { gsub(/\|/, "\\|", s); gsub(/\t/, " ", s); return s }
function basename(p,   n, a) { n = split(p, a, "/"); return a[n] }
function dirname(p) { if (p !~ /\//) return "."; sub(/\/[^\/]*$/, "", p); return p }

function render_finding(i, id,   s) {
  s = "---FINDING---\n"
  if (id != "") s = s "ID: " id "\n"
  s = s "File: " R[i, "File"] "\nLines: " R[i, "Lines"] "\nTitle: " R[i, "Title"] "\n"
  s = s "Severity: " R[i, "Severity"] "\nConfidence: " R[i, "Confidence"] "\n"
  s = s "OWASP: " R[i, "OWASP"] "\nCWE: " R[i, "CWE"] "\nSource: " R[i, "Source"] "\n"
  s = s "Excerpt:\n" RX[i]
  if (RX[i] != "" && RX[i] !~ /\n$/) s = s "\n"
  s = s "Detail: " R[i, "Detail"] "\nDataFlow: " R[i, "DataFlow"] "\nReferences: " R[i, "References"] "\n"
  return s "---END FINDING---\n"
}
