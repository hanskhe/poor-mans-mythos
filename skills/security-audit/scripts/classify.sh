#!/usr/bin/env bash
# Phase 1 file classification. Run from the root of the audited repository.
#
#   classify.sh scan        Enumerate files, apply the path rules from
#                           risk-rating-guide.md, grep the leftovers for risky
#                           primitives. Prints counts and the files that still
#                           need a decision from the orchestrator.
#   classify.sh finalize    Promote files referenced in recon.md, apply
#                           .security-audit/class-overrides.tsv, write
#                           file-classes.tsv and file-rankings.md.
#   classify.sh select N    Pick the top N Review files (or "all") for Phase 2a
#                           and write phase2a-files.tsv (path <TAB> output file).
#
# file-classes.tsv columns: bucket <TAB> priority <TAB> path <TAB> reason
# bucket is review | skim | skip | decide (decide only exists before finalize).
set -eu

A=.security-audit
BASE="$A/file-classes.base.tsv"
FINAL="$A/file-classes.tsv"
TAB=$(printf '\t')

die() { echo "$*" >&2; exit 1; }
[ -d "$A" ] || die "Run init.sh first."

# Grep pattern for "this file touches something security-relevant".
SIGNALS='exec\(|execsync|spawn\(|system\(|popen|subprocess|shell_exec|eval\(|new function|pickle|unserialize|marshal\.load|yaml\.load|deserializ|readobject|innerhtml|dangerouslysetinnerhtml|render_template|\.raw\(|\.query\(|\.execute\(|select |insert into|delete from|req\.|request\.|\$_(get|post|request|cookie|files)|fetch\(|axios|requests\.|httpx|urlopen|http\.get|readfile|writefile|sendfile|upload|password|passwd|secret|token|api_?key|private_?key|crypto|cipher|hmac|md5|sha1|random|jwt|cookie|session|redirect|cors|csrf|authori[sz]|permission|is_?admin'

enumerate() {
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git ls-files -co --exclude-standard
  else
    find . \( -name .git -o -name node_modules -o -name vendor -o -name .venv -o -name venv \
              -o -name dist -o -name build -o -name out -o -name .next -o -name target \
              -o -name coverage -o -name .security-audit \) -prune -o -type f -print | sed 's#^\./##'
  fi | while IFS= read -r p; do
    [ -f "$p" ] && [ ! -L "$p" ] && printf '%s\n' "$p"
  done | LC_ALL=C sort -u
}

# Path rules. Order matters: first match wins.
rules() {
  awk -F'\t' '
  function comp(re,   n, a, i) { n = split(lp, a, "/"); for (i = 1; i <= n; i++) if (a[i] ~ re) return 1; return 0 }
  function dircomp(re,   n, a, i) { n = split(lp, a, "/"); for (i = 1; i < n; i++) if (a[i] ~ re) return 1; return 0 }
  function set(bk, pr, rs) { BK = bk; PRI = pr; WHY = rs; return 1 }
  {
    p = $0; lp = tolower(p); n = split(lp, parts, "/"); b = parts[n]; BK = ""
    if (dircomp("^(node_modules|vendor|\\.venv|venv|dist|build|out|\\.next|target|coverage|\\.security-audit|__pycache__|bower_components)$")) set("skip", 99, "vendored / build output")
    else if (b ~ /\.lock$/ || b ~ /^(package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|go\.sum)$/) set("skip", 99, "lockfile")
    else if (b ~ /^\.env\.(example|sample|template|dist)$/) set("skim", 50, "env example (secrets surface)")
    else if (b ~ /^\.env(\..+)?$/ || b ~ /\.(pem|key|p12|pfx|jks|keystore)$/ || b ~ /^id_(rsa|dsa|ecdsa|ed25519)/ || b ~ /^(credentials\.json|\.npmrc|\.pypirc|\.htpasswd|\.netrc)$/ || b ~ /^service-account.*\.json$/) set("review", 2, "secret-bearing file")
    else if (b ~ /^(package\.json|requirements.*\.txt|pipfile|pyproject\.toml|cargo\.toml|go\.mod|gemfile|composer\.json|pom\.xml|build\.gradle(\.kts)?)$/) set("review", 9, "dependency manifest")
    else if (b ~ /^dockerfile/ || b ~ /^(docker-)?compose.*\.ya?ml$/ || b ~ /\.(tf|tfvars)$/ || b ~ /^serverless\.ya?ml$/ || b ~ /^cloudformation.*\.(ya?ml|json)$/ || b == ".gitlab-ci.yml" || lp ~ /^\.github\/workflows\/.*\.ya?ml$/) set("review", 7, "infrastructure / CI definition")
    else if (b ~ /\.(md|mdx|rst|txt|adoc)$/ || b ~ /^(license|licence|copying|changelog|authors|contributors|notice)/) set("skip", 99, "documentation")
    else if (b ~ /\.(png|jpe?g|gif|svg|ico|webp|bmp|tiff?|woff2?|ttf|otf|eot|mp[34]|wav|ogg|webm|mov|pdf|zip|gz|tgz|jar|class|pyc|so|dylib|dll|exe|wasm)$/) set("skip", 99, "static asset / binary")
    else if (b ~ /\.min\.(js|css)$/ || b ~ /\.map$/) set("skip", 99, "minified / source map")
    else if (dircomp("^(tests?|spec|specs|__tests__|__mocks__|testdata|fixtures|e2e)$") || b ~ /\.(test|spec)\.[^.]+$/ || b ~ /^test_.*\.py$/ || b ~ /_test\.(go|py|rb|exs?)$/ || b ~ /^conftest\.py$/) set("skim", 50, "test")
    else if (dircomp("^(locales?|i18n|translations|lang)$") || b ~ /\.(po|pot|mo)$/) set("skim", 50, "i18n")
    else if (b ~ /\.d\.ts$/) set("skim", 50, "type declarations")
    else if (dircomp("^(examples?|docs?|samples?)$")) set("skim", 50, "examples / docs code")
    else if (dircomp("^(migrations|migrate)$")) set("skim", 50, "migration")
    else if (b ~ /^(webpack|vite|babel|jest|vitest|rollup|postcss|tailwind|karma|playwright|cypress)\.config\./ || b ~ /^tsconfig.*\.json$/ || b ~ /^\.?eslint/ || b ~ /^\.?prettier/ || b ~ /^\.(editorconfig|gitignore|gitattributes|dockerignore|nvmrc|python-version)$/) set("skim", 50, "build / tooling config")
    else if (b ~ /\.(css|scss|sass|less|styl)$/) set("skim", 50, "stylesheet")
    else if (comp("^(auth|session|jwt|oauth|login|logout|signin|signup|password|permission|policy|policies|rbac|acl|middleware|guard)")) set("review", 3, "auth / access-control module")
    else if (dircomp("^(routes|router|routers|controllers|handlers|endpoints|views|resolvers)$") || lp ~ /(^|\/)(pages|app)\/api\//) set("review", 4, "route / handler")
    else if (comp("^(crypto|encrypt|decrypt|cipher|hash|signing|signature|tokens?)")) set("review", 5, "crypto / token module")
    else if (dircomp("^(models|repositories|repository|db|dao|database)$") || b ~ /^(queries|database|db)\./) set("review", 6, "data-access layer")
    else if (b ~ /(upload|deserializ|serializ|unmarshal|template|render)/) set("review", 6, "upload / (de)serialization / templating")
    else set("decide", 0, "")
    printf "%s\t%d\t%s\t%s\n", BK, PRI, p, WHY
  }'
}

scan() {
  enumerate | rules > "$BASE.tmp"

  # Binary or empty files among the non-skipped ones become skip.
  awk -F'\t' '$1 != "skip" { print $3 }' "$BASE.tmp" | tr '\n' '\0' \
    | xargs -0 grep -IL '' -- 2>/dev/null > "$A/.binary.tmp" || true

  # Migrations that grant privileges or touch row-level security get promoted.
  awk -F'\t' '$4 == "migration" { print $3 }' "$BASE.tmp" | tr '\n' '\0' \
    | xargs -0 grep -ilE 'grant |row level security|create policy|drop policy|security definer|disable trigger' -- 2>/dev/null > "$A/.migr.tmp" || true

  # Undecided files: record which risky primitives they mention; none -> skim.
  : > "$A/.signals.tmp"
  awk -F'\t' '$1 == "decide" { print $3 }' "$BASE.tmp" | while IFS= read -r f; do
    s=$(grep -oiE "$SIGNALS" -- "$f" 2>/dev/null | tr 'A-Z' 'a-z' | sort | uniq -c | sort -rn | head -6 \
        | awk '{ printf "%s%s(%s)", sep, $2, $1; sep = " " }') || true
    printf '%s\t%s\n' "$f" "$s" >> "$A/.signals.tmp"
  done

  awk -F'\t' -v OFS='\t' '
    FILENAME ~ /\.binary\.tmp$/ { bin[$0] = 1; next }
    FILENAME ~ /\.migr\.tmp$/   { mig[$0] = 1; next }
    FILENAME ~ /\.signals\.tmp$/ { sig[$1] = $2; next }
    {
      if ($3 in bin) { $1 = "skip"; $2 = 99; $4 = "binary or empty" }
      else if ($3 in mig) { $1 = "review"; $2 = 6; $4 = "migration with grants / RLS / policies" }
      else if ($1 == "decide") {
        if (sig[$3] == "") { $1 = "skim"; $2 = 50; $4 = "no risky-primitive signal (scripted)" }
        else $4 = "signals: " sig[$3]
      }
      print
    }' "$A/.binary.tmp" "$A/.migr.tmp" "$A/.signals.tmp" "$BASE.tmp" > "$BASE"
  rm -f "$BASE.tmp" "$A/.binary.tmp" "$A/.migr.tmp" "$A/.signals.tmp"

  awk -F'\t' '{ c[$1]++; t++ } END {
    printf "Files: %d  review %d · skim %d · skip %d · needs decision %d\n", t, c["review"], c["skim"], c["skip"], c["decide"] }' "$BASE"
  nd=$(awk -F'\t' '$1 == "decide"' "$BASE" | wc -l | tr -d ' ')
  if [ "$nd" -gt 0 ]; then
    echo
    echo "Needs decision (path <TAB> risky primitives seen):"
    awk -F'\t' '$1 == "decide" { printf "%s\t%s\n", $3, substr($4, 10) }' "$BASE" | head -200
    [ "$nd" -le 200 ] || echo "... $((nd - 200)) more: awk -F'\\t' '\$1==\"decide\"' $BASE"
  fi
}

finalize() {
  [ -f "$BASE" ] || die "Run 'classify.sh scan' first."
  [ -f "$A/recon.md" ] || die "Write $A/recon.md before finalizing (entry-point files are promoted from it)."
  ov="$A/class-overrides.tsv"; [ -f "$ov" ] || : > "$ov"

  awk -F'\t' -v OFS='\t' '
    # recon.md, minus its out-of-scope section, as one string to search for paths.
    FILENAME ~ /recon\.md$/ {
      if ($0 ~ /^#+ /) skipsec = ($0 ~ /[Oo]ut.of.[Ss]cope/)
      if (!skipsec) recon = recon "\n" $0
      next
    }
    FILENAME ~ /class-overrides\.tsv$/ {
      if (NF >= 2 && $1 ~ /^(review|skim|skip)$/) { p = $2; sub(/^\.\//, "", p); ob[p] = $1; orr[p] = (NF >= 3 ? $3 : "override") }
      next
    }
    function mentioned(p,   s, i, c) {
      s = recon
      while ((i = index(s, p)) > 0) {
        c = (i > 1) ? substr(s, i - 1, 1) : " "
        if (c !~ /[A-Za-z0-9_.\/-]/) return 1
        s = substr(s, i + length(p))
      }
      return 0
    }
    {
      if ($3 in ob) { $1 = ob[$3]; $2 = ($1 == "review" ? 5 : $1 == "skim" ? 50 : 99); $4 = orr[$3]; nov++ }
      else if (($1 == "skim" || $1 == "decide") && mentioned($3)) { $1 = "review"; $2 = 1; $4 = "referenced in recon.md (entry point / auth / outbound)"; nrec++ }
      else if ($1 == "review" && mentioned($3)) { $2 = 1; $4 = $4 "; referenced in recon.md" }
      else if ($1 == "decide") { $1 = "review"; $2 = 8; $4 = "undecided, defaulted up (" $4 ")"; nund++ }
      print
    }
    END {
      if (nrec) printf "Promoted from recon.md: %d\n", nrec > "/dev/stderr"
      if (nov)  printf "Overrides applied: %d\n", nov > "/dev/stderr"
      if (nund) printf "WARNING: %d undecided files defaulted to review\n", nund > "/dev/stderr"
    }' "$A/recon.md" "$ov" "$BASE" | LC_ALL=C sort -t "$TAB" -k2,2n -k3,3 > "$FINAL"

  {
    echo "# File Classification"
    echo
    echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    awk -F'\t' '{ c[$1]++; t++ } END { printf "Total files: %d\nReview: %d · Skim: %d · Skip: %d\n", t, c["review"], c["skim"], c["skip"] }' "$FINAL"
    for b in review skim; do
      echo
      awk -F'\t' -v b="$b" '$1 == b { n++ } END { printf "## %s (%d)\n", (b == "review" ? "Review" : "Skim"), n }' "$FINAL"
      awk -F'\t' -v b="$b" '$1 == b { printf "- %s — %s\n", $3, $4 }' "$FINAL"
    done
    echo
    awk -F'\t' '$1 == "skip" { n++ } END { printf "## Skip (%d)\n", n }' "$FINAL"
    awk -F'\t' '$1 == "skip" { c[$4]++ } END { for (r in c) printf "- %s: %d files\n", r, c[r] }' "$FINAL" | LC_ALL=C sort
  } > "$A/file-rankings.md"

  awk -F'\t' '{ c[$1]++; t++ } END { printf "Total files: %d  Review %d · Skim %d · Skip %d\n\n", t, c["review"], c["skim"], c["skip"] }' "$FINAL"
  echo "Review files, in Phase 2a priority order:"
  awk -F'\t' '$1 == "review" { n++; if (n <= 30) printf "%3d. %s — %s\n", n, $3, $4 } END { if (n > 30) printf "... and %d more (see %s)\n", n - 30, "'"$A"'/file-rankings.md" }' "$FINAL"
}

select_files() {
  [ -f "$FINAL" ] || die "Run 'classify.sh finalize' first."
  n=${1:-all}
  awk -F'\t' -v n="$n" '
    $1 == "review" {
      k++
      if (n != "all" && k > n + 0) exit
      slug = $3; gsub(/\//, "__", slug); gsub(/[^A-Za-z0-9._-]/, "_", slug)
      printf "%s\t.security-audit/findings/2a-%03d-%s.md\n", $3, k, slug
    }' "$FINAL" > "$A/phase2a-files.tsv"
  echo "Phase 2a: $(wc -l < "$A/phase2a-files.tsv" | tr -d ' ') files (path <TAB> output file):"
  cat "$A/phase2a-files.tsv"
}

case "${1:-}" in
  scan) scan ;;
  finalize) finalize ;;
  select) select_files "${2:-all}" ;;
  *) die "usage: classify.sh scan | finalize | select N|all" ;;
esac
