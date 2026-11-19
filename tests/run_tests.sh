#!/usr/bin/env bash
# Regression tests for webpeek.py against stub tools - no network, no root,
# no real scanning. Run after ANY change to webpeek.py:
#
#     bash tests/run_tests.sh
#
# The stubs in tests/stubs/ imitate each real tool's output shape (nmap XML,
# httpx JSONL with a WordPress fingerprint, \r progress meters, a WPScan stub
# that echoes its own arguments so token masking is genuinely exercised).
# They prove the orchestration and the evidence record, NOT that the real
# tools accept these flags - do one real run on a lab target for that.

set -u
export PYTHONDONTWRITEBYTECODE=1
HERE="$(cd "$(dirname "$0")" && pwd)"
A="$HERE/../webpeek.py"
OUT="$(mktemp -d)"
STUBS="$HERE/stubs"
chmod +x "$STUBS"/* 2>/dev/null
export PATH="$STUBS:/usr/bin:/bin"
WL="$OUT/wl.txt"; printf "admin\nlogin\napi\n" > "$WL"
# Isolation: a throwaway HOME so the operator's real
# ~/.config/exfiltra-webpeek/config.ini is never read, and no inherited keys.
export HOME="$OUT/home"; mkdir -p "$HOME"
# ...and an empty venv root, so real venvs in /opt/exfiltra-webpeek/venvs are
# never picked up in place of the stubs.
export WEBPEEK_VENV_ROOT="$OUT/no-venvs"; unset WEBPEEK_PIP_ARGS
# ...and nothing the installer does may reach the internet: wordlist downloads
# default to a dead local address unless a test points them at its own server.
export WEBPEEK_SECLISTS_BASE_URL="http://127.0.0.1:9"; unset WEBPEEK_SECLISTS_REF
export WEBPEEK_OPT_ROOT="$OUT/no-opt"
unset WEBPEEK_AI_PROVIDER WEBPEEK_AI_MODEL WEBPEEK_GEMINI_MODEL \
      WEBPEEK_ANTHROPIC_MODEL WEBPEEK_GEMINI_THINKING_LEVEL \
      GEMINI_API_KEY GOOGLE_API_KEY ANTHROPIC_API_KEY WPSCAN_API_TOKEN
# Config is read from webpeek.conf next to the script. Pin WEBPEEK_CONFIG (the
# path seam) at a file that does NOT exist, so tests never read the operator's
# real exfiltra_webpeek/webpeek.conf. conf() points it at a throwaway file.
export WEBPEEK_CONFIG="$OUT/no-config.conf"
PASS=0; FAIL=0
ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
# Newest run directory by modification time. NOT by name: "live.stub.test_*"
# sorts after "app.stub.test_*" regardless of when it ran.
latest(){ ls -dt "$OUT"/run/*/* 2>/dev/null | head -1; }
mf()   { python3 -c "import json,sys; m=json.load(open('$(latest)/manifest.json')); print($1)"; }
# Keys/token are read ONLY from webpeek.conf next to the script. WEBPEEK_CONFIG
# is the test-only seam that repoints the loader at a throwaway file, so the
# suite never writes a keys file into the real tool folder. conf() writes and
# arms one; noconf() disarms it.
CONF="$OUT/webpeek.conf"
conf(){ printf '%s\n' "$@" > "$CONF"; chmod 600 "$CONF"; export WEBPEEK_CONFIG="$CONF"; }
noconf(){ export WEBPEEK_CONFIG="$OUT/no-config.conf"; }   # back to a non-existent file, never the real one

cd "$HERE"

echo "== targets and the allow-list"
python3 "$A" -o "$OUT/gate" >/dev/null 2>&1
check "no target given -> error (exit 2)" '[ $? -eq 2 ]'
python3 "$A" --target app.stub.test --targets nope.txt -o "$OUT/gate" >/dev/null 2>&1
check "--target and --targets together -> error" '[ $? -eq 2 ]'
python3 "$A" --targets "$OUT/missing.txt" -o "$OUT/gate" >/dev/null 2>&1
check "missing targets file -> refused" '[ $? -ne 0 ]'
printf '# only comments\n\n   # indented\n' > "$OUT/empty.txt"
python3 "$A" --targets "$OUT/empty.txt" -o "$OUT/gate" >/dev/null 2>&1
check "targets file with no targets -> refused" '[ $? -ne 0 ]'
printf 'app.stub.test   bogusflag\n' > "$OUT/badflag.txt"
python3 "$A" --targets "$OUT/badflag.txt" -o "$OUT/gate" >/dev/null 2>&1
check "unknown per-line flag -> refused" '[ $? -ne 0 ]'
check "nothing written for refused inputs" '[ ! -d "$OUT/gate" ]'
# A targets file is scanned host by host; the file name becomes the batch label.
printf '# client X batch, authorised under SOW-2026-041\napp.stub.test\nlive.stub.test   prod   # live box\napp.stub.test\n' > "$OUT/targets.txt"
python3 "$A" --targets "$OUT/targets.txt" -o "$OUT/batch" --wordlist "$WL" -q --skip csp >/dev/null 2>&1
check "every listed host scanned, duplicates collapsed (2 run dirs)" '[ $(ls -d "$OUT"/batch/targets/*/ | wc -l) -eq 2 ]'
bm(){ python3 -c "import json,glob,sys; print(json.load(open(glob.glob('$OUT/batch/targets/$1_*/manifest.json')[0]))$2)"; }
check "per-line prod flag -> production profile" '[ "$(bm live.stub.test "[\"profile\"]")" = production ]'
check "non-prod line -> standard profile" '[ "$(bm app.stub.test "[\"profile\"]")" = standard ]'
check "manifest records the targets file as the allow-list source" 'bm app.stub.test "[\"authorisation\"][\"allowlist_source\"]" | grep -q "targets.txt"'
check "batch label taken from the targets file name" '[ "$(bm app.stub.test "[\"label\"]")" = targets ]'

# The *.stub.test hosts don't resolve, so the CSP fetch (a real HTTP request,
# not a stub) is skipped on those runs. CSP and the AI call are tested against
# the local fake server in their own section below.
echo "== full run (standard profile, token set)"
conf "[wpscan]" "api_token = TESTtoken1234567890abcdefXYZ"
python3 "$A" --target app.stub.test -o "$OUT/run" --wordlist "$WL" -q --skip csp >/dev/null 2>&1
check "exit 0" '[ $? -eq 0 ]'
R="$(latest)"
check "run status completed" '[ "$(mf "m[\"status\"]")" = completed ]'
check "integrity self-check ok" '[ "$(mf "m[\"integrity_check\"][\"ok\"]")" = True ]'
check "SHA256SUMS verifies" '(cd "$R" && sha256sum -c SHA256SUMS --quiet)'
check "no artefact overwrites: 3 httpx results for 3 web services" '[ $(ls "$R"/04_fingerprint/*_httpx.jsonl | wc -l) -eq 3 ]'
check "http and https kept apart" '[ -f "$R/04_fingerprint/http_app.stub.test_httpx.jsonl" ] && [ -f "$R/04_fingerprint/https_app.stub.test_httpx.jsonl" ]'
check "WPScan token absent from every file" '! grep -rq "TESTtoken1234567890abcdefXYZ" "$R"'
check "WPScan token shown as <REDACTED>" 'grep -q "api-token <REDACTED>" "$R"/05_vulnscan/*wpscan.txt'
check "WPScan only on the WordPress URL" '[ $(ls "$R"/05_vulnscan/*wpscan.txt | wc -l) -eq 1 ]'
check "nuclei excludes dos/intrusive by default" 'grep -q "etags dos,intrusive" "$R"/05_vulnscan/https_app.stub.test_nuclei.log'
check "ffuf progress frames dropped" '! grep -q "Progress: \[" "$R"/06_content/*_ffuf.log'
check "wpscan keeps only the 100% frame" '[ $(grep -c "%" "$R"/05_vulnscan/*wpscan.txt) -eq 1 ]'
check "transcripts open with the exact command" 'head -1 "$R/02_portscan/nmap_portscan.log" | grep -q -- "-p- -T4 --open"'
check "evidence CSV has workbook columns" 'head -1 "$R/evidence_rows.csv" | grep -q "Engagement,Activity,Tool,Artefact"'
check "evidence CSV tool names normalised (Nmap 7.98)" 'grep -q ",Nmap 7.98," "$R/evidence_rows.csv"'
check "wafw00f ran on all 3 web services" '[ $(ls "$R"/04_fingerprint/*_wafw00f.json | wc -l) -eq 3 ]'
check "wafw00f never follows redirects (-r)" 'grep -q "ARGS: .* -r " "$R"/04_fingerprint/https_app.stub.test_wafw00f.log'
check "wafw00f vendor in summary" 'grep -q "WAF identified: Cloudflare" "$R/manifest.json"'
check "gau output kept" '[ -s "$R/01_passive/gau_urls.txt" ]'
check "gau stays on the exact host (no --subs)" '! grep -q -- "--subs" "$R/01_passive/gau.log"'
check "gau summary counts interesting extensions" 'grep -q "2 with interesting extensions" "$R/manifest.json"'
noconf

echo "== production profile"
python3 "$A" --target live.stub.test --prod -o "$OUT/run" --wordlist "$WL" -q --skip csp >/dev/null 2>&1
R="$(latest)"
check "--prod selects the production profile" '[ "$(mf "m[\"profile\"]")" = production ]'
check "nmap throttled (--max-rate 100)" 'head -1 "$R/02_portscan/nmap_portscan.log" | grep -q -- "--max-rate 100"'
check "nuclei rate-limited (-rl 20)" 'head -1 "$R"/05_vulnscan/https_live.stub.test_nuclei.log | grep -q -- "-rl 20"'
python3 "$A" --target live.stub.test --prod --profile standard -o "$OUT/run" --wordlist "$WL" -q --skip csp >/dev/null 2>&1
check "operator override of a prod target is recorded" '[ "$(mf "bool(m[\"profile_note\"])")" = True ]'

echo "== URL target"
python3 "$A" --target https://app.stub.test/portal -o "$OUT/run" --wordlist "$WL" -q --skip csp >/dev/null 2>&1
check "web tools limited to the given URL" '[ "$(mf "m[\"discovered\"][\"web_urls\"]")" = "['"'"'https://app.stub.test/portal'"'"']" ]'

echo "== degraded runs"
mkdir -p "$OUT/partial" && cp -a "$STUBS"/. "$OUT/partial/" && rm "$OUT/partial/nuclei"
PATH="$OUT/partial:/usr/bin:/bin" python3 "$A" --target app.stub.test -o "$OUT/run" --wordlist "$WL" -q --skip csp >/dev/null 2>&1
check "missing tool -> completed-with-skips, not completed" '[ "$(mf "m[\"status\"]")" = completed-with-skips ]'
STUB_NMAP_SLEEP=60 timeout -s INT 3 python3 "$A" --target app.stub.test -o "$OUT/run" -q --only dns,portscan >/dev/null 2>&1
R="$(latest)"
check "Ctrl-C -> run marked interrupted" '[ "$(mf "m[\"status\"]")" = interrupted ]'
check "Ctrl-C -> step marked interrupted" '[ "$(mf "m[\"steps\"][-1][\"status\"]")" = interrupted ]'
check "Ctrl-C -> evidence still hashed" '(cd "$R" && sha256sum -c SHA256SUMS --quiet)'
sleep 1
check "Ctrl-C -> no orphaned scanner" '! ps -eo args | grep -v grep | grep -q "stubs/nmap -p-"'
python3 "$A" --target app.stub.test -o "$OUT/run" --dry-run -q >/dev/null 2>&1
check "dry run executes nothing" '[ "$(mf "m[\"status\"]")" = dry-run ] && grep -q "DRY RUN" "$(latest)/02_portscan/nmap_portscan.log"'

echo "== CSP review + AI call (local fake target and fake API)"
export FAKE_AI_LOG="$OUT/ai_requests.jsonl"     # before the server starts - it reads this
python3 "$HERE/fake_server.py" "$OUT/port" & SRV=$!
for _ in $(seq 50); do [ -s "$OUT/port" ] && break; sleep 0.1; done
PORT="$(cat "$OUT/port")"
# Keys come only from the config file now; base URLs stay as env seams.
conf "[ai]" "gemini_api_key = TESTgemkey_9876543210fedcba" "anthropic_api_key = TESTaikey_abcdef1234567890"
export WEBPEEK_GEMINI_BASE_URL="http://127.0.0.1:$PORT"
export WEBPEEK_ANTHROPIC_BASE_URL="http://127.0.0.1:$PORT"
unset WEBPEEK_AI_PROVIDER WEBPEEK_AI_MODEL
# The AI call honours env proxies on purpose (corporate egress), so it needs
# NO_PROXY for the local fake API.
export NO_PROXY="127.0.0.1,localhost" no_proxy="127.0.0.1,localhost"

# Behavioural proxy test. The env proxy points at a dead port and NO_PROXY is
# removed, so a fetch that honoured the environment would fail outright.
# (An earlier version of this test only grepped for the "proxies ignored" log
# line and set NO_PROXY - a mutant that honoured the proxy still passed it.)
( unset NO_PROXY no_proxy
  HTTP_PROXY="http://127.0.0.1:9" http_proxy="http://127.0.0.1:9" \
  HTTPS_PROXY="http://127.0.0.1:9" https_proxy="http://127.0.0.1:9" \
  python3 "$A" --target "http://127.0.0.1:$PORT/" -o "$OUT/proxy" -q --only csp --no-ai >/dev/null 2>&1 )
P="$(ls -dt "$OUT"/proxy/*/* | head -1)"
check "CSP fetch really bypasses a dead environment proxy" 'grep -q "CSP-UNSAFE-INLINE" "$P"/08_csp/*_csp_rules.json'

python3 "$A" --target "http://127.0.0.1:$PORT/" -o "$OUT/run" --wordlist "$WL" -q --only csp,gau >/dev/null 2>&1
R="$(latest)"; S="http_127.0.0.1_$PORT"
check "transcript records the fetch route" 'grep -q "direct (environment proxies ignored)" "$R/08_csp/${S}_http.txt"'
check "CSP rules step completed" '[ "$(mf "[s[\"status\"] for s in m[\"steps\"] if s[\"step\"]==\"csp\"][0]")" = completed ]'
check "rule: unquoted self caught" 'grep -q "CSP-UNQUOTED-KEYWORD" "$R/08_csp/${S}_csp_rules.json"'
check "rule: unsafe-inline caught" 'grep -q "\"CSP-UNSAFE-INLINE\"" "$R/08_csp/${S}_csp_rules.json"'
check "rule: shared-hosting wildcard caught" 'grep -q "CSP-SHARED-HOSTING" "$R/08_csp/${S}_csp_rules.json"'
check "rule: malformed wss://.host caught" 'grep -q "wss://.bad.example" "$R/08_csp/${S}_csp_rules.json"'
check "rule: duplicate img-src caught" 'grep -q "CSP-DUP" "$R/08_csp/${S}_csp_rules.json"'
check "rule: X-Frame-Options downgrades frame-ancestors to Info" 'python3 -c "import json,sys; f=[x for x in json.load(open(\"$R/08_csp/${S}_csp_rules.json\"))[\"findings\"] if x[\"id\"]==\"CSP-FRAME-ANCESTORS\"]; sys.exit(0 if f and f[0][\"severity\"]==\"Info\" else 1)"'
aistep(){ mf "[s for s in m[\"steps\"] if s[\"step\"]==\"csp-ai\"][0]$1"; }
# -- default provider: Gemini, gemini-4-hydrogen
check "default provider is gemini" '[ "$(mf "m[\"ai_provider\"]")" = gemini ]'
check "default model is gemini-4-hydrogen" '[ "$(mf "m[\"ai_model\"]")" = gemini-4-hydrogen ]'
check "Gemini step completed" '[ "$(aistep "[\"status\"]")" = completed ]'
check "Gemini generateContent endpoint for gemini-4-hydrogen" 'grep -q "/v1beta/models/gemini-4-hydrogen:generateContent" "$FAKE_AI_LOG"'
check "Gemini key sent in x-goog-api-key header" 'grep -q "\"has_api_key\": true" "$FAKE_AI_LOG"'
check "Gemini key never in the URL" '! grep -q "\"key_in_url\": true" "$FAKE_AI_LOG"'
check "Gemini asked for JSON output" 'grep -q "\"responseMimeType\": \"application/json\"" "$FAKE_AI_LOG"'
check "Gemini system instruction carries the prompt" 'grep -q "systemInstruction" "$FAKE_AI_LOG" && grep -q "UNTRUSTED" "$FAKE_AI_LOG"'
check "no thinking level sent unless configured" '! grep -q "thinkingConfig" "$FAKE_AI_LOG"'
check "AI received the CSP and the rule findings" 'grep -q "cloudfront" "$FAKE_AI_LOG" && grep -q "CSP-UNSAFE-INLINE" "$FAKE_AI_LOG"'
check "Gemini thought part ignored, answer parsed" 'grep -q "Fake Gemini output" "$R/08_csp/${S}_csp_report.md"'
check "saved request records provider + model + endpoint" 'python3 -c "import json,sys; r=json.load(open(\"$R/08_csp/${S}_csp_ai_request.json\")); sys.exit(0 if r[\"provider\"]==\"gemini\" and r[\"model\"]==\"gemini-4-hydrogen\" and \"generateContent\" in r[\"endpoint\"] else 1)"'
check "AI prompt marks target data untrusted" 'grep -q "UNTRUSTED" "$R/08_csp/${S}_csp_ai_request.json" && grep -q "<target_data>" "$R/08_csp/${S}_csp_ai_request.json"'
check "Gemini AND Anthropic keys absent from every file" '! grep -rq "TESTgemkey_9876543210fedcba" "$R" && ! grep -rq "TESTaikey_abcdef1234567890" "$R"'
check "report names the provider and labels output unverified" 'grep -q "Provider: Google Gemini API" "$R/08_csp/${S}_csp_report.md" && grep -q "AI-assisted review - UNVERIFIED" "$R/08_csp/${S}_csp_report.md"'
check "evidence CSV names provider and model" 'grep -q "Google Gemini API (gemini-4-hydrogen)" "$R/evidence_rows.csv"'
check "AI request hash recorded" '[ "$(aistep "[\"ai_request_sha256\"]" | wc -c)" -eq 65 ]'
check "gau skipped for an IP target" 'grep -q "IP target" "$R/manifest.json"'
check "CSP run integrity ok" '[ "$(mf "m[\"integrity_check\"][\"ok\"]")" = True ] && (cd "$R" && sha256sum -c SHA256SUMS --quiet)'

# -- Anthropic on request
: > "$FAKE_AI_LOG"
python3 "$A" --target "http://127.0.0.1:$PORT/" -o "$OUT/run" -q --only csp --ai-provider anthropic >/dev/null 2>&1
R="$(latest)"
check "--ai-provider anthropic uses the Messages API" 'grep -q "\"path\": \"/v1/messages\"" "$FAKE_AI_LOG" && grep -q "2023-06-01" "$FAKE_AI_LOG"'
check "anthropic default model claude-sonnet-4-5" '[ "$(mf "m[\"ai_model\"]")" = claude-sonnet-4-5 ]'
check "fenced Anthropic JSON parsed" 'grep -q "Fake model output" "$R"/08_csp/*_csp_report.md'

# -- thinking level only when configured
: > "$FAKE_AI_LOG"
WEBPEEK_GEMINI_THINKING_LEVEL=medium python3 "$A" --target "http://127.0.0.1:$PORT/" -o "$OUT/run" -q --only csp >/dev/null 2>&1
check "WEBPEEK_GEMINI_THINKING_LEVEL sent as thinkingLevel MEDIUM" 'grep -q "\"thinkingLevel\": \"MEDIUM\"" "$FAKE_AI_LOG"'

# -- unknown model: failure recorded honestly, rules unaffected
python3 "$A" --target "http://127.0.0.1:$PORT/" -o "$OUT/run" -q --only csp --ai-model no-such-model >/dev/null 2>&1
R="$(latest)"
check "unknown model -> AI step failed, not completed" '[ "$(aistep "[\"status\"]")" = failed ]'
check "unknown model -> provider error message recorded" 'aistep "[\"ai_error\"]" | grep -q "HTTP 404: models/no-such-model is not found"'
check "unknown model -> run marked completed-with-failures" '[ "$(mf "m[\"status\"]")" = completed-with-failures ]'
check "unknown model -> rule findings still delivered" 'grep -q "CSP-UNSAFE-INLINE" "$R"/08_csp/*_csp_rules.json'

# -- default provider has no key in the file: skip with reason, NO silent fallback
: > "$FAKE_AI_LOG"
conf "[ai]" "anthropic_api_key = TESTaikey_abcdef1234567890"   # file has no gemini key
python3 "$A" --target "http://127.0.0.1:$PORT/" -o "$OUT/run" -q --only csp >/dev/null 2>&1
R="$(latest)"
check "no Gemini key in the file -> skipped with reason" 'aistep "[\"reason\"]" | grep -q "GEMINI_API_KEY is not set"'
check "missing Gemini key does NOT fall back to Anthropic" '[ ! -s "$FAKE_AI_LOG" ]'
# -- credentials are file-only: an ambient env key is ignored, never a source
: > "$FAKE_AI_LOG"
GEMINI_API_KEY="TESTenvonly_must_be_ignored_1234" GOOGLE_API_KEY="TESTenvonly2_must_be_ignored" \
  python3 "$A" --target "http://127.0.0.1:$PORT/" -o "$OUT/run" -q --only csp >/dev/null 2>&1
R="$(latest)"
check "ambient GEMINI_API_KEY/GOOGLE_API_KEY are ignored, not used" 'aistep "[\"reason\"]" | grep -q "GEMINI_API_KEY is not set" && [ ! -s "$FAKE_AI_LOG" ]'
check "ignored ambient key never written to evidence" '! grep -rq "TESTenvonly" "$R"'
# re-arm both keys for the remaining CSP tests
conf "[ai]" "gemini_api_key = TESTgemkey_9876543210fedcba" "anthropic_api_key = TESTaikey_abcdef1234567890"

python3 "$A" --target "http://127.0.0.1:$PORT/redirect-out" -o "$OUT/run" -q --only csp --no-ai >/dev/null 2>&1
R="$(latest)"; T="$(ls "$R"/08_csp/*_http.txt)"
check "redirect to out-of-scope host NOT followed" 'grep -q "outside the authorised scope - not followed" "$T" && ! grep -q "> GET http://evil.example.org" "$T"'
check "--no-ai honoured" 'grep -q "\"reason\": \"--no-ai\"" "$R/manifest.json"'
python3 "$A" --target "http://127.0.0.1:$PORT/redirect-in" -o "$OUT/run" -q --only csp --no-ai >/dev/null 2>&1
R="$(latest)"
check "in-scope redirect IS followed to the CSP" 'grep -q "CSP-UNSAFE-INLINE" "$R"/08_csp/*_csp_rules.json'

# Back-to-back runs on one host in the same second must not share a directory.
python3 "$A" --target "http://127.0.0.1:$PORT/" -o "$OUT/same" -q --only csp --no-ai >/dev/null 2>&1 &
python3 "$A" --target "http://127.0.0.1:$PORT/" -o "$OUT/same" -q --only csp --no-ai >/dev/null 2>&1 &
wait %2 %3 2>/dev/null; sleep 0.5
check "simultaneous runs get separate directories" '[ $(ls -d "$OUT"/same/*/* | wc -l) -eq 2 ]'
check "each simultaneous run has exactly one manifest-listed CSP step" 'for d in "$OUT"/same/*/*; do python3 -c "import json,sys; m=json.load(open(\"$d/manifest.json\")); sys.exit(0 if len([s for s in m[\"steps\"] if s[\"step\"]==\"csp\"])==1 else 1)" || exit 1; done'
echo "== --proxy (target traffic only)"
PXLOG="$OUT/proxy_requests.log"; : > "$PXLOG"
python3 "$HERE/fake_proxy.py" "$OUT/pxport" "$PXLOG" & PXSRV=$!
for _ in $(seq 50); do [ -s "$OUT/pxport" ] && break; sleep 0.1; done
PX="http://127.0.0.1:$(cat "$OUT/pxport")"
python3 "$A" --target app.stub.test --proxy "socks5://127.0.0.1:1080" -o "$OUT/pxbad" -q >/dev/null 2>&1
check "non-http proxy scheme -> refused (exit 2)" '[ $? -eq 2 ]'
python3 "$A" --target app.stub.test --proxy "http://127.0.0.1" -o "$OUT/pxbad" -q >/dev/null 2>&1
check "proxy without a port -> refused (exit 2)" '[ $? -eq 2 ]'
python3 "$A" --target app.stub.test --proxy "http://127.0.0.1:9" -o "$OUT/pxbad" -q >/dev/null 2>&1
check "unreachable proxy -> refused (exit 2)" '[ $? -eq 2 ]'
check "nothing written for refused proxies" '[ ! -d "$OUT/pxbad" ]'
# Full stub run through a live proxy, WordPress fingerprinted so WPScan runs too.
python3 "$A" --target app.stub.test --proxy "$PX" -o "$OUT/run" --wordlist "$WL" -q --skip csp >/dev/null 2>&1
check "proxied run exit 0" '[ $? -eq 0 ]'
cmds(){ mf "\"\\n\".join(s[\"command\"] for s in m[\"steps\"] if s[\"step\"]==\"$1\")"; }
for pair in "httpx:-http-proxy" "wafw00f:--proxy" "nuclei:-proxy" "wpscan:--proxy" "ffuf:-x" "dirsearch:--proxy"; do
  t="${pair%%:*}"; f="${pair#*:}"
  check "$t gets $f <proxy> on every step" '[ -n "$(cmds '"$t"')" ] && ! cmds '"$t"' | grep -vq -- " '"$f"' $PX"'
done
for t in gau sslscan testssl dns portscan services setup; do
  check "$t ran and was NOT proxied" '[ -n "$(cmds '"$t"')" ] && ! cmds '"$t"' | grep -q "$PX"'
done
check "manifest records proxy and what it was NOT applied to" '[ "$(mf "m[\"proxy\"][\"url\"]")" = "$PX" ] && mf "m[\"proxy\"][\"not_applied\"][\"gau\"]" | grep -q archives'
# No --proxy: no tool gets a proxy flag (guards against a hard-wired default).
python3 "$A" --target app.stub.test -o "$OUT/run" --wordlist "$WL" -q --skip csp >/dev/null 2>&1
check "no --proxy -> no proxy flags, manifest proxy null" '! grep -q -- "-http-proxy\|-proxy \| -x " "$(latest)/manifest.json" && [ "$(mf "m[\"proxy\"]")" = None ]'
# Behavioural: the CSP fetch really goes through the proxy, and the
# credential in a user:pass@ proxy URL is masked everywhere.
: > "$PXLOG"
PXC="http://scanner:S3cretPxPass@127.0.0.1:$(cat "$OUT/pxport")"
python3 "$A" --target "http://127.0.0.1:$PORT/" --proxy "$PXC" -o "$OUT/run" -q --only csp --no-ai >/dev/null 2>&1
R="$(latest)"
# NO_PROXY=127.0.0.1 is set in this section (for the fake AI API). urllib's
# stock ProxyHandler would honour it and silently skip the explicit proxy.
check "CSP fetch goes through the proxy even when NO_PROXY matches the target" 'grep -q "GET http://127.0.0.1:$PORT" "$PXLOG" && grep -q "CSP-UNSAFE-INLINE" "$R"/08_csp/*_csp_rules.json'
check "proxy password masked in every file" '! grep -rq "S3cretPxPass" "$R"'
# The old CSP-only --http-proxy flag is gone; --proxy replaces it.
python3 "$A" --target "http://127.0.0.1:$PORT/" --http-proxy "$PX" -o "$OUT/pxold" -q --only csp --no-ai >/dev/null 2>&1
check "removed --http-proxy flag -> rejected (exit 2), nothing written" '[ $? -eq 2 ] && [ ! -d "$OUT/pxold" ]'
kill $PXSRV 2>/dev/null

echo "== config file (webpeek.conf is the only source)"
noconf; unset GEMINI_API_KEY ANTHROPIC_API_KEY GOOGLE_API_KEY WPSCAN_API_TOKEN
fp(){ printf %s "$1" | sha256sum | cut -c1-12; }
CFGKEY="TESTcfgGemKey_aa11bb22cc33"; CFGWP="TESTcfgWpTok_dd44ee55ff66"
CFG="$OUT/cfg/webpeek.conf"; mkdir -p "$OUT/cfg"
cat > "$CFG" <<EOF
[ai]
provider = gemini
gemini_model = cfg-model-x
gemini_api_key = $CFGKEY
anthropic_api_key = <your key here>
[wpscan]
api_token = "$CFGWP"
EOF
chmod 600 "$CFG"; export WEBPEEK_CONFIG="$CFG"

: > "$FAKE_AI_LOG"
python3 "$A" --target "http://127.0.0.1:$PORT/" -o "$OUT/run" -q --only csp >/dev/null 2>&1
R="$(latest)"
check "config: model name taken from file" 'grep -q "/v1beta/models/cfg-model-x:generateContent" "$FAKE_AI_LOG"'
check "config: Gemini key taken from file" 'grep -q "\"key_fp\": \"$(fp "$CFGKEY")\"" "$FAKE_AI_LOG"'
check "config: sources recorded by name" 'python3 -c "import json,sys; c=json.load(open(\"$R/manifest.json\"))[\"config\"]; sys.exit(0 if \"ai.gemini_api_key\" in c[\"settings_from_config\"] and c[\"path\"].endswith(\"webpeek.conf\") else 1)"'
check "config: placeholder ignored with a warning" 'grep -q "anthropic_api_key looks like a placeholder" "$R/manifest.json"'
check "config: no key value anywhere in the evidence" '! grep -rq -e "$CFGKEY" -e "$CFGWP" "$R"'
check "config: the file itself is not copied into evidence" '! grep -rlq "gemini_model = cfg-model-x" "$R"'

# Credentials are file-only: an ambient env key neither overrides nor substitutes.
: > "$FAKE_AI_LOG"
GEMINI_API_KEY="TESTenvGemKey_77889900" python3 "$A" --target "http://127.0.0.1:$PORT/" -o "$OUT/run" -q --only csp >/dev/null 2>&1
R="$(latest)"
check "environment key does NOT override the file key" 'grep -q "\"key_fp\": \"$(fp "$CFGKEY")\"" "$FAKE_AI_LOG" && ! grep -q "\"key_fp\": \"$(fp "TESTenvGemKey_77889900")\"" "$FAKE_AI_LOG"'
check "no environment override recorded in manifest" 'python3 -c "import json,sys; sys.exit(0 if \"ai.gemini_api_key\" not in json.load(open(\"$R/manifest.json\"))[\"config\"][\"overridden_by_environment\"] else 1)"'
: > "$FAKE_AI_LOG"
python3 "$A" --target "http://127.0.0.1:$PORT/" -o "$OUT/run" -q --only csp --ai-model cli-model-z >/dev/null 2>&1
check "--ai-model overrides config" 'grep -q "/models/cli-model-z:generateContent" "$FAKE_AI_LOG"'

python3 "$A" --target app.stub.test -o "$OUT/run" --wordlist "$WL" -q --skip csp >/dev/null 2>&1
R="$(latest)"
check "config: WPScan token (quoted in file) passed to WPScan, masked" 'grep -q "api-token <REDACTED>" "$R"/05_vulnscan/*wpscan.txt && ! grep -rq "$CFGWP" "$R"'
check "child tools never inherit the config's API keys" '! grep -q "LEAKED_ENV" "$R/01_dns/nslookup.txt"'
GEMINI_API_KEY="xTESTenv" ANTHROPIC_API_KEY="yTESTenv" python3 "$A" --target app.stub.test -o "$OUT/run" -q --only dns >/dev/null 2>&1
check "child tools never see keys set in the environment either" '! grep -q "LEAKED_ENV" "$(latest)/01_dns/nslookup.txt"'

check "--show-config reads webpeek.conf and shows the file model" 'python3 "$A" --show-config | grep -q "ai.gemini_model *cfg-model-x *config"'
check "--show-config never prints a secret" '! python3 "$A" --show-config | grep -q -e "$CFGKEY" -e "$CFGWP"'
check "missing config file -> not an error, just no key" 'WEBPEEK_CONFIG="$OUT/nope.conf" python3 "$A" --show-config | grep -q "ai.gemini_api_key *not set"'

# Loose mode: warn with the chmod hint, never change the file, never refuse.
chmod 644 "$CFG"
python3 "$A" --target app.stub.test -o "$OUT/run" -q --skip csp > "$OUT/loose.out" 2>&1; RC=$?
check "loose-mode config -> run proceeds" '[ $RC -eq 0 ]'
check "loose-mode config -> warning says chmod 600" 'grep -q "mode 644 .*chmod 600" "$OUT/loose.out"'
check "loose-mode config -> mode left untouched" '[ "$(stat -c %a "$CFG")" = 644 ]'
chmod 600 "$CFG"
python3 "$A" --target app.stub.test -o "$OUT/run" -q --skip csp > "$OUT/tight.out" 2>&1
check "0600 config -> no permission warning" '! grep -q "chmod 600" "$OUT/tight.out"'
chmod 600 "$CFG"
echo "gemini_key = typo" >> "$CFG"
python3 "$A" --show-config >/dev/null 2>&1
check "unknown setting refused (typo protection)" '[ $? -eq 2 ]'

noconf
kill $SRV 2>/dev/null
unset ANTHROPIC_API_KEY GEMINI_API_KEY WEBPEEK_GEMINI_BASE_URL WEBPEEK_ANTHROPIC_BASE_URL FAKE_AI_LOG

echo "== Python tool venvs (real venvs, offline wheels built from the stubs)"
VR="$OUT/venvs"; WH="$OUT/wheels"; ILOG="$OUT/venv_install.log"
python3 "$HERE/make_wheel.py" dirsearch 9.9.9 "$STUBS/dirsearch" "$WH" >/dev/null
python3 "$HERE/make_wheel.py" wafw00f 9.9.9 "$STUBS/wafw00f" "$WH" >/dev/null
# Drive the real Installer directly (it normally needs root, which tests don't have).
ensure(){ WEBPEEK_VENV_ROOT="$VR" WEBPEEK_PIP_ARGS="--no-index --find-links $WH" A="$A" \
  python3 - "$ILOG" "$@" <<'PYEOF'
import os, runpy, sys
from pathlib import Path
g = runpy.run_path(os.environ["A"], run_name="not_main")
inst = g["Installer"](Path(sys.argv[1]), g["Console"](True), g["Masker"]())
sys.exit(0 if all(inst.ensure(t) for t in sys.argv[2:]) else 1)
PYEOF
}
ensure dirsearch wafw00f >/dev/null 2>&1
check "installer succeeded for both Python tools" '[ $? -eq 0 ]'
check "each tool has its own venv" '[ -x "$VR/dirsearch/bin/python" ] && [ -x "$VR/wafw00f/bin/python" ]'
check "venvs are isolated (dirsearch absent from wafw00f venv)" '! "$VR/wafw00f/bin/python" -m pip freeze 2>/dev/null | grep -qi dirsearch'
check "every pip call used a tool venv's own python" '[ $(grep -c "pip install" "$ILOG") -gt 0 ] && ! grep "pip install" "$ILOG" | grep -v -q "$VR/[a-z0-9]*/bin/python -m pip install"'
check "no apt, pipx or system pip for Python tools" '! grep -E "apt-get install.*(dirsearch|wafw00f)|pipx|^# .*\\$ (pip|pip3) install" "$ILOG"'
N=$(grep -c -- "-m venv" "$ILOG")
ensure dirsearch wafw00f >/dev/null 2>&1
check "second ensure does not rebuild existing venvs" '[ $(grep -c -- "-m venv" "$ILOG") -eq $N ]'
rm -rf "$VR/wafw00f/bin"
ensure wafw00f >/dev/null 2>&1
check "half-built venv is rebuilt" '[ -x "$VR/wafw00f/bin/wafw00f" ] && "$VR/wafw00f/bin/wafw00f" --version | grep -q venv'

WEBPEEK_VENV_ROOT="$VR" python3 "$A" --target app.stub.test -o "$OUT/run" --wordlist "$WL" -q --skip csp --no-install >/dev/null 2>&1
R="$(latest)"
check "venv copy preferred over the copy on PATH" '[ "$(mf "m[\"tools\"][\"dirsearch\"][\"source\"]")" = venv ] && [ "$(mf "m[\"tools\"][\"wafw00f\"][\"source\"]")" = venv ]'
check "venv tool is what actually ran" 'head -1 "$R"/06_content/https_app.stub.test_dirsearch.log | grep -q "$VR/dirsearch/bin/dirsearch"'
check "venv package set recorded in manifest" 'mf "m[\"tools\"][\"dirsearch\"][\"venv_packages\"]" | grep -q "dirsearch==9.9.9"'
check "venv tool version recorded" '[ "$(mf "m[\"tools\"][\"wafw00f\"][\"version\"]")" = "9.9.9-venv" ]'

chmod o+w "$VR/dirsearch"
check "venv writable by others is NOT used" 'WEBPEEK_VENV_ROOT="$VR" python3 "$A" --check-tools 2>/dev/null | grep -E "^dirsearch" | grep -q "system (not in its venv)"'
chmod o-w "$VR/dirsearch"
check "--check-tools reports the venv source" 'WEBPEEK_VENV_ROOT="$VR" python3 "$A" --check-tools 2>/dev/null | grep -E "^wafw00f" | grep -q " venv$"'
python3 "$A" --target app.stub.test -o "$OUT/run" --wordlist "$WL" -q --skip csp --no-install >/dev/null 2>&1
check "no venv yet -> system copy used, and the manifest says so" '[ "$(mf "m[\"tools\"][\"dirsearch\"][\"source\"]")" = "system (not in its venv)" ]'

echo "== installer on a non-Kali system (fake apt/go/git/gem imitating Ubuntu 24.04)"
# Reproduces the first real --install-only run: Kali-only packages missing from
# apt, testssl.sh not in apt, and gau's `go install` failing.
FPM="$HERE/fakepm"; chmod +x "$FPM"/*
iroot="$OUT/inst"; mkdir -p "$iroot/fakebin"
printf 'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nID=ubuntu\nID_LIKE=debian\n' > "$iroot/os-ubuntu"
printf 'PRETTY_NAME="Kali GNU/Linux Rolling"\nID=kali\nID_LIKE=debian\n' > "$iroot/os-kali"
# A minimal system bin dir, so the test machine's own nslookup/git/go etc.
# can't be found in place of what the installer is supposed to install.
SB="$iroot/sysbin"; mkdir -p "$SB"
for b in bash sh env mkdir chmod basename cat; do ln -sf "$(command -v $b)" "$SB/$b"; done
PY="$(command -v python3)"
# Local stand-in for raw.githubusercontent.com/danielmiessler/SecLists/<ref>/...
WLD="$iroot/seclists-mirror"
mkdir -p "$WLD/master/Discovery/Web-Content" "$WLD/htmlref/Discovery/Web-Content"
printf 'admin\nlogin\napi\nbackup\n' > "$WLD/master/Discovery/Web-Content/raft-medium-directories.txt"
printf 'index\nrobots.txt\n' > "$WLD/master/Discovery/Web-Content/common.txt"
for f in raft-medium-directories.txt common.txt; do
  printf '<!DOCTYPE html><html>rate limited</html>\n' > "$WLD/htmlref/Discovery/Web-Content/$f"; done
python3 "$HERE/static_server.py" "$WLD" "$iroot/wl.port" & WSRV=$!
for _ in $(seq 50); do [ -s "$iroot/wl.port" ] && break; sleep 0.1; done
WLURL="http://127.0.0.1:$(cat "$iroot/wl.port")"
export SLB="$WLURL" SLR=""      # per-run overrides used by install_all
install_all(){  # $1 = os-release file, $2 = output dir
  WEBPEEK_SECLISTS_BASE_URL="$SLB" WEBPEEK_SECLISTS_REF="$SLR" \
  FAKEPM_LOG="$2/pm.log" FAKEBIN="$iroot/fakebin" WEBPEEK_OS_RELEASE_FILE="$1" \
  WEBPEEK_OPT_ROOT="$2/opt" WEBPEEK_VENV_ROOT="$2/opt/venvs" \
  PATH="$FPM:$iroot/fakebin:$SB" A="$A" "$PY" - "$2/install.log" <<'PYEOF' > "$2/console.txt" 2>&1
import os, runpy, sys
from pathlib import Path
g = runpy.run_path(os.environ["A"], run_name="not_main")
inst = g["Installer"](Path(sys.argv[1]), g["Console"](False), g["Masker"]())
for t in ("nslookup", "httpx", "nuclei", "wpscan", "ffuf", "sslscan", "testssl", "gau"):
    inst.ensure(t)
inst.ensure_wordlists()
PYEOF
}
U="$OUT/inst/ubuntu"; mkdir -p "$U"; rm -f "$iroot"/fakebin/*
install_all "$iroot/os-ubuntu" "$U"
check "OS announced as not Kali, Kali-only route explained" 'grep -q "Ubuntu 24.04.1 LTS (not Kali)" "$U/console.txt"'
# (No "$" anchor: fake-apt log lines end with an env suffix. An earlier version
# anchored on "$", could never match, and passed against broken code.)
check "Kali-only packages NOT tried via apt on Ubuntu" '! grep -qE "apt-get install -y --no-install-recommends (httpx-toolkit|nuclei|wpscan|getallurls) " "$U/pm.log"'
check "...and that check can see apt installs at all" 'grep -qE "apt-get install -y --no-install-recommends bind9-dnsutils " "$U/pm.log"'
check "nslookup via bind9-dnsutils (dnsutils not needed)" 'grep -q "installed nslookup via apt" "$U/console.txt" && ! grep -q "install.* dnsutils " "$U/pm.log"'
check "apt runs non-interactively (needrestart suppressed)" '! grep "apt-get install" "$U/pm.log" | grep -v -q "NEEDRESTART_MODE=a DEBIAN_FRONTEND=noninteractive"'
check "go tools go to /opt bin, not /root/go/bin" 'grep -q "GOBIN=$U/opt/bin" "$U/pm.log" && [ -x "$U/opt/bin/httpx" ] && [ -x "$U/opt/bin/nuclei" ]'
check "go-installed httpx and nuclei reported installed" 'grep -q "installed httpx via go" "$U/console.txt" && grep -q "installed nuclei via go" "$U/console.txt"'
check "testssl: why apt didn't work is shown even though git succeeded" 'grep -q "(apt failed - testssl.sh: E: Unable to locate package testssl.sh)" "$U/console.txt"'
check "testssl: falls back to git, release branch 3.2" 'grep -q "installed testssl via git" "$U/console.txt" && grep -q "git clone --depth 1 --branch 3.2 https://github.com/testssl/testssl.sh.git" "$U/pm.log"'
check "gau failure shows go's actual error" 'grep -q "go failed - go: github.com/lc/gau/v2/cmd/gau@latest: module requires go >= 1.99" "$U/console.txt"'
check "go progress lines filtered out of the reason" '! grep -A2 "could not install gau" "$U/console.txt" | grep -q "downloading"'
check "gau failure doesn't pretend apt was tried" '! grep -A3 "could not install gau" "$U/console.txt" | grep -q "apt failed"'
check "failures point at the full log" 'grep -q "full output: $U/install.log" "$U/console.txt"'
check "seclists: apt NOT tried on Ubuntu (Kali-only package)" '! grep -q "install -y --no-install-recommends seclists " "$U/pm.log"'
check "seclists: wordlists downloaded instead" '[ -s "$U/opt/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt" ] && [ -s "$U/opt/wordlists/seclists/Discovery/Web-Content/common.txt" ]'
check "seclists: download URL is <base>/<ref>/<path>, ref defaults to master" 'grep -q "GET $WLURL/master/Discovery/Web-Content/raft-medium-directories.txt" "$U/install.log"'
RMD="$WLD/master/Discovery/Web-Content/raft-medium-directories.txt"
check "seclists: size, lines and SHA-256 logged" 'grep -q "raft-medium-directories.txt ($(wc -c < "$RMD") bytes, 4 lines, sha256 $(sha256sum "$RMD" | cut -c1-64))" "$U/install.log"'
check "seclists: ffuf wordlist reported" 'grep -q "ffuf wordlist: $U/opt/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt" "$U/console.txt"'
check "seclists: downloaded files readable by all, not writable" '[ "$(stat -c %a "$U/opt/wordlists/seclists/Discovery/Web-Content/common.txt")" = 644 ]'

U2="$OUT/inst/ubuntu-dead"; mkdir -p "$U2"; rm -f "$iroot"/fakebin/*
SLB="http://127.0.0.1:9" install_all "$iroot/os-ubuntu" "$U2"
check "seclists: unreachable download reported with reason and a way out" 'grep -q "download failed - Discovery/Web-Content/raft-medium-directories.txt: URLError" "$U2/console.txt" && grep -q "pass --wordlist PATH" "$U2/console.txt"'

U3="$OUT/inst/ubuntu-html"; mkdir -p "$U3"; rm -f "$iroot"/fakebin/*
SLR="htmlref" install_all "$iroot/os-ubuntu" "$U3"
check "seclists: HTML error page rejected, not saved as a wordlist" 'grep -q "response is not a wordlist (empty or HTML)" "$U3/console.txt" && [ ! -e "$U3/opt/wordlists/seclists/Discovery/Web-Content/common.txt" ]'
check "full output really is in the install log" 'grep -q "E: Unable to locate package getallurls\|module requires go >= 1.99" "$U/install.log"'

K="$OUT/inst/kali"; mkdir -p "$K"; rm -f "$iroot"/fakebin/*
install_all "$iroot/os-kali" "$K"
check "on Kali, Kali-only packages ARE tried via apt first" 'grep -q "apt-get install -y --no-install-recommends nuclei" "$K/pm.log"'
check "on Kali, seclists via apt first; download only as fallback, reason shown" 'grep -q "install -y --no-install-recommends seclists " "$K/pm.log" && grep -q "(apt failed - seclists: E: Unable to locate package seclists)" "$K/console.txt" && [ -s "$K/opt/wordlists/seclists/Discovery/Web-Content/common.txt" ]'
kill $WSRV 2>/dev/null

echo "== wordlist recorded in the run"
python3 "$A" --target app.stub.test -o "$OUT/run" --wordlist "$WL" -q --skip csp --only ffuf,portscan,services >/dev/null 2>&1
check "ffuf wordlist path and SHA-256 in manifest" '[ "$(mf "m[\"ffuf_wordlist\"][\"sha256\"]")" = "$(sha256sum "$WL" | cut -c1-64)" ] && [ "$(mf "m[\"ffuf_wordlist\"][\"lines\"]")" = 3 ]'
check "tools installed under /opt reported as webpeek-managed" 'mkdir -p "$OUT/srcopt/bin" && cp "$STUBS/ffuf" "$OUT/srcopt/bin/ffuf" && cp "$STUBS/_common.py" "$OUT/srcopt/bin/" && PATH="/usr/bin:/bin" WEBPEEK_OPT_ROOT="$OUT/srcopt" python3 "$A" --check-tools 2>/dev/null | grep -E "^ffuf" | grep -q "webpeek (/opt)"'

echo
echo "passed: $PASS  failed: $FAIL"
rm -rf "$OUT"
[ "$FAIL" -eq 0 ]
