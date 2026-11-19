# WebP33k

Automates the enumeration phase against one target — or a list of targets from a plain-
text file — and keeps everything it does as evidence.

```bash
chmod +x webpeek.py tests/stubs/*      # once, after copying from Windows
sudo ./webpeek.py --install-only       # installs everything; Python tools into their own venvs
sudo ./webpeek.py --target app.client.com           # one target
sudo ./webpeek.py --targets targets.txt             # a list (see targets.txt.example)
```

## What it runs

| Folder | Step | Command (standard profile) | Methodology |
|---|---|---|---|
| `01_dns` | dns | `nslookup <host>` | Name resolution |
| `01_passive` | gau | `gau --providers wayback,commoncrawl,otx,urlscan --blacklist <static> --o gau_urls.txt <host>` — archived URLs, **no requests to the target** | Passive reconnaissance |
| `02_portscan` | portscan | `nmap -p- -T4 --open -oN open_ports.txt -oX open_ports.xml <host>` | Network scanning |
| `03_services` | services | `nmap -sV -sC -p <open ports> -oA service_scan <host>` | Service discovery |
| `04_fingerprint` | httpx | `httpx -u <url> -td -sc -title -server -ip -cdn -fr -j` | System fingerprinting (Wappalyzer fingerprints) |
| `04_fingerprint` | wafw00f | `wafw00f <url> -a -r -o …json -f json` | System fingerprinting (WAF / edge) |
| `05_vulnscan` | nuclei | `nuclei -u <url> -severity info,low,medium,high,critical -stats -etags dos,intrusive -o … -jle …` | Vulnerability scanning |
| `05_vulnscan` | wpscan | `wpscan --url <url> --random-user-agent [--api-token …]` — **only when WordPress is fingerprinted** | Vulnerability scanning |
| `06_content` | ffuf | `ffuf -u <url>/FUZZ -w <wordlist> -ac -mc 200,204,301,302,307,401,403,405,500` | Content discovery |
| `06_content` | dirsearch | `dirsearch -u <url> -o …` (its built-in wordlist, so it complements ffuf rather than repeating it) | Content discovery |
| `07_tls` | sslscan, testssl | `sslscan --xml=… host:port`; `testssl --jsonfile … host:port` on every TLS port | SSL/TLS enumeration |
| `08_csp` | csp, csp-ai | one GET per web URL, then rule-based CSP review, then optional AI review | Vulnerability assessment (CSP) |

Steps chain: the port sweep feeds the service scan, the service scan decides
which ports are web (→ httpx, wafw00f, nuclei, ffuf, dirsearch, CSP) and which
are TLS (→ sslscan, testssl), and httpx's fingerprint decides whether WPScan runs.

**wafw00f runs with `-r`** (no redirect following). It sends attack-like probe
strings to provoke a WAF; following a redirect could deliver them to an
out-of-scope host such as a third-party SSO provider.

**gau stays on the exact host** (no `--subs`, since other subdomains may be out
of scope) and its results are recorded, **never fed to the active tools**

## CSP review

For each web URL, one GET request fetches the response headers and page. Then
two layers run:

1. **Rules (always, offline, deterministic).** `csp_check.py` parses every
   enforced header, `<meta>` policy and report-only policy and checks for
   misconfigured attributes and values: unquoted keywords (`self` instead of
   `'self'` — silently treated as a hostname), malformed sources
   (`wss://.host` — silently ignored), unknown/typo'd, deprecated and duplicate
   directives, `'none'` mixed with sources, directives that are ignored in
   `<meta>`, `'unsafe-inline'`/`'unsafe-eval'`, `*`, `https:`, `data:`,
   wildcards over shared hosting (`*.cloudfront.net`), hosts with known bypass
   gadgets (JSONP, AngularJS), and missing `object-src`, `base-uri`,
   `frame-ancestors`, `form-action` and reporting. Nonces/hashes and
   `'strict-dynamic'` are understood, an exact file path on a bypass host is not
   flagged, and `X-Frame-Options` downgrades a missing `frame-ancestors` to Info.
2. **AI review (optional).** The policy, related headers and the rule findings
   go to an AI model — **Google Gemini `gemini-4-hydrogen` by default**, or
   Anthropic Claude with `--ai-provider anthropic`. The model says whether it
   agrees with each rule finding and adds context-specific points the rules
   can't know. The target's headers are wrapped as untrusted data in the prompt.

The rules are the reproducible record; the AI is a second opinion. Its output
is labelled **AI-assisted — UNVERIFIED** everywhere, the exact request is saved
with its SHA-256, and nothing it says is a finding until a tester reproduces it.


```bash
sudo ./webpeek.py --target …                          # Gemini (default) - keys from the config file
sudo ./webpeek.py --target … --ai-provider anthropic  # Claude
python3 csp_check.py --policy "default-src 'self'; script-src self"   # offline, no target contact
python3 csp_check.py --policy-file csp.txt --ai                        # with AI
```

Keys come **only** from `webpeek.conf` (`gemini_api_key` / `anthropic_api_key`) — see
[Configuration](#configuration-keys-and-model-names). 

| Provider | Key (config file) | Default model | Endpoint |
|---|---|---|---|
| `gemini` (default) | `[ai] gemini_api_key` | `gemini-4-hydrogen` | `…/v1beta/models/<model>:generateContent` |
| `anthropic` | `[ai] anthropic_api_key` | `claude-sonnet-4-5` | `…/v1/messages` |

| Setting | |
|---|---|
| `--ai-provider` / `WEBPEEK_AI_PROVIDER` | `gemini` (default) or `anthropic` |
| `--ai-model` / `WEBPEEK_AI_MODEL` | override the model for whichever provider is in use |
| `WEBPEEK_GEMINI_MODEL`, `WEBPEEK_ANTHROPIC_MODEL` | per-provider model (what the config file's `gemini_model` / `anthropic_model` set) |
| `WEBPEEK_GEMINI_THINKING_LEVEL` | `low`, `medium`, `high` or `xhigh`. Unset = the model's own default (HIGH on Hydrogen). Lower is faster and cheaper; a CSP review rarely needs more than `medium` |
| `WEBPEEK_GEMINI_BASE_URL`, `WEBPEEK_ANTHROPIC_BASE_URL` | override the API host (internal gateway, tests) |
| `--no-ai` | rules only |
| `--proxy http://127.0.0.1:8080` | route the CSP fetch (and all other target HTTP traffic) through Burp/Caido — see [Proxy](#proxy) |

- Every configured AI key is masked in every file, whichever provider is used.
- The Gemini key goes in the `x-goog-api-key` header, never the `?key=` query
  string, so it can't end up in a logged URL.
- **No silent fallback.** If the selected provider has no key, the AI step is
  skipped with that reason recorded; it does not quietly switch to the other
  provider, because the manifest must say which vendor received the data.
- An unknown or retired model name fails the AI step with the provider's error
  message recorded (e.g. `HTTP 404: models/… is not found`); the rule findings
  are unaffected.
- Gemini runs at the model's default temperature (Google advises against
  lowering it on its reasoning models); Claude runs at temperature 0. Either
  way the AI output is not reproducible — that is what the rule layer is for.
- Gemini's "thought" parts are discarded; only the answer is parsed.
- Only publicly served data goes to the model: the CSP and related response
  headers any browser receives, plus the rule findings. A paid-tier Gemini key
  gives higher rate limits than the free tier.

**Redirects** are followed only while they stay on a host that is on the
allow-list (the targets you named); a redirect elsewhere is logged as
"outside the authorised scope — not followed".

**Hostname target** — web tools run against every web service found.
**URL target** (`--target https://app.client.com/portal`) — web tools run
against that URL only; ports are still scanned and TLS still checked.

### Wappalyzer

The official Wappalyzer CLI has been withdrawn. Fingerprinting uses
ProjectDiscovery's httpx with `-td`, which embeds Wappalyzer's open
fingerprint set (wappalyzergo). Describe it as *"httpx technology detection
using Wappalyzer fingerprints"* in evidence, not as "Wappalyzer".

## Targets and the allow-list

You name what to scan: one `--target`, or a `--targets FILE` with one entry per
line (hostname, IP, URL, or CIDR; `#` comments; a trailing `prod` flag — see
[Profiles](#profiles)). See `targets.txt.example`.

That list **is the allow-list**. The active tools only ever touch what you
named, and during the CSP fetch a redirect off to any host not on the list is
refused ("outside the authorised scope — not followed"). A bare CIDR line is
containment-only: never scanned itself, but a redirect into that range is
allowed.

There is **no engagement-window check**. Authorisation for the engagement lives
in the engagement contract; the targets file is your record of what that
contract permits. If you want an audit trail, keep the file under change control
(e.g. in the engagement repo) — its path and SHA-256 are written into every
run's `manifest.json`.


## Profiles

| | standard (default) | production |
|---|---|---|
| nmap sweep | `-T4` | `-T3 --max-rate 100 --max-retries 2` (~11 min for 65,535 ports) |
| nmap services | default timing | `-T3 --max-rate 100` |
| nuclei | default rate | `-rl 20 -c 5` |
| ffuf | `-t 40` | `-t 5 -rate 20` |
| dirsearch | `-t 25` | `-t 5 --delay 0.2` |
| WPScan | default | `--throttle 500` |

A target flagged `prod` (the `--prod` flag, or a `prod` token on its line in the
targets file) gets the production profile automatically. `--profile standard`
overrides it, and the override is written into the manifest so the choice is on
record. This is the methodology's *Scan Conduct and Safety Controls* section in
executable form.

Nuclei templates tagged `dos` or `intrusive` are excluded unless
`--allow-intrusive` is given — which needs written client authorisation.

## Evidence it leaves

```
webpeek_output/<label>/<host>_<YYYYMMDD-HHMMSS>/
  00_setup/        tool installs, nuclei template update, WPScan DB update
  01_dns/ … 07_tls/  one transcript per step + each tool's native output
  manifest.json    who, where, when, target + allow-list source, profile, tool
                   versions, exact command per step, exit codes, SHA-256 of every output
  evidence_rows.csv  one row per completed step, in the column order of the
                   Enumeration Evidence sheet of the CREST 3.3/3.4 workbook
  summary.md       human-readable run summary
  SHA256SUMS       verify with:  sha256sum -c SHA256SUMS
  run.log          start/end of every step
```

- Every transcript opens with the exact command line.
- Clean runs are kept — a scan that found nothing is evidence the check was done.
- `manifest.json` is rewritten after every step, so a crash or Ctrl-C still
  leaves a complete record of what ran. Interrupted and timed-out steps are
  recorded as such, never as completed.
- At the end the tool re-hashes every output against the hash recorded when its
  step finished. A mismatch fails the integrity check loudly.
- Run status is `completed`, `completed-with-skips` (a tool was unavailable),
  `completed-with-failures`, `interrupted`, `failed` or `dry-run`.
- Progress meters (ffuf, dirsearch, WPScan) are collapsed to their final frame
  so a transcript stays readable.

## Configuration (keys and model names)

API keys, the AI provider, model names and the WPScan token live in one file —
`webpeek.conf`, in this folder, next to `webpeek.py`:

```bash
cp webpeek.conf.example webpeek.conf
chmod 600 webpeek.conf
nano webpeek.conf
./webpeek.py --show-config        # what was picked up, and from where (secrets masked)
```

> ⚠️ **This file holds live keys and sits inside the evidence-pack folder.** Keep
> `webpeek.conf` out of anything you submit or commit — add it to `.gitignore`
> and exclude it from the delivery zip. `webpeek.conf.example` is the safe,
> keyless template.

```ini
[ai]
provider = gemini                   ; gemini or anthropic
gemini_model = gemini-4-hydrogen
anthropic_model = claude-sonnet-4-5
gemini_thinking_level =             ; low / medium / high / xhigh, empty = model default
gemini_api_key = …
anthropic_api_key = …
gemini_base_url =                   ; only for an internal gateway
anthropic_base_url =

[wpscan]
api_token = …
```

**What the tool enforces:**

| Rule | Why |
|---|---|
| On Unix, warns if the config is accessible to group/others and tells you to `chmod 600` it. Advisory only: it never changes the file's permissions and never refuses to load it | Keeps the keys-file hint visible without blocking runs (e.g. on a mounted Windows drive, where every file reads `0777` and chmod does nothing) |
| Unknown setting names are an error | A typo like `gemini_key` would otherwise silently switch the AI review off |
| Placeholder values (`<…>`, `YOUR_…`, `CHANGE_ME`) are ignored with a warning | So a half-filled example doesn't send `<your key>` to an API |
| Invalid `provider` / `gemini_thinking_level` values are an error | Fail at start, not halfway through a run |
| Keys are stripped from the environment of every child tool | nmap, nuclei, ffuf and the rest never see them; WPScan gets its token only as its own `--api-token` |
| Every configured key is masked as `<REDACTED>` in every file written | Stops live API keys and tokens ending up in evidence files |
| `manifest.json` records the config path and which settings came from the file (and which non-secret ones the `WEBPEEK_*` seam overrode) — names only | So a run's settings are traceable without the file itself ever entering the evidence |

Values may be quoted (`api_token = "abc"`), and may contain `%`.

## Tools and installation

```bash
./webpeek.py --check-tools        # what's installed, which versions
sudo ./webpeek.py --install-only  # install everything missing, then exit
```

During a scan, missing tools are installed automatically when running as root.
Works on Kali, Debian and Ubuntu; the installer reads `/etc/os-release` and
says up front which kind of system it is on.

| Tool | Route |
|---|---|
| nmap, ffuf, sslscan | apt |
| nslookup | apt `bind9-dnsutils`, then `dnsutils` (only a transitional name on newer releases) |
| testssl.sh | apt `testssl.sh`, then a git checkout of the official repo's release branch (`3.2`, set `[install] testssl_ref` to change) into `/opt/exfiltra-webpeek/testssl.sh` |
| httpx, nuclei, gau | apt on Kali (`httpx-toolkit`, `nuclei`, `getallurls`); everywhere else straight to `go install` |
| wpscan | apt on Kali; everywhere else `gem install` |
| dirsearch, wafw00f | their own venvs (below) |
| wordlists | Kali: apt `seclists`. Elsewhere SecLists isn't packaged, so just the two files ffuf uses (`raft-medium-directories.txt`, `common.txt`) are downloaded from the official SecLists repo into `/opt/exfiltra-webpeek/wordlists/seclists` — not the multi-GB full clone. Or pass `--wordlist` |

- **Kali-only apt packages aren't attempted on Debian/Ubuntu**, where they
  would only fail — the go/gem route is used directly.
- **Every failure says why**, on the console: apt's `E:` line, go's error,
  git's `fatal:`. When a fallback succeeds, the reason the first route
  failed is still shown. Full output is in `install.log`.
- **Go tools install to `/opt/exfiltra-webpeek/bin`**, not `/root/go/bin`
  (which a non-root user can't read, so `--check-tools` without sudo would
  report them missing). Tools already in `/root/go/bin` are still found.
- Downloaded wordlists are checked (an empty body or an HTML error page is rejected, not saved),
  and each file's URL, size and SHA-256 go to `install.log`. Every scan also records which wordlist
  ffuf used, with its SHA-256, in `manifest.json` — so the content-discovery evidence is pinned to an
  exact list. `[install] seclists_ref` / `seclists_base_url` choose the branch or a mirror.
- `--check-tools` labels tools as `venv`, `webpeek (/opt)` (installed by this tool) or `system`.
- apt runs fully non-interactively, including Ubuntu's `needrestart`
  "restart services?" prompt.

Use `--no-install` to forbid installing. A tool that still can't be found is
skipped, and the run is marked `completed-with-skips`.

### Python tools: one venv each

**dirsearch** and **wafw00f** — the Python tools — are never installed with
apt, system pip or pipx. Each gets its **own virtual environment**:

```
/opt/exfiltra-webpeek/venvs/dirsearch/   ← python -m venv, then pip install dirsearch
/opt/exfiltra-webpeek/venvs/wafw00f/     ← python -m venv, then pip install wafw00f
```

- Every `pip install` runs as `<venv>/bin/python -m pip`, so nothing touches
  the system Python. (Kali blocks system-wide pip under PEP 668 anyway, and an
  apt copy changes under you on every OS upgrade.)
- Separate venvs mean the two tools' dependencies can't break each other.
- **The venv copy is always the one that runs.** If a system copy exists (e.g.
  Kali's apt `dirsearch`), the first root run still builds the venv and uses
  it from then on. A non-root run before any venv exists falls back to the
  system copy, warns, and the manifest records `"source": "system (not in its
  venv)"`.
- Each run's `manifest.json` records, per Python tool, its venv path and the
  exact package set inside it (`pip freeze`), so the versions behind a piece
  of evidence are known.
- A venv that other users can write to, or that is owned by someone other
  than you or root, is **not used** — the tools run as root, so a writable venv
  would let another user swap the binary root executes.
- A half-built venv from an interrupted install is detected and rebuilt.
- If `python3 -m venv` fails (Debian/Kali ship it separately), `python3-venv`
  is installed via apt and the venv retried.

| Setting (config `[install]` / env) | |
|---|---|
| `venv_root` / `WEBPEEK_VENV_ROOT` | where the per-tool venvs live (default `/opt/exfiltra-webpeek/venvs`) |
| `pip_args` / `WEBPEEK_PIP_ARGS` | extra pip arguments, e.g. `--index-url https://pypi.internal/simple` for a mirror, or `--no-index --find-links /path/to/wheels` offline |

`./webpeek.py --check-tools` shows each tool's source (`venv` / `system`) and
warns if a Python tool is not running from its venv. To update the Python
tools, delete their venv (`sudo rm -rf /opt/exfiltra-webpeek/venvs/<tool>`)
and run `sudo ./webpeek.py --install-only`.

webpeek itself uses only the Python standard library — it needs no venv of
its own and no `pip install`.

Debian's `python3-httpx` ships an unrelated `httpx` command; the tool checks
it's ProjectDiscovery's before using it.

## Proxy

`--proxy http://127.0.0.1:8080` sends **traffic to the target** through an
intercepting proxy (Burp, Caido, ZAP) so it lands in proxy history.
(It replaces the old CSP-only `--http-proxy`, which has been removed.)

| Step | Proxied? | How |
|---|---|---|
| httpx | yes | `-http-proxy <url>` |
| wafw00f | yes | `--proxy <url>` |
| nuclei | yes | `-proxy <url>` (interactsh/OAST callbacks stay direct) |
| WPScan | yes | `--proxy <url>` |
| ffuf | yes | `-x <url>` |
| dirsearch | yes | `--proxy <url>` |
| CSP fetch, WordPress fallback check | yes | in-process, via the proxy |
| gau | **no** | queries public archives, not the target |
| AI CSP review | **no** | goes to the AI provider, not the target |
| nmap | **no** | SYN scans and NSE can't be carried by an HTTP proxy |
| nslookup | **no** | DNS |
| sslscan, testssl | **no** | an intercepting proxy terminates TLS, so they would grade the proxy's TLS, not the target's |
| nuclei template / WPScan DB updates | **no** | vendor traffic, not target traffic |

- `http://` or `https://` proxies only, as `scheme://host:port` (optionally
  `user:pass@host:port`; the password is masked in every file).
- The proxy is checked before anything is written: if nothing is listening the
  run is refused (exit 2) rather than producing a folder of failed steps.
  (`--dry-run` skips this check.)
- The explicit proxy wins over `NO_PROXY`. Python's stock proxy handler would
  silently go direct for hosts matching `NO_PROXY`, which on corporate builds
  often covers internal targets; the in-process fetches don't.
- Without `--proxy`, everything is direct and `HTTP_PROXY`/`HTTPS_PROXY` are
  ignored, as before.
- The manifest records the proxy URL (password masked), which steps used it,
  and the reason each other step did not.
- Burp's own throughput becomes the bottleneck on ffuf/dirsearch/nuclei; expect
  slower runs, and consider `--only` to proxy just the steps you want in
  history.

## Useful options

| Option | |
|---|---|
| `--ports 80,443,8443` | skip the full sweep, use these ports |
| `--pn` | add `-Pn` to nmap (host drops ping) |
| `--only nuclei,ffuf` / `--skip dirsearch` | choose steps (`dns gau portscan services httpx wafw00f nuclei wpscan ffuf dirsearch sslscan testssl csp`) |
| `--wpscan always\|never` | override WordPress auto-detection |
| `--wordlist PATH` | ffuf wordlist (default: SecLists raft-medium-directories) |
| `--dirsearch-wordlist PATH` | dirsearch wordlist (default: its own) |
| `--no-update` | skip nuclei template / WPScan DB updates |
| `--prod` | scan `--target` at production intensity (per-line `prod` does the same in a targets file) |
| `--label NAME` | name for the batch (output dir + evidence CSV Engagement column) |
| `--dry-run` | check targets and tools, write the planned commands, run nothing |
| `-q` | don't echo tool output to the console |

## Tests

```bash
bash tests/run_tests.sh
```

149 checks — no network, no root, no real scanning. The suite runs with a
throwaway `HOME` and an empty venv root, so it never reads your real config
or runs your real tools. The venv tests build real venvs and install
stand-in wheels offline. Tools are stubs in
`tests/stubs/`; the CSP fetch and the AI calls run for real over HTTP against
`tests/fake_server.py` on 127.0.0.1 (a flawed CSP, an in-scope and an
out-of-scope redirect, and fake Gemini `generateContent` and Anthropic
`/v1/messages` endpoints that record what they were sent, including a Gemini
404 for an unknown model). Covered: the targets file and allow-list, artefact separation, token and API-key
masking, progress filtering, profiles, Ctrl-C, timeouts, the integrity check,
every CSP rule family, both AI providers' request shapes, key placement and
masking, thought-part filtering, no silent provider fallback, the config file
(discovery, precedence, permission warning, typo and placeholder
handling, keys kept out of child processes and evidence), per-tool venv
installs (isolation, venv-only pip, preference over PATH, rebuild, trust
check), the installer on a non-Kali system (fake apt/go/git/gem
reproducing the first real Ubuntu install), out-of-scope redirects,
environment-proxy bypass, `--proxy` (which steps get it, which must not,
refusals, `NO_PROXY` override, credential masking), and
concurrent runs.
**Run them after any change.** They prove the orchestration and the evidence
record; they do not prove the real tools accept these flags, so do one real run
against a lab target after installing.

Bugs the suite has caught, each now guarded by a test that was confirmed to
fail when the bug is reintroduced:

- `http://host` and `https://host` produced the same filenames, so the port-443
  run silently overwrote the port-80 artefacts.
- The CSP fetch honoured `HTTP_PROXY` and analysed a proxy's error page as the
  target's response. (The first test for this checked a log line instead of
  behaviour and passed against the broken code; it now uses a dead proxy.)
- Two runs on one host in the same second shared a run directory and mixed
  their evidence.
- With a proxy set, the CSP fetch still went direct for any target
  matching `NO_PROXY` (urllib consults it even for an explicit proxy).
