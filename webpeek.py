#!/usr/bin/env python3
"""
webpeek.py - Automated Enumeration.

Runs the enumeration phase against one target, or a list of targets from a
plain-text file, and keeps every artefact as evidence:

    01_dns          nslookup
    01_passive      gau - archived URLs; no requests to the target
    02_portscan     nmap -p- --open                      (network scanning)
    03_services     nmap -sV -sC on the open ports       (service discovery)
    04_fingerprint  httpx -td (Wappalyzer fingerprints); wafw00f
    05_vulnscan     nuclei; WPScan when WordPress found   (vulnerability scanning)
    06_content      ffuf; dirsearch                      (content discovery)
    07_tls          sslscan; testssl                     (SSL/TLS enumeration)
    08_csp          CSP review: deterministic rules + optional AI review

Every run writes manifest.json (tool versions, exact commands, timestamps,
exit codes, SHA-256 of every output), SHA256SUMS, summary.md and
evidence_rows.csv - helpful for CREST "Enumeration and Analysis Evidence"

The operator names what to scan - one --target, or a targets file (one entry
per line). That list is the allow-list: the active tools only touch what is on
it, and a redirect off to a host not on it is refused. There is no engagement-
window check - authorisation for the engagement lives in the contract, and the
targets file is the operator's record of it. Keep that file under change control
if you want an audit trail.

Missing tools are installed when the script runs as root: apt first, then
go / gem. Python tools (dirsearch, wafw00f) are different - each is installed
from PyPI into its OWN venv under /opt/exfiltra-webpeek/venvs, never with
apt, system pip or pipx, and the venv copy is always the one that runs. Designed for Kali; works on any apt-based distribution.

Quick start:
    sudo ./webpeek.py --target app.client.com
    sudo ./webpeek.py --target https://app.client.com/portal
    sudo ./webpeek.py --targets targets.txt
    ./webpeek.py --check-tools
    sudo ./webpeek.py --install-only

Run ./webpeek.py --help for everything else.
"""

import argparse
import datetime as dt
import getpass
import hashlib
import ipaddress
import json
import os
import queue
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import csp_check  # noqa: E402  (lives alongside this script)
import enum_config  # noqa: E402

VERSION = "1.1.0"

# --------------------------------------------------------------------------
# Scan profiles
#
# "standard" is for dedicated test and staging hosts and follows the commands
# the team runs by hand. "production" is for live customer-facing hosts:
# A full 65,535-port sweep at --max-rate 100 takes roughly 11 minutes per host.
# --------------------------------------------------------------------------
PROFILES = {
    "standard": {
        "nmap_portscan": ["-T4"],
        "nmap_services": [],
        "nuclei": [],
        "ffuf": ["-t", "40"],
        "dirsearch": ["-t", "25"],
        "wpscan": [],
    },
    "production": {
        "nmap_portscan": ["-T3", "--max-rate", "100", "--max-retries", "2"],
        "nmap_services": ["-T3", "--max-rate", "100"],
        "nuclei": ["-rl", "20", "-c", "5"],
        "ffuf": ["-t", "5", "-rate", "20"],
        "dirsearch": ["-t", "5", "--delay", "0.2"],
        "wpscan": ["--throttle", "500"],
    },
}

# Per-step ceilings in seconds. Generous on purpose - a timeout is recorded in
# the manifest as a failed step, so set these to "something is wrong", not to
# "this is taking a while".
TIMEOUTS = {
    "dns": 60,
    "portscan": 4 * 3600,
    "services": 2 * 3600,
    "httpx": 600,
    "nuclei": 3 * 3600,
    "wpscan": 3600,
    "ffuf": 2 * 3600,
    "dirsearch": 2 * 3600,
    "sslscan": 900,
    "testssl": 1800,
    "wafw00f": 600,
    "gau": 1800,
    "setup": 1800,
}

STEPS = ["dns", "gau", "portscan", "services", "httpx", "wafw00f", "nuclei", "wpscan",
         "ffuf", "dirsearch", "sslscan", "testssl", "csp"]

GAU_PROVIDERS = "wayback,commoncrawl,otx,urlscan"

# Activity labels use the wording of CREST 3.3.1 and methodology v1.2 so the
# evidence CSV drops straight into the workbook.
ACTIVITY = {
    "dns": "Name resolution",
    "portscan": "Network scanning",
    "services": "Service discovery",
    "httpx": "System fingerprinting",
    "nuclei": "Vulnerability scanning",
    "wpscan": "Vulnerability scanning",
    "ffuf": "Content and parameter discovery",
    "dirsearch": "Content and parameter discovery",
    "sslscan": "Service discovery (TLS)",
    "testssl": "Service discovery (TLS)",
    "wafw00f": "System fingerprinting",
    "gau": "Passive reconnaissance",
    "csp": "Vulnerability assessment (CSP review)",
    "csp-ai": "Vulnerability assessment (CSP review, AI-assisted - unverified)",
}

# SecLists is packaged only for Kali. Elsewhere the installer downloads just
# these files from the official repository (not the multi-GB full clone).
SECLISTS_FILES = [
    "Discovery/Web-Content/raft-medium-directories.txt",
    "Discovery/Web-Content/common.txt",
]
SECLISTS_BASE = "https://raw.githubusercontent.com/danielmiessler/SecLists"


def own_wordlist_dir():
    return opt_root() / "wordlists" / "seclists"


def ffuf_wordlists():
    """Candidate ffuf wordlists, best first: SecLists raft-medium (system or our
    own downloaded copy), then SecLists common, then dirb's common."""
    sys_sl, own = Path("/usr/share/seclists"), own_wordlist_dir()
    return [str(sys_sl / SECLISTS_FILES[0]), str(own / SECLISTS_FILES[0]),
            str(sys_sl / SECLISTS_FILES[1]), str(own / SECLISTS_FILES[1]),
            "/usr/share/wordlists/dirb/common.txt", "/usr/share/dirb/wordlists/common.txt"]


def first_wordlist():
    return next((w for w in ffuf_wordlists() if os.path.exists(w)), None)

# --------------------------------------------------------------------------
# Tool registry. "bins" are tried in order. "validate" guards against name
# clashes - Debian's python3-httpx ships an unrelated `httpx` command.
# --------------------------------------------------------------------------
# "apt" may be one package or a list tried in order. "kali_only": the apt
# package exists only in Kali's repositories, so on Debian/Ubuntu apt is not
# attempted and the go/gem/git route is used directly.
TOOLS = {
    "nmap": {"bins": ["nmap"], "apt": "nmap", "version": ["--version"]},
    # bind9-dnsutils is the real package on current Debian/Ubuntu/Kali;
    # "dnsutils" is only a transitional name and is gone from newer releases.
    "nslookup": {"bins": ["nslookup"], "apt": ["bind9-dnsutils", "dnsutils"],
                 "version": ["-version"]},
    "httpx": {"bins": ["httpx-toolkit", "httpx"], "apt": "httpx-toolkit", "kali_only": True,
              "go": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
              "version": ["-version"],
              "validate": r"(?i)projectdiscovery|current version"},
    "nuclei": {"bins": ["nuclei"], "apt": "nuclei", "kali_only": True,
               "go": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
               "version": ["-version"]},
    "wpscan": {"bins": ["wpscan"], "apt": "wpscan", "kali_only": True, "gem": "wpscan",
               "version": ["--version"]},
    "ffuf": {"bins": ["ffuf"], "apt": "ffuf",
             "go": "github.com/ffuf/ffuf/v2@latest", "version": ["-V"]},
    # Python tools: "venv" = PyPI package installed into the tool's OWN venv
    # (see PYTHON TOOL VENVS below). Never apt, never system pip, never pipx.
    "dirsearch": {"bins": ["dirsearch"], "venv": "dirsearch", "version": ["--version"]},
    "sslscan": {"bins": ["sslscan"], "apt": "sslscan", "version": ["--version"]},
    # testssl.sh's own recommended install is a git checkout. Used when the apt
    # package is unavailable. Pinned to a release branch, not the dev branch.
    "testssl": {"bins": ["testssl", "testssl.sh"], "apt": "testssl.sh",
                "git": {"url": "https://github.com/testssl/testssl.sh.git",
                        "dir": "testssl.sh", "bin": "testssl.sh"},
                "version": ["--version"]},
    "wafw00f": {"bins": ["wafw00f"], "venv": "wafw00f", "version": ["--version"]},
    # Kali packages gau as "getallurls" (the name "gau" clashes with an
    # oh-my-zsh git alias). Either binary works.
    "gau": {"bins": ["gau", "getallurls"], "apt": "getallurls", "kali_only": True,
            "go": "github.com/lc/gau/v2/cmd/gau@latest", "version": ["--version"]},
}

# Names as they are written in the evidence workbook ("Nmap 7.98", "WPScan 3.8.28").
DISPLAY = {"nmap": "Nmap", "nslookup": "nslookup", "httpx": "httpx", "nuclei": "Nuclei",
           "wpscan": "WPScan", "ffuf": "ffuf", "dirsearch": "dirsearch",
           "sslscan": "sslscan", "testssl": "testssl.sh", "wafw00f": "wafw00f",
           "gau": "gau", "csp_check": "csp_check", "anthropic": "Anthropic API",
           "gemini": "Google Gemini API"}

# --------------------------------------------------------------------------
# --proxy: which tools route their TARGET traffic through it, and with what flag.
# Only traffic to the target goes through the proxy. Anything not listed here
# connects directly, for the reason given in PROXY_NOT_APPLIED - that reason is
# copied into every run's manifest so the evidence says what was NOT proxied.
# --------------------------------------------------------------------------
PROXY_FLAGS = {
    "httpx": "-http-proxy",      # httpx: -http-proxy / -proxy
    "nuclei": "-proxy",          # nuclei: -proxy / -p (interactsh traffic stays direct)
    "wpscan": "--proxy",         # WPScan: --proxy protocol://host:port
    "ffuf": "-x",                # ffuf: -x proxy URL
    "dirsearch": "--proxy",      # dirsearch: --proxy URL
    "wafw00f": "--proxy",        # wafw00f: -p / --proxy URL
}
PROXY_IN_PROCESS = ["csp_check (CSP fetch)", "WordPress fallback check"]
PROXY_NOT_APPLIED = {
    "gau": "queries public archives, not the target",
    "csp AI review": "goes to the AI provider, not the target",
    "nmap": "raw TCP/SYN scanning and NSE cannot be carried by an HTTP proxy",
    "nslookup": "DNS, not HTTP",
    "sslscan": "an intercepting proxy terminates TLS, so the proxy's TLS would be "
               "assessed instead of the target's",
    "testssl": "an intercepting proxy terminates TLS, so the proxy's TLS would be "
               "assessed instead of the target's",
    "updates": "nuclei template and WPScan database updates go to their vendors, "
               "not the target",
}


def parse_proxy(raw):
    """Validate --proxy. Returns (url, display_url) or raises ValueError.
    http(s) only: the in-process fetches use urllib, which has no SOCKS support,
    and one proxy must carry every proxied step or the record is inconsistent."""
    u = urllib.parse.urlsplit(raw.strip())
    if u.scheme.lower() not in ("http", "https"):
        raise ValueError("must start with http:// or https:// (e.g. http://127.0.0.1:8080)")
    try:
        port = u.port
    except ValueError:
        raise ValueError("port is not a number")
    if not u.hostname or not port:
        raise ValueError("needs a host and a port (e.g. http://127.0.0.1:8080)")
    if u.path not in ("", "/") or u.query or u.fragment:
        raise ValueError("must be just scheme://host:port")
    url = f"{u.scheme.lower()}://{u.netloc}"
    display = url if u.password is None else url.replace(":" + u.password + "@", ":***@", 1)
    return url, display


def proxy_reachable(url, timeout=5):
    u = urllib.parse.urlsplit(url)
    try:
        socket.create_connection((u.hostname, u.port), timeout=timeout).close()
        return None
    except OSError as e:
        return str(e)


def proxy_args(tool, proxy):
    """Extra argv for `tool` when a proxy is in use ([] for unproxied tools)."""
    if not proxy or tool not in PROXY_FLAGS:
        return []
    return [PROXY_FLAGS[tool], proxy]


def short_version(raw):
    """'Nmap version 7.98 ( https://nmap.org )' -> '7.98'; 'v1.6.9' -> '1.6.9';
    'testssl.sh 3.2rc3' -> '3.2rc3'; '2.1.0-dev' -> '2.1.0-dev'."""
    m = re.search(r"(\d+\.\d+(?:\.\d+)*(?:[-.]?[A-Za-z][A-Za-z0-9]*)?)", raw or "")
    return m.group(1) if m else ""


STEP_TOOL = {"dns": "nslookup", "portscan": "nmap", "services": "nmap",
             "httpx": "httpx", "nuclei": "nuclei", "wpscan": "wpscan",
             "ffuf": "ffuf", "dirsearch": "dirsearch", "sslscan": "sslscan",
             "testssl": "testssl", "wafw00f": "wafw00f", "gau": "gau",
             "csp": None}   # None = runs in-process, nothing to install

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][0-9A-Za-z]")

# Live progress meters redraw with \r. Kept in full they turn a 20-line log
# into 20,000 lines. Drop the in-flight frames, keep anything at 100%.
PROGRESS = [
    re.compile(r"^:: Progress: \["),                       # ffuf
    re.compile(r"job:\d+/\d+\s+errors:\d+"),                # dirsearch
    re.compile(r"\(\s*\d+\s*/\s*\d+\s*\)\s+\d+\.\d+%"),     # wpscan
]


def now():
    return dt.datetime.now().astimezone()


def iso(t):
    return t.isoformat(timespec="seconds")


def slug(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")[:80] or "target"


def url_slug(url):
    """Filename stem for a URL. MUST keep scheme and port: http://h and https://h
    are different services, and an earlier version that dropped the scheme let
    the 443 run silently overwrite the port-80 artefacts."""
    u = urllib.parse.urlsplit(url)
    stem = f"{u.scheme}_{u.hostname}" + (f"_{u.port}" if u.port else "")
    if u.path and u.path != "/":
        stem += "_" + u.path.strip("/")
    return slug(stem)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


# ==========================================================================
# Console
# ==========================================================================
class Console:
    def __init__(self, quiet=False):
        self.quiet = quiet
        self.color = sys.stdout.isatty()

    def _c(self, code, s):
        return f"\x1b[{code}m{s}\x1b[0m" if self.color else s

    def info(self, s):
        print(self._c("36", "[*] ") + s, flush=True)

    def ok(self, s):
        print(self._c("32", "[+] ") + s, flush=True)

    def warn(self, s):
        print(self._c("33", "[!] ") + s, flush=True)

    def err(self, s):
        print(self._c("31", "[x] ") + s, file=sys.stderr, flush=True)

    def stream(self, s):
        if not self.quiet:
            print("    " + s, flush=True)


# ==========================================================================
# Secret masking - the WPScan token must never reach a log file.
# ==========================================================================
class Masker:
    def __init__(self):
        self.secrets = []

    def add(self, value):
        if value and len(value) >= 6:
            self.secrets.append(value)

    def __call__(self, text):
        for s in self.secrets:
            text = text.replace(s, "<REDACTED>")
        return re.sub(r"(--api-token[ =])\S+", r"\1<REDACTED>", text)


# ==========================================================================
# Targets and the allow-list
#
# The operator names what to scan: either one --target, or a plain-text targets
# file (one entry per line). That list IS the allow-list - the active tools only
# ever touch what is on it, and a redirect off to any host not on it is refused
# (see in_allowlist, used by the CSP fetch). There is no engagement-window check:
# authorisation for the engagement lives in the engagement contract, and the
# targets file is the operator's record of what that contract permits. Keep that
# file under change control if you want an audit trail.
# ==========================================================================
def parse_targets_line(line):
    """One targets-file line -> (token, prod) or None for blank/comment lines.

    'app.example.com            prod   # main app'  -> ('app.example.com', True)
    A line may be a host, an IP, a CIDR range, or a URL, optionally followed by
    the flag `prod` (scan at reduced 'production' intensity). '#' starts a
    comment, anywhere on the line."""
    line = line.split("#", 1)[0].strip()
    if not line:
        return None
    fields = line.split()
    token, flags = fields[0], {f.lower() for f in fields[1:]}
    unknown = flags - {"prod", "production"}
    if unknown:
        raise SystemExit(f"targets file: unknown flag(s) {', '.join(sorted(unknown))} on line '{line}'")
    return token, bool(flags & {"prod", "production"})


def load_targets(path):
    """Read a targets file into an ordered list of {raw, prod}. Raises SystemExit
    with a clear message on a missing file or an empty list."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise SystemExit(f"cannot read targets file {path}: {e}")
    entries, seen = [], set()
    for raw_line in text.splitlines():
        parsed = parse_targets_line(raw_line)
        if not parsed:
            continue
        token, prod = parsed
        if token.lower() in seen:
            continue                        # a duplicate line is not two runs
        seen.add(token.lower())
        cidr = False
        if "/" in token and not re.match(r"^https?://", token, re.I):
            try:
                ipaddress.ip_network(token, strict=False)
                cidr = True                 # containment range, not a scan target
            except ValueError:
                cidr = False
        entries.append({"raw": token, "prod": prod, "cidr": cidr})
    if not entries:
        raise SystemExit(f"targets file {path} has no targets (only blanks/comments)")
    return entries


def build_allowlist(entries):
    """From the scan targets, the set of hosts and the CIDR ranges the active
    tools are allowed to touch. A URL contributes its hostname; a bare IP its
    address; a CIDR entry its whole range (and such an entry is containment-only,
    never itself a scan target)."""
    hosts, nets = set(), []
    for e in entries:
        tok = e["raw"]
        if e.get("cidr"):
            try:
                nets.append(ipaddress.ip_network(tok, strict=False))
            except ValueError:
                pass
            continue
        host, _ = parse_target(tok)
        if host:
            hosts.add(host.lower().rstrip("."))
    return hosts, nets


def in_allowlist(host, hosts, nets):
    """True if host (a name or IP) is one of the named targets or inside an
    authorised CIDR range. Used to contain redirects during the CSP fetch."""
    h = (host or "").lower().rstrip(".")
    if not h:
        return False
    if h in hosts:
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return any(ip in n for n in nets)


# ==========================================================================
# Tool discovery and installation
# ==========================================================================
def opt_root():
    """Everything the installer builds lives here: venvs/, bin/ (go tools),
    testssl.sh/ (git checkout). Root-owned, 755 - readable by a non-root
    operator, unlike /root/go/bin."""
    return Path(os.environ.get("WEBPEEK_OPT_ROOT", "/opt/exfiltra-webpeek"))


def os_release():
    """/etc/os-release as a dict. WEBPEEK_OS_RELEASE_FILE is for the tests."""
    d = {}
    try:
        with open(os.environ.get("WEBPEEK_OS_RELEASE_FILE", "/etc/os-release"), encoding="utf-8") as f:
            for line in f:
                if "=" in line:
                    k, v = line.rstrip("\n").split("=", 1)
                    d[k] = v.strip().strip('"')
    except OSError:
        pass
    return d


def is_kali():
    r = os_release()
    return "kali" in f"{r.get('ID', '')} {r.get('ID_LIKE', '')}".lower()


ERROR_LINE = re.compile(r"^(E:|error|fatal:|go: |ERROR|Unable to|.*not found)", re.I)
# go prints progress with the same "go: " prefix as its errors.
INFO_LINE = re.compile(r"^go: (downloading|finding|extracting|upgraded|added) ", re.I)


def failure_reason(output, n=3):
    """The few lines that say WHY an install failed - apt's 'E:' lines, go's
    'go:' error lines, git's 'fatal:' - else the last lines of output."""
    lines = [l.strip() for l in ANSI.sub("", output or "").splitlines() if l.strip()]
    hits = [l for l in lines if ERROR_LINE.match(l) and not INFO_LINE.match(l)]
    return [l[:220] for l in (hits or lines)[-n:]]


def extra_paths():
    """Places go/gem/git installs put binaries that are often not on root's PATH."""
    paths = [str(opt_root() / "bin"), str(opt_root() / "testssl.sh")]
    for home in {os.path.expanduser("~"), "/root"}:
        paths += [f"{home}/go/bin", f"{home}/.local/bin"]
    if shutil.which("go"):
        try:
            gp = subprocess.run(["go", "env", "GOPATH"], capture_output=True, text=True,
                                timeout=20, env=enum_config.child_env()).stdout.strip()
            if gp:
                paths.append(os.path.join(gp, "bin"))
        except Exception:
            pass
    paths += ["/usr/local/bin", "/usr/share/testssl.sh"]
    return [p for p in dict.fromkeys(paths) if os.path.isdir(p)]


def tool_version(path, args):
    try:
        r = subprocess.run([path] + args, capture_output=True, text=True,
                           timeout=60, stdin=subprocess.DEVNULL, env=enum_config.child_env())
        out = ANSI.sub("", (r.stdout or "") + "\n" + (r.stderr or ""))
    except Exception as e:
        return None, f"<version check failed: {e}>"
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    # Prefer a line that actually carries a version number.
    pick = next((l for l in lines if re.search(r"\d+\.\d+", l)
                 and not l.startswith("__")), lines[0] if lines else "")
    return out, pick[:200]


# ==========================================================================
# PYTHON TOOL VENVS
#
# Every Python tool lives in its own virtual environment:
#     /opt/exfiltra-webpeek/venvs/<tool>/       (WEBPEEK_VENV_ROOT / [install] venv_root)
# Why: Kali refuses system-wide pip (PEP 668); apt copies change under you on
# every OS upgrade; and two tools sharing site-packages can break each other's
# dependencies. A per-tool venv is isolated, and its exact package set is
# recorded in each run's manifest.
#
# The venv copy is ALWAYS preferred. A system copy on PATH is used only as a
# fallback (e.g. a non-root run before the venv exists), and the manifest says
# which one ran.
# ==========================================================================
def venv_root():
    return Path(os.environ.get("WEBPEEK_VENV_ROOT", "") or opt_root() / "venvs")


def venv_dir(name):
    return venv_root() / name


def venv_bin(name):
    return venv_dir(name) / "bin" / TOOLS[name]["bins"][0]


def venv_trusted(d):
    """Tools are run as root. A venv that other users can write to would let
    them swap the binary root executes, so it is not used. Same idea as the
    config-file permission check."""
    if os.name != "posix":
        return True
    allowed = {os.geteuid(), 0}
    if os.environ.get("SUDO_UID", "").isdigit():
        allowed.add(int(os.environ["SUDO_UID"]))
    for p in (d, d / "bin"):
        try:
            st = os.stat(p)
        except OSError:
            return False
        if st.st_mode & 0o022 or st.st_uid not in allowed:
            return False
    return True


def tool_source(name, path):
    if not path:
        return None
    if TOOLS[name].get("venv"):
        try:
            Path(path).resolve().relative_to(venv_dir(name).resolve())
            return "venv"
        except ValueError:
            return "system (not in its venv)"
    try:
        Path(path).resolve().relative_to(opt_root().resolve())
        return "webpeek (/opt)"            # installed by us, e.g. go tools in /opt/.../bin
    except ValueError:
        return "system"


def venv_packages(name):
    """Exact package set inside a tool's venv - recorded in the manifest."""
    py = venv_dir(name) / "bin" / "python"
    if not py.exists():
        return []
    try:
        r = subprocess.run([str(py), "-m", "pip", "freeze", "--all"], capture_output=True,
                           text=True, timeout=60, stdin=subprocess.DEVNULL,
                           env=enum_config.child_env())
        return [l for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        return []


def find_tool(name):
    spec = TOOLS[name]
    if spec.get("venv"):
        vb = venv_bin(name)
        if vb.exists() and os.access(vb, os.X_OK):
            if venv_trusted(venv_dir(name)):
                return str(vb)
            print(f"[!] {venv_dir(name)} is writable by other users or not owned by you/root "
                  f"- not using it", file=sys.stderr)
    search = os.environ.get("PATH", "") + os.pathsep + os.pathsep.join(extra_paths())
    for b in spec["bins"]:
        path = shutil.which(b, path=search)
        if not path:
            continue
        if spec.get("validate"):
            raw, _ = tool_version(path, spec["version"])
            if not raw or not re.search(spec["validate"], raw):
                continue
        return path
    return None


class Installer:
    def __init__(self, log_path, console, masker):
        self.log_path = log_path
        self.console = console
        self.masker = masker
        self.apt_updated = False
        self.announced = False
        self.last_reason = []

    def _announce(self):
        """Say once, up front, what kind of system this is - it decides which
        install route each tool takes."""
        if self.announced:
            return
        self.announced = True
        name = os_release().get("PRETTY_NAME", "unknown OS")
        if is_kali():
            self.console.info(f"system: {name}")
        else:
            kali = ", ".join(n for n, s in TOOLS.items() if s.get("kali_only"))
            self.console.info(f"system: {name} (not Kali) - {kali} are Kali-only apt packages, "
                              "so they come from go/gem directly")

    def _run(self, argv, env=None):
        """Run one install command. Full output goes to the install log; the
        lines that explain a failure are kept in self.last_reason for the console."""
        self._announce()
        self.console.info("install: " + " ".join(argv))
        self.last_reason = []
        with open(self.log_path, "a", encoding="utf-8") as log:
            log.write(f"\n# {iso(now())}  $ {' '.join(map(shlex.quote, argv))}\n")
            log.flush()
            try:
                r = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL, env=enum_config.child_env(env),
                                   timeout=TIMEOUTS["setup"])
                out = self.masker(r.stdout.decode("utf-8", "replace"))
                log.write(out)
                log.write(f"\n# exit={r.returncode}\n")
                if r.returncode != 0:
                    self.last_reason = failure_reason(out) or [f"exit code {r.returncode}"]
                return r.returncode == 0
            except subprocess.TimeoutExpired:
                self.last_reason = [f"timed out after {TIMEOUTS['setup']}s"]
            except FileNotFoundError:
                self.last_reason = [f"{argv[0]}: command not found"]
            except Exception as e:
                self.last_reason = [f"{type(e).__name__}: {e}"]
            log.write(f"# failed: {'; '.join(self.last_reason)}\n")
            return False

    def apt(self, pkgs):
        """Install the first package of `pkgs` (str or list) that apt can provide."""
        if not shutil.which("apt-get"):
            self.last_reason = ["apt-get not available on this system"]
            return False
        # NEEDRESTART_*: Ubuntu's needrestart hook otherwise opens an
        # interactive "restart services?" dialog in the middle of an install.
        env = {"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "a",
               "NEEDRESTART_SUSPEND": "1"}
        if not self.apt_updated:
            self._run(["apt-get", "update"], env)
            self.apt_updated = True
        reasons = []
        for pkg in ([pkgs] if isinstance(pkgs, str) else pkgs):
            if self._run(["apt-get", "install", "-y", "--no-install-recommends", pkg], env):
                return True
            reasons.append(f"{pkg}: " + "; ".join(self.last_reason))
        self.last_reason = reasons
        return False

    def go(self, module):
        if not shutil.which("go") and not self.apt("golang-go"):
            return False
        gobin = opt_root() / "bin"
        gobin.mkdir(parents=True, exist_ok=True)
        # GOBIN in /opt, not /root/go/bin: a non-root operator can't even read
        # /root, so tools installed there vanish for `--check-tools` without sudo.
        return self._run(["go", "install", "-v", module], {"GOBIN": str(gobin)})

    def gem(self, name):
        if not shutil.which("gem") and not self.apt("ruby-dev"):
            return False
        self.apt("build-essential")
        return self._run(["gem", "install", name])

    def git(self, spec):
        """Shallow checkout of a release branch into /opt/exfiltra-webpeek/<dir>."""
        if not shutil.which("git") and not self.apt("git"):
            return False
        dest = opt_root() / spec["dir"]
        ref = os.environ.get("WEBPEEK_TESTSSL_REF", "").strip() or "3.2"
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            shutil.rmtree(dest)
        if not self._run(["git", "clone", "--depth", "1", "--branch", ref, spec["url"], str(dest)]):
            return False
        return (dest / spec["bin"]).exists()

    def venv(self, name):
        """Install a Python tool into its own venv. Returns True on success."""
        d = venv_dir(name)
        py = d / "bin" / "python"
        pkg = TOOLS[name]["venv"]
        extra = shlex.split(os.environ.get("WEBPEEK_PIP_ARGS", ""))
        d.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d.parent, 0o755)               # readable by all, writable by owner only
        except OSError:
            pass                                    # not ours; venv_trusted() still guards use
        if not py.exists():
            if d.exists():
                shutil.rmtree(d)                    # half-built venv from a failed attempt
            base = sys.executable or "python3"
            if not self._run([base, "-m", "venv", str(d)]):
                # Debian/Kali ship the venv module separately.
                shutil.rmtree(d, ignore_errors=True)
                if not (self.apt("python3-venv") and self._run([base, "-m", "venv", str(d)])):
                    return False
        # Best effort: newer pip/setuptools/wheel (Python 3.12+ venvs ship no
        # setuptools). Not fatal - an offline mirror may not carry them.
        self._run([str(py), "-m", "pip", "install", "--disable-pip-version-check",
                   "--upgrade", "pip", "setuptools", "wheel"] + extra)
        if not self._run([str(py), "-m", "pip", "install", "--disable-pip-version-check",
                          "--upgrade", pkg] + extra):
            return False
        return venv_bin(name).exists()

    def ensure(self, name):
        spec = TOOLS[name]
        if spec.get("venv"):
            # Python tools: the venv copy, installed even if a system copy exists.
            if venv_bin(name).exists() and venv_trusted(venv_dir(name)):
                return True
            if self.venv(name):
                self.console.ok(f"installed {name} into its venv {venv_dir(name)}")
                return True
            self._report_failure(name, [f"venv install failed - {'; '.join(self.last_reason) or 'no output'}"])
            return False
        if find_tool(name):
            return True
        reasons = []
        for method in ("apt", "go", "gem", "git"):
            if not spec.get(method):
                continue
            if method == "apt" and spec.get("kali_only") and not is_kali():
                continue                    # announced once in _announce()
            if getattr(self, method)(spec[method]):
                if find_tool(name):
                    self.console.ok(f"installed {name} via {method}")
                    for r in reasons:       # say why the earlier route didn't work
                        self.console.info(f"    ({r})")
                    return True
                reasons.append(f"{method} succeeded but no {'/'.join(spec['bins'])} "
                               f"binary was found on PATH or in {opt_root()}")
            else:
                reasons.append(f"{method} failed - " + ("; ".join(self.last_reason) or "no output"))
        self._report_failure(name, reasons)
        return False

    def _report_failure(self, name, reasons):
        self.console.warn(f"could not install {name}:")
        for r in reasons:
            self.console.warn(f"    {r}")
        self.console.warn(f"    full output: {self.log_path}")

    def download_wordlists(self):
        """Fetch SECLISTS_FILES from the official SecLists repository into
        /opt/exfiltra-webpeek/wordlists/seclists. Returns True if at least one
        arrived intact. Each file's URL, size and SHA-256 go to the install log."""
        ref = os.environ.get("WEBPEEK_SECLISTS_REF", "").strip() or "master"
        base = (os.environ.get("WEBPEEK_SECLISTS_BASE_URL", "").strip() or SECLISTS_BASE).rstrip("/")
        self._announce()
        reasons, got = [], 0
        with open(self.log_path, "a", encoding="utf-8") as log:
            for rel in SECLISTS_FILES:
                url = f"{base}/{ref}/{rel}"
                self.console.info(f"install: download {url}")
                log.write(f"\n# {iso(now())}  GET {url}\n")
                try:
                    # Vendor download, not target traffic: certificate-verified,
                    # and environment proxies (corporate egress) are honoured.
                    req = urllib.request.Request(url, headers={"User-Agent": f"exfiltra-webpeek/{VERSION}"})
                    with urllib.request.urlopen(req, timeout=120) as r:
                        data = r.read()
                except Exception as e:
                    reasons.append(f"{rel}: {type(e).__name__}: {e}")
                    log.write(f"# failed: {reasons[-1]}\n")
                    continue
                if not data.strip() or data.lstrip()[:1] == b"<":
                    # An empty body or an HTML error page is not a wordlist.
                    reasons.append(f"{rel}: response is not a wordlist (empty or HTML)")
                    log.write(f"# rejected: {reasons[-1]}\n")
                    continue
                dest = own_wordlist_dir() / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                tmp = dest.with_suffix(dest.suffix + ".part")
                tmp.write_bytes(data)
                os.chmod(tmp, 0o644)
                tmp.replace(dest)
                lines = data.count(b"\n")       # outside the f-string: pre-3.12 Pythons reject '\' there
                log.write(f"# saved {dest} ({len(data)} bytes, {lines} lines, "
                          f"sha256 {hashlib.sha256(data).hexdigest()})\n")
                got += 1
        self.last_reason = reasons
        return got > 0

    def ensure_wordlists(self):
        found = first_wordlist()
        reasons = []
        if not found and is_kali():
            if self.apt("seclists"):
                found = first_wordlist()
            else:
                reasons.append("apt failed - " + "; ".join(self.last_reason))
        if not found:
            # Not Kali (no seclists package), or apt failed on Kali.
            if self.download_wordlists():
                found = first_wordlist()
            else:
                reasons.append("download failed - " + "; ".join(self.last_reason))
        if found:
            self.console.ok(f"ffuf wordlist: {found}")
            for r in reasons:
                self.console.info(f"    ({r})")
            return True
        self._report_failure("ffuf wordlist (SecLists)", reasons + ["or pass --wordlist PATH at scan time"])
        return False


# ==========================================================================
# Step runner
# ==========================================================================
class Run:
    def __init__(self, root, console, masker, manifest_writer, dry_run=False):
        self.root = Path(root)
        self.console = console
        self.mask = masker
        self.write_manifest = manifest_writer
        self.dry_run = dry_run
        self.steps = []
        self.proc = None
        self.claimed = set()
        self.runlog = open(self.root / "run.log", "a", encoding="utf-8")

    def note(self, s):
        self.runlog.write(f"{iso(now())}  {self.mask(s)}\n")
        self.runlog.flush()

    def write_artifact(self, rel, text):
        """Write an output file from in-process code - always through the masker."""
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.mask(text), encoding="utf-8")

    def _run_fn(self, fn, log):
        """In-process work gets the same transcript discipline as a subprocess:
        everything it logs is masked, and an exception is a failed step, not a crash."""
        mask = self.mask

        class MaskedLog:
            def write(self, s):
                log.write(mask(s))

            def flush(self):
                log.flush()
        try:
            return fn(MaskedLog()) or "completed"
        except KeyboardInterrupt:
            raise
        except Exception as e:
            log.write(f"\n# error: {type(e).__name__}: {mask(str(e))}\n")
            return "failed"

    def step(self, key, label, tool, version, argv, log_rel, outputs=(),
             timeout=None, summarise=None, fn=None, extra=None):
        """Run one evidence-producing step.

        argv  - the command (executed unless `fn` is given, in which case it is
                only the description recorded as the command line).
        fn    - optional in-process callable fn(log) -> status; used for the CSP
                fetch and the AI call so they leave the same record as a tool.
        extra - dict merged into the step record afterwards (fn may fill it in).
        """
        # Two steps writing the same file is evidence destruction, not a
        # cosmetic problem: the first step's recorded hash stops matching.
        # Fail loudly rather than overwrite.
        for rel in [log_rel] + list(outputs):
            if str(rel) in self.claimed:
                raise RuntimeError(f"artefact path collision on {rel} - refusing to overwrite evidence")
            self.claimed.add(str(rel))
        log_path = self.root / log_rel
        log_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = self.mask(" ".join(shlex.quote(a) for a in argv))
        started = now()
        rec = {
            "step": key, "label": label, "activity": ACTIVITY.get(key, key),
            "tool": tool, "tool_version": version, "command": cmd,
            "started": iso(started), "finished": None, "duration_s": None,
            "exit_code": None, "status": "running", "log": str(log_rel),
            "outputs": [], "summary": "",
        }
        self.steps.append(rec)
        self.console.info(f"{label}")
        self.console.stream("$ " + cmd)
        self.note(f"START {label}: {cmd}")

        with open(log_path, "w", encoding="utf-8") as log:
            log.write(f"{cmd}\n")
            log.write(f"# exfiltra-webpeek {VERSION} | step: {label}\n")
            log.write(f"# tool: {tool} {version}\n")
            log.write(f"# started: {iso(started)}\n\n")
            log.flush()

            if self.dry_run:
                log.write("# DRY RUN - command not executed\n")
                rec.update(status="dry-run", exit_code=None)
            else:
                try:
                    if fn:
                        rec["status"] = self._run_fn(fn, log)
                        rec["exit_code"] = 0 if rec["status"] == "completed" else 1
                    else:
                        rec["exit_code"], rec["status"] = self._execute(argv, log, timeout)
                except KeyboardInterrupt:
                    rec["status"] = "interrupted"
                    rec["finished"] = iso(now())
                    log.write(f"# finished: {rec['finished']} | status: interrupted\n")
                    self.note(f"INTR  {label}")
                    self.write_manifest()
                    raise

            finished = now()
            log.write(f"\n# finished: {iso(finished)} | exit: {rec['exit_code']}"
                      f" | status: {rec['status']}\n")

        rec["finished"] = iso(finished)
        rec["duration_s"] = round((finished - started).total_seconds(), 1)
        if extra:
            rec.update(extra)

        for rel in [log_rel] + list(outputs):
            p = self.root / rel
            if p.exists() and p.is_file():
                rec["outputs"].append({"path": str(rel), "bytes": p.stat().st_size,
                                       "sha256": sha256(p)})
        if summarise and rec["status"] == "completed":
            try:
                rec["summary"] = summarise() or ""
            except Exception as e:
                rec["summary"] = f"(summary unavailable: {e})"

        tag = {"completed": self.console.ok, "dry-run": self.console.info}.get(
            rec["status"], self.console.warn)
        tag(f"{label}: {rec['status']} ({rec['duration_s']}s)"
            + (f" - {rec['summary']}" if rec["summary"] else ""))
        self.note(f"END   {label}: {rec['status']} exit={rec['exit_code']}")
        self.write_manifest()
        return rec

    def skip(self, key, label, tool, reason):
        rec = {"step": key, "label": label, "activity": ACTIVITY.get(key, key),
               "tool": tool, "status": "skipped", "reason": reason,
               "started": iso(now())}
        self.steps.append(rec)
        self.console.warn(f"{label}: skipped - {reason}")
        self.note(f"SKIP  {label}: {reason}")
        self.write_manifest()
        return rec

    def _execute(self, argv, log, timeout):
        lines = queue.Queue()
        last = [None]

        def sink(raw):
            s = ANSI.sub("", raw.decode("utf-8", "replace")).rstrip()
            if any(p.search(s) for p in PROGRESS) and "100.00%" not in s:
                return
            if s == last[0] and s:
                return
            last[0] = s
            lines.put(self.mask(s))

        def pump(stream):
            buf = b""
            while True:
                chunk = stream.read1(8192)
                if not chunk:
                    break
                buf = (buf + chunk).replace(b"\r\n", b"\n")
                parts = re.split(rb"[\r\n]", buf)
                buf = parts.pop()
                for part in parts:
                    sink(part)
            if buf:
                sink(buf)
            lines.put(None)

        try:
            # child_env(): the tools never inherit API keys. The WPScan token
            # reaches WPScan only as its own --api-token argument.
            self.proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT,
                                         stdin=subprocess.DEVNULL, cwd=str(self.root),
                                         env=enum_config.child_env())
        except OSError as e:
            log.write(f"# could not start: {e}\n")
            return None, "failed"

        t = threading.Thread(target=pump, args=(self.proc.stdout,), daemon=True)
        t.start()
        deadline = time.time() + timeout if timeout else None
        status = None
        try:
            while True:
                try:
                    item = lines.get(timeout=1)
                except queue.Empty:
                    item = ""
                if item is None:
                    break
                if item != "":
                    log.write(item + "\n")
                    log.flush()
                    self.console.stream(item)
                if deadline and time.time() > deadline:
                    status = "timeout"
                    self._stop()
                    break
            code = self.proc.wait()
        except KeyboardInterrupt:
            self._stop()
            log.write("\n# INTERRUPTED by operator\n")
            self.proc = None
            raise
        self.proc = None
        if status:
            return code, status
        return code, ("completed" if code == 0 else "failed")

    def _stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# ==========================================================================
# Parsers for the summaries and for chaining steps
# ==========================================================================
def nmap_open_ports(xml_path):
    if not xml_path.exists():
        return []
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        return []
    ports = []
    for p in root.iter("port"):
        st = p.find("state")
        if st is not None and st.get("state") == "open" and p.get("protocol") == "tcp":
            ports.append(int(p.get("portid")))
    return sorted(set(ports))


def nmap_services(xml_path):
    """[{port, name, product, version, tunnel}] for open TCP ports."""
    out = []
    if not xml_path.exists():
        return out
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        return out
    for p in root.iter("port"):
        st = p.find("state")
        if st is None or st.get("state") != "open":
            continue
        sv = p.find("service")
        d = {"port": int(p.get("portid")), "name": "", "product": "",
             "version": "", "tunnel": ""}
        if sv is not None:
            for k in ("name", "product", "version", "tunnel"):
                d[k] = sv.get(k, "") or ""
        out.append(d)
    return out


def is_web(svc):
    n = svc["name"].lower()
    return "http" in n or svc["port"] in (80, 443, 8000, 8008, 8080, 8443, 8888)


def is_tls(svc):
    n = svc["name"].lower()
    return svc["tunnel"] == "ssl" or n.startswith("ssl") or n in ("https", "https-alt") \
        or svc["port"] in (443, 8443)


def url_for(host, svc):
    scheme = "https" if is_tls(svc) else "http"
    default = 443 if scheme == "https" else 80
    port = "" if svc["port"] == default else f":{svc['port']}"
    return f"{scheme}://{host}{port}"


def read_jsonl(path):
    rows = []
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return rows


def httpx_techs(path):
    techs = []
    for r in read_jsonl(path):
        techs += r.get("tech") or r.get("technologies") or []
    return list(dict.fromkeys(techs))


def nuclei_counts(path):
    counts = {}
    for r in read_jsonl(path):
        sev = (r.get("info") or {}).get("severity", "unknown")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def ffuf_hits(path):
    if not path.exists():
        return 0
    try:
        return len(json.loads(path.read_text(encoding="utf-8")).get("results", []))
    except (json.JSONDecodeError, AttributeError):
        return 0


def dirsearch_hits(path):
    """dirsearch plain output: one result per line, starting with the status code."""
    if not path.exists():
        return 0
    return sum(1 for l in path.read_text(encoding="utf-8", errors="replace").splitlines()
               if re.match(r"^\s*\d{3}\s", l))


INTERESTING_EXT = re.compile(
    r"\.(js|json|xml|config|conf|env|ini|bak|old|orig|sql|db|zip|tar|gz|7z|log|txt|ya?ml|map)(\?|$)",
    re.I)


def gau_summary(path):
    if not path.exists():
        return "no output file"
    urls = [l.strip() for l in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if l.strip()]
    params = sum(1 for u in urls if "?" in u)
    hits = sum(1 for u in urls if INTERESTING_EXT.search(u))
    return (f"{len(urls)} archived URLs ({params} with parameters, {hits} with "
            f"interesting extensions); passive - no requests sent to the target")


def wafw00f_summary(path):
    if not path.exists():
        return "no output file"
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return "output not parseable"
    rows = rows if isinstance(rows, list) else [rows]
    found = [f"{r.get('firewall')} ({r.get('manufacturer')})" for r in rows
             if r.get("detected") and r.get("firewall") not in (None, "None", "Generic")]
    generic = any(r.get("detected") and r.get("firewall") in ("Generic",) for r in rows)
    if found:
        return "WAF identified: " + ", ".join(found)
    return "generic WAF behaviour detected, vendor not identified" if generic else "no WAF detected"


def looks_like_wordpress(url, console, proxy=None):
    """Fallback detector used only when httpx is unavailable. One GET request."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        # Direct unless --proxy was given; environment proxies are never used
        # (same reason as csp_check.fetch).
        opener = urllib.request.build_opener(csp_check.ExplicitProxyHandler(proxy),
                                             urllib.request.HTTPSHandler(context=ctx))
        body = opener.open(req, timeout=15).read(400000)
        return b"/wp-content/" in body or b"/wp-includes/" in body
    except Exception as e:
        console.warn(f"WordPress check on {url} failed: {e}")
        return False


# ==========================================================================
# Main pipeline
# ==========================================================================
def parse_target(raw):
    if re.match(r"^https?://", raw, re.I):
        u = urllib.parse.urlsplit(raw)
        return u.hostname.lower(), raw.rstrip("/") if u.path in ("", "/") else raw
    return raw.lower().rstrip("."), None


def resolve(host):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except socket.gaierror:
        return []


def check_tools(console):
    rows = []
    for name in TOOLS:
        path = find_tool(name)
        ver = short_version(tool_version(path, TOOLS[name]["version"])[1]) if path else ""
        rows.append((name, path or "-", ver, tool_source(name, path) or "-"))
    w = max(len(r[1]) for r in rows)
    print(f"{'tool':10}  {'path':{w}}  {'version':12}  source")
    for n, p, v, s in rows:
        print(f"{n:10}  {p:{w}}  {v:12}  {s}")
    have = sum(1 for r in rows if r[1] != "-")
    console.info(f"{have}/{len(rows)} tools available; Python tool venvs under {venv_root()}")
    not_venv = [r[0] for r in rows if r[3].startswith("system (not")]
    if not_venv:
        console.warn(f"not running from their venv: {', '.join(not_venv)} - "
                     "run `sudo ./webpeek.py --install-only`")
    return have == len(rows) and not not_venv


def main():
    ap = argparse.ArgumentParser(
        description="Exfiltra automated enumeration runner (methodology v1.2 s.2.2-2.3).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Steps: " + ", ".join(STEPS))
    ap.add_argument("--target", help="hostname, IP, or URL to scan (URL limits web tools to that URL)")
    ap.add_argument("-tL", "--targets", metavar="FILE",
                    help="file of targets to scan, one per line; '#' comments and blank lines "
                         "are ignored, and a line may end with the flag `prod` (see --prod). "
                         "The list is the allow-list for redirect containment.")
    ap.add_argument("--prod", action="store_true",
                    help="scan --target at reduced 'production' intensity (per-line `prod` does "
                         "the same in a targets file)")
    ap.add_argument("--label", help="name for this batch - groups the output directory and fills "
                                     "the evidence CSV's Engagement column (default: the targets "
                                     "file name, or the single target)")
    ap.add_argument("-o", "--outdir", default="webpeek_output",
                    help="base output directory (default: ./webpeek_output)")
    ap.add_argument("--profile", choices=list(PROFILES),
                    help="scan intensity; default is 'production' for targets flagged prod, "
                         "otherwise 'standard'")
    ap.add_argument("--ports", help="skip the full sweep and use these ports, e.g. 80,443,8443")
    ap.add_argument("--pn", action="store_true", help="add -Pn (treat host as up) to nmap")
    ap.add_argument("--skip", default="", help="comma-separated steps to skip")
    ap.add_argument("--only", default="", help="comma-separated steps to run (others skipped)")
    ap.add_argument("--wpscan", choices=["auto", "always", "never"], default="auto",
                    help="auto = only when WordPress is fingerprinted (default)")
    ap.add_argument("--wordlist", help="ffuf wordlist (default: first of SecLists/dirb lists found)")
    ap.add_argument("--dirsearch-wordlist", help="dirsearch wordlist (default: its built-in list)")
    ap.add_argument("--proxy", dest="proxy", default=None, metavar="URL",
                    help="send all HTTP traffic to the target through this proxy, e.g. "
                         "http://127.0.0.1:8080 for Burp/Caido: httpx, wafw00f, nuclei, "
                         "WPScan, ffuf, dirsearch, the CSP fetch and the WordPress fallback "
                         "check. NOT used for gau, the AI review, nmap, nslookup, sslscan "
                         "or testssl (see README). Default: direct; environment proxy "
                         "variables are always ignored")
    ap.add_argument("--no-ai", action="store_true",
                    help="skip the AI review of the CSP (the rule-based review still runs)")
    ap.add_argument("--ai-provider", choices=list(csp_check.PROVIDERS), default=None,
                    help="AI provider for the CSP review (default: config file ai.provider, "
                         "else gemini)")
    ap.add_argument("--ai-model", default=None,
                    help="model for the CSP AI review (default: config file, else "
                         "gemini-4-hydrogen / claude-sonnet-4-5)")
    ap.add_argument("--show-config", action="store_true",
                    help="show the effective settings from ./webpeek.conf (secrets masked) and exit")
    ap.add_argument("--allow-intrusive", action="store_true",
                    help="let nuclei run templates tagged dos/intrusive (needs written client authorisation)")
    ap.add_argument("--no-install", action="store_true", help="never install missing tools")
    ap.add_argument("--install-only", action="store_true", help="install missing tools and exit")
    ap.add_argument("--check-tools", action="store_true", help="list tools and versions and exit")
    ap.add_argument("--no-update", action="store_true",
                    help="skip nuclei template and WPScan database updates")
    ap.add_argument("--dry-run", action="store_true",
                    help="check targets and tools, write the planned commands, execute nothing")
    ap.add_argument("-q", "--quiet", action="store_true", help="do not echo tool output")
    ap.add_argument("--version", action="version", version=f"exfiltra-webpeek {VERSION}")
    args = ap.parse_args()
    console = Console(args.quiet)
    masker = Masker()

    # ---- config file: keys, provider, models, WPScan token ----------------
    # Loaded before anything else so every later step sees the same settings.
    try:
        cfg_info = enum_config.load()
    except enum_config.ConfigError as e:
        console.err(f"config error: {e}")
        sys.exit(2)
    if not args.show_config:              # --show-config prints them itself
        for w in cfg_info["warnings"]:
            console.warn(f"config: {w}")
    if args.show_config:
        print(enum_config.describe(cfg_info, csp_check.config_defaults()))
        sys.exit(0)

    # ---- tool-only modes --------------------------------------------------
    if args.check_tools:
        sys.exit(0 if check_tools(console) else 1)

    if args.install_only:
        if not is_root():
            raise SystemExit("installing tools needs root - re-run with sudo")
        Path(args.outdir).mkdir(parents=True, exist_ok=True)
        inst = Installer(Path(args.outdir) / "install.log", console, masker)
        for name in TOOLS:
            inst.ensure(name)
        inst.ensure_wordlists()
        sys.exit(0 if check_tools(console) else 1)

    if not args.target and not args.targets:
        ap.error("give something to scan: --target HOST, or --targets FILE")
    if args.target and args.targets:
        ap.error("use either --target or --targets, not both")

    # ---- what to scan: the operator's list IS the allow-list --------------
    if args.targets:
        targets = load_targets(args.targets)
        label = args.label or slug(Path(args.targets).stem)
        targets_file = os.path.abspath(args.targets)
    else:
        targets = [{"raw": args.target, "prod": args.prod, "cidr": False}]
        label = args.label or slug(parse_target(args.target)[0] or args.target)
        targets_file = None
    scan_targets = [t for t in targets if not t.get("cidr")]
    if not scan_targets:
        raise SystemExit("targets file lists only CIDR ranges - nothing to scan "
                         "(a bare range is containment-only; name the hosts to scan)")
    allow_hosts, allow_nets = build_allowlist(targets)

    # ---- proxy: validated and checked before anything is written ----------
    proxy = None
    if args.proxy:
        try:
            proxy, proxy_display = parse_proxy(args.proxy)
        except ValueError as e:
            ap.error(f"--proxy {args.proxy!r}: {e}")
        u = urllib.parse.urlsplit(proxy)
        if u.password:
            masker.add(u.password)
        if not args.dry_run:
            # A dead proxy would fail every proxied step and leave a run full of
            # failed evidence. Refuse up front instead.
            why = proxy_reachable(proxy)
            if why:
                console.err(f"proxy {proxy_display} is not reachable ({why}) - start it "
                            "or drop --proxy")
                sys.exit(2)
        console.info(f"proxy: target HTTP traffic via {proxy_display} "
                     f"({', '.join(sorted(PROXY_FLAGS))}, csp fetch); "
                     "nmap, TLS scanners, gau and the AI review stay direct")
    args.proxy = proxy

    # ---- shared settings: secrets, AI provider, step selection ------------
    token = os.environ.get("WPSCAN_API_TOKEN", "").strip()
    masker.add(token)
    ai_provider = args.ai_provider or csp_check.default_provider()
    ai_label = csp_check.PROVIDERS[ai_provider]["label"]
    ai_key, ai_key_env = csp_check.provider_key(ai_provider)
    for k in csp_check.all_provider_keys():   # mask every configured AI key, used or not
        masker.add(k)
    ai_model = args.ai_model or csp_check.default_model(ai_provider)
    ai_endpoint = csp_check.endpoint(ai_provider, ai_model)

    selected = [s for s in STEPS if s not in {x.strip() for x in args.skip.split(",") if x.strip()}]
    if args.only:
        only = {x.strip() for x in args.only.split(",") if x.strip()}
        bad = only - set(STEPS)
        if bad:
            raise SystemExit(f"unknown step(s): {', '.join(sorted(bad))}")
        selected = [s for s in selected if s in only]
    if args.ports and "portscan" in selected:
        selected.remove("portscan")

    if len(scan_targets) > 1:
        console.info(f"{len(scan_targets)} targets to scan (batch '{label}')")
    statuses = []
    for entry in scan_targets:
        statuses.append(run_target(
            entry, targets_file, allow_hosts, allow_nets, label, args, console, masker,
            token, ai_provider, ai_label, ai_key, ai_key_env, ai_model, ai_endpoint,
            selected, cfg_info))
    good = {"completed", "completed-with-skips", "dry-run"}
    sys.exit(0 if statuses and all(s in good for s in statuses) else 1)


def run_target(entry, targets_file, allow_hosts, allow_nets, label, args, console,
               masker, token, ai_provider, ai_label, ai_key, ai_key_env, ai_model,
               ai_endpoint, selected, cfg_info):
    """Scan one target end to end into its own evidence directory. Returns the
    run's final status string."""
    host, given_url = parse_target(entry["raw"])
    profile = args.profile or ("production" if entry.get("prod") else "standard")
    profile_note = None
    if entry.get("prod") and profile != "production":
        profile_note = (f"{host} is flagged production but was run with profile "
                        f"'{profile}' by operator choice")
        console.warn(profile_note)
    P = PROFILES[profile]

    # ---- run directory ----------------------------------------------------
    # A run directory is never shared. Two runs against the same host in the
    # same second (e.g. a loop over several URLs on one host) used to land in
    # the same folder and mix their evidence; mkdir(exist_ok=False) plus a
    # suffix makes each run's directory its own.
    stamp = now().strftime("%Y%m%d-%H%M%S")
    base = Path(args.outdir) / slug(label)
    base.mkdir(parents=True, exist_ok=True)
    for n in range(1, 1000):
        root = base / (f"{slug(host)}_{stamp}" + ("" if n == 1 else f"-{n}"))
        try:
            root.mkdir()
            break
        except FileExistsError:
            continue
    else:
        raise SystemExit("could not create a unique run directory")

    authorisation = {
        "mode": "operator-named target (no engagement-window check)",
        "target": entry["raw"],
        "host": host,
        "production_flag": bool(entry.get("prod")),
        "allowlist_source": targets_file or "--target argument",
        "note": ("Only operator-named targets are scanned, and redirects off the "
                 "allow-list are refused. Engagement authorisation is held in the "
                 "engagement contract, not enforced by this tool."),
    }

    manifest = {
        "generator": f"exfiltra-webpeek {VERSION}",
        "methodology": "Exfiltra Penetration Testing Methodology v1.2, s.2.2-2.3",
        "label": label,
        "targets_file": targets_file,
        "targets_file_sha256": sha256(targets_file) if targets_file else None,
        "authorisation": authorisation,
        "target": entry["raw"],
        "host": host,
        "resolved_addresses": [],
        "profile": profile,
        "profile_note": profile_note,
        "nuclei_intrusive_templates": bool(args.allow_intrusive),
        "csp_fetch_route": masker(args.proxy) if args.proxy else "direct",
        "proxy": ({"url": masker(args.proxy),
                   "applied_to": sorted(PROXY_FLAGS) + PROXY_IN_PROCESS,
                   "not_applied": PROXY_NOT_APPLIED} if args.proxy else None),
        "ai_provider": ai_provider,
        "ai_model": ai_model,
        # Names and sources only - never values. The file itself is not copied.
        "config": {"path": cfg_info["path"],
                   "settings_from_config": cfg_info["from_config"],
                   "overridden_by_environment": cfg_info["overridden_by_environment"],
                   "warnings": cfg_info["warnings"]},
        "operator": os.environ.get("SUDO_USER") or getpass.getuser(),
        "workstation": socket.gethostname(),
        "running_as_root": is_root(),
        "dry_run": args.dry_run,
        "started": iso(now()),
        "finished": None,
        "status": "running",
        "tools": {},
        "discovered": {"open_ports": [], "services": [], "web_urls": [],
                       "tls_endpoints": [], "technologies": {}, "wordpress": []},
        "steps": [],
    }

    holder = {}

    def _write():
        """Rewritten after every step, atomically, so a crash still leaves a record."""
        manifest["steps"] = holder["run"].steps if "run" in holder else []
        tmp = root / "manifest.json.tmp"
        tmp.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        tmp.replace(root / "manifest.json")

    run = Run(root, console, masker, _write, args.dry_run)
    holder["run"] = run

    console.ok(f"TARGET: {entry['raw']} (host {host})")
    console.info(f"profile: {profile} | output: {root}")
    run.note(f"target: {json.dumps(authorisation)}")
    if not is_root():
        console.warn("not running as root - nmap will fall back to a TCP connect scan "
                     "and missing tools cannot be installed")

    # ---- tools ------------------------------------------------------------
    needed = sorted({STEP_TOOL[s] for s in selected if STEP_TOOL[s]})
    inst = Installer(root / "00_setup" / "install.log", console, masker)
    (root / "00_setup").mkdir(exist_ok=True)
    tool_path = {}
    for name in needed:
        path = find_tool(name)
        # Python tools are (re)installed into their venv whenever the venv copy
        # is missing - even if a system copy exists - so the venv is what runs.
        needs_venv = bool(TOOLS[name].get("venv")) and tool_source(name, path) != "venv"
        if (not path or needs_venv) and not args.no_install and not args.dry_run and is_root():
            if inst.ensure(name):
                path = find_tool(name)
        if path:
            raw, ver = tool_version(path, TOOLS[name]["version"])
            tool_path[name] = path
            src = tool_source(name, path)
            manifest["tools"][name] = {"path": path, "version": short_version(ver) or ver,
                                       "version_output": ver, "source": src}
            if TOOLS[name].get("venv"):
                manifest["tools"][name]["venv"] = str(venv_dir(name))
                if src == "venv":
                    manifest["tools"][name]["venv_packages"] = venv_packages(name)
                else:
                    console.warn(f"{name}: using {path}, not its venv - run with sudo once "
                                 f"to install it into {venv_dir(name)}")
        else:
            manifest["tools"][name] = {"path": None, "version": None}
            console.warn(f"{name} not available - its steps will be skipped")
    wordlist = args.wordlist or first_wordlist()
    if "ffuf" in selected and not wordlist and not args.no_install and is_root() and not args.dry_run:
        if inst.ensure_wordlists():
            wordlist = first_wordlist()
    if "ffuf" in selected and wordlist and os.path.isfile(wordlist):
        # Which wordlist produced the content-discovery evidence, pinned by hash.
        data = Path(wordlist).read_bytes()
        manifest["ffuf_wordlist"] = {"path": wordlist, "lines": data.count(b"\n"),
                                     "sha256": hashlib.sha256(data).hexdigest()}
    _write()

    def ver(name):
        return (manifest["tools"].get(name) or {}).get("version") or ""

    def have(step):
        return STEP_TOOL[step] is None or STEP_TOOL[step] in tool_path or args.dry_run

    def bin_(name):
        return tool_path.get(name) or TOOLS[name]["bins"][0]

    D = manifest["discovered"]
    try:
        # ---- updates (logged, so the database date is on record) ---------
        if not args.no_update and not args.dry_run:
            if "nuclei" in selected and "nuclei" in tool_path:
                run.step("setup", "Nuclei template update", "nuclei", ver("nuclei"),
                         [bin_("nuclei"), "-update-templates", "-nc"],
                         "00_setup/nuclei_template_update.log", timeout=TIMEOUTS["setup"])
            if "wpscan" in selected and "wpscan" in tool_path and args.wpscan != "never":
                run.step("setup", "WPScan database update", "wpscan", ver("wpscan"),
                         [bin_("wpscan"), "--update", "--format", "cli-no-colour"],
                         "00_setup/wpscan_db_update.log", timeout=TIMEOUTS["setup"])

        # ---- 01 name resolution -------------------------------------------
        manifest["resolved_addresses"] = resolve(host)
        if len(manifest["resolved_addresses"]) > 1:
            console.warn(f"{host} resolves to {len(manifest['resolved_addresses'])} addresses; "
                         "nmap scans the first. Record this when reading the results.")
        if "dns" in selected:
            if have("dns"):
                run.step("dns", "Name resolution", "nslookup", ver("nslookup"),
                         [bin_("nslookup"), host], "01_dns/nslookup.txt",
                         timeout=TIMEOUTS["dns"],
                         summarise=lambda: "resolved to " + (", ".join(manifest["resolved_addresses"]) or "nothing"))
            else:
                run.skip("dns", "Name resolution", "nslookup", "tool unavailable")

        # ---- 01 passive URL discovery (gau) -------------------------------
        # Queries public archives about the host; sends nothing to the target.
        # Without --subs it stays on the exact host, so other subdomains (which
        # may be out of scope) are not collected. Results are recorded, never
        # fed to the active tools - an archived URL is not an authorised target.
        if "gau" in selected:
            is_ip = True
            try:
                ipaddress.ip_address(host)
            except ValueError:
                is_ip = False
            if is_ip:
                run.skip("gau", "Passive URL discovery (gau)", "gau",
                         "IP target - archives are indexed by hostname")
            elif have("gau"):
                out = root / "01_passive" / "gau_urls.txt"
                run.step("gau", "Passive URL discovery (gau)", "gau", ver("gau"),
                         [bin_("gau"), "--providers", GAU_PROVIDERS, "--threads", "2",
                          "--blacklist", "png,jpg,jpeg,gif,svg,ico,webp,css,woff,woff2,ttf,eot,mp4",
                          "--o", "01_passive/gau_urls.txt", host],
                         "01_passive/gau.log", outputs=["01_passive/gau_urls.txt"],
                         timeout=TIMEOUTS["gau"], summarise=lambda: gau_summary(out))
            else:
                run.skip("gau", "Passive URL discovery (gau)", "gau", "tool unavailable")

        pn = ["-Pn"] if args.pn else []

        # ---- 02 full port sweep -------------------------------------------
        ports = []
        if args.ports:
            ports = sorted({int(p) for p in re.split(r"[,\s]+", args.ports) if p})
            run.note(f"operator supplied ports, full sweep not run: {ports}")
        elif "portscan" in selected:
            if have("portscan"):
                xml = root / "02_portscan" / "open_ports.xml"
                run.step("portscan", "Full TCP port scan (65,535 ports)", "nmap", ver("nmap"),
                         [bin_("nmap"), "-p-"] + P["nmap_portscan"] + pn +
                         ["--open", "-oN", "02_portscan/open_ports.txt",
                          "-oX", "02_portscan/open_ports.xml", host],
                         "02_portscan/nmap_portscan.log",
                         outputs=["02_portscan/open_ports.txt", "02_portscan/open_ports.xml"],
                         timeout=TIMEOUTS["portscan"],
                         summarise=lambda: "open TCP: " + (", ".join(map(str, nmap_open_ports(xml))) or "none"))
                ports = nmap_open_ports(xml)
            else:
                run.skip("portscan", "Full TCP port scan", "nmap", "tool unavailable")
        if args.dry_run and not ports:
            ports = [80, 443]
            run.note("dry run: assuming ports 80,443 for planning")
        D["open_ports"] = ports

        # ---- 03 service / version / default scripts ------------------------
        services = []
        if "services" in selected and ports:
            if have("services"):
                xml = root / "03_services" / "service_scan.xml"
                run.step("services", "Service, version and default-script scan", "nmap", ver("nmap"),
                         [bin_("nmap"), "-sV", "-sC", "-p", ",".join(map(str, ports))]
                         + P["nmap_services"] + pn +
                         ["-oA", "03_services/service_scan", host],
                         "03_services/nmap_services.log",
                         outputs=["03_services/service_scan.nmap", "03_services/service_scan.xml",
                                  "03_services/service_scan.gnmap"],
                         timeout=TIMEOUTS["services"],
                         summarise=lambda: "; ".join(
                             f"{s['port']}/{s['name']}" + (f" {s['product']} {s['version']}".rstrip()
                                                           if s['product'] else "")
                             for s in nmap_services(xml)) or "no services identified")
                services = nmap_services(xml)
            else:
                run.skip("services", "Service scan", "nmap", "tool unavailable")
        elif "services" in selected:
            run.skip("services", "Service scan", "nmap", "no open ports found")
        if not services:
            # No service data (skipped, dry run, filtered host): infer from port numbers.
            services = [{"port": p, "name": "", "product": "", "version": "", "tunnel": ""}
                        for p in ports]
        D["services"] = services

        # ---- web targets and TLS endpoints ---------------------------------
        if given_url:
            urls = [given_url]
            u = urllib.parse.urlsplit(given_url)
            given_port = u.port or (443 if u.scheme == "https" else 80)
            tls = sorted({s["port"] for s in services if is_tls(s)} |
                         ({given_port} if u.scheme == "https" else set()))
        else:
            urls = list(dict.fromkeys(url_for(host, s) for s in services if is_web(s)))
            tls = sorted({s["port"] for s in services if is_tls(s)})
        D["web_urls"], D["tls_endpoints"] = urls, [f"{host}:{p}" for p in tls]
        if not urls:
            console.warn("no web services identified - web steps will be skipped")
        _write()

        # ---- 04 fingerprinting (Wappalyzer fingerprints via httpx) ---------
        wp_urls = []
        for url in urls:
            s = url_slug(url)
            if "httpx" in selected:
                if have("httpx"):
                    out = root / "04_fingerprint" / f"{s}_httpx.jsonl"
                    run.step("httpx", f"Technology fingerprinting - {url}", "httpx", ver("httpx"),
                             [bin_("httpx"), "-u", url, "-td", "-sc", "-title", "-server",
                              "-ip", "-cdn", "-fr", "-nc", "-silent", "-j",
                              "-o", f"04_fingerprint/{s}_httpx.jsonl"]
                             + proxy_args("httpx", args.proxy),
                             f"04_fingerprint/{s}_httpx.log",
                             outputs=[f"04_fingerprint/{s}_httpx.jsonl"],
                             timeout=TIMEOUTS["httpx"],
                             summarise=lambda out=out: "technologies: " + (", ".join(httpx_techs(out)) or "none identified"))
                    techs = httpx_techs(out)
                    D["technologies"][url] = techs
                    if any("wordpress" in t.lower() for t in techs):
                        wp_urls.append(url)
                else:
                    run.skip("httpx", f"Technology fingerprinting - {url}", "httpx", "tool unavailable")
                    if args.wpscan == "auto" and not args.dry_run and looks_like_wordpress(url, console, args.proxy):
                        run.note(f"fallback WordPress check: GET {url} -> WordPress markers found")
                        wp_urls.append(url)
            if "wafw00f" in selected:
                if have("wafw00f"):
                    out = root / "04_fingerprint" / f"{s}_wafw00f.json"
                    # -r: do not follow redirects. wafw00f sends attack-like probe
                    # strings; following a redirect could deliver them to an
                    # out-of-scope host (e.g. a third-party SSO provider).
                    run.step("wafw00f", f"WAF detection - {url}", "wafw00f", ver("wafw00f"),
                             [bin_("wafw00f"), url, "-a", "-r",
                              "-o", f"04_fingerprint/{s}_wafw00f.json", "-f", "json"]
                             + proxy_args("wafw00f", args.proxy),
                             f"04_fingerprint/{s}_wafw00f.log",
                             outputs=[f"04_fingerprint/{s}_wafw00f.json"],
                             timeout=TIMEOUTS["wafw00f"],
                             summarise=lambda out=out: wafw00f_summary(out))
                else:
                    run.skip("wafw00f", f"WAF detection - {url}", "wafw00f", "tool unavailable")
        D["wordpress"] = wp_urls

        # ---- 05 vulnerability scanning -------------------------------------
        for url in urls:
            s = url_slug(url)
            if "nuclei" in selected:
                if have("nuclei"):
                    out = root / "05_vulnscan" / f"{s}_nuclei.jsonl"
                    run.step("nuclei", f"Nuclei scan - {url}", "nuclei", ver("nuclei"),
                             [bin_("nuclei"), "-u", url,
                              "-severity", "info,low,medium,high,critical",
                              "-stats", "-si", "30", "-nc"]
                             + ([] if args.allow_intrusive else ["-etags", "dos,intrusive"])
                             + P["nuclei"] +
                             ["-o", f"05_vulnscan/{s}_nuclei_results.txt",
                              "-jle", f"05_vulnscan/{s}_nuclei.jsonl"]
                             + proxy_args("nuclei", args.proxy),
                             f"05_vulnscan/{s}_nuclei.log",
                             outputs=[f"05_vulnscan/{s}_nuclei_results.txt",
                                      f"05_vulnscan/{s}_nuclei.jsonl"],
                             timeout=TIMEOUTS["nuclei"],
                             summarise=lambda out=out: (", ".join(f"{v} {k}" for k, v in sorted(nuclei_counts(out).items()))
                                                        or "no template matches") + " (unverified scanner output)")
                else:
                    run.skip("nuclei", f"Nuclei scan - {url}", "nuclei", "tool unavailable")

            run_wp = "wpscan" in selected and (args.wpscan == "always" or
                                               (args.wpscan == "auto" and (url in wp_urls or args.dry_run)))
            if run_wp:
                if have("wpscan"):
                    argv = [bin_("wpscan"), "--url", url, "--random-user-agent",
                            "--format", "cli-no-colour", "--no-update", "--disable-tls-checks"] + P["wpscan"]
                    argv += proxy_args("wpscan", args.proxy)
                    if token:
                        argv += ["--api-token", token]
                    run.step("wpscan", f"WPScan - {url}", "wpscan", ver("wpscan"), argv,
                             f"05_vulnscan/{s}_wpscan.txt", timeout=TIMEOUTS["wpscan"],
                             summarise=lambda: "WordPress scan" + ("" if token else
                                               " (no API token - vulnerability data not retrieved)"))
                else:
                    run.skip("wpscan", f"WPScan - {url}", "wpscan", "tool unavailable")
            elif "wpscan" in selected and args.wpscan == "auto":
                run.note(f"WPScan not run on {url}: WordPress not fingerprinted")

        # ---- 06 content discovery ------------------------------------------
        for url in urls:
            s = url_slug(url)
            if "ffuf" in selected:
                if have("ffuf") and (wordlist or args.dry_run):
                    out = root / "06_content" / f"{s}_ffuf.json"
                    run.step("ffuf", f"ffuf content discovery - {url}", "ffuf", ver("ffuf"),
                             [bin_("ffuf"), "-u", url.rstrip("/") + "/FUZZ",
                              "-w", wordlist or "<wordlist>", "-ac",
                              "-mc", "200,204,301,302,307,401,403,405,500",
                              "-noninteractive"] + P["ffuf"] +
                             ["-o", f"06_content/{s}_ffuf.json", "-of", "json"]
                             + proxy_args("ffuf", args.proxy),
                             f"06_content/{s}_ffuf.log",
                             outputs=[f"06_content/{s}_ffuf.json"],
                             timeout=TIMEOUTS["ffuf"],
                             summarise=lambda out=out: f"{ffuf_hits(out)} paths returned")
                else:
                    run.skip("ffuf", f"ffuf - {url}", "ffuf",
                             "tool unavailable" if not have("ffuf") else "no wordlist found (use --wordlist)")
            if "dirsearch" in selected:
                if have("dirsearch"):
                    out = root / "06_content" / f"{s}_dirsearch.txt"
                    argv = [bin_("dirsearch"), "-u", url] + P["dirsearch"]
                    if args.dirsearch_wordlist:
                        argv += ["-w", args.dirsearch_wordlist]
                    argv += proxy_args("dirsearch", args.proxy)
                    argv += ["-o", str(out.resolve())]
                    run.step("dirsearch", f"dirsearch content discovery - {url}", "dirsearch",
                             ver("dirsearch"), argv, f"06_content/{s}_dirsearch.log",
                             outputs=[f"06_content/{s}_dirsearch.txt"],
                             timeout=TIMEOUTS["dirsearch"],
                             summarise=lambda out=out: f"{dirsearch_hits(out)} paths returned")
                else:
                    run.skip("dirsearch", f"dirsearch - {url}", "dirsearch", "tool unavailable")

        # ---- 07 TLS --------------------------------------------------------
        for port in tls:
            ep = f"{host}:{port}"
            s = slug(ep)
            if "sslscan" in selected:
                if have("sslscan"):
                    run.step("sslscan", f"sslscan - {ep}", "sslscan", ver("sslscan"),
                             [bin_("sslscan"), "--no-colour", f"--xml=07_tls/{s}_sslscan.xml", ep],
                             f"07_tls/{s}_sslscan.txt", outputs=[f"07_tls/{s}_sslscan.xml"],
                             timeout=TIMEOUTS["sslscan"])
                else:
                    run.skip("sslscan", f"sslscan - {ep}", "sslscan", "tool unavailable")
            if "testssl" in selected:
                if have("testssl"):
                    run.step("testssl", f"testssl - {ep}", "testssl", ver("testssl"),
                             [bin_("testssl"), "--quiet", "--color", "0", "--warnings", "batch",
                              "--jsonfile", f"07_tls/{s}_testssl.json", ep],
                             f"07_tls/{s}_testssl.txt", outputs=[f"07_tls/{s}_testssl.json"],
                             timeout=TIMEOUTS["testssl"])
                else:
                    run.skip("testssl", f"testssl - {ep}", "testssl", "tool unavailable")

        # ---- 08 CSP review: rules, then optional AI ------------------------
        def in_scope(h):
            return in_allowlist(h, allow_hosts, allow_nets)

        for url in (urls if "csp" in selected else []):
            s = url_slug(url)
            state = {}

            def do_rules(log, url=url, s=s, state=state):
                r = csp_check.fetch(url, in_scope, log, proxy=args.proxy)
                enforced, ro, meta = csp_check.extract_policies(r["headers"], r["body"])
                hl = {k.lower(): v for k, v in r["headers"].items()}
                findings = csp_check.check_response(enforced, ro, meta, hl)
                state.update(r=r, enforced=enforced, ro=ro, meta=meta, hl=hl, findings=findings)
                log.write(f"# policies: {len(enforced)} enforced header, {len(meta)} meta, "
                          f"{len(ro)} report-only\n")
                for f in findings:
                    log.write(f"# [{f['severity']}] {f['id']} {f['directive']} {f['value']}\n")
                run.write_artifact(f"08_csp/{s}_csp_rules.json", json.dumps({
                    "url": url, "final_url": r["final_url"], "status": r["status"],
                    "note": r["note"], "content_security_policy": enforced,
                    "content_security_policy_report_only": ro, "meta_csp": meta,
                    "findings": findings}, indent=2))
                return "completed"

            run.step("csp", f"CSP review (rules) - {url}", "csp_check", VERSION,
                     ["csp_check", "GET", url, "# in-process; redirects followed only within scope"],
                     f"08_csp/{s}_http.txt", outputs=[f"08_csp/{s}_csp_rules.json"],
                     fn=do_rules,
                     summarise=lambda state=state: "rules: " + csp_check.counts(state.get("findings", [])))

            ai_meta = {"provider": ai_provider, "model": ai_model}
            has_policy = bool(state.get("enforced") or state.get("meta") or state.get("ro"))
            # An explicit operator decision (--no-ai) is recorded ahead of
            # circumstantial reasons, so the manifest says WHY by choice.
            if args.dry_run:
                skip_reason = None
            elif args.no_ai:
                skip_reason = "--no-ai"
            elif "findings" not in state:
                skip_reason = "CSP fetch failed"
            elif not has_policy:
                skip_reason = "no CSP present - nothing for the AI to review (rule CSP-MISSING stands)"
            elif not ai_key:
                skip_reason = f"{ai_key_env} is not set ({ai_label})"
            else:
                skip_reason = None

            if skip_reason:
                ai_meta["reason"] = skip_reason
                run.skip("csp-ai", f"CSP review (AI-assisted) - {url}", ai_provider, skip_reason)
            else:
                extra = {}

                def do_ai(log, url=url, s=s, state=state, extra=extra):
                    related = {k: state["hl"][k] for k in
                               ("x-frame-options", "reporting-endpoints", "report-to",
                                "strict-transport-security", "x-content-type-options")
                               if k in state["hl"]}
                    called = iso(now())
                    rec, raw, parsed, err = csp_check.ai_review(
                        state["r"]["final_url"], state["enforced"], state["ro"], state["meta"],
                        related, state["findings"], ai_key, ai_model, ai_provider)
                    req_text = json.dumps(rec, indent=2)
                    run.write_artifact(f"08_csp/{s}_csp_ai_request.json", req_text)
                    run.write_artifact(f"08_csp/{s}_csp_ai_response.json", raw or "")
                    req_sha = csp_check.sha256_text(req_text)
                    extra.update(ai_provider=ai_provider, ai_model=ai_model, ai_endpoint=ai_endpoint,
                                 ai_called=called, ai_request_sha256=req_sha, ai_error=err)
                    ai_meta.update(called=called, request_sha256=req_sha, reason=err)
                    state["ai"] = parsed
                    log.write(f"# provider: {ai_label}\n# model: {ai_model}\n# endpoint: {ai_endpoint}\n"
                              f"# request sha256: {req_sha}\n")
                    if err:
                        log.write(f"# AI review failed: {err}\n")
                        return "failed"
                    log.write(f"# rule findings reviewed: {len(parsed.get('rule_review', []))}; "
                              f"additional points: {len(parsed.get('additional_findings', []))}\n")
                    return "completed"

                run.step("csp-ai", f"CSP review (AI-assisted) - {url}", ai_provider, ai_model,
                         ["POST", ai_endpoint, f"model={ai_model}",
                          "# CSP headers + rule findings; API key sent as header, never logged"],
                         f"08_csp/{s}_csp_ai.log",
                         outputs=[f"08_csp/{s}_csp_ai_request.json", f"08_csp/{s}_csp_ai_response.json"],
                         fn=do_ai, extra=extra,
                         summarise=lambda state=state: (
                             f"{len((state.get('ai') or {}).get('additional_findings', []))} additional "
                             "points raised (unverified)"))

            if "findings" in state:
                run.write_artifact(f"08_csp/{s}_csp_report.md", csp_check.render_markdown(
                    url, state["r"], state["enforced"], state["ro"], state["meta"],
                    state["findings"], state.get("ai"), ai_meta))
                D.setdefault("csp_reports", []).append(f"08_csp/{s}_csp_report.md")
            _write()

        statuses = [st.get("status") for st in run.steps]
        if args.dry_run:
            manifest["status"] = "dry-run"
        elif any(s not in ("completed", "skipped") for s in statuses):
            manifest["status"] = "completed-with-failures"
        elif any(st.get("reason") == "tool unavailable" for st in run.steps):
            # Not plain "completed": part of the planned enumeration did not happen.
            manifest["status"] = "completed-with-skips"
        else:
            manifest["status"] = "completed"
    except KeyboardInterrupt:
        manifest["status"] = "interrupted"
        console.warn("interrupted - finalising the evidence record")
        run.note("run interrupted by operator")
    except Exception as e:
        manifest["status"] = "failed"
        manifest["error"] = f"{type(e).__name__}: {e}"
        console.err(f"run aborted: {manifest['error']}")
        run.note(f"run aborted: {manifest['error']}")
    finally:
        manifest["finished"] = iso(now())
        _write()
        finalise(root, manifest, run, console)

    return manifest["status"]


# ==========================================================================
# Evidence outputs
# ==========================================================================
def finalise(root, manifest, run, console):
    run.runlog.close()

    # Self-check: every output's hash, recorded when its step finished, must
    # still match the file on disk. A mismatch means something overwrote
    # evidence after the fact - exactly what the url_slug bug once did.
    problems = []
    for st in run.steps:
        for o in st.get("outputs", []):
            p = root / o["path"]
            if not p.exists():
                problems.append(f"{o['path']} recorded but missing")
            elif sha256(p) != o["sha256"]:
                problems.append(f"{o['path']} changed after step '{st['label']}' finished")
    manifest["integrity_check"] = {"ok": not problems, "problems": problems}
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    if problems:
        console.err("INTEGRITY CHECK FAILED - recorded hashes do not match files:")
        for p in problems:
            console.err("  " + p)
    else:
        console.ok("integrity check passed - every recorded hash matches its file")

    # evidence_rows.csv - one row per completed step, columns of the
    # Enumeration Evidence sheet. "What it shows" is a factual auto-summary;
    # the analyst still owns the wording before it goes into the workbook.
    import csv
    with open(root / "evidence_rows.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Engagement", "Activity", "Tool", "Artefact",
                    "What the artefact shows", "Date(s)", "Evidence status"])
        for st in run.steps:
            if st.get("status") != "completed" or st.get("step") == "setup":
                continue
            arts = ", ".join(o["path"] for o in st.get("outputs", []))
            if st["tool"] in csp_check.PROVIDERS:
                tool = f"{csp_check.PROVIDERS[st['tool']]['label']} ({st.get('tool_version')})"
            else:
                tool = f"{DISPLAY.get(st['tool'], st['tool'])} {short_version(st.get('tool_version'))}".strip()
            w.writerow([manifest.get("label") or "", st["activity"], tool, arts,
                        st.get("summary") or st["label"], st["started"][:10], "Evidenced"])

    # summary.md
    lines = [f"# Enumeration run - {manifest['host']}", "",
             f"- Batch: {manifest.get('label') or ''}",
             f"- Target: {manifest['target']}",
             f"- Allow-list source: {manifest['authorisation']['allowlist_source']}",
             f"- Profile: {manifest['profile']}"
             + (f" ({manifest['profile_note']})" if manifest.get("profile_note") else ""),
             f"- Operator: {manifest['operator']} on {manifest['workstation']}",
             f"- Started: {manifest['started']}  Finished: {manifest['finished']}",
             f"- Status: **{manifest['status']}**", "",
             "## Discovered", "",
             f"- Resolved: {', '.join(manifest['resolved_addresses']) or '-'}",
             f"- Open TCP ports: {', '.join(map(str, manifest['discovered']['open_ports'])) or '-'}",
             f"- Web: {', '.join(manifest['discovered']['web_urls']) or '-'}",
             f"- TLS: {', '.join(manifest['discovered']['tls_endpoints']) or '-'}",
             f"- WordPress: {', '.join(manifest['discovered']['wordpress']) or '-'}", "",
             "## Steps", "",
             "| Step | Status | Duration | Summary |", "|---|---|---|---|"]
    for st in run.steps:
        summ = (st.get("summary") or st.get("reason") or "").replace("|", "/")
        lines.append(f"| {st['label']} | {st['status']} | {st.get('duration_s', '')}s | {summ} |")
    lines += ["", "Scanner output is unverified until it has been through the analysis "
              "procedure (methodology v1.2 s.2.4). Nothing here is a finding yet.", ""]
    (root / "summary.md").write_text("\n".join(lines), encoding="utf-8")

    # SHA256SUMS over everything except itself - `sha256sum -c SHA256SUMS`
    entries = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.name != "SHA256SUMS" and not p.name.endswith(".tmp"):
            entries.append(f"{sha256(p)}  {p.relative_to(root).as_posix()}")
    (root / "SHA256SUMS").write_text("\n".join(entries) + "\n", encoding="utf-8")

    # Hand the files back to the operator when run under sudo.
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and gid and is_root():
        for p in [root] + list(root.rglob("*")):
            try:
                os.chown(p, int(uid), int(gid))
            except OSError:
                pass

    console.ok(f"evidence written to {root}")
    console.info("  manifest.json  summary.md  evidence_rows.csv  SHA256SUMS")


if __name__ == "__main__":
    main()
