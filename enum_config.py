"""
enum_config.py - config file for webpeek: API keys, AI provider and
model names, WPScan token.

    webpeek.conf   (chmod 600), in the same folder as webpeek.py

Rules this module enforces, and why:

  * The file sits next to the script, inside the evidence pack. KEEP webpeek.conf
    OUT OF ANY SUBMISSION (it holds live keys) - exclude it from the zip/repo.
  * On Unix, a warning (never a refusal, never a chmod) if the file is
    accessible to group/others: restrict it with chmod 600.
  * Unknown keys are an error, not ignored: a typo such as "gemini_key" would
    otherwise silently disable the AI review.
  * Placeholder values (<...>, YOUR_..., CHANGE_ME) are ignored with a warning.
  * Credential values are loaded into the process environment so every code path
    sees one source of truth - and stripped back out of the environment handed
    to child tools (child_env), so nmap, nuclei and the rest never inherit them.
"""

import configparser
import os
import stat
from pathlib import Path

# (section, key) -> environment variable it sets
SETTINGS = {
    ("ai", "provider"): "WEBPEEK_AI_PROVIDER",
    ("ai", "gemini_model"): "WEBPEEK_GEMINI_MODEL",
    ("ai", "anthropic_model"): "WEBPEEK_ANTHROPIC_MODEL",
    ("ai", "gemini_thinking_level"): "WEBPEEK_GEMINI_THINKING_LEVEL",
    ("ai", "gemini_api_key"): "GEMINI_API_KEY",
    ("ai", "anthropic_api_key"): "ANTHROPIC_API_KEY",
    ("ai", "gemini_base_url"): "WEBPEEK_GEMINI_BASE_URL",
    ("ai", "anthropic_base_url"): "WEBPEEK_ANTHROPIC_BASE_URL",
    ("wpscan", "api_token"): "WPSCAN_API_TOKEN",
    # Python tools each get their own venv under this directory.
    ("install", "venv_root"): "WEBPEEK_VENV_ROOT",
    # Extra pip arguments for venv installs, e.g. an internal mirror:
    #   pip_args = --index-url https://pypi.internal/simple
    ("install", "pip_args"): "WEBPEEK_PIP_ARGS",
    # Root for everything the installer builds (venvs/, bin/, testssl.sh/).
    ("install", "opt_root"): "WEBPEEK_OPT_ROOT",
    # testssl.sh release branch to check out when apt has no package.
    ("install", "testssl_ref"): "WEBPEEK_TESTSSL_REF",
    # SecLists download (non-Kali systems): branch/tag, and a mirror if needed.
    ("install", "seclists_ref"): "WEBPEEK_SECLISTS_REF",
    ("install", "seclists_base_url"): "WEBPEEK_SECLISTS_BASE_URL",
}
SECRET_KEYS = {("ai", "gemini_api_key"), ("ai", "anthropic_api_key"), ("wpscan", "api_token")}
# Environment variables that hold secrets. GOOGLE_API_KEY is accepted as a
# Gemini key from the environment even though the config spells it gemini_api_key.
SECRET_ENV = {"GEMINI_API_KEY", "GOOGLE_API_KEY", "ANTHROPIC_API_KEY", "WPSCAN_API_TOKEN"}

PROVIDERS = ("gemini", "anthropic")
THINKING_LEVELS = ("low", "medium", "high", "xhigh")


class ConfigError(Exception):
    pass


def default_path():
    """webpeek.conf in the same directory as the scripts. WEBPEEK_CONFIG is an
    internal override for the test suite only (so tests never write a keys file
    into the real tool folder); it is not a user-facing config path."""
    override = os.environ.get("WEBPEEK_CONFIG", "").strip()
    if override:
        return Path(override).expanduser()
    return Path(__file__).resolve().parent / "webpeek.conf"


def find():
    """The one config file, if it exists. A missing file is not an error - the
    tool just runs on defaults (and the AI step will report no key)."""
    d = default_path()
    return d if d.is_file() else None


def check_permissions(path):
    """Advisory only. On a Unix machine, warn if the keys file is readable,
    writable or executable by group/others. Never changes the file and never
    refuses to load it. Returns a list of warnings."""
    if os.name != "posix":
        return []
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        return [f"{path} is mode {mode:03o} and holds API keys - restrict it with: "
                f"chmod 600 {path}"]
    return []


def _placeholder(v):
    u = v.upper()
    return v.startswith("<") or u.startswith("YOUR_") or "CHANGE_ME" in u or u in ("XXX", "TODO")


def load():
    """Read webpeek.conf (if present) into os.environ. The API keys and WPScan
    token come ONLY from the file: any ambient credential environment variables
    are cleared first so they can never be a source. Non-secret settings keep
    the file > WEBPEEK_* seam > default precedence. Returns a description for
    the manifest - names and sources only, never values."""
    info = {"path": None, "from_config": [], "overridden_by_environment": [], "warnings": []}
    # Credentials are file-only: drop any inherited values so nothing in the
    # environment can stand in for (or override) what the file provides.
    for env in SECRET_ENV:
        os.environ.pop(env, None)
    path = find()
    if path is None:
        return info
    info["warnings"].extend(check_permissions(path))

    # interpolation=None: API keys may contain '%', which ConfigParser would
    # otherwise try to expand.
    cp = configparser.ConfigParser(interpolation=None)
    try:
        with open(path, encoding="utf-8") as f:
            cp.read_file(f)
    except configparser.Error as e:
        raise ConfigError(f"{path}: {e}")

    valid = {f"{s}.{k}" for s, k in SETTINGS}
    unknown = [f"{s}.{k}" for s in cp.sections() for k in cp[s] if (s, k) not in SETTINGS]
    if unknown:
        raise ConfigError(f"{path}: unknown setting(s) {', '.join(unknown)}. "
                          f"Valid settings: {', '.join(sorted(valid))}")

    info["path"] = str(path)
    for (sec, key), env in SETTINGS.items():
        if not cp.has_option(sec, key):
            continue
        val = cp.get(sec, key).strip().strip('"').strip("'").strip()
        if not val:
            continue
        name = f"{sec}.{key}"
        if _placeholder(val):
            info["warnings"].append(f"{name} looks like a placeholder - ignored")
            continue
        if sec == "ai" and key == "provider" and val.lower() not in PROVIDERS:
            raise ConfigError(f"{path}: ai.provider must be one of {', '.join(PROVIDERS)}, not '{val}'")
        if key == "gemini_thinking_level" and val.lower() not in THINKING_LEVELS:
            raise ConfigError(f"{path}: ai.gemini_thinking_level must be one of "
                              f"{', '.join(THINKING_LEVELS)}, not '{val}'")
        if os.environ.get(env, "").strip():
            info["overridden_by_environment"].append(name)   # environment wins
            continue
        os.environ[env] = val.lower() if key == "provider" else val
        info["from_config"].append(name)
    return info


def child_env(extra=None):
    """Environment for child processes: everything except the secrets."""
    env = {k: v for k, v in os.environ.items() if k not in SECRET_ENV}
    if extra:
        env.update(extra)
    return env


def describe(info, defaults):
    """Lines for --show-config. Secrets show as 'set'/'not set', never a value."""
    out = []
    if info["path"]:
        mode = stat.S_IMODE(os.stat(info["path"]).st_mode) if os.name == "posix" else 0
        out.append(f"config file: {info['path']}" + (f" (mode {mode:03o})" if mode else ""))
    else:
        out.append(f"config file: none found (looked for {default_path()})")
    for w in info["warnings"]:
        out.append(f"warning: {w}")
    out.append("")
    from_cfg = set(info["from_config"])
    for (sec, key), env in SETTINGS.items():
        name = f"{sec}.{key}"
        raw = os.environ.get(env, "").strip()
        if (sec, key) in SECRET_KEYS:
            # Credentials are file-only; show set/not set and never the value.
            shown = "set" if raw else "not set"
            source = "config" if raw else "-"
        else:
            shown = raw or defaults.get(name, "")
            source = ("config" if name in from_cfg else f"environment ({env})" if raw
                      else "default" if defaults.get(name) else "-")
        out.append(f"  {name:26} {shown:44} {source}")
    return "\n".join(out)
