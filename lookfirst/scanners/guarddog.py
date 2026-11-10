"""GuardDog: code patterns that malicious packages use.

GuardDog 3.2 reports "risks": threat patterns, each with its own severity of low, medium
or high. On trusted packages it's noisy: when lookfirst tested it (9 Nov 2026), 5 of 8
popular PyPI packages had a "high" risk, mostly in tests, examples and dev scripts. So
its risks are worth knowing and never change the verdict, and those in tests, examples,
docs and dev scripts are only counted. Scanning a local folder sends nothing anywhere.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from lookfirst.core.textsafe import one_line
from lookfirst.scanners.base import ToolFailed, last_line, run_tool
from lookfirst.static.files import exists
from lookfirst.targets.models import ResolvedTarget

INSTALL_HINT = "uv tool install --python 3.12 guarddog"
_RULE = re.compile(r"^[a-z0-9][a-z0-9-]{0,80}$")
_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# What each GuardDog threat rule means, finishing the sentence "The code ...".
WORDING: dict[str, str] = {
    "threat-filesystem-autostart": "sets itself up to start automatically",
    "threat-filesystem-destruction": "deletes files or folders in bulk",
    "threat-filesystem-read": "reads sensitive files, such as keys and settings",
    "threat-network-dns-exfil": "hides data in DNS lookups",
    "threat-network-exfil-messenger": "holds a chat-service token or webhook that can receive data",
    "threat-network-exfil-sysinfo": "sends details about this computer over the network",
    "threat-network-exfiltration": "links to a domain often used to collect stolen data",
    "threat-network-outbound-shady-links": "links to a URL shortener or file-sharing site",
    "threat-network-reverse-shell": "can give someone remote control of this computer",
    "threat-npm-dependency-confusion": "shows signs of a dependency-confusion attack",
    "threat-npm-http-dependency": "installs a dependency from a web address, not the registry",
    "threat-npm-preinstall-script": "runs a script before it installs",
    "threat-process-cryptomining": "mines cryptocurrency",
    "threat-process-download-exec": "downloads a file and runs it",
    "threat-process-hooks": "runs system tools from its install hooks",
    "threat-process-injection-dll": "injects code into other programs",
    "threat-process-memory": "reads other programs' memory",
    "threat-process-powershell-encoded": "runs hidden or encoded PowerShell",
    "threat-process-spawn-silent": "starts programs with all their output hidden",
    "threat-process-sysinfo": "runs system tools to collect information",
    "threat-runtime-dynamic-loader": "loads code while it runs",
    "threat-runtime-enumeration": "surveys this computer and its network",
    "threat-runtime-environment-read": "reads environment variables, which often hold secrets",
    "threat-runtime-keylogging": "records keystrokes",
    "threat-runtime-obfuscation": "hides what its code does",
    "threat-runtime-obfuscation-api": "hides which functions it calls",
    "threat-runtime-obfuscation-base64exec": "runs code hidden in base64",
    "threat-runtime-obfuscation-chr": "runs code built from character codes",
    "threat-runtime-obfuscation-dynamic-eval": "runs JavaScript that decodes itself",
    "threat-runtime-obfuscation-general": "hides what its code does",
    "threat-runtime-obfuscation-hidden-code": "hides code behind blank space or aliases",
    "threat-runtime-obfuscation-import-exec": "runs code through dynamic imports",
    "threat-runtime-obfuscation-js-mangling": "mangles JavaScript names to hide what it does",
    "threat-runtime-obfuscation-log-suppress": "turns off logging while running hidden code",
    "threat-runtime-obfuscation-pyarmor": "is obfuscated with PyArmor",
    "threat-runtime-obfuscation-steganography": "runs code hidden inside an image or other data",
    "threat-runtime-obfuscation-unicode": "uses unusual characters that can hide code",
    "threat-runtime-screencapture": "takes screenshots",
    "threat-runtime-self-propagation": "publishes copies of itself to a package registry",
    "threat-runtime-system-info": "collects details about this computer",
    "threat-setup-import-aliasing": "renames dangerous functions in its setup script",
    "threat-setup-network-in-install": "uses the network from its setup script",
    "threat-setup-suspicious-imports": "imports unusual modules in its setup script",
}


@dataclass(frozen=True)
class Risk:
    rule: str
    severity: str  # GuardDog's own: low, medium or high
    meaning: str  # finishes "The code ..."
    path: str  # relative to the scanned folder
    line: int | None
    code: str


def ecosystems_for(target: ResolvedTarget) -> list[str]:
    """Which GuardDog scanners apply: the package's own registry, or for a repo or folder,
    what it is at its root."""
    kind = target.spec.kind
    if kind in ("npm", "pypi"):
        return [kind]
    if kind == "mcp_command" and target.spec.package is not None:
        return [target.spec.package.ecosystem]
    root = target.root
    if root is None:
        return []
    found = []
    if exists(root, "package.json"):
        found.append("npm")
    if any(exists(root, n) for n in ("pyproject.toml", "setup.py", "setup.cfg")):
        found.append("pypi")
    if any(exists(root, n) for n in ("action.yml", "action.yaml")):
        found.append("github_action")
    return found


def scan(executable: Path, ecosystem: str, folder: Path) -> list[Risk]:
    out = run_tool(executable, [ecosystem, "scan", str(folder), "--output-format=json"])
    text = out.stdout.strip()
    if out.returncode != 0 and not text.startswith("{"):
        detail = one_line(last_line(out.stderr), 120)
        raise ToolFailed(f"stopped with an error ({detail})" if detail else "stopped with an error")
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ToolFailed("its output couldn't be read") from exc
    risks = data.get("risks") if isinstance(data, dict) else None
    found = [r for r in (_risk(item) for item in risks or []) if r is not None]
    return sorted(found, key=lambda r: (_SEVERITY_ORDER.get(r.severity, 3), r.path, r.line or 0))


def _risk(item: object) -> Risk | None:
    if not isinstance(item, dict):
        return None
    rule = str(item.get("threat_rule") or "")
    if not _RULE.match(rule):
        return None
    location = str(item.get("threat_location") or item.get("file_path") or "")
    path, _, line = location.rpartition(":")
    if not line.isdigit():
        path, line = location, ""
    rel = PurePosixPath(path)
    if not path or rel.is_absolute() or ".." in rel.parts:
        path = rel.name or "(unknown file)"
    description = str(item.get("threat_description") or "")
    meaning = WORDING.get(rule) or _from_description(description) or "matches a malware pattern"
    code = str(item.get("threat_match") or item.get("threat_code") or "").strip()
    return Risk(
        rule=rule,
        severity=str(item.get("severity") or "").lower(),
        meaning=meaning,
        path=one_line(path, 200),
        line=int(line) if line else None,
        code=one_line(code.split("\n")[0], 200),
    )


def _from_description(description: str) -> str:
    """GuardDog's own wording ("Detects reading of ..."), for rules newer than WORDING."""
    text = one_line(description, 120).strip().rstrip(".")
    if text.lower().startswith("detects "):
        return "matches GuardDog's check for " + text[8:]
    return text
