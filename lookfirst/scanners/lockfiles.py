"""Does an install fetch this package from a registry, or use the project's own copy?

osv.dev matches packages by name. A project's own local package can share its name with
a malicious package on npm, which is how dependency-confusion attacks work, and
osv-scanner can't tell the two apart. Before calling a dependency known malware,
lookfirst reads its lockfile entry: a download from a registry counts, a local link or
folder doesn't. Lockfiles are untrusted text: anything unexpected means "can't tell",
which is treated as fetched.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

from lookfirst.static.files import read_text

_MAX_LOCKFILE = 32 * 1024 * 1024
_LOCAL = ("link:", "file:", "workspace:", "portal:")
_PEP503 = re.compile(r"[-_.]+")


def normal_name(name: str) -> str:
    return _PEP503.sub("-", name).lower()


def fetched_from_registry(root: Path, lockfile: str, name: str, version: str) -> bool | None:
    """True if the lockfile installs name@version from a registry, False if it uses a
    local copy, None if lookfirst can't tell."""
    rel = PurePosixPath(lockfile)
    if rel.is_absolute() or ".." in rel.parts:
        return None
    text = read_text(root, lockfile, max_bytes=_MAX_LOCKFILE)
    if text is None:
        return None
    base = rel.name.lower()
    try:
        if base in ("package-lock.json", "npm-shrinkwrap.json"):
            return _package_lock(json.loads(text), name, version)
        if base == "yarn.lock":
            return _yarn(text, name, version)
        if base == "pnpm-lock.yaml":
            return _pnpm(text, name, version)
        if base in ("uv.lock", "poetry.lock", "pdm.lock", "cargo.lock"):
            return _toml_lock(base, tomllib.loads(text), name, version)
        if base == "pipfile.lock":
            return _pipfile(json.loads(text), name)
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError):
        return None
    return None


def _package_lock(data: Any, name: str, version: str) -> bool | None:
    if not isinstance(data, dict):
        return None
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfile v2 and v3
        found: bool | None = None
        for key, entry in packages.items():
            if not isinstance(entry, dict) or not key:
                continue
            if key == f"node_modules/{name}" or key.endswith(f"/node_modules/{name}"):
                if entry.get("link"):
                    found = False if found is None else found
                    continue
                if entry.get("version") != version:
                    continue
                resolved = entry.get("resolved")
                if isinstance(resolved, str) and resolved.startswith(("https://", "http://")):
                    return True
                if isinstance(resolved, str) and resolved:
                    found = False
                elif entry.get("integrity"):
                    return True
            elif "node_modules/" not in key and entry.get("name") == name:
                found = False if found is None else found  # a workspace package
        return found
    deps = data.get("dependencies")  # lockfile v1
    return _package_lock_v1(deps, name, version) if isinstance(deps, dict) else None


def _package_lock_v1(deps: dict, name: str, version: str, depth: int = 0) -> bool | None:
    if depth > 50:
        return None
    entry = deps.get(name)
    if isinstance(entry, dict):
        v = str(entry.get("version") or "")
        if v.startswith(_LOCAL):
            return False
        resolved = entry.get("resolved")
        if v == version and isinstance(resolved, str) and resolved.startswith("http"):
            return True
    for child in deps.values():
        nested = child.get("dependencies") if isinstance(child, dict) else None
        if isinstance(nested, dict):
            found = _package_lock_v1(nested, name, version, depth + 1)
            if found is not None:
                return found
    return None


def _descriptor_name(descriptor: str) -> str:
    descriptor = descriptor.strip().strip('"')
    at = descriptor.find("@", 1)  # a scoped name starts with "@"
    return descriptor[:at] if at > 0 else descriptor


def _yarn(text: str, name: str, version: str) -> bool | None:
    found: bool | None = None
    for block in re.split(r"\n\s*\n", text):
        lines = block.strip("\n").splitlines()
        if not lines or lines[0].startswith((" ", "#")) or not lines[0].endswith(":"):
            continue
        descriptors = [d.strip().strip('"') for d in lines[0][:-1].split(", ")]
        mine = [d for d in descriptors if _descriptor_name(d) == name]
        if not mine:
            continue
        body = "\n".join(lines[1:])
        m = re.search(r'^\s+version:?\s+"?([^"\s]+)"?', body, re.MULTILINE)
        if m is None or m.group(1) != version:
            continue
        ranges = [d[len(name) + 1 :] for d in mine]
        if re.search(r'^\s+resolved\s+"https?://', body, re.MULTILINE) or re.search(
            rf'^\s+resolution:\s+"?{re.escape(name)}@npm:', body, re.MULTILINE
        ):
            return True
        if any(r.startswith(_LOCAL) for r in ranges) or re.search(
            rf'^\s+resolution:\s+"?{re.escape(name)}@(?:link|file|workspace|portal):',
            body,
            re.MULTILINE,
        ):
            found = False
    return found


def _pnpm(text: str, name: str, version: str) -> bool | None:
    n, v = re.escape(name), re.escape(version)
    registry = (
        rf"^\s+['\"]?/?{n}@{v}(?:\(.*\))?['\"]?:\s*$",  # v6 and v9 package keys
        rf"^\s+['\"]?/{n}/{v}(?:_\S*)?['\"]?:\s*$",  # v5
    )
    if any(re.search(p, text, re.MULTILINE) for p in registry):
        return True
    local = (
        rf"^\s+['\"]?{n}['\"]?:\s*(?:link|file):",  # v5 importers
        rf"^\s+['\"]?{n}['\"]?:\s*\n\s+specifier:[^\n]*\n\s+version:\s*(?:link|file):",  # v9
    )
    if any(re.search(p, text, re.MULTILINE) for p in local):
        return False
    return None


def _toml_lock(base: str, data: Any, name: str, version: str) -> bool | None:
    entries = data.get("package") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return None
    pypi = base != "cargo.lock"
    want = normal_name(name) if pypi else name
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        entry_name = str(entry.get("name") or "")
        if (normal_name(entry_name) if pypi else entry_name) != want:
            continue
        if str(entry.get("version") or "") != version:
            continue
        source = entry.get("source")
        if base == "uv.lock":
            if isinstance(source, dict):
                return not any(k in source for k in ("editable", "directory", "virtual", "path"))
            return None
        if base == "poetry.lock":
            kind = source.get("type") if isinstance(source, dict) else None
            return kind not in ("directory", "file")
        if base == "pdm.lock":
            return not ("path" in entry or entry.get("editable"))
        return bool(source)  # Cargo.lock: path and workspace crates have no source
    return None


def _pipfile(data: Any, name: str) -> bool | None:
    if not isinstance(data, dict):
        return None
    for section in ("default", "develop"):
        packages = data.get(section)
        if not isinstance(packages, dict):
            continue
        for key, entry in packages.items():
            if normal_name(str(key)) == normal_name(name) and isinstance(entry, dict):
                return not ("path" in entry or entry.get("editable"))
    return None
