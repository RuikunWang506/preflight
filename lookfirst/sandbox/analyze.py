"""Turning what a dry run saw into findings (SPEC section 8's table).

- critical: a decoy secret in outgoing traffic, in any common encoding
- high: a decoy file read by anything but the tool that owns it; a write, or an attempt,
  to a startup file or scheduled job; a program downloaded into a temporary or home
  folder and then run
- medium: requests to sites other than registries and the project's own; connections
  that tried to go around the proxy; processes still running at the time limit
- info: the install command failed, so the dry run may have missed later steps
Attempts count even when the sandbox's permissions blocked them.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field

from lookfirst.core.textsafe import one_line
from lookfirst.sandbox.honeytokens import HOME, Decoy, DecoyEnv, find
from lookfirst.sandbox.proxy import Flow
from lookfirst.sandbox.trace_parse import Trace
from lookfirst.static.rules_catalog import rule
from lookfirst.verdict.schema import Evidence, Finding

MAX_EVIDENCE = 10
_PERSISTENCE = re.compile(
    r"^/etc/cron|^/var/spool/cron|^/etc/systemd/|^/(?:usr/)?lib/systemd/|^/etc/init\.d/"
    r"|^/etc/rc\.local$|^/etc/profile(?:\.d/|$)|^/etc/bash\.bashrc$|^/etc/environment$"
    r"|^/etc/zsh/|^/etc/ld\.so\.preload$"
    rf"|^{HOME}/\.config/(?:systemd|autostart|fish)/|^{HOME}/\.ssh/authorized_keys"
    rf"|^{HOME}/\.(?:bashrc|bash_profile|bash_login|profile|zshrc|zprofile|zshenv|zlogin)$"
)
_STARTUP_NAMES = frozenset(
    {
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".profile",
        ".zshrc",
        ".zprofile",
        "authorized_keys",
    }
)
_RUN_AREAS = ("/tmp/", "/var/tmp/", "/dev/shm/", f"{HOME}/")
# Where package managers keep and run what they install: not "downloaded and run".
_INSTALLED = (
    "/tmp/lookfirst/",
    f"{HOME}/.npm/",
    f"{HOME}/.npm-global/",
    f"{HOME}/.cache/",
    f"{HOME}/.local/",
)
_LOCAL = frozenset({"127.0.0.1", "::1", "127.0.0.11", "0.0.0.0", "::"})  # noqa: S104


@dataclass
class Observed:
    trace: Trace
    flows: list[Flow]
    decoys: list[Decoy]
    env_decoys: list[DecoyEnv]
    allow: list[dict]  # the sites the proxy forwards to in sinkhole mode
    proxy_ip: str | None
    exit_code: int | None
    timed_out: bool
    network: str
    still_running: list[str] = field(default_factory=list)


def allowed(host: str, path: str, rules: list[dict]) -> bool:
    """The same test the proxy's addon makes."""
    host = host.lower().rstrip(".")
    path = (path or "/").split("?", 1)[0].lower()
    for r in rules:
        if host != r["host"] and not host.endswith("." + r["host"]):
            continue
        prefix = (r.get("path") or "").lower()
        if not prefix or path == prefix or path.startswith((prefix + "/", prefix + ".git")):
            return True
    return False


def hosts_contacted(flows: list[Flow]) -> list[str]:
    return sorted({f.host for f in flows if f.host})[:50]


def _finding(rule_id: str, evidence: list[Evidence], more: int = 0) -> Finding:
    r = rule(rule_id)
    if more and evidence:
        last = evidence[-1]
        evidence[-1] = last.model_copy(update={"data": {**last.data, "more": more}})
    return Finding(
        id=r.id,
        check=r.check,
        severity=r.severity,
        title=r.title,
        evidence=evidence,
        explanation=r.explanation,
        recommendation=r.recommendation,
    )


def _capped(rule_id: str, evidence: list[Evidence]) -> list[Finding]:
    if not evidence:
        return []
    return [_finding(rule_id, evidence[:MAX_EVIDENCE], max(0, len(evidence) - MAX_EVIDENCE))]


def _request(flow: Flow) -> str:
    if flow.kind == "http":
        return one_line(f"{flow.method} {flow.scheme}://{flow.host}{flow.path}", 300)
    return one_line(f"{flow.host}:{flow.port}", 300)


def _sent(o: Observed) -> list[Evidence]:
    found = []
    secrets = [(d.what, d.secret) for d in o.decoys] + [(e.what, e.secret) for e in o.env_decoys]
    for flow in o.flows:
        text = flow.text()
        for what, secret in secrets:
            how = find(text, secret)
            if how is None:
                continue
            fate = "the sandbox held it back" if flow.action == "held" else "it was sent"
            found.append(
                Evidence(
                    type="network",
                    ref=_request(flow),
                    data={"what": one_line(f"{what}, {how}; {fate}", 200)},
                )
            )
    return found


def _read(o: Observed) -> list[Evidence]:
    by_path = {d.path: d for d in o.decoys}
    found, seen = [], set()
    for event in o.trace.opens:
        decoy = by_path.get(event.path)
        if decoy is None or event.write or event.program in decoy.owners:
            continue
        key = (event.path, event.program)
        if key in seen:
            continue
        seen.add(key)
        verb = "read by" if event.ok else "tried by"
        found.append(
            Evidence(
                type="filesystem",
                ref=event.path,
                data={"what": one_line(f"{decoy.what}, {verb} {event.program}", 200)},
            )
        )
    return found


def _is_startup(path: str) -> bool:
    if path.startswith("/"):
        return bool(_PERSISTENCE.search(path))
    return posixpath.basename(path) in _STARTUP_NAMES  # relative to a folder lookfirst lost


def _failed(error: str) -> str:
    if error in ("EACCES", "EPERM", "EROFS"):
        return "tried; the sandbox's permissions blocked it"
    if error == "ENOENT":
        return "tried; that folder doesn't exist in the sandbox"
    return f"tried; it failed ({error or 'error'})"


def _persistence(o: Observed) -> list[Evidence]:
    found, seen = [], set()
    for event in o.trace.opens:
        if event.write and _is_startup(event.path) and event.path not in seen:
            seen.add(event.path)
            result = "written" if event.ok else _failed(event.error)
            found.append(
                Evidence(
                    type="filesystem",
                    ref=event.path,
                    data={"what": one_line(f"{result}, by {event.program}", 200)},
                )
            )
    for move in o.trace.moves:
        if _is_startup(move.target) and move.target not in seen:
            seen.add(move.target)
            found.append(
                Evidence(
                    type="filesystem",
                    ref=move.target,
                    data={"what": one_line(f"replaced, by {move.program}", 200)},
                )
            )
    return found


def _downloaded_and_run(o: Observed) -> list[Evidence]:
    written = {e.path for e in o.trace.opens if e.write and e.ok}
    written |= {m.target for m in o.trace.moves}
    found, seen = [], set()
    for ex in o.trace.execs:
        path = ex.path
        if path not in written or path in seen:
            continue
        if not path.startswith(_RUN_AREAS) or path.startswith(_INSTALLED):
            continue
        if "/node_modules/" in path:
            continue  # a package's own program, installed by npm
        seen.add(path)
        how = "saved during the install, then run"
        if not ex.ok:
            how += f" (it didn't start: {ex.error or 'error'})"
        found.append(Evidence(type="process", ref=path, data={"what": how}))
    return found


def _other_sites(o: Observed) -> list[Evidence]:
    found, seen = [], set()
    for flow in o.flows:
        if not flow.host or flow.host in seen:
            continue
        if flow.action == "forwarded" and allowed(flow.host, flow.path, o.allow):
            continue
        seen.add(flow.host)
        fate = {
            "answered": "answered by the sandbox; it never reached the site",
            "held": "held back by the sandbox",
            "closed": "closed by the sandbox",
            "refused": "the program refused the sandbox's certificate",
            "forwarded": "reached the site",
        }.get(flow.action, flow.action)
        found.append(Evidence(type="network", ref=_request(flow), data={"what": fate}))
    return found


def _direct(o: Observed) -> list[Evidence]:
    found, seen = [], set()
    for c in o.trace.connects:
        if c.family not in ("AF_INET", "AF_INET6") or not c.address:
            continue
        if c.address in _LOCAL or c.address == o.proxy_ip or c.address.startswith("127."):
            continue
        key = (c.address, c.port)
        if key in seen:
            continue
        seen.add(key)
        where = f"[{c.address}]:{c.port}" if c.family == "AF_INET6" else f"{c.address}:{c.port}"
        found.append(Evidence(type="network", ref=where, data={"what": f"tried by {c.program}"}))
    return found


def judge(o: Observed) -> list[Finding]:
    findings: list[Finding] = []
    findings += _capped("sandbox.decoy_sent", _sent(o))
    findings += _capped("sandbox.decoy_read", _read(o))
    findings += _capped("sandbox.persistence", _persistence(o))
    findings += _capped("sandbox.ran_downloaded_program", _downloaded_and_run(o))
    findings += _capped("sandbox.contacted_other_sites", _other_sites(o))
    findings += _capped("sandbox.direct_connection", _direct(o))
    if o.timed_out and o.still_running:
        running = [
            Evidence(type="process", ref=one_line(p, 300)) for p in o.still_running[:MAX_EVIDENCE]
        ]
        findings.append(_finding("sandbox.still_running", running))
    elif o.timed_out:
        findings.append(_finding("sandbox.still_running", []))
    if not o.timed_out and o.exit_code not in (None, 0):
        exit_ = Evidence(
            type="metric", ref="exit code", data={"what": f"it exited with {o.exit_code}"}
        )
        findings.append(_finding("sandbox.install_failed", [exit_]))
    return findings
