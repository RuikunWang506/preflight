"""The recording proxy's addon. It runs inside the mitmproxy container, never in lookfirst
itself, so it imports only mitmproxy and the standard library.

Every request is written to flows.jsonl: method, host, path, headers and the start of the
body. Then:
- If it carries a decoy secret, in any form lookfirst listed, it's answered locally and
  never forwarded, even to an allowed site.
- In sinkhole mode, only allowed sites (package registries, the project's own) get it.
  Everything else gets an empty "200 OK" from here.
- In passthrough mode, every other site gets it too.
Plain TCP connections are recorded the same way, and closed unless the site is allowed.
"""

import base64
import json

from mitmproxy import http, tcp, tls

HERE = "/home/mitmproxy/lookfirst"
MAX_BODY = 256 * 1024
MAX_HEADER = 512

with open(f"{HERE}/config.json", encoding="utf-8") as _f:
    _CONFIG = json.load(_f)
MODE = _CONFIG["mode"]  # "sinkhole" or "passthrough"
ALLOW = _CONFIG["allow"]  # [{"host": ..., "path": "/owner/repo" or ""}]
TERMS = [t.encode() for t in _CONFIG["terms"] if t]

# lookfirst waits for this file before starting a run, so a proxy without its addon (one
# that would forward everything) is never used.
with open(f"{HERE}/ready", "w", encoding="utf-8") as _ready:
    _ready.write("ready\n")


def _allowed(host, path):
    host = (host or "").lower().rstrip(".")
    path = (path or "/").split("?", 1)[0].lower()
    for rule in ALLOW:
        if host != rule["host"] and not host.endswith("." + rule["host"]):
            continue
        prefix = (rule.get("path") or "").lower()
        if not prefix or path == prefix or path.startswith((prefix + "/", prefix + ".git")):
            return True
    return False


def _has_decoy(*chunks):
    return any(term in chunk for chunk in chunks for term in TERMS)


def _write(record):
    with open(f"{HERE}/flows.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def request(flow: http.HTTPFlow) -> None:
    req = flow.request
    body = req.get_content(strict=False) or b""
    headers = [[k, v[:MAX_HEADER]] for k, v in list(req.headers.items(multi=True))[:40]]
    head = "\n".join(f"{k}: {v}" for k, v in req.headers.items(multi=True)).encode()
    if _has_decoy(req.pretty_url.encode(), head, body):
        action = "held"  # never forward a decoy, wherever it was going
    elif MODE == "passthrough" or _allowed(req.pretty_host, req.path):
        action = "forwarded"
    else:
        action = "answered"
    _write(
        {
            "kind": "http",
            "method": req.method[:16],
            "scheme": req.scheme,
            "host": req.pretty_host,
            "port": req.port,
            "path": req.path[:2048],
            "headers": headers,
            "body": base64.b64encode(body[:MAX_BODY]).decode(),
            "size": len(body),
            "action": action,
        }
    )
    if action != "forwarded":
        flow.response = http.Response.make(200, b"", {"content-type": "text/plain"})


def tcp_start(flow: tcp.TCPFlow) -> None:
    host, port = (flow.server_conn.address or ("", 0))[:2]
    allowed = MODE == "passthrough" or _allowed(host, "")
    _write(
        {
            "kind": "tcp",
            "host": str(host),
            "port": port,
            "action": "forwarded" if allowed else "closed",
        }
    )
    if not allowed:
        flow.kill()


def tcp_message(flow: tcp.TCPFlow) -> None:
    message = flow.messages[-1]
    if message.from_client and _has_decoy(message.content):
        host, port = (flow.server_conn.address or ("", 0))[:2]
        _write(
            {
                "kind": "tcp",
                "host": str(host),
                "port": port,
                "body": base64.b64encode(message.content[:MAX_BODY]).decode(),
                "size": len(message.content),
                "action": "held",
            }
        )
        flow.kill()


def tls_failed_client(data: tls.TlsData) -> None:
    # A program that refused the sandbox's certificate still tried to reach the site.
    sni = data.conn.sni or ""
    _write({"kind": "tls_refused", "host": sni, "port": 443, "action": "refused"})
