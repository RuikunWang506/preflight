"""Decoy secrets for the sandbox's home folder (SPEC section 8).

Each decoy holds a unique random value made for this run. Seeing that value in the
proxy's records means the install sent the secret out; strace shows which programs read
the file. Values look like the real thing (an `AKIA` key, a `gho_` token), because
stealers search for those shapes. They're made fresh for every run and never stored.
"""

from __future__ import annotations

import base64
import binascii
import secrets
import string
from dataclasses import dataclass
from urllib.parse import quote

HOME = "/home/sandbox"
_ALNUM = string.ascii_letters + string.digits
# Built from pieces so secret scanners don't mistake this file for a real key.
_KEY_LABEL = "OPENSSH " + "PRIVATE KEY"


@dataclass(frozen=True)
class Decoy:
    what: str  # plain English, finishing "it read ..." or "it sent ..."
    path: str  # where it is in the container
    secret: str  # the unique value to look for
    content: bytes
    owners: tuple[str, ...] = ()  # programs that read this file legitimately
    mode: int = 0o600


@dataclass(frozen=True)
class DecoyEnv:
    """A decoy secret in the environment, where stealers look too."""

    what: str
    name: str
    secret: str


def _token(n: int, alphabet: str = _ALNUM) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def make_decoys(*, project_has_env: bool = False) -> tuple[list[Decoy], list[DecoyEnv]]:
    ssh = _token(48)
    key_body = base64.b64encode(f"openssh-key-v1 lookfirst decoy {ssh}".encode()).decode()
    aws_id, aws_secret = "AKIA" + _token(16, string.ascii_uppercase + string.digits), _token(40)
    gh = "gho_" + _token(36)
    npm = "npm_" + _token(36)
    env_secret = "sk-proj-" + _token(48)
    chrome, cookies, exodus, electrum = _token(40), _token(40), _token(48), _token(48)
    decoys = [
        Decoy(
            "the decoy SSH key",
            f"{HOME}/.ssh/id_ed25519",
            ssh,
            f"-----BEGIN {_KEY_LABEL}-----\n{key_body}\n-----END {_KEY_LABEL}-----\n".encode(),
            owners=("ssh", "ssh-add", "ssh-keygen", "git"),
        ),
        Decoy(
            "the decoy AWS keys",
            f"{HOME}/.aws/credentials",
            aws_secret,
            f"[default]\naws_access_key_id = {aws_id}\n"
            f"aws_secret_access_key = {aws_secret}\n".encode(),
            owners=("aws",),
        ),
        Decoy(
            "the decoy GitHub token",
            f"{HOME}/.config/gh/hosts.yml",
            gh,
            f"github.com:\n    oauth_token: {gh}\n    user: sandbox\n".encode(),
            owners=("gh",),
        ),
        # For a registry installs never use, so npm doesn't send it while installing.
        Decoy(
            "the decoy npm token",
            f"{HOME}/.npmrc",
            npm,
            f"//npm.pkg.github.com/:_authToken={npm}\n".encode(),
            owners=("npm", "npx", "pnpm", "yarn"),
        ),
        Decoy(
            "the decoy browser passwords",
            f"{HOME}/.config/google-chrome/Default/Login Data",
            chrome,
            b"SQLite format 3\x00" + f"https://accounts.example.com sandbox {chrome}".encode(),
            owners=("chrome", "google-chrome"),
        ),
        Decoy(
            "the decoy browser cookies",
            f"{HOME}/.config/google-chrome/Default/Cookies",
            cookies,
            b"SQLite format 3\x00" + f".example.com session={cookies}".encode(),
            owners=("chrome", "google-chrome"),
        ),
        Decoy(
            "the decoy crypto wallet",
            f"{HOME}/.config/Exodus/exodus.wallet/seed.seco",
            exodus,
            f"SECO{exodus}".encode(),
            owners=("exodus",),
        ),
        Decoy(
            "the decoy crypto wallet",
            f"{HOME}/.electrum/wallets/default_wallet",
            electrum,
            f'{{"seed_version": 51, "keystore": {{"seed": "{electrum}"}}}}\n'.encode(),
            owners=("electrum",),
        ),
    ]
    if not project_has_env:  # the project's own .env, if it has one, is left alone
        decoys.append(
            Decoy(
                "the decoy .env file",
                "/work/.env",
                env_secret,
                f"OPENAI_API_KEY={env_secret}\nDATABASE_URL=postgres://app@db:5432/app\n".encode(),
            )
        )
    env = [
        DecoyEnv("the decoy GitHub token in the environment", "GITHUB_TOKEN", "ghp_" + _token(36)),
        DecoyEnv("the decoy npm token in the environment", "NPM_TOKEN", "npm_" + _token(36)),
    ]
    return decoys, env


def _base64_runs(secret: bytes) -> list[str]:
    """What the secret looks like inside base64 of a longer text, at each of the three
    alignments it can fall on."""
    runs = []
    for shift in range(3):
        encoded = base64.b64encode(b"\x00" * shift + secret).decode()
        start = (shift * 4 + 2) // 3 + (1 if shift else 0)
        end = len(encoded) - 4  # the last group may hold padding or the next byte
        runs.append(encoded[start:end])
    return [r for r in runs if len(r) >= 16]


def encodings(secret: str) -> dict[str, list[str]]:
    """The forms of a secret to search for, by encoding."""
    raw = secret.encode()
    b64 = _base64_runs(raw)
    return {
        "as plain text": [secret],
        "encoded as base64": b64,
        "encoded as URL-safe base64": [r.replace("+", "-").replace("/", "_") for r in b64],
        "encoded as hex": [binascii.hexlify(raw).decode(), binascii.hexlify(raw).decode().upper()],
        "URL-encoded": [quote(secret, safe="")],
    }


def search_terms(secrets_: list[str]) -> list[str]:
    """Every form of every secret, for the proxy to refuse to forward."""
    terms = []
    for secret in secrets_:
        for forms in encodings(secret).values():
            terms += [f for f in forms if f not in terms]
    return terms


def find(text: str, secret: str) -> str | None:
    """How the secret appears in the text ("as plain text", "encoded as base64", ...)."""
    for how, forms in encodings(secret).items():
        if any(form and form in text for form in forms):
            return how
    return None
