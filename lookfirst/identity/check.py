"""The identity check: is this the real project, or a copy posing as it? (SPEC section 4)

1. Find the original it might imitate: official.yaml, the popular-repos list, a live
   GitHub search for the same name, and a fork's parent.
2. Compare the signals copies show: the name, a copied README, a brand-new account or
   repo, inflated stars, downloads the original doesn't ship, a fork's changed install.
3. Combine them. "Likely impersonation" needs a resemblance (a lookalike name or a
   copied README) plus a sign of deception (a brand-new account or repo, or inflated
   stars), or a lookalike name and a copied README together. A fork resembles its parent
   by nature, and established forks routinely ship their own builds, so a fork needs a
   sign of deception and a change it ships (a download or a changed install). It's
   Don't run when a risky download, a README warning or inflated stars come with it, and
   Caution otherwise.

The README is also checked on its own for download passwords, file-sharing links and
instructions to turn off antivirus. Wording never accuses anyone: findings say what
matches patterns impersonation campaigns use, with the evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from lookfirst.core.errors import FetchError
from lookfirst.core.textsafe import one_line
from lookfirst.core.urls import split_url
from lookfirst.identity import official, provenance
from lookfirst.identity.github import GitHubData, RateLimited, valid_full_name
from lookfirst.identity.names import compare
from lookfirst.identity.popular_index import PopularIndex
from lookfirst.identity.readme_sim import similarity
from lookfirst.static.files import read_text
from lookfirst.static.rules_catalog import rule
from lookfirst.targets.models import ResolvedTarget
from lookfirst.verdict.schema import Evidence, Finding, IdentityResult

# What kind of signal each finding is (see step 3 above).
_GROUPS = {
    "identity.name_lookalike": "name",
    "identity.readme_copy": "readme",
    "identity.new_account": "age",
    "identity.young_repo": "age",
    "identity.suspicious_stars": "stars",
    "identity.extra_downloads": "download",
    "identity.offsite_download": "download",
    "identity.archive_password": "warning",
    "identity.disable_protection": "warning",
    "identity.fork_changed_install": "fork",
}
_RESEMBLANCE = frozenset({"name", "readme"})
_DECEPTION = frozenset({"age", "stars"})
_SHIPPED = frozenset({"download", "fork"})
_SEVERE = frozenset({"stars", "download", "warning"})
# Findings that only compare the target with the original. When it turns out not to be
# posing as that original, they'd just be noise.
_COMPARISONS = frozenset({"identity.name_lookalike", "identity.extra_downloads"})
_SUMMARIES = ("identity.likely_impersonation", "identity.possible_impersonation")
_RISKY_DOWNLOADS = (
    ".zip",
    ".7z",
    ".rar",
    ".exe",
    ".msi",
    ".dmg",
    ".pkg",
    ".apk",
    ".scr",
    ".bat",
    ".cmd",
    ".iso",
    ".jar",
    ".appimage",
    ".deb",
    ".rpm",
    ".tar.gz",
    ".tgz",
)
_INSTALL_FILES = re.compile(
    r"(?:^|/)(?:install|setup|bootstrap|get)[^/]*\.(?:sh|ps1|bat|cmd|py)$"
    r"|(?:^|/)(?:setup\.py|package\.json|Makefile|justfile|Dockerfile|pyproject\.toml)$"
    r"|(?:^|/)\.(?:vscode|devcontainer|claude)/|(?:^|/)\.mcp\.json$|(?:^|/)\.envrc$"
)
_README_NAMES = ("README.md", "readme.md", "Readme.md", "README.markdown", "README")
_ANY_PATH = re.compile(r"^/.")  # anything but the site's home page
# File-sharing and paste sites, with the address paths that point at a shared file or
# folder there. Links to the site itself (its home page, blog or developer docs) don't
# count: lists of tools link to those all the time.
_FILE_SHARES: dict[str, re.Pattern[str]] = {
    "mediafire.com": re.compile(r"^/(?:file|file_premium|folder|download|view)/"),
    "mega.nz": re.compile(r"^/(?:file|folder)/|^/#"),
    "gofile.io": re.compile(r"^/d/"),
    "pixeldrain.com": re.compile(r"^/(?:u|l|api/file)/"),
    "anonfiles.com": _ANY_PATH,
    "files.catbox.moe": _ANY_PATH,
    "transfer.sh": _ANY_PATH,
    "sendspace.com": re.compile(r"^/(?:file|filegroup)/"),
    "workupload.com": re.compile(r"^/(?:file|archive)/"),
    "dropbox.com": re.compile(r"^/(?:s|sh|scl|l|t)/"),
    "dl.dropbox.com": _ANY_PATH,
    "dl.dropboxusercontent.com": _ANY_PATH,
    "drive.google.com": re.compile(r"^/(?:file/d/|drive/(?:u/\d+/)?folders/|uc\b|open\b)"),
    "drive.usercontent.google.com": _ANY_PATH,
    "1drv.ms": _ANY_PATH,
    "onedrive.live.com": _ANY_PATH,
    "cdn.discordapp.com": re.compile(r"^/attachments/"),
    "media.discordapp.net": re.compile(r"^/attachments/"),
    "pastebin.com": re.compile(r"^/(?:raw/|dl/)?[A-Za-z0-9]{8}$"),
    "rentry.co": _ANY_PATH,
    "rentry.org": _ANY_PATH,
    "files.fm": re.compile(r"^/(?:u|f)/"),
    "krakenfiles.com": re.compile(r"^/view/"),
    "qiwi.gg": re.compile(r"^/(?:file|folder)/"),
    "upload.ee": re.compile(r"^/files/"),
    "dosya.co": _ANY_PATH,
}
_PASSWORD = re.compile(
    r"\b(?:password|passcode|passwd|pwd|pass)\s*(?P<sep>:|=|\bis\b)\s*"
    r"(?P<mark>[`'\"*_]*)(?P<value>[A-Za-z0-9!@#$%^&._-]{3,40})",
    re.IGNORECASE,
)
# Words that follow "password:" or "password is" without being a password.
_NOT_A_PASSWORD = frozenset(
    {
        "required",
        "needed",
        "optional",
        "protected",
        "empty",
        "blank",
        "none",
        "not",
        "the",
        "same",
        "set",
        "below",
        "above",
        "provided",
        "shown",
        "stored",
        "saved",
        "encrypted",
        "hashed",
        "incorrect",
        "wrong",
        "invalid",
        "missing",
        "changed",
        "reset",
        "generated",
        "random",
        "unique",
        "sent",
        "given",
        "listed",
    }
)
_ARCHIVE_WORDS = re.compile(
    r"\b(?:zip|rar|7z|7-zip|archive|extract|unzip|unpack|winrar)\b|\.exe\b", re.IGNORECASE
)
_DISABLE = re.compile(
    r"\b(?:disable|turn\s+off|deactivate|pause|switch\s+off|temporarily\s+disable)\s+(?:your\s+|the\s+|windows\s+|microsoft\s+)?"
    r"(?:antivirus|anti-virus|virus\s+protection|defender|smartscreen|gatekeeper|real[-\s]?time\s+protection)\b"
    r"|\badd\s+(?:an?\s+)?exclusion\b[^.\n]{0,40}\b(?:defender|antivirus)\b"
    r"|\ballow\s+apps\s+(?:downloaded\s+)?from\s+anywhere\b",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s)\]>\"'`]+")
_REMOTE = re.compile(
    r"url\s*=\s*(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)"
    r"([A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}?)(?:\.git)?\s*$",
    re.MULTILINE,
)
_GITHUB_HOSTS = ("github.com", "raw.githubusercontent.com", "gist.githubusercontent.com")


@dataclass
class IdentityOutcome:
    result: IdentityResult | None = None
    findings: list[Finding] = field(default_factory=list)
    gaps: list[tuple[str, str, str | None]] = field(default_factory=list)  # what, reason, how
    ran: bool = True


@dataclass
class _Candidate:
    full_name: str
    stars: int
    created: datetime | None
    source: str  # "official", "parent", "index" or "search"
    default_branch: str = "main"

    @property
    def owner(self) -> str:
        return self.full_name.split("/", 1)[0]

    @property
    def name(self) -> str:
        return self.full_name.split("/", 1)[1]


class _Signals:
    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.ids: list[str] = []

    @property
    def groups(self) -> set[str]:
        return {_GROUPS[i] for i in self.ids if i in _GROUPS}

    def add(self, rule_id: str, evidence: list[Evidence], **values: object) -> None:
        r = rule(rule_id)
        safe = {k: one_line(str(v), 140) for k, v in values.items()}
        self.findings.append(
            Finding(
                id=r.id,
                check=r.check,
                severity=r.severity,
                title=one_line(r.title.format(**safe), 90),
                evidence=evidence,
                explanation=r.explanation.format(**safe),
                recommendation=r.recommendation.format(**safe),
            )
        )
        self.ids.append(rule_id)


def _date(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) < 10:
        return None
    try:
        return datetime.fromisoformat(value[:10]).replace(tzinfo=UTC)
    except ValueError:
        return None


def _days(now: datetime, then: datetime | None) -> int | None:
    return None if then is None else max((now - then).days, 0)


def _gh(full_name: str, suffix: str = "") -> str:
    return f"https://github.com/{full_name}{suffix}"


def _local_readme(root: Path | None) -> tuple[str, str] | None:
    if root is None:
        return None
    for name in _README_NAMES:
        text = read_text(root, name)
        if text is not None:
            return name, text
    return None


def _gives_password(line: str) -> bool:
    """Whether the line hands out a password ("Password: 2026", "the password is `x`").

    Only a value counts: a feature list that mentions "password-protected archives", or
    "the password is required", doesn't.
    """
    for m in _PASSWORD.finditer(line):
        value = m.group("value").lower().strip("._-")
        if value in _NOT_A_PASSWORD or value.startswith(("your", "my")):
            continue
        if m.group("sep").lower() == "is" and not (
            m.group("mark") or any(ch.isdigit() for ch in value)
        ):
            continue  # "the password is ..." counts only with a quoted or numeric value
        return True
    return False


def _file_share(url: str) -> bool:
    """Whether the address points at a file or folder shared on a file-sharing site."""
    parts = split_url(url)
    if parts is None:
        return False
    host = (parts.hostname or "").lower().removeprefix("www.")
    pattern = _FILE_SHARES.get(host)
    if pattern is None:
        return False
    where = parts.path or "/"
    if parts.query:
        where += "?" + parts.query
    if parts.fragment:
        where += "#" + parts.fragment
    return bool(pattern.search(where))


def _readme_content(readme: tuple[str, str] | None, sig: _Signals) -> None:
    """Download passwords, file-sharing links and "turn off antivirus" in the README."""
    if readme is None:
        return
    path, text = readme
    lines = text.splitlines()
    in_code = False
    passwords: list[Evidence] = []
    hosts: list[Evidence] = []
    disables: list[Evidence] = []
    for i, line in enumerate(lines):
        if line.lstrip().startswith(("```", "~~~")):
            in_code = not in_code
            continue
        if in_code:
            continue  # config examples ("password: changeme") live in code blocks
        window = " ".join(lines[max(0, i - 2) : i + 3])
        if _gives_password(line) and _ARCHIVE_WORDS.search(window):
            passwords.append(
                Evidence(type="file", ref=path, line=i + 1, excerpt=one_line(line, 200))
            )
        if _DISABLE.search(line):
            disables.append(
                Evidence(type="file", ref=path, line=i + 1, excerpt=one_line(line, 200))
            )
        for url in _URL.findall(line):
            if _file_share(url):
                hosts.append(
                    Evidence(
                        type="url",
                        ref=url[:2048],
                        line=i + 1,
                        data={"what": f"{path} line {i + 1}"},
                    )
                )
    if passwords:
        sig.add("identity.archive_password", passwords[:5])
    if disables:
        sig.add("identity.disable_protection", disables[:5])
    if hosts:
        sig.add("identity.offsite_download", hosts[:5])


def _candidates(
    meta: dict,
    owner: str,
    name: str,
    data: GitHubData | None,
    index: PopularIndex,
    gaps: list[tuple[str, str, str | None]],
) -> list[_Candidate]:
    found: list[_Candidate] = []
    parent = meta.get("parent")
    if meta.get("fork") and isinstance(parent, dict) and valid_full_name(parent.get("full_name")):
        found.append(_from_api(parent, "parent"))
    for project in official.projects_named_in(name, owner):
        entry = index.get(project.canonical)
        if entry is not None:
            found.append(_Candidate(entry.full_name, entry.stars, _date(entry.created), "official"))
        elif data is not None and (canon := data.repo(project.canonical)):
            found.append(_from_api(canon, "official"))
    for entry, _matches in index.lookalikes(owner, name):
        found.append(_Candidate(entry.full_name, entry.stars, _date(entry.created), "index"))
    if data is not None:
        # Search has its own, much smaller limit (10 a minute without a token, 30 with).
        # Without it, the official list and the popular-repos list still apply.
        try:
            same_name = data.search_same_name(name)
        except FetchError as err:
            same_name = []
            reason = (
                "GitHub's search limit is used up for now; it resets within a minute"
                if isinstance(err, RateLimited)
                else f"couldn't search GitHub: {err.message.rstrip('.')}"
            )
            gaps.append(("Repos with the same name", reason, "run the check again in a minute"))
        for item in same_name:
            full = item.get("full_name")
            if valid_full_name(full):
                o, n = full.split("/", 1)
                if any(m.kind != "lookalike_owner" for m in compare(owner, name, o, n)):
                    found.append(_from_api(item, "search"))
    return found


def _from_api(item: dict, source: str) -> _Candidate:
    return _Candidate(
        full_name=str(item["full_name"]),
        stars=int(item.get("stargazers_count") or 0),
        created=_date(item.get("created_at")),
        source=source,
        default_branch=str(item.get("default_branch") or "main"),
    )


def _pick(
    found: list[_Candidate], full: str, stars: int, created: datetime | None
) -> _Candidate | None:
    """The original to compare with: official or a fork's parent first, then the most-starred
    look-alike that is clearly more established than the target."""
    eligible = []
    for c in found:
        if c.full_name.lower() == full.lower():
            continue
        if c.source in ("official", "parent"):
            eligible.append(c)
            continue
        older = c.created is None or created is None or c.created < created
        if c.stars >= max(100, 3 * stars) and older:
            eligible.append(c)
    # A fork is compared with its own parent first, even when it also names an official project.
    priority = {"parent": 0, "official": 1, "index": 2, "search": 2}
    return min(eligible, key=lambda c: (priority[c.source], -c.stars)) if eligible else None


def _new_or_empty(account: dict, now: datetime) -> bool:
    created = _date(account.get("createdAt"))
    new = created is not None and (now - created).days < 30
    followers = (account.get("followers") or {}).get("totalCount", 0)
    repos = (account.get("repositories") or {}).get("totalCount", 0)
    return new or (followers == 0 and repos == 0)


def _stars(
    meta: dict,
    full: str,
    data: GitHubData | None,
    sig: _Signals,
    now: datetime,
    gaps: list,
    *,
    commits: int | None,
    sample: bool,
) -> None:
    stars = int(meta.get("stargazers_count") or 0)
    age = _days(now, _date(meta.get("created_at")))
    if age is None:
        return
    reasons = []
    if age <= 30 and stars >= 200 and stars / max(age, 1) >= 20:
        if commits is None and data is not None:
            commits = data.commit_count(full)
        if commits is not None and commits <= 5:
            reasons.append(f"{stars} stars in {max(age, 1)} days, with {commits} commits")
    if sample and stars >= 20 and data is not None:
        if data.has_token:
            accounts = data.recent_stargazers(full)
            if accounts and len(accounts) >= 20:
                odd = sum(1 for a in accounts if _new_or_empty(a, now))
                if odd / len(accounts) > 0.5:
                    reasons.append(
                        f"{odd} of its last {len(accounts)} stars come from new or empty accounts"
                    )
        else:
            gaps.append(
                ("Star sample", "needs a GitHub token", "set GITHUB_TOKEN, or run gh auth login")
            )
    if reasons:
        sig.add(
            "identity.suspicious_stars",
            [Evidence(type="url", ref=_gh(full, "/stargazers"), data={"what": "; ".join(reasons)})],
        )


def _risky_types(releases: list[dict]) -> dict[str, str]:
    """File types offered in releases that run or unpack, mapped to an example name."""
    found: dict[str, str] = {}
    for release in releases:
        for asset in release.get("assets") or []:
            name = str(asset.get("name") or "") if isinstance(asset, dict) else ""
            for ext in _RISKY_DOWNLOADS:
                if name.lower().endswith(ext):
                    found.setdefault(ext, name)
                    break
    return found


def _check_repo(
    meta: dict,
    readme: tuple[str, str] | None,
    data: GitHubData | None,
    index: PopularIndex,
    now: datetime,
) -> IdentityOutcome:
    full = meta.get("full_name")
    if not valid_full_name(full):
        return IdentityOutcome(
            ran=False,
            gaps=[("Is this the real project?", "GitHub sent an unexpected answer", None)],
        )
    owner, name = str(full).split("/", 1)
    sig = _Signals()
    gaps: list[tuple[str, str, str | None]] = []
    _readme_content(readme, sig)
    if official.project_owning_repo(full) is not None:
        return IdentityOutcome(
            IdentityResult(status="original", original=full, confidence=1.0), sig.findings
        )

    stars = int(meta.get("stargazers_count") or 0)
    created = _date(meta.get("created_at"))
    age = _days(now, created)
    best = _pick(_candidates(meta, owner, name, data, index, gaps), full, stars, created)
    if best is None:
        _stars(meta, full, data, sig, now, gaps, commits=None, sample=age is not None and age <= 90)
        established = stars >= 1000 and age is not None and age > 180
        result = IdentityResult(
            status="original" if established else "unrelated",
            original=full if established else None,
            confidence=0.7 if established else 0.5,
            top_signals=sig.ids[:3],
        )
        return IdentityOutcome(result, sig.findings, gaps)

    original = best.full_name
    is_fork = best.source == "parent"
    if not is_fork:
        matches = compare(owner, name, best.owner, best.name)
        if matches:
            what = "; ".join(m.detail for m in matches)
            sig.add(
                "identity.name_lookalike",
                [Evidence(type="url", ref=_gh(full), data={"what": what})],
                original=original,
            )
        target_text = readme[1] if readme else (data.readme(full) if data else None)
        if readme is None and target_text:
            _readme_content(
                ("README.md", target_text), sig
            )  # no download on disk: use GitHub's copy
        original_text = data.readme(original) if data else None
        if target_text and original_text:
            s = similarity(target_text, original_text)
            if s.copied:
                sig.add(
                    "identity.readme_copy",
                    [
                        Evidence(
                            type="url",
                            ref=_gh(original),
                            data={
                                "jaccard": round(s.jaccard, 2),
                                "containment": round(s.containment, 2),
                            },
                        )
                    ],
                    original=original,
                    percent=s.percent,
                )
    if data is not None:
        account = data.user(owner)
        account_age = _days(now, _date(account.get("created_at"))) if account else None
        original_age = _days(now, best.created)
        if (
            account_age is not None
            and account_age < 30
            and (original_age is None or original_age > 180)
        ):
            sig.add(
                "identity.new_account", [Evidence(type="url", ref=_gh(owner))], days=account_age
            )
    commits = None
    if age is not None and age < 30 and data is not None:
        commits = data.commit_count(full)
        if commits is not None and commits <= 3:
            sig.add(
                "identity.young_repo",
                [Evidence(type="url", ref=_gh(full, "/commits"))],
                days=age,
                commits=commits,
            )
    _stars(meta, full, data, sig, now, gaps, commits=commits, sample=True)
    if data is not None:
        theirs = _risky_types(data.releases(full))
        ours = _risky_types(data.releases(original))
        extra = [example for ext, example in theirs.items() if ext not in ours]
        if extra:
            sig.add(
                "identity.extra_downloads",
                [
                    Evidence(
                        type="url", ref=_gh(full, "/releases"), data={"what": ", ".join(extra[:5])}
                    )
                ],
                original=original,
            )
        if is_fork:
            changed = data.changed_files(
                original, best.default_branch, owner, str(meta.get("default_branch") or "main")
            )
            install = [f for f in changed or [] if _INSTALL_FILES.search(f)]
            if install:
                sig.add(
                    "identity.fork_changed_install",
                    [Evidence(type="url", ref=_gh(full), data={"what": ", ".join(install[:5])})],
                    original=original,
                )

    groups = sig.groups
    deceptive = bool(groups & _DECEPTION)
    if is_fork:
        counted = groups - _RESEMBLANCE  # a fork shares its parent's name and README
        posing = deceptive and bool(groups & _SHIPPED)
    else:
        counted = groups
        posing = bool(groups & _RESEMBLANCE) and (deceptive or groups >= _RESEMBLANCE)
    if posing:
        severe = bool(counted & _SEVERE)
        summary = _SUMMARIES[0] if severe else _SUMMARIES[1]
        top = [i for i in sig.ids if i not in _SUMMARIES][:3]
        sig.add(
            summary,
            [Evidence(type="url", ref=_gh(original), data={"what": "the project it resembles"})],
            original=original,
        )
        confidence = {2: 0.7, 3: 0.85}.get(len(counted), 0.95)
        result = IdentityResult(
            status="likely_impersonation", original=original, confidence=confidence, top_signals=top
        )
    elif is_fork:
        result = IdentityResult(
            status="fork_benign", original=original, confidence=0.8, top_signals=sig.ids[:3]
        )
    else:
        # Many projects share a name or ship their own builds. Unless the README is copied
        # too, comparing this one with the original would just be noise.
        dropped = _COMPARISONS if "readme" not in groups else {"identity.name_lookalike"}
        kept = [f for f in sig.findings if f.id not in dropped]
        top = [i for i in sig.ids if i not in dropped][:3]
        result = IdentityResult(status="unrelated", original=None, confidence=0.6, top_signals=top)
        return IdentityOutcome(result, kept, gaps)
    return IdentityOutcome(result, sig.findings, gaps)


def _check_package(
    target: ResolvedTarget,
    readme: tuple[str, str] | None,
    data: GitHubData | None,
    index: PopularIndex,
    now: datetime,
) -> IdentityOutcome:
    package = target.spec.package
    sig = _Signals()
    _readme_content(readme, sig)
    declared = target.source_repo
    repo = str(declared) if valid_full_name(declared) else None
    no_repo_gap = (
        "Comparing it with the project it might copy",
        "the package doesn't name a GitHub repo",
        None,
    )
    if package is None:
        return IdentityOutcome(None, sig.findings, [no_repo_gap])

    # Published by the project itself: listed in official.yaml, or under an npm scope or
    # PyPI organization it owns. Registries control both, unlike the repo a package names.
    owner = official.project_owning_package(package.ecosystem, package.name)
    if owner is None and package.ecosystem == "pypi":
        ownership = (target.metadata.get("pypi") or {}).get("ownership")
        org = ownership.get("organization") if isinstance(ownership, dict) else None
        owner = official.project_with_pypi_org(org) if isinstance(org, str) else None
    if owner is not None:
        own_repo = repo if repo and owner.owns_repo(repo) else owner.canonical
        return IdentityOutcome(
            IdentityResult(status="original", original=own_repo, confidence=1.0), sig.findings
        )
    if repo is None:
        return IdentityOutcome(None, sig.findings, [no_repo_gap])

    project = official.project_owning_repo(repo)
    if project is not None:
        # It names one of the project's repos. Believe it only if the registry's provenance
        # record says one of the project's repos built it.
        try:
            built = _built_from(target, package.ecosystem, data)
        except FetchError as err:
            gap = (
                "Where the package was built",
                f"couldn't ask the registry: {err.message.rstrip('.')}",
                None,
            )
            return IdentityOutcome(None, sig.findings, [gap])
        if built is not None and project.owns_repo(built):
            return IdentityOutcome(
                IdentityResult(status="original", original=built, confidence=1.0), sig.findings
            )
        evidence = [
            Evidence(
                type="url",
                ref=_gh(repo),
                data={"what": f"the {package.ecosystem} package {package.name}"},
            )
        ]
        if built is not None:
            evidence.append(
                Evidence(type="url", ref=_gh(built), data={"what": "the repo that built it"})
            )
        sig.add("identity.claims_official_repo", evidence, original=repo, project=project.name)
        result = IdentityResult(
            status="likely_impersonation",
            original=project.canonical,
            confidence=0.8,
            top_signals=["identity.claims_official_repo"],
        )
        return IdentityOutcome(result, sig.findings)
    meta = data.repo(repo) if data is not None else None
    if meta is None:
        return IdentityOutcome(
            None,
            sig.findings,
            [
                (
                    "Comparing it with the project it might copy",
                    "lookfirst couldn't find the package's GitHub repo",
                    None,
                )
            ],
        )
    repo_outcome = _check_repo(meta, None, data, index, now)
    return IdentityOutcome(
        repo_outcome.result,
        sig.findings + repo_outcome.findings,
        repo_outcome.gaps,
        repo_outcome.ran,
    )


def _built_from(target: ResolvedTarget, ecosystem: str, data: GitHubData | None) -> str | None:
    """The repo the registry's provenance record says built the package, if it has one."""
    if data is None:
        return None
    if ecosystem == "npm":
        manifest = target.metadata.get("npm")
        return (
            provenance.npm_built_from(data.client, manifest) if isinstance(manifest, dict) else None
        )
    pypi = target.metadata.get("pypi") or {}
    info, file = pypi.get("info") or {}, pypi.get("file") or {}
    name, version, filename = info.get("name"), info.get("version"), file.get("filename")
    if not all(isinstance(v, str) and v for v in (name, version, filename)):
        return None
    return provenance.pypi_built_from(data.client, name, version, filename)


def _check_command(command: str) -> IdentityOutcome:
    sig = _Signals()
    matched: official.OfficialProject | None = None
    for url in _URL.findall(command):
        parts = split_url(url)
        if parts is None:
            continue
        host = (parts.hostname or "").lower()
        if host in _GITHUB_HOSTS:
            m = re.match(r"^/([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100})", parts.path)
            if not m or official.project_owning_repo(f"{m.group(1)}/{m.group(2)}"):
                continue
            for project in official.projects_named_in(m.group(2), m.group(1)):
                sig.add(
                    "identity.lookalike_installer_link",
                    [Evidence(type="url", ref=url[:2048])],
                    project=project.name,
                )
        else:
            for project in official.projects_named_in(host):
                if not project.owns_host(host):
                    sig.add(
                        "identity.lookalike_installer_site",
                        [Evidence(type="url", ref=url[:2048])],
                        project=project.name,
                    )
                    matched = project
    result = None
    if matched is not None:
        result = IdentityResult(
            status="likely_impersonation",
            original=matched.canonical,
            confidence=0.7,
            top_signals=sig.ids[:3],
        )
    return IdentityOutcome(result, sig.findings)


def github_remote(root: Path | None) -> str | None:
    if root is None:
        return None
    text = read_text(root, ".git/config")
    m = _REMOTE.search(text or "")
    return m.group(1) if m else None


def check_identity(
    target: ResolvedTarget, data: GitHubData | None, index: PopularIndex, *, now: datetime
) -> IdentityOutcome:
    kind = target.spec.kind
    readme = _local_readme(target.root)
    if kind == "github":
        return _check_repo(target.metadata.get("repo") or {}, readme, data, index, now)
    if kind in ("npm", "pypi", "mcp_command"):
        return _check_package(target, readme, data, index, now)
    if kind == "oneliner":
        return _check_command(target.spec.command or "")
    remote = github_remote(target.root)
    meta = data.repo(remote) if remote and data is not None else None
    if meta is not None:
        return _check_repo(meta, readme, data, index, now)
    sig = _Signals()
    _readme_content(readme, sig)
    reason = (
        "this folder has no GitHub remote"
        if remote is None
        else "lookfirst couldn't look up its GitHub remote"
    )
    return IdentityOutcome(
        None, sig.findings, [("Comparing it with the project it might copy", reason, None)]
    )
