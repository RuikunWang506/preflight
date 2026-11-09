"""Every rule lookfirst's static checks can report, with its plain-English wording.

All user-facing wording for these findings lives here, so it can be reviewed in one
place (the M4 review freezes it). Titles are at most 90 characters and never include
text from the target.
"""

from __future__ import annotations

from dataclasses import dataclass

from lookfirst.verdict.schema import CheckKind, Severity

C, H, M, I = Severity.critical, Severity.high, Severity.medium, Severity.info  # noqa: E741


@dataclass(frozen=True)
class Rule:
    id: str
    check: CheckKind
    severity: Severity
    title: str
    explanation: str
    recommendation: str


def _rules(check: CheckKind, *rows: tuple[str, Severity, str, str, str]) -> dict[str, Rule]:
    return {
        f"{check.value}.{name}": Rule(f"{check.value}.{name}", check, sev, title, why, todo)
        for name, sev, title, why, todo in rows
    }


_DONT = "Don't run it. If you already did, change the passwords and keys it could reach."

RULES: dict[str, Rule] = {
    **_rules(
        CheckKind.install_path,
        # --- critical ---
        (
            "credential_theft",
            C,
            "Reads your saved keys or passwords and sends data over the network",
            "Scripts that read keys, tokens or browser data and then send something over the "
            "network can steal access to your accounts.",
            _DONT,
        ),
        (
            "fake_password_prompt",
            C,
            "Shows a fake password prompt",
            "It pops up a password box that looks like it comes from macOS. "
            "Real installers let macOS ask for your password itself.",
            "Don't run it, and never type your password into a box it shows.",
        ),
        (
            "persistence",
            C,
            "Sets itself up to run again later",
            "It adds something that runs on its own later: a login item, a scheduled job, "
            "a startup file that downloads code, or a key that lets someone log in.",
            "Don't run it. If you did, look for the entries listed below and remove them.",
        ),
        # --- high ---
        (
            "decode_and_run",
            H,
            "Decodes hidden code and runs it",
            "It hides the commands it runs, for example in base64 or escape codes, so you "
            "can't read them before they run. Honest installers have no reason to do this.",
            "Don't run it unless you can see exactly what the hidden part does.",
        ),
        (
            "download_and_run_binary",
            H,
            "Downloads a program from an unknown site and runs it",
            "It downloads a program from a site that isn't the project's own or a well-known "
            "source, and runs it straight away.",
            "Don't run it unless you trust that site and the program it downloads.",
        ),
        (
            "quarantine_removed",
            H,
            "Removes macOS's safety check from downloaded files",
            "macOS marks downloaded files so it can check them before they first open. "
            "Removing that mark skips the check.",
            "Don't run it unless you know why the project needs to skip macOS's check.",
        ),
        (
            "gatekeeper_off",
            H,
            "Turns off Gatekeeper, macOS's app checker",
            "Gatekeeper stops apps from unknown developers. Turning it off lowers protection "
            "for every app on your Mac, not just this one.",
            "Don't run it. No normal install needs Gatekeeper switched off.",
        ),
        (
            "sudo_piped_download",
            H,
            "Runs a downloaded script as administrator",
            "It downloads a script and runs it with administrator rights straight away, so "
            "whatever the script does, it can do to your whole computer.",
            "Download the script first, read it, then decide whether to run it.",
        ),
        (
            "escaping_archive_path",
            H,
            "Its files try to write outside their own folder",
            "Some files in the download are named to land outside the folder they unpack "
            "into, a known trick for overwriting other files on your computer.",
            "Don't install it.",
        ),
        # --- medium ---
        (
            "remote_script_unknown_site",
            M,
            "Runs a script from a site lookfirst can't vouch for",
            "It downloads a script and runs it without showing it to you first. The script "
            "comes from a site that isn't the project's own or a well-known installer.",
            "Open the script's link and read it before you run it.",
        ),
        (
            "unpinned_remote_script",
            M,
            "Runs a remote script that can change at any time",
            "The script comes from the project's own repo, but from a branch rather than a "
            "fixed version, so what runs can change after you looked.",
            "Prefer instructions that point at a tagged release.",
        ),
        (
            "remote_unreadable",
            M,
            "Runs a remote script lookfirst couldn't read",
            "It downloads and runs a script that lookfirst couldn't get, so lookfirst can't "
            "say what it does.",
            "Read the script yourself before running it.",
        ),
        (
            "download_and_run_release",
            M,
            "Downloads and runs a program from another project's releases",
            "It downloads a program from a GitHub release of a different project and runs it.",
            "Check that the other project is the one you expect.",
        ),
        (
            "global_install",
            M,
            "Installs things for your whole computer",
            "It installs packages globally or with administrator rights, so they affect every "
            "project and user, not just this folder.",
            "Prefer installing inside the project, or in a virtual environment.",
        ),
        (
            "plain_http",
            M,
            "Downloads over unencrypted http",
            "Anyone on your network could swap what an http download returns.",
            "Use the https link instead.",
        ),
        (
            "autorun_on_open",
            M,
            "Runs commands when you open the folder",
            "Some editors and tools run these commands automatically when you open the folder, "
            "before you've looked at anything.",
            "Read the commands below before you open the folder in that tool.",
        ),
        (
            "custom_package_index",
            M,
            "Installs packages from outside the usual registries",
            "It installs packages straight from a link, a git repo or a different package "
            "index, which skips the usual registry's checks.",
            "Check each source below is one you trust.",
        ),
        (
            "background_service",
            M,
            "Installs a background service",
            "It sets up a service that keeps running in the background, which some tools need "
            "and others don't.",
            "Check that the tool is supposed to run in the background.",
        ),
        (
            "credential_read",
            M,
            "Reads your saved keys or passwords",
            "It reads files where keys, tokens or passwords are kept. lookfirst didn't see it "
            "send anything, but it's worth knowing why it needs them.",
            "Check why it needs these files before you run it.",
        ),
        (
            "outside_link",
            M,
            "Contains links that point outside its folder",
            "Some files are links to places outside the project, such as your home folder. "
            "lookfirst doesn't follow them.",
            "Check what the links point to before you open the project.",
        ),
        (
            "case_collision",
            M,
            "Has files whose names differ only in capital letters",
            "On a Mac only one of each pair survives, so what you see and what runs can differ.",
            "Check which version of each file you end up with.",
        ),
        # --- info ---
        (
            "known_installer",
            I,
            "Runs a well-known installer from its official site",
            "It downloads and runs an installer that lookfirst recognises, from its official "
            "address. lookfirst still read it with every rule.",
            "Nothing to do, unless you didn't expect it to install this.",
        ),
        (
            "own_remote_script",
            I,
            "Downloads and runs code from the project's own repo or site",
            "It downloads a script or program from the project's own repo, releases or site, "
            "and runs it.",
            "Nothing to do.",
        ),
        (
            "install_hook",
            I,
            "Runs its own code during install",
            "Installing it runs code from the project itself. That's common, and lookfirst "
            "checked the code it could find.",
            "Nothing to do, unless other findings point at this code.",
        ),
        (
            "adds_commands",
            I,
            "Adds commands to your computer",
            "Installing it adds new commands you can type in the terminal.",
            "Nothing to do.",
        ),
        (
            "shell_rc_change",
            I,
            "Changes your shell startup files",
            "It adds lines to files that run every time you open a terminal, usually to add a "
            "folder to your PATH.",
            "Nothing to do, unless you'd rather add these lines yourself.",
        ),
        (
            "unparsed",
            I,
            "Part of a script couldn't be fully read",
            "lookfirst couldn't make sense of some lines, so the rules may have missed "
            "something in them.",
            "Read the lines listed below yourself.",
        ),
    ),
    # Identity rules: {original}, {project}, {percent}, {days} and {commits} are filled in
    # with GitHub names and numbers, never with text from the target.
    **_rules(
        CheckKind.identity,
        (
            "likely_impersonation",
            C,
            "Matches impersonation patterns: looks like a copy of {original}",
            "Fake copies of popular projects are a common way to spread malware. This one "
            "resembles {original} in several of the ways copies do, listed below.",
            "Use the original, {original}, unless you know why this copy exists.",
        ),
        (
            "possible_impersonation",
            H,
            "May be a copy of {original}",
            "It resembles {original} in more than one of the ways fake copies do, though "
            "nothing here is dangerous on its own.",
            "Compare it with {original}, and prefer the original.",
        ),
        (
            "archive_password",
            H,
            "Gives a password for its download",
            "Password-protected archives hide what's inside from antivirus scans, which is "
            "why malware campaigns use them.",
            "Don't download or open it.",
        ),
        (
            "disable_protection",
            H,
            "Tells you to turn off your antivirus or Gatekeeper",
            "Real software doesn't ask you to turn off your computer's protection to install it.",
            "Don't follow these instructions, and don't run it.",
        ),
        (
            "claims_official_repo",
            H,
            "Says it comes from {original}, but isn't its official package",
            "The package names {original} as its source, but it isn't one of that "
            "project's official packages.",
            "Install {project}'s official package instead.",
        ),
        (
            "lookalike_installer_site",
            H,
            "Looks like {project}'s installer, but isn't from its official site",
            "The download address uses {project}'s name, but it isn't one of {project}'s "
            "official sites. Fake installers copy names this way.",
            "Get {project}'s installer from its official site.",
        ),
        (
            "name_lookalike",
            M,
            "Its name looks like {original}'s",
            "Copies of popular projects use the same or a look-alike name, so people find "
            "them instead of the original.",
            "Check this is the project you meant.",
        ),
        (
            "readme_copy",
            M,
            "Its README is {percent}% the same as {original}'s",
            "Impersonation campaigns copy a popular project's README into a new repo.",
            "Use the original repo unless you know why this copy exists.",
        ),
        (
            "new_account",
            M,
            "Made by an account that's {days} days old",
            "Fake copies are usually posted from brand-new accounts, while the project they "
            "copy is years old.",
            "Prefer the original project's own account.",
        ),
        (
            "young_repo",
            M,
            "Created {days} days ago, with {commits} commits",
            "Real projects build up history. Copies are usually uploaded in a few commits.",
            "Look at the project's history before you trust it.",
        ),
        (
            "suspicious_stars",
            M,
            "Its star count looks inflated",
            "Stars from brand-new or empty accounts, or far more than a project this young "
            "usually gets, are signs someone inflated it to look popular.",
            "Don't trust the star count. Check the project's history and owner instead.",
        ),
        (
            "extra_downloads",
            M,
            "Offers downloads {original} doesn't",
            "Its releases include programs or archives the original doesn't offer. Copies "
            "use downloads like these to deliver malware.",
            "Download only from the original project's releases.",
        ),
        (
            "offsite_download",
            M,
            "Sends you to a file-sharing site to download it",
            "Real projects publish downloads on GitHub or their own site. File-sharing links "
            "are hard to trace and easy to swap.",
            "Download from the project's GitHub releases or official site instead.",
        ),
        (
            "fork_changed_install",
            M,
            "A fork of {original} with different install steps",
            "It's a fork of {original}, and it changed files that run when you install it.",
            "Read what the fork changed before using it instead of {original}.",
        ),
        (
            "lookalike_installer_link",
            M,
            "Uses {project}'s name, but isn't from {project}'s own repo",
            "The script comes from a repo named after {project} that isn't {project}'s own.",
            "Check where the script really comes from.",
        ),
    ),
    **_rules(
        CheckKind.agent_config,
        (
            "auto_approve",
            H,
            "Pre-approves commands for AI agents",
            "It ships settings that let an AI agent run commands without asking you first.",
            "Don't let an agent work in this folder with these settings. Remove them first.",
        ),
        (
            "redirects_api",
            H,
            "Sends your AI agent's traffic to another server",
            "It ships settings that point your AI agent at a different server, which could "
            "read your requests and your API key.",
            "Remove these settings before using an AI agent in this folder.",
        ),
        (
            "claude_hooks",
            M,
            "Ships Claude Code hooks that run commands",
            "Claude Code runs these commands automatically while it works in this folder, "
            "once you trust the folder.",
            "Read the commands below before trusting the folder in Claude Code.",
        ),
        (
            "mcp_servers",
            M,
            "Adds MCP servers that start programs",
            "AI agents that read this folder's MCP settings can start these programs.",
            "Check each server below before letting an agent use them.",
        ),
        (
            "agent_instructions",
            I,
            "Ships instructions for AI agents",
            "It includes files that AI coding agents read as instructions. That's common, and "
            "lookfirst checked them for hidden or harmful instructions.",
            "Nothing to do, unless other findings point at these files.",
        ),
    ),
    **_rules(
        CheckKind.injection,
        (
            "hidden_instructions",
            H,
            "Hides instructions for AI agents",
            "It contains text people can't easily see, such as HTML comments, image "
            "descriptions or invisible characters, with instructions aimed at AI agents.",
            "Don't let an AI agent work with this project until you've read the text below.",
        ),
        (
            "agent_directed",
            H,
            "Tells AI agents to run commands or ignore their instructions",
            "It contains text written to steer AI agents: telling them to run commands, skip "
            "checks, or keep things from you.",
            "Don't let an AI agent act on this project. lookfirst never follows these "
            "instructions.",
        ),
        (
            "trojan_source",
            H,
            "Code contains characters that make it read differently than it runs",
            "Direction-changing characters can make code look harmless on screen while it "
            "does something else when it runs.",
            "Don't run this code until the characters are removed.",
        ),
        (
            "invisible_characters",
            M,
            "Contains invisible characters",
            "Invisible characters can hide text from people while machines still read it.",
            "Check the places listed below.",
        ),
    ),
}


def rule(rule_id: str) -> Rule:
    return RULES[rule_id]
