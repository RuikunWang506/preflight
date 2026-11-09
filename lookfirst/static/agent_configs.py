"""Agent settings shipped in the repo (SPEC section 6, first half): Claude Code settings
and hooks, MCP servers, VS Code agent settings, and instruction files for AI agents."""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any

import yaml

from lookfirst.core.urls import url_host
from lookfirst.static import jsonc
from lookfirst.static.files import read_text, walk
from lookfirst.static.model import Collector, Origin, Snippet
from lookfirst.static.readme import _COMMANDS
from lookfirst.static.shell_rules import ShellAnalyzer

_CLAUDE_SETTINGS = (".claude/settings.json", ".claude/settings.local.json")
_CLAUDE_COMMAND_KEYS = (
    "apiKeyHelper",
    "awsAuthRefresh",
    "awsCredentialExport",
    "otelHeadersHelper",
)
_MCP_FILES = (
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".gemini/settings.json",
    ".roo/mcp.json",
)
_INSTRUCTION_FILES = (
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    ".github/copilot-instructions.md",
    ".windsurfrules",
    ".clinerules",
    ".cursorrules",
)
_INSTRUCTION_DIRS = (
    ".claude/commands",
    ".claude/agents",
    ".claude/skills",
    ".cursor/rules",
    ".github/instructions",
)
_REDIRECT_ENV = (
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_API_URL",
    "OPENAI_BASE_URL",
    "OPENAI_API_BASE",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "ALL_PROXY",
    "https_proxy",
    "http_proxy",
    "NODE_EXTRA_CA_CERTS",
)
_OFFICIAL_API_HOSTS = ("anthropic.com", "openai.com")
_BROAD_BASH = re.compile(
    r"^Bash(?:\(\s*(?:\*|:\*|\*:\*|(?:sudo|curl|wget|bash|sh|zsh|eval|python3?|node|rm)\b[^)]*)\s*\))?$"
)
_VSCODE_AUTO_APPROVE = (
    "chat.tools.autoApprove",
    "chat.tools.global.autoApprove",
    "chat.agent.autoApprove",
    "github.copilot.chat.agent.autoApprove",
)
_FENCE = re.compile(r"^```[ \t]*(\w*)[^\n]*\n(.*?)^```", re.MULTILINE | re.DOTALL)
_FRONTMATTER = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)


def _line_of(text: str, needle: str) -> int:
    at = text.find(needle)
    return 1 if at < 0 else text.count("\n", 0, at) + 1


def _load(root: Path, rel: str, out: Collector) -> tuple[str, Any] | None:
    text = read_text(root, rel)
    if text is None:
        return None
    try:
        return text, jsonc.loads(text)
    except ValueError:
        out.add("install_path.unparsed", path=rel)
        return None


def _claude_settings(root: Path, analyzer: ShellAnalyzer, out: Collector) -> None:
    for rel in _CLAUDE_SETTINGS:
        loaded = _load(root, rel, out)
        if loaded is None or not isinstance(loaded[1], dict):
            continue
        text, data = loaded
        runs = "while Claude Code works in this folder"
        hooks = data.get("hooks") if isinstance(data.get("hooks"), dict) else {}
        for event, groups in hooks.items():
            for group in groups if isinstance(groups, list) else []:
                for hook in (group.get("hooks") or []) if isinstance(group, dict) else []:
                    command = hook.get("command") if isinstance(hook, dict) else None
                    if isinstance(command, str):
                        line = _line_of(text, command[:40])
                        out.add(
                            "agent_config.claude_hooks",
                            path=rel,
                            line=line,
                            excerpt=command,
                            runs=f"{runs} ({event})",
                        )
                        analyzer.analyze(Snippet(command, Origin(rel, line, f"{runs} ({event})")))
        status = data.get("statusLine")
        commands = [(k, data.get(k)) for k in _CLAUDE_COMMAND_KEYS]
        if isinstance(status, dict):
            commands.append(("statusLine", status.get("command")))
        for key, command in commands:
            if isinstance(command, str) and command.strip():
                line = _line_of(text, f'"{key}"')
                out.add(
                    "agent_config.claude_hooks",
                    path=rel,
                    line=line,
                    excerpt=f"{key}: {command}",
                    runs=runs,
                )
                analyzer.analyze(Snippet(command, Origin(rel, line, runs)))
        permissions = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
        for entry in permissions.get("allow") or []:
            if isinstance(entry, str) and _BROAD_BASH.match(entry.strip()):
                out.add(
                    "agent_config.auto_approve",
                    path=rel,
                    line=_line_of(text, entry),
                    excerpt=f"allow: {entry}",
                    data={"what": "lets Claude Code run these commands without asking"},
                )
        if permissions.get("defaultMode") == "bypassPermissions":
            out.add(
                "agent_config.auto_approve",
                path=rel,
                line=_line_of(text, "defaultMode"),
                excerpt="defaultMode: bypassPermissions",
                data={"what": "turns off Claude Code's permission prompts"},
            )
        if data.get("enableAllProjectMcpServers") is True:
            out.add(
                "agent_config.auto_approve",
                path=rel,
                line=_line_of(text, "enableAllProjectMcpServers"),
                excerpt="enableAllProjectMcpServers: true",
                data={"what": "starts every MCP server in .mcp.json without asking"},
            )
        env = data.get("env") if isinstance(data.get("env"), dict) else {}
        for key, value in env.items():
            if key in _REDIRECT_ENV and isinstance(value, str):
                host = url_host(value)
                if not any(host == h or host.endswith("." + h) for h in _OFFICIAL_API_HOSTS):
                    out.add(
                        "agent_config.redirects_api",
                        path=rel,
                        line=_line_of(text, key),
                        excerpt=f"{key}={value}",
                    )


def _mcp_servers(root: Path, analyzer: ShellAnalyzer, out: Collector) -> None:
    for rel in _MCP_FILES:
        loaded = _load(root, rel, out)
        if loaded is None or not isinstance(loaded[1], dict):
            continue
        text, data = loaded
        servers = data.get("mcpServers") or data.get("servers") or {}
        for name, server in servers.items() if isinstance(servers, dict) else []:
            if not isinstance(server, dict):
                continue
            line = _line_of(text, f'"{name}"')
            runs = "when an AI agent starts this MCP server"
            command = server.get("command")
            if isinstance(command, str):
                args = (
                    [a for a in server.get("args", []) if isinstance(a, str)]
                    if isinstance(server.get("args"), list)
                    else []
                )
                full = shlex.join([command, *args])
                out.add(
                    "agent_config.mcp_servers",
                    path=rel,
                    line=line,
                    excerpt=f"{name}: {full}",
                    runs=runs,
                )
                analyzer.analyze(Snippet(full, Origin(rel, line, runs)))
            elif isinstance(server.get("url"), str):
                out.add(
                    "agent_config.mcp_servers",
                    path=rel,
                    line=line,
                    excerpt=f"{name}: {server['url']}",
                    runs="when an AI agent connects to this MCP server",
                )
            env = server.get("env") if isinstance(server.get("env"), dict) else {}
            for key, value in env.items():
                if key in _REDIRECT_ENV and isinstance(value, str):
                    out.add(
                        "agent_config.redirects_api",
                        path=rel,
                        line=_line_of(text, key),
                        excerpt=f"{key}={value}",
                    )


def _vscode_settings(root: Path, out: Collector) -> None:
    rel = ".vscode/settings.json"
    loaded = _load(root, rel, out)
    if loaded is None or not isinstance(loaded[1], dict):
        return
    text, data = loaded
    for key in _VSCODE_AUTO_APPROVE:
        if data.get(key) is True:
            out.add(
                "agent_config.auto_approve",
                path=rel,
                line=_line_of(text, key),
                excerpt=f"{key}: true",
                data={"what": "lets the editor's AI agent run tools without asking"},
            )
    terminal = data.get("chat.tools.terminal.autoApprove")
    if isinstance(terminal, dict) and any(
        v is True and (k in ("/.*/", "*", ".*") or k.startswith("/")) for k, v in terminal.items()
    ):
        out.add(
            "agent_config.auto_approve",
            path=rel,
            line=_line_of(text, "chat.tools.terminal.autoApprove"),
            excerpt="chat.tools.terminal.autoApprove",
            data={"what": "lets the editor's AI agent run terminal commands without asking"},
        )
    if data.get("task.allowAutomaticTasks") == "on":
        out.add(
            "agent_config.auto_approve",
            path=rel,
            line=_line_of(text, "task.allowAutomaticTasks"),
            excerpt='task.allowAutomaticTasks: "on"',
            data={"what": "runs this folder's tasks on open without asking"},
        )


def instruction_files(root: Path) -> list[str]:
    found = [rel for rel in _INSTRUCTION_FILES if read_text(root, rel) is not None]
    for folder in _INSTRUCTION_DIRS:
        path = root / folder
        if path.is_dir() and not path.is_symlink():
            found += [
                f"{folder}/{p}" for p in walk(path, max_files=200) if p.endswith((".md", ".mdc"))
            ]
    found += [
        p
        for p in walk(root, max_files=20_000)
        if p.rsplit("/", 1)[-1] == "SKILL.md" and p not in found
    ][:100]
    return list(dict.fromkeys(found))


def _instructions(root: Path, files: list[str], analyzer: ShellAnalyzer, out: Collector) -> None:
    for rel in files:
        text = read_text(root, rel)
        if text is None:
            continue
        out.add("agent_config.agent_instructions", path=rel, group="instruction files")
        runs = "if an AI agent follows these instructions"
        front = _FRONTMATTER.match(text)
        if front:
            try:
                meta = yaml.safe_load(front.group(1))
            except yaml.YAMLError:
                meta = None
            tools = meta.get("allowed-tools") if isinstance(meta, dict) else None
            entries = (
                re.split(r",\s*|\s+(?=[A-Z])", tools)
                if isinstance(tools, str)
                else (tools if isinstance(tools, list) else [])
            )
            for entry in entries:
                if isinstance(entry, str) and _BROAD_BASH.match(entry.strip()):
                    out.add(
                        "agent_config.auto_approve",
                        path=rel,
                        line=_line_of(text, "allowed-tools"),
                        excerpt=f"allowed-tools: {entry.strip()}",
                        data={"what": "lets an AI agent run these commands without asking"},
                    )
        for m in _FENCE.finditer(text):
            lang = m.group(1).lower()
            body = m.group(2)
            if lang in ("sh", "bash", "shell", "zsh", "console") or (
                lang == "" and any(_COMMANDS.match(x) for x in body.splitlines())
            ):
                analyzer.analyze(
                    Snippet(
                        body,
                        Origin(rel, text.count("\n", 0, m.start(2)) + 1, runs),
                        report_unparsed=False,
                    )
                )


def check_agent_configs(root: Path, analyzer: ShellAnalyzer, out: Collector) -> list[str]:
    """Run the agent-settings check. Returns the instruction files it found."""
    _claude_settings(root, analyzer, out)
    _mcp_servers(root, analyzer, out)
    _vscode_settings(root, out)
    files = instruction_files(root)
    _instructions(root, files, analyzer, out)
    return files
