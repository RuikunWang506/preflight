# Install-path fixtures

Harmless fakes written for lookfirst's tests. lookfirst only **reads** them.

- Never run anything here. Each script starts with a guard: outside the lookfirst sandbox it only creates
  `~/LOOKFIRST_HOST_CANARY` and exits, and the test suite fails if that file exists.
- Network sends go only to `127.0.0.1:8765`, the sandbox's local test server.
- Files that tools load automatically are stored under neutral names, so no editor or AI agent working in this
  repo loads them: a `dot_` prefix means a leading `.` (`dot_claude/` is `.claude/`), and a `.fixture` suffix is
  dropped (`AGENTS.md.fixture` is `AGENTS.md`). Tests rebuild the real names in a temporary folder.
- `remote/` holds what a fake remote URL serves; `case.toml` says what lookfirst must find.
