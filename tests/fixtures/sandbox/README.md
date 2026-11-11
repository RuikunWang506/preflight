# Sandbox fixtures

Harmless fakes for the sandbox dry run (SPEC section 11). They run **only inside the
lookfirst sandbox**, through the real runner, in tests marked `sandbox` (opt in with
`LOOKFIRST_SANDBOX_TESTS=1`; CI runs them on Linux).

- Never run anything here yourself. Each script starts with a guard: outside the sandbox
  it only creates `~/LOOKFIRST_HOST_CANARY` and exits, and the test suite fails if that
  file exists.
- What they read is the sandbox's decoy home, made fresh for each run.
- Network sends go to `*.example.net`, names reserved so they never belong to a real
  site. The sandbox's proxy answers them itself.
- `case.toml` says what the dry run must find, and the verdict.
