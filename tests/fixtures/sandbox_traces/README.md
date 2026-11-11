# Recorded sandbox traces

strace output from real dry runs of the fixtures in `../sandbox/`, recorded on
11 Nov 2026 inside the lookfirst sandbox (arm64). The parser and the findings are tested
against them without Docker.

They hold only paths, program names and arguments: strace isn't asked to show what
programs read or write, so no decoy secret appears in them.
