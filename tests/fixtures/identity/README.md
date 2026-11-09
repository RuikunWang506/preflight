# Identity fixtures: made-up lookalike pairs

Each `pairs/*.json` describes a **made-up** repo and what lookfirst must conclude about it. The originals
(ollama/ollama, ggml-org/llama.cpp, yt-dlp/yt-dlp, openai/codex) are real and come from recordings in
`tests/fixtures/http/identity_originals`; the copies only exist in these files.

- Every made-up owner name was checked to not exist on GitHub on 9 Nov 2026, so no test points at a real
  person or organization. Two names first considered (`anthroplcs`, `ggmI-org`) do exist and weren't used.
- A copy's README is built at test time from the original's recorded README, plus the text in `append`.
- `expect` is what lookfirst must find: the status, the original it names, and the findings.
