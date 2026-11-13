# How the demo images were made

All three come from lookfirst's real output, made by `scripts/make_demo_images.py`:

```bash
uv run python scripts/make_demo_images.py               # all three; the sandbox one needs Docker
uv run python scripts/make_demo_images.py --no-sandbox  # just the hook and lookalike images
```

| Image | What it shows | How it was made |
| --- | --- | --- |
| `hook.svg` | The hook's answer to `npm install` in a freshly cloned repo | A fake repo, csvplot, built from the `credential_theft_javascript` test fixture and cloned into a temporary folder. The hook gets the same JSON Claude Code sends it. The folder's path is shown as `~/code` |
| `sandbox.svg` | `lookfirst check csvplot --sandbox` on the same repo | A real dry run in the Docker sandbox. The install reads the decoy npm token there |
| `lookalike.svg` | The identity check on a copy of Ollama | A made-up pair from the test suite (`tests/fixtures/identity/pairs/copied_readme_new_account.json`), served from recordings, so no GitHub account is involved. The account name `0llama-dev` didn't exist on GitHub when the image was made |

Nothing from the fake repo runs on the computer making the images: the hook only reads it, and the sandbox runs it inside Docker. The fixture's script starts with a guard that only creates `~/LOOKFIRST_HOST_CANARY` and stops when it's outside the sandbox.

**Not shown:** a recording of the hook stopping a live Claude Code session. In five tries with current Claude models, the agent read the install script before running it and refused on its own, so the hook had nothing to stop (`docs/PLAN-v0.1.md`, M6 and M7).
