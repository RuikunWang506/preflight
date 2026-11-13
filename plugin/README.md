# lookfirst plugin for Claude Code

Checks code from strangers before your agent runs it. It has three parts:

- **A hook** that runs before every shell command. Most commands pass straight through in a few
  milliseconds. Commands that install something or run downloaded code are checked first:
  - **Don't run:** the command is blocked, and Claude gets the evidence to show you.
  - **Caution:** you get a permission prompt that lists the findings.
  - **Looks OK:** nothing changes.
- **An MCP server** with two tools: `lookfirst_check` and `lookfirst_explain`.
- **A skill** that tells Claude when to check and how to act on the verdict.

lookfirst lowers risk; it doesn't guarantee safety.

## Install

1. Install the `lookfirst` command. The plugin runs it but doesn't include it.

   ```bash
   uv tool install lookfirst
   ```

   Until lookfirst is on PyPI, install it from a copy of this repository instead:
   `uv tool install --editable <path to the repo>`.

2. Add this repository as a plugin marketplace, then install the plugin. In Claude Code:

   ```text
   /plugin marketplace add <path or GitHub address of this repository>
   /plugin install lookfirst@lookfirst
   ```

   Or from a terminal: `claude plugin marketplace add <path>`, then
   `claude plugin install lookfirst@lookfirst`.

## How it behaves

- If the hook itself fails or takes longer than 20 seconds, the command goes ahead with a warning.
  A broken check never stops your agent from working.
- If lookfirst can't read what a command would run (for example, a script at a private address),
  you're asked before it runs.
- If the `lookfirst` command isn't installed, commands go ahead unchecked and you see a reminder,
  at most once a day.
- Claude Code also offers `"onFailure": "block"` for hooks. Add it to the hook in your own settings
  if you'd rather block commands when the check can't run.
