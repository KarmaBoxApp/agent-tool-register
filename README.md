# agent-tool-register

A small register for scripts that AI coding agents wrote for people who aren't engineers. You list the scripts people keep running. The tool reads each one (it never runs it) and tells you which ones have crossed a line where somebody who can read code should own them.

One Python file, standard library only, Python 3.9 or later.

## Why it exists

In October 2026 Goldman Sachs updated internal guidance so that Claude Code and GitHub's coding tools were limited to engineers, according to Bloomberg's report of 2 November 2026. In July the bank's CIO had praised traders and bankers for "vibe coding" tools and handing them to one of the firm's 12,000 engineers to improve. So the bank went from encouraging business staff to build tools to taking the coding agents back, in about three months.

Our guide on the subject argues for a middle path. Business staff keep the agent for personal work, register any script they run more than a few times, and a script moves to review when one of five things happens:

| Trigger | What it means | How this tool finds it |
|---|---|---|
| `second_user` | two or more people run it regularly | you declare users with `--user` |
| `sensitive_data` | it names paths to client, HR, key or other sensitive files | static scan against globs you can extend |
| `acts_on_systems` | it can reach the network, send e-mail, call a database or run other programs | static scan of imports and calls (`ast`) |
| `stored_credentials` | key-shaped strings or hard-coded passwords sit in the file | regex and assignment checks; the value is never printed or saved |
| `quantitative` | people make decisions from its numbers | you declare it with `--quantitative`; numeric imports produce a hint |

Hitting a trigger doesn't mean the script is bad. It means the script now needs an owner who can read it.

## Quickstart

No install. Copy `agent_tool_register.py` anywhere.

```bash
# look at a folder without changing anything
python3 agent_tool_register.py scan path/to/scripts

# register one, with the person who answers for it
python3 agent_tool_register.py add path/to/scripts/flows.py --owner dana --purpose "morning client flow note"

# someone else starts using it, and the desk acts on its numbers
python3 agent_tool_register.py add path/to/scripts/flows.py --user lee --quantitative

# see where things stand, and write a report for the reviewer
python3 agent_tool_register.py list
python3 agent_tool_register.py report --out review.md
```

The register is a JSON file, `./agent-tools.json` by default. Use `--registry FILE` or set `AGENT_TOOL_REGISTRY` to keep a shared one.

Other options worth knowing:

- `add --sensitive-glob "*/deals/*"` adds a glob to the register for every later scan.
- `add --reviewed-by sam` records a review. The script shows as `reviewed` until a trigger appears that the review didn't cover, then it goes back to `needs review`.
- `scan --json` prints machine-readable findings. `scan --fail-on-trigger` exits with code 2 if any file has a trigger, so you can put it in CI.

## What we saw

Run on 9 November 2026 on an Apple M4 Mac mini (macOS 15.6.1, Python 3.9.6) against the three placeholder scripts in `examples/`:

```
$ python3 agent_tool_register.py scan examples
examples/client_flow_summary.py  [not registered]
  trigger: touches sensitive data paths
  trigger: acts on other systems
  trigger: stored credentials
    line 4: import urllib.request (network)
    line 14: urllib.request.urlopen() (network)
    line 8: path matches *client*
    line 6: hard-coded api_token (value not shown)
examples/shock_estimate.py  [not registered]
  no triggers found
    hint: imports numeric libraries; declare with add --quantitative if people act on its numbers
examples/tidy_notes.py  [not registered]
  no triggers found
3 file(s) scanned, 1 with triggers

$ python3 agent_tool_register.py add examples/shock_estimate.py --user lee --quantitative
shock_estimate: needs review
  trigger: a second regular user
  trigger: produces quantitative estimates

$ python3 agent_tool_register.py list
client_flow_summary  needs review  lee             sensitive_data, acts_on_systems, stored_credentials
shock_estimate       needs review  dana            second_user, quantitative
tidy_notes           personal      dana            -
```

`shock_estimate.py` shows the gap in the static scan. It estimates how positions move under a rate shock, which is exactly the kind of script a model risk team would want to see, and the scan alone can't tell. It only notices `import pandas` and suggests a declaration. A person has to say that others act on the numbers.

The test suite (19 tests, `python3 -m unittest -v test_agent_tool_register.py`) passed in 0.016 s on the same machine.

## Limits

Read these before trusting a clean result.

- It reads code and never runs it. Dynamic imports (`importlib.import_module("req" + "uests")`), `eval`, code downloaded at run time and anything in a library the script calls are all invisible. One test in the suite exists to prove the dynamic-import miss is still there.
- Only Python gets a proper parse. Shell, JavaScript, Ruby and PowerShell files get text checks for `curl`, `wget`, `ssh`, `fetch(` and similar, plus credential and path patterns.
- Sensitive paths are matched only when they appear as literal strings. A path built from variables or read from a config file won't match.
- Credential patterns cover common shapes (OpenAI-style `sk-`, AWS `AKIA`, GitHub `ghp_`, Slack `xox`, Google `AIza`, private key blocks, and variables or arguments named like `password` or `api_key` given a literal string). Encoded or split secrets get through.
- Users and the quantitative flag are self-declared. The register is only as honest as the people filling it in.
- It does not decide who may run an agent, review the code, or tell you whether a script falls under a regulation. It produces a short list for someone who can.

## Background

The longer guide this tool comes from covers access tiers by role, what regulators already say, and the promotion path from personal script to shared tool: [AI coding agents for non-engineers](https://www.karmaboxai.com/en/concept/factory/resources/ai-coding-agents-for-non-engineers) (this page goes live after 9 November 2026; until then a related piece on [AI agent sprawl vs control](https://www.karmaboxai.com/en/concept/factory/resources/ai-agent-sprawl-vs-control-2026) is up).

Maintained by [Karma Box](https://www.karmaboxai.com/en/concept/factory/product). The tool doesn't depend on any Karma Box product and works with scripts from any coding agent.

## License

MIT. See [LICENSE](LICENSE).
