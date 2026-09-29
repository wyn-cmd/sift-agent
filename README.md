# sift-agent

sift-agent is a small memory forensics agent. It gives a Gemini model four read-only Volatility 3 plugins, lets it investigate a Windows memory image on its own, and then checks every claim it makes against a log of what the tools really returned. It is a research prototype, not a production tool.

## What it does

The model may call only windows.info, windows.pslist, windows.netscan and windows.cmdline. Each call runs Volatility 3 against one evidence file that is never modified and never executed. The raw plugin output is capped and ranked before the model sees it, wrapped in an untrusted-data marker, and stored in full on disk. When the model finishes it must return a JSON list of findings. Each finding carries a claim, the tool call ids it relies on and a verbatim excerpt. The report marks a finding as confirmed only if the cited ids exist and every excerpt line appears word for word in a cited raw output. Anything else is downgraded to an unconfirmed inference, and a model that answers in plain prose is kept as a single unconfirmed inference rather than dropped.

## Design choices

Evidence access is locked to one directory (SIFT_EVIDENCE_DIR, default ./evidence) and path traversal is rejected. Tool names are checked against a fixed allow list, and a call to anything else is refused and logged. Tool output is treated as data, so text inside a memory image that tries to give the model instructions is only ever an artifact. If the model tries to stop before it has run all four plugins, the loop sends it back up to three times, and the report lists any plugin that never ran. Large outputs are cut to 150 rows using a generic suspicion score (processes outside a list of normal system names, commonly abused binaries, unusual ports). The score does not know about any particular sample, and the report says when a plugin was truncated.

## Audit log

Every tool call is written to runs/audit.jsonl with its real arguments, the SHA-256 and length of the raw output, the hash of the capped output the model saw, and a pointer to runs/raw/<call id>.txt, which holds the complete raw output. Refused calls, API failures and the model's raw final answer are logged as events.

## Setup

    python3 -m venv .venv
    .venv/bin/pip install -r requirements.txt
    export GEMINI_API_KEY=your-key
    mkdir -p evidence && cp /path/to/image.raw evidence/
    .venv/bin/python -m sift_agent run --evidence image.raw --model gemini-3.5-flash-lite

The key is read only from the environment and is never written to disk. Volatility 3 installs a command called vol. On the first run against a Windows image it downloads the matching symbol table, which took about 90 seconds and needs internet access. A built-in rate limiter keeps requests under the free tier limits, and a run is capped at 15 tool calls.

## Tests

    .venv/bin/python -m pytest -q

The 26 tests use fake models and fake Volatility runners, so they need neither a key nor an image. They cover the guardrails, the ranking, the audit log, the report checks, the early-stop nudge, the Gemini message conversion and a prompt injection attempt.

## What has been tested for real

The agent has been run about a dozen times on MemLabs Lab 4 (github.com/stuxnet999/MemLabs), a public Windows 7 SP1 x64 image, with gemini-3.5-flash-lite. Every run called all four plugins, and the findings I checked against fresh Volatility output were correct. Runs typically produced two or three confirmed findings such as process ids and command lines. One run produced no confirmed findings and could not be reproduced.

## Limitations

The agent reports facts it can read from tables, such as which process has which command line. It has not been shown to spot a real intrusion. Lab 4 is about a deleted file, which none of these four plugins can find, and its write-up is public, so a model may have seen it. Only Windows 7 and later images have been tried, and Windows XP images are not expected to work with windows.netscan. The excerpt check proves a quote is real, not that the conclusion drawn from it is right. The memory images themselves are not in this repository.
