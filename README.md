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

The key is read only from the environment and is never written to disk. Volatility 3 installs a command called vol. On the first run against a Windows image it downloads the matching symbol table, which took about a minute on my connection and needs internet access. The built-in rate limiter defaults to 15 requests per minute, 250,000 tokens per minute and 500 requests per day, which are the free tier limits I observed on my own account at build time. Google does not publish these as a guarantee, so the agent also waits and retries when the API returns a real 429, and it stops cleanly when the daily count is reached. A run is capped at 15 tool calls.

## Tests

    .venv/bin/python -m pytest -q

The 34 tests use fake models and fake Volatility runners, so they need neither a key nor an image. They cover the guardrails, the ranking, the audit log, the report checks, the early-stop nudge, the Gemini message conversion and a prompt injection attempt.

## What has been tested for real

The main evaluation is on Cridex (cridex.vmem, Windows XP SP3, 536,870,912 bytes), the sample the project was specified against. Across three runs with gemini-3.5-flash-lite the agent always found reader_sl.exe (PID 1640) and its command line, and none of the 11 confirmed claims was contradicted by fresh Volatility output. It never called the process suspicious, and it never found the port 8080 connection, because windows.netscan does not support Windows XP in Volatility 3 and the run reports that failure honestly. The full comparison against the ground truth is in accuracy.md. I also ran the agent more than a dozen times on MemLabs Lab 4 (github.com/stuxnet999/MemLabs), a Windows 7 SP1 x64 image where all four plugins work, and it reported process ids and command lines that matched the Volatility output.

A complete real run, with its audit log and every raw plugin output, is committed under examples/cridex-run/ (local paths removed). The audit log holds one line per tool call, for example the pslist call:

    {"tool": "windows.pslist", "args": {}, "raw_output_sha256": "e6c729c7...", "raw_output_len": 1621, "raw_output_file": "raw/f454c769-....txt", ...}

The matching report lists each finding with its status, call ids and excerpt:

    - Claim: Process reader_sl.exe is running with PID 1640 and path C:\Program Files\Adobe\Reader 9.0\Reader\Reader_sl.exe.
      Status: confirmed
      Tool Call IDs: f454c769-702a-4583-80ae-c2c2e62c1422, cc42b56c-0249-4c4d-b377-8969d8328597
      Excerpt: 1640 1484 reader_sl.exe 0x81e7bda0 5 39 0 False 2012-07-22 02:42:36.000000 UTC N/A Disabled

## Limitations

This is a training and portfolio exercise against public samples with known ground truth, not production DFIR tooling, and it does not claim to detect malware in general. It triages one memory image with four read-only plugins under a citation constraint, and it does not replace an analyst. The evidence is only read and the malware is never executed, but for a real sample you should still work in an isolated VM with the network disabled. On Cridex the agent read the tables correctly but did not flag the malicious process, and on Windows XP images windows.netscan fails, so no network findings are possible with these four plugins. The excerpt check proves a quote is real, not that the conclusion drawn from it is right. The Lab 4 write-up is public, so a model may have seen it. Only three runs were made on Cridex, and the memory images are not in this repository.

## Licence

MIT, see LICENSE. Volatility 3 has its own licence (the Volatility Software License) and is installed from PyPI and called only as a subprocess, so none of its code is included here.
