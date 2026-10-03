# sift-agent

sift-agent is a small memory forensics agent. It gives a Gemini model a small set of read-only Volatility 3 plugins (four by default, eight with the extended allowlist), lets it investigate a Windows memory image on its own, and then checks every claim it makes against a log of what the tools really returned. It is a research prototype, not a production tool.

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

The key is read only from the environment and is never written to disk. Volatility 3 installs a command called vol. On the first run against a Windows image it downloads the matching symbol table, which took about a minute on my connection and needs internet access. The built-in rate limiter defaults to 15 requests per minute, 250,000 tokens per minute and 500 requests per day, which are the free tier limits I observed on my own account at build time. Google does not publish these as a guarantee, so the agent also waits and retries when the API returns a real 429, and it stops cleanly when the daily count is reached. A run is capped at 15 tool calls by default; pass `--max-calls N` to change it, and `--max-nudges N` to change how often a model that stops early is sent back.

## Tests

    .venv/bin/python -m pytest -q

The 120 tests use fake models, fake Volatility runners and synthetic run directories, so they need neither a key nor an image. They cover the guardrails, the ranking, the audit log, the report checks, the early-stop nudge, the Gemini message conversion, a prompt injection attempt, the tool call cap, and every offline command against a saved run, including the HTML page and the handover bundle.

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

## Extra commands

`python -m sift_agent replay --runs runs` rebuilds the report from a saved run with no model, Volatility or network, and re-validates every finding against the raw outputs. `python -m sift_agent verify-audit --runs runs` re-hashes every raw output against the audit log and exits non-zero on a mismatch or a missing file; every log line also stores the hash of the previous line and its own hash, so an edited, deleted, inserted or reordered line is reported too. Logs written before the chain existed are reported as unchained, not failed. The chain proves the log was not changed after it was written, but someone who rewrites every line and every hash from the start would not be caught. `run --dump-hash` dumps the most suspicious processes with windows.dumpfiles (falling back to windows.pslist --dump), SHA-256 hashes each process's executable image and lists them in the report, and `--vt` also looks each hash up on VirusTotal using VT_API_KEY (free tier, one request every 15.5 seconds). Images rebuilt from memory can differ from the file on disk where pages were never loaded, so a VirusTotal miss proves nothing. Each finding carries a confidence derived from the evidence: high when a verified claim cites two or more different plugins, medium for one plugin, low for anything that failed verification.

`python -m sift_agent timeline --runs runs --out timeline.html` writes a static HTML page with one row per tool call and the report claims that cite it. `python -m sift_agent compare runs-a runs-b` diffs the confirmed claims of two saved runs, for example from two different models, and lists disagreements. The approved plugin list is in sift_agent/allowlist.json (or the file named by SIFT_ALLOWLIST), and only windows.* names are accepted. `run --runs DIR` chooses where the audit log, raw outputs and dumps are written.

The default allowlist is the four plugins the project was specified against. `SIFT_ALLOWLIST=sift_agent/allowlist-extended.json` adds windows.psscan, windows.psxview, windows.netstat and windows.malfind, which cover hidden processes, connections on newer Windows and injected code. The system prompt and tool schemas follow whichever allowlist is loaded. `run --yara RULES` scans the dumped process images with a YARA rules file or directory (sift_agent/rules has two small generic rules) and needs the optional yara-python package. A run prints the audit log head hash on stderr; keep it somewhere outside the run directory and pass it to `verify-audit --expect-head HASH` to detect a rewrite of the whole chain.

A second case was run for real on MemLabs Lab 4 (Windows 7 SP1 x64, 1 GB) with the extended allowlist. It used 8 of 15 calls, ran all eight plugins, and flagged DumpIt.exe, the memory acquisition tool, as anomalous. This is one run with no accuracy scoring, so treat it as a smoke test and not a result.


## Offline analysis commands

These work on a saved run directory with no model, Volatility or network. `tree` draws the process tree from windows.pslist and stars processes whose parent is missing. `anomalies` applies fixed rules (wrong parent for system processes, duplicate singletons, lookalike names, system processes outside session 0, a child created before its parent); the output is a list of leads, not verdicts. `iocs --format text|json|csv` lists public IP addresses, URLs, domains and hashes found in the raw outputs, skipping private addresses and PDB symbol GUIDs. `stats` summarises calls, raw output sizes and duration. `export-json` prints the validated findings and call hashes as JSON. `replay` now takes `--out FILE`, `--redact` (masks IP addresses, user names in profile paths and UNC host names) and `--extras` (appends the tree and anomalies). `doctor` checks Python, Volatility, the API key, the Gemini library, the evidence directory and the allowlist, and exits non-zero if a required item is missing. `hash-evidence --evidence FILE` prints the SHA-256 of the image so a report can name exactly what it describes.

`netmap` groups windows.netscan and windows.netstat rows by owning process and marks external remote addresses. `cmdflags` flags unusual windows.cmdline entries (encoded PowerShell, hidden windows, download cradles, script host binaries, writable paths, URLs); these are leads, and legitimate software can match. `--version` prints the package version, and CHANGELOG.md lists what changed in each release.

Seven more commands work the same way, reading a saved run with no model, no Volatility and no network. `search PATTERN` matches a regular expression across the raw outputs and takes `--plugin` to narrow it, `-i`, `-C N` for context lines, `--max-hits` and `--json`. `risk` fuses the anomaly rules, the flagged command lines, the public connections and the non routine listening ports into one score per process, so the top of the list is where to read first; the weights are fixed by design and the output says the table is leads and not a verdict. `injection` reports lines in plugin output that read like instructions aimed at the model, and the same check now runs inside the agent loop, where it puts a notice in front of the message the model sees and logs an event for the report. `stix` writes a STIX 2.1 bundle of the indicators with deterministic ids, so the same run always produces the same bundle. `sigma` turns the flagged command lines into Sigma rules as YAML text with no extra dependency, one rule per distinct flag, capped at 20. `html-report --out FILE` writes one self contained dark themed HTML page with the run summary, the findings coloured by status, and every section above inside it. `bundle --out FILE.zip` packages a run with a hash manifest of every file, the audit head hash and the optional evidence image hash, so the recipient can tell whether anything changed since it was handed over.
