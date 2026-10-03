# Changelog

## 0.3.0

Added seven offline commands that read a saved run and need no model, no Volatility and no network. `search` matches a regular expression across the raw plugin outputs, with `--plugin`, `-i`, `-C` for context, `--max-hits` and `--json`. `risk` fuses the rule anomalies, the flagged command lines, the public connections and the low listening ports into one score per process, capped and sorted so the top of the list is where to read first. `injection` flags lines in plugin output that read like instructions aimed at the model, and the same check now runs inside the agent loop, where a notice is prepended to the message the model sees and the hit is logged as an event. `stix` exports the indicators of a run as a STIX 2.1 bundle with deterministic ids. `sigma` turns the flagged command lines into Sigma rules as YAML text with no dependencies. `html-report` writes one self contained dark themed HTML page with the summary, the findings and every offline section in it. `bundle` writes a zip of the run with a hash manifest, so the recipient can tell whether anything changed.

The tool call cap and the nudge count are options on `run` now (`--max-calls`, `--max-nudges`) and the chosen cap is carried into the report instead of a hardcoded 15.

## 0.2.0

Added offline analysis commands that work on a saved run: tree, anomalies, netmap, cmdflags, iocs, stats and export-json. Added doctor and hash-evidence, `replay --redact --out --extras`, and `--version`. Added a table parser shared by these commands.

## 0.1.0

Initial agent: allowlisted Volatility 3 plugins, claim verification against raw output, hash-chained audit log, replay, timeline and compare, optional hashing, YARA and VirusTotal lookups.
