import html
import json
from pathlib import Path
from sift_agent.audit import AuditLog
from sift_agent.report import parse_findings, validate_findings

# Render a single static HTML page: one row per tool call in time order, and each row lists the
# report claims that cite it. No server and no framework; the run data is embedded as JSON.
def build_timeline(runs_dir: Path) -> str:
    log_path = Path(runs_dir) / 'audit.jsonl'
    if not log_path.exists():
        raise FileNotFoundError(f'no audit.jsonl in {runs_dir}')
    audit = AuditLog(log_path)
    calls, events, answer = [], [], None
    for line in log_path.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        if 'tool_call_id' in e:
            calls.append(e)
        else:
            events.append(e)
            if e.get('event_type') == 'final model answer':
                answer = e['details'].get('answer', '')
    findings = validate_findings(parse_findings(answer), audit) if answer is not None else []
    cited = {}
    for n, f in enumerate(findings, 1):
        for cid in f['tool_call_ids']:
            cited.setdefault(cid, []).append(n)

    rows = []
    for c in calls:
        refs = ''.join(f'<li>claim {n}: {html.escape(findings[n - 1]["claim"][:160])} ({findings[n - 1]["status"]})</li>' for n in cited.get(c['tool_call_id'], []))
        rows.append(f"<tr><td>{html.escape(c['ts'])}</td><td>{html.escape(c['tool'])}</td>"
                    f"<td><code>{c['tool_call_id'][:8]}</code></td><td>{c['raw_output_len']}</td>"
                    f"<td><code>{c['raw_output_sha256'][:12]}</code></td><td><ul>{refs or '<li>not cited</li>'}</ul></td></tr>")
    ev = ''.join(f"<li>{html.escape(e['ts'])} {html.escape(e.get('event_type', ''))}</li>" for e in events if e.get('event_type') != 'final model answer')
    # Escape the closing script tag so evidence text can never break out of the embedded JSON
    data = json.dumps({'calls': calls, 'findings': findings}).replace('</', '<\\/')
    return ('<!doctype html><meta charset="utf-8"><title>sift-agent timeline</title>'
            '<style>body{font:14px sans-serif;margin:2em}td,th{border:1px solid #999;padding:4px;vertical-align:top}table{border-collapse:collapse}</style>'
            '<h1>Run timeline</h1><table><tr><th>Time (UTC)</th><th>Tool</th><th>Call</th><th>Raw bytes</th><th>SHA-256</th><th>Cited by</th></tr>'
            + ''.join(rows) + '</table><h2>Other events</h2><ul>' + ev + '</ul>'
            '<script type="application/json" id="run-data">' + data + '</script>')
