import json
from pathlib import Path
from sift_agent.export import export_json
from sift_agent.tables import rows_for
from sift_agent.anomalies import find_anomalies

# Short plain-text digest of a saved run: counts only, so it is safe to paste into a ticket
def run_summary(runs_dir: Path) -> str:
    data = json.loads(export_json(runs_dir))
    findings = data['findings']
    by_status = ', '.join(f'{k} {v}' for k, v in data['summary'].items()) or 'none'
    conf = {c: sum(1 for f in findings if f['confidence'] == c) for c in ('high', 'medium', 'low')}
    lines = [f"tool calls: {len(data['tool_calls'])}",
             f'findings: {len(findings)} ({by_status})',
             f"confidence: high {conf['high']}, medium {conf['medium']}, low {conf['low']}"]
    rows = rows_for(runs_dir, 'windows.pslist')
    if rows:
        lines.append(f'processes: {len(rows)}, rule-based anomalies: {len(find_anomalies(rows))}')
    return '\n'.join(lines)
