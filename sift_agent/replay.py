import json
from pathlib import Path
from sift_agent.audit import AuditLog
from sift_agent.guardrails import ALLOWED_TOOLS
from sift_agent.report import generate_report, parse_findings
from sift_agent.tools import process_output
from sift_agent.dump import format_hash_section

# Rebuild the report from a saved run with no model, Volatility or network. The saved final answer
# is re-parsed and every finding is validated again against the raw outputs on disk.
def replay(runs_dir: Path) -> str:
    log_path = Path(runs_dir) / 'audit.jsonl'
    if not log_path.exists():
        raise FileNotFoundError(f'no audit.jsonl in {runs_dir}')
    audit = AuditLog(log_path)
    answer, tools_run, calls, truncated, dumps = None, set(), 0, [], []
    for line in log_path.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        if 'tool_call_id' in e:
            calls += 1
            tools_run.add(e['tool'])
            raw = audit.read_raw(e['tool_call_id']) or ''
            if process_output(raw, '', 0, e.get('tool', ''))[2]:
                name = e['tool'].split('.')[-1]
                if name not in truncated:
                    truncated.append(name)
        elif e.get('event_type') == 'final model answer':
            # Keep the last answer if the run logged more than one
            answer = e['details'].get('answer', '')
        elif e.get('event_type') == 'process dump':
            dumps.append(e['details'])
    if answer is None:
        raise ValueError('the run has no final model answer to replay')
    not_run = sorted(ALLOWED_TOOLS - tools_run)
    report = generate_report(parse_findings(answer), audit, truncated, calls, False, not_run)
    if dumps:
        report += '\n\n' + '\n'.join(format_hash_section(dumps))
    return report
