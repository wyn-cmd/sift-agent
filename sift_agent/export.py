import json
from pathlib import Path
from sift_agent.audit import AuditLog
from sift_agent.report import parse_findings, validate_findings
from sift_agent.dump import sha256_file

# Machine-readable copy of the validated findings of a saved run, for other tools to consume
def export_json(runs_dir: Path) -> str:
    log = Path(runs_dir) / 'audit.jsonl'
    if not log.exists():
        raise FileNotFoundError(f'no audit.jsonl in {runs_dir}')
    audit = AuditLog(log)
    answer, calls = None, []
    for line in log.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        if 'tool_call_id' in e:
            calls.append({'id': e['tool_call_id'], 'tool': e['tool'], 'raw_output_sha256': e['raw_output_sha256']})
        elif e.get('event_type') == 'final model answer':
            answer = e['details'].get('answer', '')
    if answer is None:
        raise ValueError('the run has no final model answer to export')
    findings = validate_findings(parse_findings(answer), audit)
    summary = {s: sum(1 for f in findings if f['status'] == s) for s in sorted({f['status'] for f in findings})}
    return json.dumps({'tool_calls': calls, 'summary': summary, 'findings': findings}, indent=2)

# SHA-256 of the evidence file, so a report can state exactly which image it describes
def evidence_hash_line(path: Path) -> str:
    return f'{sha256_file(Path(path))}  {Path(path).name}'
