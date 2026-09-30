import json
import re
from pathlib import Path
from sift_agent.audit import AuditLog
from sift_agent.report import parse_findings, validate_findings

norm = lambda t: re.sub(r'\s+', ' ', t).strip().lower()

def load_findings(runs_dir: Path) -> list[dict]:
    log_path = Path(runs_dir) / 'audit.jsonl'
    if not log_path.exists():
        raise FileNotFoundError(f'no audit.jsonl in {runs_dir}')
    answer = None
    for line in log_path.read_text(encoding='utf-8').splitlines():
        if line.strip():
            e = json.loads(line)
            if e.get('event_type') == 'final model answer':
                answer = e['details'].get('answer', '')
    if answer is None:
        raise ValueError(f'{runs_dir} has no final model answer')
    return validate_findings(parse_findings(answer), AuditLog(log_path))

def excerpt_lines(f: dict) -> set:
    return {norm(l) for l in f['excerpt'].splitlines() if l.strip()}

# Two claims are treated as the same when they quote at least one identical evidence line.
# Compare two saved runs, typically made with different models, and list where they disagree.
def compare_runs(dir_a: Path, dir_b: Path) -> str:
    a, b = load_findings(dir_a), load_findings(dir_b)
    out = ['# Cross-run comparison', '', f'A: {dir_a}  B: {dir_b}', '']
    both, only_a, only_b, split = [], [], [], []
    for fa in [x for x in a if x['status'] == 'confirmed']:
        match = [fb for fb in b if excerpt_lines(fa) & excerpt_lines(fb)]
        if any(m['status'] == 'confirmed' for m in match):
            both.append(fa)
        elif match:
            split.append((fa, match[0], 'A'))
        else:
            only_a.append(fa)
    for fb in [x for x in b if x['status'] == 'confirmed']:
        match = [fa for fa in a if excerpt_lines(fa) & excerpt_lines(fb)]
        if not match:
            only_b.append(fb)
        elif not any(m['status'] == 'confirmed' for m in match):
            split.append((fb, match[0], 'B'))
    out.append(f'Confirmed in both runs: {len(both)}')
    out.append(f'Confirmed only in A: {len(only_a)}')
    out.append(f'Confirmed only in B: {len(only_b)}')
    out.append(f'Confirmed in one run but not in the other: {len(split)}')
    out.append('')
    for title, items in (('Only in A', only_a), ('Only in B', only_b)):
        if items:
            out.append(f'## {title}')
            out.extend(f"- {f['claim']}" for f in items)
            out.append('')
    if split:
        out.append('## Disagreements (worth investigating)')
        for f, other, who in split:
            out.append(f"- Run {who} confirms: {f['claim']}")
            out.append(f"  The other run has it as {other['status']}: {other['claim']}")
        out.append('')
    return '\n'.join(out)
