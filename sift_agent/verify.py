import hashlib
import json
from pathlib import Path

# Re-check every logged tool call against the raw file on disk. Detects edited or missing raw
# output. It cannot detect an edited log line, because the log is not hash-chained.
def verify_audit(log_path: Path) -> tuple[bool, list[str]]:
    log_path = Path(log_path)
    problems = []
    if not log_path.exists():
        return False, [f'audit log not found: {log_path}']
    checked = 0
    for n, line in enumerate(log_path.read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip():
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            problems.append(f'line {n}: not valid JSON')
            continue
        if 'tool_call_id' not in e:
            continue
        checked += 1
        cid = e['tool_call_id']
        f = e.get('raw_output_file', '')
        # Guard against a log line pointing outside the raw directory
        if not f.startswith('raw/') or '..' in f:
            problems.append(f'{cid}: unsafe raw file path {f!r}')
            continue
        p = log_path.parent / f
        if not p.is_file():
            problems.append(f'{cid}: raw file missing ({f})')
            continue
        data = p.read_text(encoding='utf-8')
        if len(data) != e.get('raw_output_len'):
            problems.append(f'{cid}: length {len(data)} does not match logged {e.get("raw_output_len")}')
        if hashlib.sha256(data.encode('utf-8')).hexdigest() != e.get('raw_output_sha256'):
            problems.append(f'{cid}: SHA-256 mismatch')
    return not problems, [f'{checked} tool calls checked'] + problems
