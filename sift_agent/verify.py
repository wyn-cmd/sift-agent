import hashlib
import json
from pathlib import Path
from sift_agent.audit import GENESIS, entry_hash

# Re-check the log in two ways: every line's own hash and its link to the previous line (catches
# edited, deleted, inserted or reordered lines), and every tool call's raw file on disk (catches
# edited or missing raw output). Lines written before the chain existed carry no hash and are
# reported as unchained rather than failed.
def verify_audit(log_path: Path) -> tuple[bool, list[str]]:
    log_path = Path(log_path)
    problems = []
    if not log_path.exists():
        return False, [f'audit log not found: {log_path}']
    checked = 0
    prev = GENESIS
    unchained = 0
    for n, line in enumerate(log_path.read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip():
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            problems.append(f'line {n}: not valid JSON')
            continue
        if 'line_sha256' not in e:
            unchained += 1
        else:
            if e.get('prev_sha256') != prev:
                problems.append(f'line {n}: chain broken (a line before it was removed, inserted or reordered)')
            if entry_hash(e) != e['line_sha256']:
                problems.append(f'line {n}: line hash mismatch (line was edited)')
            prev = e['line_sha256']
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
    head = [f'{checked} tool calls checked']
    if unchained:
        head.append(f'{unchained} lines have no hash chain (written by an older version)')
    return not problems, head + problems
