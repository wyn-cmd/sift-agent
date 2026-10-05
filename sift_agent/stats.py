import json
from collections import Counter
from pathlib import Path
from sift_agent.tables import iter_entries

# One-screen summary of a saved run: calls per plugin, output sizes, failures, run duration
def run_stats(runs_dir: Path) -> str:
    log = Path(runs_dir) / 'audit.jsonl'
    if not log.exists():
        raise FileNotFoundError(f'no audit.jsonl in {runs_dir}')
    per, sizes, events, stamps = Counter(), {}, Counter(), []
    for e in iter_entries(log):
        stamps.append(e.get('ts', ''))
        if 'tool_call_id' in e:
            per[e['tool']] += 1
            sizes[e['tool']] = sizes.get(e['tool'], 0) + e.get('raw_output_len', 0)
        else:
            events[e.get('event_type', 'unknown')] += 1
    if not stamps:
        raise ValueError('audit log is empty')
    from datetime import datetime
    secs = (datetime.fromisoformat(max(stamps)) - datetime.fromisoformat(min(stamps))).total_seconds()
    out = [f'tool calls: {sum(per.values())}', f'duration: {secs:.0f}s']
    for t in sorted(per):
        out.append(f'  {t}: {per[t]} call(s), {sizes[t]} bytes of raw output')
    if events:
        out.append('events: ' + ', '.join(f'{k} x{v}' for k, v in sorted(events.items())))
    return '\n'.join(out)
