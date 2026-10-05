import csv
import io
from pathlib import Path
from sift_agent.tables import iter_entries

# Every audit entry as one CSV row in log order, for loading into a spreadsheet or a SIEM
def timeline_csv(runs_dir: Path) -> str:
    log = Path(runs_dir) / 'audit.jsonl'
    if not log.exists():
        raise FileNotFoundError(f'no audit.jsonl in {runs_dir}')
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator='\n')
    w.writerow(['ts', 'kind', 'name', 'call_id', 'raw_len', 'raw_sha256'])
    for e in iter_entries(log):
        if 'tool_call_id' in e:
            w.writerow([e.get('ts'), 'tool', e.get('tool'), e['tool_call_id'], e.get('raw_output_len'), e.get('raw_output_sha256')])
        else:
            w.writerow([e.get('ts'), 'event', e.get('event_type'), '', '', ''])
    return buf.getvalue().rstrip('\n')
