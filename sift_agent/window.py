from pathlib import Path
from sift_agent.tables import rows_for

# Processes created inside a time window. Times are compared as text, which works because
# Volatility prints ISO style timestamps; give --start and --end in the same form, for example 2012-07-22 02:42.
def window_from_run(runs_dir: Path, start: str, end: str) -> str:
    rows = rows_for(runs_dir, 'windows.pslist')
    if not rows:
        raise ValueError('the run has no usable windows.pslist output')
    if start > end:
        raise ValueError('--start is after --end')
    # Sort on time then PID only; two processes can share a timestamp and dicts cannot be compared
    hits = sorted(((r['CreateTime'], r) for r in rows if r.get('CreateTime', 'N/A') not in ('N/A', '') and start <= r['CreateTime'] <= end),
                  key=lambda x: (x[0], int(x[1]['PID']) if x[1]['PID'].isdigit() else 0))
    if not hits:
        return 'no processes were created in that window.'
    return '\n'.join(f"{t}  PID {r['PID']} {r['ImageFileName']} (parent {r['PPID']})" for t, r in hits)
