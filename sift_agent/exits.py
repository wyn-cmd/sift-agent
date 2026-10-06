from datetime import datetime
from pathlib import Path
from sift_agent.tables import rows_for

def _when(text: str):
    try:
        return datetime.strptime(text[:19], '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return None

# Processes that have already exited, shortest lifetime first. Short-lived processes are normal
# for installers and shells, so the threshold only decides which ones are marked as short.
def exits_from_run(runs_dir: Path, under: float = 60.0) -> str:
    rows = rows_for(runs_dir, 'windows.pslist')
    if not rows:
        raise ValueError('the run has no usable windows.pslist output')
    gone = []
    for r in rows:
        if r.get('ExitTime', 'N/A') in ('N/A', ''):
            continue
        a, b = _when(r.get('CreateTime', '')), _when(r['ExitTime'])
        gone.append((None if a is None or b is None else (b - a).total_seconds(), r))
    if not gone:
        return 'no exited processes in the list.'
    gone.sort(key=lambda x: (x[0] is None, x[0] if x[0] is not None else 0, x[1]['PID']))
    lines = []
    for secs, r in gone:
        life = 'lifetime unknown' if secs is None else f'lived {secs:.0f}s' + (' (short)' if secs < under else '')
        lines.append(f"PID {r['PID']} {r['ImageFileName']}: {life}, exited {r['ExitTime']}")
    return '\n'.join(lines)
