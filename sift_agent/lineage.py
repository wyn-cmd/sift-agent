from pathlib import Path
from sift_agent.tables import rows_for

# Walk from one PID up through its parents. A loop or a missing parent ends the chain, and a
# missing parent is said out loud because it is often the interesting part.
def lineage(rows: list[dict], pid: int) -> str:
    by_pid = {r['PID']: r for r in rows if r.get('PID')}
    cur, chain, seen = str(pid), [], set()
    if cur not in by_pid:
        raise ValueError(f'PID {pid} is not in the process list')
    while cur in by_pid and cur not in seen:
        seen.add(cur)
        r = by_pid[cur]
        chain.append(f"{r.get('ImageFileName', '?')} ({cur})")
        cur = r.get('PPID', '')
    tail = ''
    if cur in seen:
        tail = ' -> (loop)'
    elif cur not in ('', '0'):
        tail = f' -> (parent PID {cur} not in the list)'
    return ' <- '.join(chain) + tail

def lineage_from_run(runs_dir: Path, pid: int) -> str:
    rows = rows_for(runs_dir, 'windows.pslist')
    if not rows:
        raise ValueError('the run has no usable windows.pslist output')
    return lineage(rows, pid)
