from pathlib import Path
from sift_agent.tables import rows_for

# Processes found by pool scanning (windows.psscan) but missing from the active list
# (windows.pslist). Rows with an exit time are normal leftovers of ended processes, so they are
# reported separately from rows that look like they are still running.
def find_hidden(pslist: list[dict], psscan: list[dict]) -> tuple[list[dict], list[dict]]:
    live = {r['PID'] for r in pslist}
    running, ended = [], []
    for r in psscan:
        if r.get('PID') in live:
            continue
        (ended if r.get('ExitTime', 'N/A') not in ('N/A', '') else running).append(r)
    return running, ended

def hidden_from_run(runs_dir: Path) -> str:
    pslist, psscan = rows_for(runs_dir, 'windows.pslist'), rows_for(runs_dir, 'windows.psscan')
    if not pslist or not psscan:
        raise ValueError('the run needs both windows.pslist and windows.psscan (use the extended allowlist)')
    running, ended = find_hidden(pslist, psscan)
    out = [f"PID {r['PID']} {r.get('ImageFileName')}: in psscan, not in pslist, no exit time (possibly hidden)" for r in running]
    out += [f"PID {r['PID']} {r.get('ImageFileName')}: in psscan, not in pslist, exited {r['ExitTime']}" for r in ended]
    return '\n'.join(out) or 'psscan and pslist agree.'
