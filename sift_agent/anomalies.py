from pathlib import Path
from sift_agent.tables import rows_for

# Expected parent for classic Windows system processes (lowercase names)
EXPECTED_PARENT = {
    'smss.exe': {'system'},
    'csrss.exe': {'smss.exe'},
    'wininit.exe': {'smss.exe'},
    'winlogon.exe': {'smss.exe'},
    'services.exe': {'wininit.exe', 'winlogon.exe'},
    'lsass.exe': {'wininit.exe', 'winlogon.exe'},
    'lsm.exe': {'wininit.exe'},
    'svchost.exe': {'services.exe'},
    'spoolsv.exe': {'services.exe'},
    'taskhost.exe': {'services.exe'},
}
# These should exist once per boot
SINGLETONS = {'lsass.exe', 'services.exe', 'wininit.exe', 'lsm.exe', 'smss.exe'}
# Common one-letter-off imitations of system names
LOOKALIKES = {'svch0st.exe': 'svchost.exe', 'scvhost.exe': 'svchost.exe', 'svhost.exe': 'svchost.exe',
              'lsas.exe': 'lsass.exe', 'lssas.exe': 'lsass.exe', 'csrs.exe': 'csrss.exe',
              'expl0rer.exe': 'explorer.exe', 'explorer32.exe': 'explorer.exe'}

# Deterministic checks that need no model: wrong parent, duplicate singletons, lookalike names,
# system processes in the wrong session, and children whose parent started after them.
# Returns (pid, name, reason) tuples. These are leads for an analyst, not verdicts.
def find_anomalies(rows: list[dict]) -> list[tuple[str, str, str]]:
    by_pid = {r['PID']: r for r in rows if r.get('PID')}
    out = []
    counts: dict[str, list[str]] = {}
    for r in rows:
        name = r.get('ImageFileName', '').lower()
        pid = r.get('PID', '')
        counts.setdefault(name, []).append(pid)
        if name in LOOKALIKES:
            out.append((pid, r['ImageFileName'], f'name imitates {LOOKALIKES[name]}'))
        want = EXPECTED_PARENT.get(name)
        parent = by_pid.get(r.get('PPID', ''))
        if want and parent and parent.get('ImageFileName', '').lower() not in want:
            out.append((pid, r['ImageFileName'], f"parent is {parent.get('ImageFileName')} (PID {r.get('PPID')}), expected {' or '.join(sorted(want))}"))
        if name in ('csrss.exe', 'smss.exe', 'wininit.exe', 'services.exe', 'lsass.exe') and r.get('SessionId') not in ('', 'N/A', '0') and name != 'csrss.exe':
            out.append((pid, r['ImageFileName'], f"runs in session {r.get('SessionId')}, system processes run in session 0"))
        ct, pt = r.get('CreateTime', ''), (parent or {}).get('CreateTime', '')
        if parent and ct not in ('', 'N/A') and pt not in ('', 'N/A') and ct < pt:
            out.append((pid, r['ImageFileName'], f"created before its parent {parent.get('ImageFileName')}"))
    for name, pids in counts.items():
        if name in SINGLETONS and len(pids) > 1:
            out.append((pids[1], name, f"{len(pids)} instances (PIDs {', '.join(pids)}), expected one"))
    return out

def format_anomalies(found: list[tuple[str, str, str]]) -> str:
    if not found:
        return 'No rule-based anomalies found in the process list.'
    return '\n'.join(f'PID {p} {n}: {why}' for p, n, why in found)

def anomalies_from_run(runs_dir: Path) -> str:
    rows = rows_for(runs_dir, 'windows.pslist')
    if not rows:
        raise ValueError('the run has no usable windows.pslist output')
    return format_anomalies(find_anomalies(rows))
