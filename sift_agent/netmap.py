import ipaddress
from collections import defaultdict
from pathlib import Path
from sift_agent.tables import parse_table, raw_for

def _external(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_global
    except ValueError:
        return False

# Group network rows from windows.netscan and windows.netstat by owning process, keeping only
# established or listening sockets with a real remote or local port. External remote addresses
# are flagged because they are the ones worth chasing first.
def build_netmap(rows: list[dict]) -> str:
    by_owner = defaultdict(set)
    for r in rows:
        # Rows from a failed plugin (stderr text, no protocol) are not connections
        if not r.get('Proto') or not r.get('LocalPort'):
            continue
        owner = f"{r.get('Owner') or '?'} (PID {r.get('PID') or '?'})"
        state = r.get('State', '')
        remote, rport = r.get('ForeignAddr', ''), r.get('ForeignPort', '')
        if state == 'LISTENING' or remote in ('*', '0.0.0.0', '::', ''):
            by_owner[owner].add(f"listens on {r.get('LocalAddr')}:{r.get('LocalPort')} ({r.get('Proto')})")
        else:
            flag = ' [external]' if _external(remote) else ''
            by_owner[owner].add(f"{r.get('Proto')} to {remote}:{rport} {state}{flag}")
    if not by_owner:
        return 'No network rows in the saved output.'
    lines = []
    for owner in sorted(by_owner):
        lines.append(owner)
        lines.extend(f'  {c}' for c in sorted(by_owner[owner]))
    return '\n'.join(lines)

def netmap_from_run(runs_dir: Path) -> str:
    rows = []
    for plugin in ('windows.netscan', 'windows.netstat'):
        for raw in raw_for(runs_dir, plugin):
            rows.extend(parse_table(raw))
    return build_netmap(rows)
