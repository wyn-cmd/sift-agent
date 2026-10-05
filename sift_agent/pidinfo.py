from pathlib import Path
from sift_agent.tables import rows_for
from sift_agent.lineage import lineage

# Everything the saved run knows about one PID: its process row, command line, sockets and parent chain
def pidinfo_from_run(runs_dir: Path, pid: int) -> str:
    rows = rows_for(runs_dir, 'windows.pslist')
    if not rows:
        raise ValueError('the run has no usable windows.pslist output')
    mine = [r for r in rows if r.get('PID') == str(pid)]
    if not mine:
        raise ValueError(f'PID {pid} is not in the process list')
    r = mine[0]
    out = [f"process: {r['ImageFileName']} (PID {pid}, parent {r.get('PPID')}, created {r.get('CreateTime')}, exited {r.get('ExitTime')})",
           'chain: ' + lineage(rows, pid)]
    cmd = [c for c in rows_for(runs_dir, 'windows.cmdline') if c.get('PID') == str(pid)]
    out.append('command line: ' + (cmd[0].get('Args', '') if cmd else 'not in this run'))
    socks = []
    for plugin in ('windows.netscan', 'windows.netstat'):
        socks += [s for s in rows_for(runs_dir, plugin) if s.get('PID') == str(pid)]
    out.append('sockets: ' + ('; '.join(f"{s.get('Proto')} {s.get('LocalAddr')}:{s.get('LocalPort')} -> {s.get('ForeignAddr')}:{s.get('ForeignPort')} {s.get('State')}" for s in socks) or 'none in this run'))
    return '\n'.join(out)
