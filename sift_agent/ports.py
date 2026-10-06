from collections import Counter
from pathlib import Path
from sift_agent.tables import raw_for, parse_table

# Remote ports that routine Windows traffic uses; anything else is listed as unusual
COMMON = {'20', '21', '22', '25', '53', '80', '110', '123', '135', '137', '138', '139', '143', '389', '443',
          '445', '465', '587', '636', '993', '995', '3268', '3389'}

# Summarise sockets from netscan and netstat: listening ports, remote ports by count, and the
# processes behind remote ports outside the common set. A lead for the analyst, not a verdict.
def ports_from_run(runs_dir: Path) -> str:
    rows = []
    for plugin in ('windows.netscan', 'windows.netstat'):
        for raw in raw_for(runs_dir, plugin):
            rows.extend(r for r in parse_table(raw) if r.get('Proto') and r.get('LocalPort'))
    if not rows:
        return 'No network rows in the saved output.'
    listening = sorted({(r['LocalPort'], r.get('Owner') or '?') for r in rows if r.get('State') == 'LISTENING'},
                       key=lambda x: (int(x[0]) if x[0].isdigit() else 0, x[1]))
    remote = [r for r in rows if r.get('State') != 'LISTENING' and r.get('ForeignPort') not in (None, '', '0', '*')]
    counts = Counter(r['ForeignPort'] for r in remote)
    out = ['listening: ' + (', '.join(f'{p} ({o})' for p, o in listening) or 'none'),
           'remote ports: ' + (', '.join(f'{p} x{n}' for p, n in sorted(counts.items(), key=lambda x: (-x[1], x[0]))) or 'none')]
    odd = sorted({(r['ForeignPort'], r.get('Owner') or '?', r.get('PID') or '?') for r in remote if r['ForeignPort'] not in COMMON})
    out.append('unusual remote ports: ' + ('; '.join(f'{p} from {o} (PID {pid})' for p, o, pid in odd) or 'none'))
    return '\n'.join(out)
