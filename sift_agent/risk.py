import ipaddress
from pathlib import Path
from sift_agent.tables import rows_for
from sift_agent.anomalies import find_anomalies
from sift_agent.cmdflags import scan_cmdlines
from sift_agent.tools import SYSTEM_NAMES, LOLBINS, COMMON_PORTS

# Fixed weights for the fused score. These are heuristics, so the table is a reading order and not a verdict.
ANOMALY_WEIGHT = 4
CMDFLAG_WEIGHT = 3
REMOTE_WEIGHT = 2
REMOTE_CAP = 4
LOW_PORT_WEIGHT = 2
LOLBIN_WEIGHT = 3
MISSING_PARENT_WEIGHT = 1
UNKNOWN_BINARY_WEIGHT = 1

# netscan prints address:port, a bare address has no colon, and IPv6 arrives wrapped in brackets
def _public_addr(value: str) -> str | None:
    text = (value or '').strip()
    if not text:
        return None
    head, _, tail = text.rpartition(':')
    if head and tail.isdigit():
        text = head
    text = text.strip('[]')
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    return text if ip.is_global else None

# Both network plugins share the same column names, so their rows are pooled
def _net_rows(runs_dir: Path) -> list[dict]:
    rows = []
    for plugin in ('windows.netscan', 'windows.netstat'):
        try:
            rows.extend(rows_for(runs_dir, plugin))
        except (FileNotFoundError, ValueError):
            continue
    return rows

# Fuse every rule-based check into one score per process, so the analyst reads the top of a list
# instead of diffing four commands. find_anomalies and scan_cmdlines return tuples, not pid maps.
def risk_report(runs_dir: Path) -> dict:
    pslist_rows = rows_for(runs_dir, 'windows.pslist')
    if not pslist_rows:
        raise ValueError('the run has no usable windows.pslist output')
    cmdline_rows = rows_for(runs_dir, 'windows.cmdline')
    net_rows = _net_rows(runs_dir)

    anomaly_by_pid: dict[str, list[str]] = {}
    for pid, _name, why in find_anomalies(pslist_rows):
        anomaly_by_pid.setdefault(str(pid), []).append(why)
    cmdflag_by_pid: dict[str, list[str]] = {}
    for pid, _name, why, _args in scan_cmdlines(cmdline_rows):
        cmdflag_by_pid.setdefault(str(pid), []).append(why)

    remote_by_pid: dict[str, list[str]] = {}
    low_port_by_pid: dict[str, list[str]] = {}
    for row in net_rows:
        pid = str(row.get('PID', ''))
        addr = _public_addr(row.get('ForeignAddr') or row.get('RemoteAddr') or '')
        if addr:
            remote_by_pid.setdefault(pid, []).append(addr)
        state = (row.get('State') or '').upper()
        port = (row.get('LocalPort') or '').strip()
        if state == 'LISTENING' and port.isdigit() and int(port) < 1024 and int(port) not in COMMON_PORTS:
            low_port_by_pid.setdefault(pid, []).append(port)

    known_pids = {str(r.get('PID', '')) for r in pslist_rows}
    processes = []
    clean = 0
    for row in pslist_rows:
        pid = str(row.get('PID', ''))
        name = row.get('ImageFileName', '?')
        lower = name.lower()
        score = 0
        reasons = []
        # sorting each signal group keeps the same run scoring identically every time
        for why in sorted(set(anomaly_by_pid.get(pid, []))):
            score += ANOMALY_WEIGHT
            reasons.append(f'rule anomaly: {why}')
        for why in sorted(set(cmdflag_by_pid.get(pid, []))):
            score += CMDFLAG_WEIGHT
            reasons.append(f'flagged command line: {why}')
        for addr in sorted(set(remote_by_pid.get(pid, [])))[:REMOTE_CAP // REMOTE_WEIGHT]:
            score += REMOTE_WEIGHT
            reasons.append(f'connection to public address {addr}')
        for port in sorted(set(low_port_by_pid.get(pid, []))):
            score += LOW_PORT_WEIGHT
            reasons.append(f'listening on port {port}, below 1024 and not a routine port')
        if lower in LOLBINS:
            score += LOLBIN_WEIGHT
            reasons.append('name is a script host or proxy binary')
        ppid = str(row.get('PPID', ''))
        if ppid != '0' and ppid not in known_pids:
            score += MISSING_PARENT_WEIGHT
            reasons.append('parent is not in the process list')
        if lower not in SYSTEM_NAMES and lower not in LOLBINS:
            score += UNKNOWN_BINARY_WEIGHT
            reasons.append('binary is not a known system name')
        if score == 0:
            clean += 1
            continue
        processes.append({'pid': pid, 'name': name, 'score': score, 'reasons': reasons,
                          'parent': ppid, 'session': row.get('SessionId', '')})

    processes.sort(key=lambda p: (-p['score'], int(p['pid']) if p['pid'].isdigit() else 0))
    return {'processes': processes, 'clean': clean, 'notes': [
        f'{clean} of {len(pslist_rows)} processes scored 0',
        'weights are fixed heuristics, so read this as leads and not as a verdict',
    ]}

def format_risk(report: dict) -> str:
    processes = report['processes']
    lines = [f'{len(processes)} process(es) carry at least one signal, {report["clean"]} scored 0']
    for p in processes:
        lines.append(f'SCORE {p["score"]} PID {p["pid"]} {p["name"]}: ' + '; '.join(p['reasons']))
    lines.extend(report['notes'])
    return '\n'.join(lines)

def risk_from_run(runs_dir: Path) -> str:
    return format_risk(risk_report(runs_dir))
