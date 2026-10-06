import re
from pathlib import Path
from sift_agent.tables import rows_for

# Patterns that are rarely seen in routine command lines. A match is a lead to read, not a verdict.
PATTERNS = [
    (re.compile(r'-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}', re.I), 'encoded PowerShell command'),
    (re.compile(r'-w(indowstyle)?\s+hidden', re.I), 'hidden window'),
    (re.compile(r'-nop|-noprofile', re.I), 'PowerShell profile skipped'),
    (re.compile(r'\\(temp|appdata\\local\\temp|users\\public|programdata)\\[^\\]+\.(exe|dll|bat|ps1|vbs)', re.I), 'runs from a temp or shared writable path'),
    (re.compile(r'(downloadstring|invoke-webrequest|iwr |certutil.*-urlcache|bitsadmin.*/transfer)', re.I), 'download cradle'),
    (re.compile(r'(rundll32|regsvr32|mshta|wscript|cscript)', re.I), 'script host or proxy binary'),
    (re.compile(r'https?://', re.I), 'URL in the arguments'),
    (re.compile(r'(vssadmin.*delete\s+shadows|wbadmin.*delete|bcdedit.*recoveryenabled\s+no|wevtutil\s+cl\b)', re.I), 'backup, recovery or log tampering'),
    (re.compile(r'(net1?\s+user\s+\S+.*/add|net1?\s+localgroup\s+administrators.*/add)', re.I), 'local account creation'),
    (re.compile(r'(schtasks.*/create|reg(\.exe)?\s+add.*\\run\b|sc(\.exe)?\s+create)', re.I), 'persistence setup'),
]

# Scan windows.cmdline rows for the patterns above; returns (pid, process, reason, args)
def scan_cmdlines(rows: list[dict]) -> list[tuple[str, str, str, str]]:
    out = []
    for r in rows:
        args = r.get('Args', '')
        for rx, why in PATTERNS:
            if rx.search(args):
                out.append((r.get('PID', '?'), r.get('Process', '?'), why, args[:160]))
    return out

def cmdflags_from_run(runs_dir: Path) -> str:
    rows = rows_for(runs_dir, 'windows.cmdline')
    if not rows:
        raise ValueError('the run has no usable windows.cmdline output')
    found = scan_cmdlines(rows)
    if not found:
        return 'No flagged command lines.'
    return '\n'.join(f'PID {p} {n}: {why}\n  {a}' for p, n, why, a in found)
