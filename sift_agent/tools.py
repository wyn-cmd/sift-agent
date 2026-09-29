import subprocess
import shutil
import sys
from pathlib import Path
import re

# Names that normally appear on a clean Windows host; anything else scores higher
SYSTEM_NAMES = {
    'system', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
    'services.exe', 'lsass.exe', 'svchost.exe', 'explorer.exe', 'dwm.exe',
    'fontdrvhost.exe', 'spoolsv.exe', 'taskhostw.exe', 'sihost.exe', 'ctfmon.exe',
    'searchindexer.exe', 'runtimebroker.exe', 'conhost.exe', 'dllhost.exe',
    'wmiprvse.exe', 'audiodg.exe', 'memcompression', 'msmpeng.exe', 'lsaiso.exe',
}
# Interpreters and living-off-the-land binaries that attackers commonly abuse
LOLBINS = {
    'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe',
    'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe',
    'nc.exe', 'ncat.exe', 'psexec.exe',
}
# Ports that are routine for Windows services and browsing
COMMON_PORTS = {53, 67, 68, 80, 123, 135, 137, 138, 139, 389, 443, 445, 500, 1900, 3389, 5353, 5355}
EXE_RE = re.compile(r'[\w.\-]+\.exe', re.IGNORECASE)
# ip:port, or an address column followed by a port column
PORT_RES = [re.compile(r'\d{1,3}(?:\.\d{1,3}){3}:(\d{1,5})\b'), re.compile(r'\d{1,3}(?:\.\d{1,3}){3}\s+(\d{1,5})\b')]

# Generic heuristic, deliberately blind to any specific case: unknown binaries, abusable
# binaries, and non-routine ports below the ephemeral range
def suspicion_score(line: str) -> int:
    score = 0
    names = [n.lower() for n in EXE_RE.findall(line)]
    for name in names:
        if name in LOLBINS:
            score += 5
        elif name not in SYSTEM_NAMES:
            score += 4
    # A shell or interpreter spawned by a non-system process is a stronger signal
    if len(names) >= 2 and names[0] not in SYSTEM_NAMES and any(n in LOLBINS for n in names[1:]):
        score += 3
    for rx in PORT_RES:
        for m in rx.findall(line):
            port = int(m)
            if port not in COMMON_PORTS and 0 < port < 49152:
                score += 4
    return score

from typing import Protocol, List, Dict, Any

# Prefer vol on PATH, then the one installed beside the running interpreter
def find_vol() -> str:
    found = shutil.which('vol') or shutil.which('vol3')
    if found:
        return found
    beside = Path(sys.executable).parent / 'vol'
    return str(beside) if beside.exists() else 'vol'

class Runner(Protocol):
    def run(self, plugin: str, evidence_path: str) -> tuple[int, str, str]:
        ...

class SubprocessRunner:
    def run(self, plugin: str, evidence_path: str) -> tuple[int, str, str]:
        # Run volatility via subprocess with list args, never shell=True
        cmd = [find_vol(), '-q', '-f', evidence_path, plugin]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return res.returncode, res.stdout, res.stderr
        except Exception as e:
            return 1, '', str(e)

def process_output(stdout: str, stderr: str, returncode: int) -> tuple[str, bool, bool]:
    failed = returncode != 0 and not stdout.strip()
    if failed:
        return stderr, True, False

    lines = stdout.splitlines()
    if not lines:
        return stdout, False, False

    # Volatility prints a banner and blank lines before the column header; drop them so the
    # real header is preserved and ranked rows are only data
    start = 0
    while start < len(lines) and (not lines[start].strip() or lines[start].startswith('Volatility 3 Framework')):
        start += 1
    lines = lines[start:]
    if not lines:
        return '', False, False
    header = lines[0]
    data_lines = [l for l in lines[1:] if l.strip()]

    def score_line(line: str) -> int:
        return suspicion_score(line)

    # Sort to put suspicious rows first
    sorted_data = sorted(data_lines, key=score_line, reverse=True)

    truncated = False
    if len(sorted_data) > 150:
        sorted_data = sorted_data[:150]
        truncated = True

    final_lines = [header] + sorted_data
    return '\n'.join(final_lines), False, truncated
