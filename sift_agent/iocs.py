import csv
import io
import ipaddress
import json
import re
from pathlib import Path
from sift_agent.tables import iter_entries, raw_for

IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
URL_RE = re.compile(r'https?://[^\s"\'<>\\]+', re.I)
# A 32-hex run followed by -digits is a PDB symbol GUID, not an MD5, so it is skipped
HASH_RE = re.compile(r'\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32}(?!-\d))\b', re.I)
DOMAIN_RE = re.compile(r'\b(?:[a-z0-9-]+\.)+(?:com|net|org|ru|cn|info|biz|xyz|top|io|cc|tk)\b', re.I)

def _public_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return ip.is_global

# Pull indicators out of every raw plugin output in a saved run. Private, loopback and unspecified
# addresses are dropped, so only addresses that could be external remain.
def extract_iocs(runs_dir: Path) -> dict:
    log = Path(runs_dir) / 'audit.jsonl'
    if not log.exists():
        raise FileNotFoundError(f'no audit.jsonl in {runs_dir}')
    found = {'ip': set(), 'url': set(), 'hash': set(), 'domain': set()}
    for e in iter_entries(log):
        if 'raw_output_file' not in e:
            continue
        p = Path(runs_dir) / e['raw_output_file']
        if not p.is_file():
            continue
        text = p.read_text(encoding='utf-8')
        found['ip'].update(i for i in IP_RE.findall(text) if _public_ip(i))
        found['url'].update(URL_RE.findall(text))
        found['hash'].update(h.lower() for h in HASH_RE.findall(text))
        found['domain'].update(d.lower() for d in DOMAIN_RE.findall(text))
    return {k: sorted(v) for k, v in found.items()}

def format_iocs(iocs: dict, fmt: str = 'text') -> str:
    if fmt == 'json':
        return json.dumps(iocs, indent=2)
    if fmt == 'csv':
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator='\n')
        w.writerow(['type', 'value'])
        for kind, vals in iocs.items():
            for v in vals:
                w.writerow([kind, v])
        return buf.getvalue().rstrip('\n')
    lines = []
    for kind, vals in iocs.items():
        lines.append(f'{kind}: {len(vals)}')
        lines.extend(f'  {v}' for v in vals)
    return '\n'.join(lines)
