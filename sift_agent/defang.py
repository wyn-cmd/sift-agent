from pathlib import Path
from sift_agent.iocs import extract_iocs

# Make an indicator safe to paste into a ticket or chat: dots in brackets, http turned into hxxp
def defang_value(value: str) -> str:
    v = value.replace('.', '[.]')
    for scheme in ('https', 'http', 'ftp'):
        if v.lower().startswith(scheme + '://'):
            v = {'https': 'hxxps', 'http': 'hxxp', 'ftp': 'fxp'}[scheme] + v[len(scheme):]
            break
    return v

# One defanged indicator per line as "kind value". Hashes carry no dots and are printed as found.
def defang_from_run(runs_dir: Path) -> str:
    found = extract_iocs(runs_dir)
    lines = [f'{kind} {defang_value(v)}' for kind in ('ip', 'url', 'domain', 'hash') for v in found.get(kind, [])]
    return '\n'.join(lines) or 'no indicators found.'
