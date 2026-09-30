import hashlib
from pathlib import Path
from sift_agent.tools import suspicion_score

# Pick the PIDs of the most suspicious pslist rows, using the column header to find PID and name
def pick_pids(pslist_raw: str, limit: int = 3, min_score: int = 4) -> list[tuple[int, str]]:
    rows = [l for l in pslist_raw.splitlines() if l.strip() and not l.startswith('Volatility 3 Framework')]
    if len(rows) < 2:
        return []
    header = rows[0].split('\t')
    if 'PID' not in header:
        return []
    pid_i = header.index('PID')
    name_i = header.index('ImageFileName') if 'ImageFileName' in header else None
    scored = []
    for line in rows[1:]:
        cols = line.split('\t')
        if len(cols) <= pid_i or not cols[pid_i].strip().isdigit():
            continue
        score = suspicion_score(line)
        if score >= min_score:
            name = cols[name_i].strip() if name_i is not None and len(cols) > name_i else ''
            scored.append((score, int(cols[pid_i]), name))
    scored.sort(key=lambda s: -s[0])
    seen, out = set(), []
    for _, pid, name in scored:
        if pid not in seen:
            seen.add(pid)
            out.append((pid, name))
    return out[:limit]

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()

# Dump each picked process, hash every file the dump produced, and optionally look the hash up.
# The audit log gets one event per process so the result can be traced later.
def dump_and_hash(runner, evidence: str, pslist_raw: str, dump_dir: Path, audit_log, vt=None, limit: int = 3) -> list[dict]:
    results = []
    dump_dir = Path(dump_dir)
    dump_dir.mkdir(parents=True, exist_ok=True)
    for pid, name in pick_pids(pslist_raw, limit):
        before = {p.name for p in dump_dir.iterdir()}
        rc, out, err = runner.dump(evidence, pid, str(dump_dir))
        files = sorted(p for p in dump_dir.iterdir() if p.name not in before and p.is_file())
        entry = {'pid': pid, 'name': name, 'files': []}
        if rc != 0 or not files:
            entry['error'] = f'dump exited with code {rc}' if rc != 0 else 'no files were written'
        for p in files:
            digest = sha256_file(p)
            item = {'file': p.name, 'sha256': digest, 'size': p.stat().st_size}
            if vt is not None:
                item['virustotal'] = vt.lookup(digest)
            entry['files'].append(item)
        audit_log.log_event('process dump', entry)
        results.append(entry)
    return results

def format_hash_section(results: list[dict]) -> list[str]:
    lines = ['## Dumped file hashes', '',
             'These are SHA-256 hashes of images reconstructed from memory. They usually differ from the on-disk file, so a VirusTotal miss does not mean the file is clean.', '']
    for r in results:
        lines.append(f"- PID {r['pid']} {r['name']}")
        if r.get('error'):
            lines.append(f"  Error: {r['error']}")
        for f in r['files']:
            lines.append(f"  {f['file']} sha256 {f['sha256']} ({f['size']} bytes)")
            vt = f.get('virustotal')
            if vt is None:
                continue
            if vt.get('error'):
                lines.append(f"  VirusTotal: lookup failed ({vt['error']})")
            elif not vt.get('found'):
                lines.append('  VirusTotal: hash not found')
            else:
                lines.append(f"  VirusTotal: {vt['malicious']} malicious, {vt['suspicious']} suspicious, {vt['harmless']} harmless, {vt['undetected']} undetected. {vt['link']}")
    lines.append('')
    return lines
