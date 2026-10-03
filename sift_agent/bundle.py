import json
import hashlib
import zipfile
import datetime
from pathlib import Path
from sift_agent.verify import head_hash
from sift_agent.replay import replay
from sift_agent.redact import redact

# build_manifest: generates a manifest of files and counts for a run directory
def build_manifest(runs_dir: Path, evidence: Path | None = None) -> dict:
    audit_log = runs_dir / 'audit.jsonl'
    if not audit_log.exists():
        raise FileNotFoundError(f'no audit.jsonl in {runs_dir}')
    
    files = []
    tool_calls = 0
    events = 0
    plugins = {}
    
    # helper for hashing
    def get_hash(p):
        sha = hashlib.sha256()
        with open(p, 'rb') as f:
            while chunk := f.read(65536):
                sha.update(chunk)
        return sha.hexdigest()

    # collect files
    for p in runs_dir.rglob('*'):
        if p.is_file():
            rel = p.relative_to(runs_dir).as_posix()
            files.append({'path': rel, 'bytes': p.stat().st_size, 'sha256': get_hash(p)})
    
    files.sort(key=lambda x: x['path'])
    
    # parse audit log
    for line in audit_log.read_text(encoding='utf-8').splitlines():
        if not line.strip(): continue
        e = json.loads(line)
        if 'tool' in e:
            tool_calls += 1
            tool = e['tool']
            plugins[tool] = plugins.get(tool, 0) + 1
        if 'event_type' in e:
            events += 1
            
    return {
        'created': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'runs_dir': runs_dir.name,
        'audit_head_hash': head_hash(audit_log),
        'tool_calls': tool_calls,
        'events': events,
        'plugins': plugins,
        'files': files,
        'evidence': {
            'path': evidence.name,
            'bytes': evidence.stat().st_size,
            'sha256': get_hash(evidence)
        } if evidence else None
    }

# write_bundle: bundles files into a zip archive
def write_bundle(runs_dir: Path, out_zip: Path, evidence: Path | None = None, redact_text: bool = False) -> dict:
    manifest = build_manifest(runs_dir, evidence)
    manifest_json = json.dumps(manifest, indent=2).encode('utf-8')
    manifest_sha = hashlib.sha256(manifest_json).hexdigest()
    
    report_md = replay(runs_dir)
    if redact_text:
        report_md = "REDACTED\n" + redact(report_md)
        
    entries = []
    with zipfile.ZipFile(out_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        fixed_time = (1980, 1, 1, 0, 0, 0)

        # A ZipInfo carries its own compression setting, so it has to ask for DEFLATED
        # explicitly or these entries end up stored uncompressed
        def add(name, data):
            info = zipfile.ZipInfo(name, date_time=fixed_time)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
            entries.append(name)

        add('manifest.json', manifest_json)
        add('report.md', report_md.encode('utf-8'))
        for p in sorted(runs_dir.rglob('*')):
            rel = p.relative_to(runs_dir).as_posix()
            if p.is_file() and rel not in ('report.md', 'manifest.json'):
                add(rel, p.read_bytes())

    return {
        'out': str(out_zip),
        'entries': entries,
        'bytes': out_zip.stat().st_size,
        'manifest_sha256': manifest_sha
    }
