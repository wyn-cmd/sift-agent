import uuid
import json
import datetime
from pathlib import Path
from sift_agent.iocs import extract_iocs

# build a deterministic indicator id
def _make_id(kind: str, value: str) -> str:
    ns = uuid.uuid5(uuid.NAMESPACE_URL, 'https://sift-agent.local/')
    return f'{kind}--{uuid.uuid5(ns, value)}'

# build stix bundle from iocs dict
def build_stix(iocs: dict, created: str | None = None) -> dict:
    if created is None:
        created = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    
    objects = []
    
    # identity object
    identity_id = f'identity--{uuid.uuid5(uuid.NAMESPACE_URL, "sift-agent")}'
    objects.append({
        'type': 'identity',
        'spec_version': '2.1',
        'id': identity_id,
        'created': created,
        'modified': created,
        'name': 'sift-agent',
        'identity_class': 'system'
    })
    
    # helper to escape stix patterns
    def _esc(s: str) -> str:
        return s.replace('\\', '\\\\').replace("'", "\\'")

    # indicator objects
    for kind, vals in iocs.items():
        for val in vals:
            pattern = None
            if kind == 'ip':
                pattern = f"[ipv4-addr:value = '{_esc(val)}']"
            elif kind == 'domain':
                pattern = f"[domain-name:value = '{_esc(val)}']"
            elif kind == 'url':
                pattern = f"[url:value = '{_esc(val)}']"
            elif kind == 'hash':
                h_len = len(val)
                if h_len == 64:
                    pattern = f"[file:hashes.'SHA-256' = '{_esc(val)}']"
                elif h_len == 40:
                    pattern = f"[file:hashes.'SHA-1' = '{_esc(val)}']"
                elif h_len == 32:
                    pattern = f"[file:hashes.MD5 = '{_esc(val)}']"
            
            if pattern:
                objects.append({
                    'type': 'indicator',
                    'spec_version': '2.1',
                    'id': _make_id('indicator', f'{kind}:{val}'),
                    'created': created,
                    'modified': created,
                    'valid_from': created,
                    'name': f'{kind} indicator {val}',
                    'pattern_type': 'stix',
                    'pattern': pattern
                })
                
    return {
        'type': 'bundle',
        'id': f'bundle--{uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(iocs, sort_keys=True))}',
        'spec_version': '2.1',
        'objects': objects
    }

# return stix json for a run
def stix_from_run(runs_dir: Path, created: str | None = None) -> str:
    iocs = extract_iocs(runs_dir)
    return json.dumps(build_stix(iocs, created), indent=2)
