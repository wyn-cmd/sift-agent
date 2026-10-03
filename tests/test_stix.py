import pytest
import json
import uuid
from pathlib import Path
from sift_agent.stix import build_stix

def test_empty_iocs():
    bundle = build_stix({})
    assert len(bundle['objects']) == 1
    assert bundle['objects'][0]['type'] == 'identity'

def test_indicators():
    iocs = {
        'ip': ['1.2.3.4'],
        'domain': ['example.com'],
        'url': ['http://a.b/c'],
        'hash': ['a' * 64, 'b' * 40, 'c' * 32, 'd' * 10]
    }
    bundle = build_stix(iocs)
    # 1 identity + 1 ip + 1 domain + 1 url + 3 valid hashes
    assert len(bundle['objects']) == 7
    
    types = [o['type'] for o in bundle['objects']]
    assert types.count('indicator') == 6

def test_hash_types():
    iocs = {'hash': ['a' * 64, 'b' * 40, 'c' * 32]}
    bundle = build_stix(iocs)
    patterns = [o['pattern'] for o in bundle['objects'] if o['type'] == 'indicator']
    assert any("SHA-256" in p for p in patterns)
    assert any("SHA-1" in p for p in patterns)
    assert any("MD5" in p for p in patterns)

def test_deterministic():
    iocs = {'ip': ['1.1.1.1']}
    b1 = build_stix(iocs)
    b2 = build_stix(iocs)
    assert b1 == b2

def test_quoting():
    iocs = {'domain': ["example'site.com"]}
    bundle = build_stix(iocs)
    pattern = bundle['objects'][1]['pattern']
    assert "\\'" in pattern
    assert pattern == "[domain-name:value = 'example\\'site.com']"

def test_created():
    ts = "2026-10-03T00:00:00.000Z"
    iocs = {'ip': ['8.8.8.8']}
    bundle = build_stix(iocs, created=ts)
    for obj in bundle['objects']:
        assert obj['created'] == ts
        assert obj.get('modified', ts) == ts
        if obj['type'] == 'indicator':
            assert obj['valid_from'] == ts

def test_json_roundtrip():
    iocs = {'url': ['http://x.y/z']}
    bundle = build_stix(iocs)
    assert json.loads(json.dumps(bundle)) == bundle
