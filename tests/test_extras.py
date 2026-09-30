import json
import pytest
from sift_agent.audit import AuditLog
from sift_agent.guardrails import load_allowlist
from sift_agent.timeline import build_timeline
from sift_agent.compare import compare_runs

PS = 'PID\tImageFileName\n1640\treader_sl.exe\n'

def make_run(path, findings_fn):
    audit = AuditLog(path / 'audit.jsonl')
    cid = audit.log_tool('windows.pslist', {}, PS)
    audit.log_event('final model answer', {'answer': json.dumps(findings_fn(cid))})
    return path

def test_allowlist_loads_and_rejects_bad_config(tmp_path):
    assert 'windows.pslist' in load_allowlist()
    bad = tmp_path / 'a.json'
    bad.write_text('{"tools": ["rm -rf /"]}')
    with pytest.raises(ValueError):
        load_allowlist(bad)

def test_timeline_links_claims_to_calls(tmp_path):
    make_run(tmp_path, lambda c: [{'claim': 'reader runs <b>', 'status': 'confirmed', 'tool_call_ids': [c], 'excerpt': '1640 reader_sl.exe'}])
    page = build_timeline(tmp_path)
    assert 'windows.pslist' in page and 'claim 1' in page and '&lt;b&gt;' in page and 'run-data' in page

def test_compare_finds_disagreement(tmp_path):
    good = lambda c: [{'claim': 'reader runs', 'status': 'confirmed', 'tool_call_ids': [c], 'excerpt': '1640 reader_sl.exe'}]
    weak = lambda c: [{'claim': 'reader maybe runs', 'status': 'inference', 'tool_call_ids': [], 'excerpt': '1640 reader_sl.exe'}]
    a, b, c = make_run(tmp_path / 'a', good), make_run(tmp_path / 'b', good), make_run(tmp_path / 'c', weak)
    assert 'Confirmed in both runs: 1' in compare_runs(a, b)
    assert 'Disagreements' in compare_runs(a, c)
