import json
from sift_agent.audit import AuditLog
from sift_agent.agent import SYSTEM_PROMPT
from sift_agent.report import generate_report, parse_findings

# The triage clause exists, is generic, and names no sample
def test_prompt_has_generic_triage_clause():
    p = SYSTEM_PROMPT.lower()
    assert 'assessment' in p and 'anomalous' in p and 'parent' in p
    for banned in ('reader_sl', '8080', 'cridex', 'stuxnet', 'zeus'):
        assert banned not in p

# A confirmed claim with an empty excerpt cannot stay confirmed
def test_empty_excerpt_is_not_confirmed(tmp_path):
    audit = AuditLog(tmp_path / 'a.jsonl')
    cid = audit.log_tool('windows.pslist', {}, 'PID\n1 a.exe')
    rep = generate_report([{'claim': 'c', 'status': 'confirmed', 'tool_call_ids': [cid], 'excerpt': ''}], audit, [], 1, False)
    assert 'Status: unconfirmed inference' in rep

# Assessment and reason are parsed, validated and rendered as a model judgment
def test_assessment_parsed_and_rendered(tmp_path):
    audit = AuditLog(tmp_path / 'a.jsonl')
    cid = audit.log_tool('windows.pslist', {}, 'PID\n1 a.exe')
    raw = json.dumps([{'claim': 'x', 'status': 'confirmed', 'tool_call_ids': [cid], 'excerpt': '1 a.exe',
                       'assessment': 'Anomalous', 'reason': 'odd parent'},
                      {'claim': 'y', 'status': 'inference', 'assessment': 'nonsense'}])
    fs = parse_findings(raw)
    assert fs[0]['assessment'] == 'anomalous' and fs[1]['assessment'] == ''
    rep = generate_report(fs, audit, [], 1, False)
    assert 'Assessment (model judgment): anomalous. odd parent' in rep
