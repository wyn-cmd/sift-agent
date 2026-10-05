from sift_agent.audit import AuditLog
from sift_agent.report import validate_findings

def test_exact_repeats_collapse_but_different_status_kept(tmp_path):
    log = AuditLog(tmp_path / 'audit.jsonl')
    cid = log.log_tool('windows.pslist', {}, 'PID\n4\n')
    good = {'claim': 'System runs', 'status': 'confirmed', 'tool_call_ids': [cid], 'excerpt': '4'}
    dup = dict(good, claim='  system RUNS ')
    guess = {'claim': 'System runs', 'status': 'inference', 'tool_call_ids': []}
    other = dict(good, excerpt='4 ')
    out = validate_findings([good, dup, guess], log)
    assert [f['status'] for f in out] == ['confirmed', 'inference']
