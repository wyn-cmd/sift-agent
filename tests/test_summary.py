import json
from runhelp import make_run
from sift_agent.summary import run_summary
from sift_agent.audit import AuditLog

def test_summary_counts(tmp_path):
    log = AuditLog(tmp_path / 'audit.jsonl')
    cid = log.log_tool('windows.pslist', {}, 'PID\tPPID\tImageFileName\n4\t0\tSystem\n')
    ans = json.dumps([{'claim': 'System runs', 'status': 'confirmed', 'tool_call_ids': [cid], 'excerpt': '4\t0\tSystem'},
                      {'claim': 'guess', 'status': 'inference', 'tool_call_ids': []}])
    log.log_event('final model answer', {'answer': ans})
    out = run_summary(tmp_path)
    assert 'tool calls: 1' in out and 'findings: 2' in out and 'confirmed 1' in out
    assert 'medium 1, low 1' in out and 'processes: 1' in out

def test_summary_without_answer_raises(tmp_path):
    log = AuditLog(tmp_path / 'audit.jsonl')
    log.log_tool('windows.pslist', {}, 'x')
    try:
        run_summary(tmp_path)
        assert False
    except ValueError:
        pass
