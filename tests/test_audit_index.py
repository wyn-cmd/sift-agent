from sift_agent.audit import AuditLog

def test_lookup_sees_new_entries_after_cache(tmp_path):
    log = AuditLog(tmp_path / 'audit.jsonl')
    a = log.log_tool('windows.info', {}, 'one')
    assert log.lookup(a)['tool'] == 'windows.info'
    b = log.log_tool('windows.pslist', {}, 'two')
    assert log.lookup(b)['tool'] == 'windows.pslist'
    assert log.lookup('missing') is None

def test_lookup_skips_bad_lines(tmp_path):
    log = AuditLog(tmp_path / 'audit.jsonl')
    a = log.log_tool('windows.info', {}, 'one')
    with open(tmp_path / 'audit.jsonl', 'a') as f:
        f.write('not json\n')
    assert log.lookup(a) is not None
