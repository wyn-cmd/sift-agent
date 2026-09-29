import json
from sift_agent.audit import AuditLog
from sift_agent.agent import Agent
from sift_agent.rate_limiter import RateLimiter
from sift_agent.report import generate_report, parse_findings

# The full raw output is stored beside the log even when far over the 2000 char head cap
def test_full_raw_output_is_kept(tmp_path):
    audit = AuditLog(tmp_path / 'a.jsonl')
    raw = 'x' * 5000 + 'TAILMARK'
    cid = audit.log_tool('windows.pslist', {}, raw, 'short')
    assert audit.read_raw(cid) == raw
    assert audit.lookup(cid)['raw_output_file'] == f'raw/{cid}.txt'
    assert audit.read_raw('../etc/passwd') is None and audit.read_raw('nope') is None

# A confirmed claim whose excerpt is not in the cited raw output is downgraded
def test_excerpt_must_appear_in_cited_output(tmp_path):
    audit = AuditLog(tmp_path / 'a.jsonl')
    cid = audit.log_tool('windows.pslist', {}, 'PID Name\n' + 'a' * 3000 + '\n77 realproc.exe')
    good = {'claim': 'c', 'status': 'confirmed', 'tool_call_ids': [cid], 'excerpt': '77   realproc.exe'}
    bad = {'claim': 'c', 'status': 'confirmed', 'tool_call_ids': [cid], 'excerpt': '99 invented.exe'}
    rep = generate_report([good, bad], audit, [], 1, False)
    assert rep.count('Status: confirmed') == 1 and rep.count('Status: unconfirmed inference') == 1

def test_parse_findings_variants():
    items = [{'claim': 'a', 'status': 'confirmed', 'tool_call_ids': ['1'], 'excerpt': 'e'}]
    assert parse_findings(json.dumps(items))[0]['claim'] == 'a'
    assert parse_findings('Here you go:\n```json\n' + json.dumps(items) + '\n```')[0]['tool_call_ids'] == ['1']
    fb = parse_findings('just prose, no json')
    assert fb[0]['status'] == 'unconfirmed inference' and 'just prose' in fb[0]['claim']

# End to end with a scripted model: an honest and a fabricated finding come out differently
def test_build_report_validates_model_findings(tmp_path):
    audit = AuditLog(tmp_path / 'a.jsonl')
    rl = RateLimiter(state_file=str(tmp_path / 'u.json'))
    class L:
        n = 0
        def chat(self, messages, tools):
            L.n += 1
            if L.n == 1:
                return {'tool_calls': [{'name': 'windows.pslist', 'arguments': {}}]}
            cid = [m for m in messages if m['role'] == 'tool'][0]['tool_call_id']
            f = [{'claim': 'real', 'status': 'confirmed', 'tool_call_ids': [cid], 'excerpt': '5 blorp.exe'},
                 {'claim': 'made up', 'status': 'confirmed', 'tool_call_ids': [cid], 'excerpt': '6 ghost.exe'}]
            return {'content': json.dumps(f)}
    class R:
        def run(self, plugin, ev):
            return 0, 'PID Name\n5 blorp.exe', ''
    rep = Agent(L(), R(), audit, rl, 'e.raw').build_report()
    assert rep.count('Status: confirmed') == 1
    assert 'Status: unconfirmed inference' in rep and 'Calls used vs cap: 1 / 15' in rep

# Non-adjacent real rows are accepted, but one invented row among them downgrades the claim
def test_multi_row_excerpt_needs_every_line_real(tmp_path):
    audit = AuditLog(tmp_path / 'a.jsonl')
    cid = audit.log_tool('windows.netscan', {}, 'h\n1 aaa\n2 filler\n3 bbb\n4 more\n5 ccc')
    ok = {'claim': 'c', 'status': 'confirmed', 'tool_call_ids': [cid], 'excerpt': '1 aaa\n3 bbb\n5 ccc'}
    bad = {'claim': 'c', 'status': 'confirmed', 'tool_call_ids': [cid], 'excerpt': '1 aaa\n9 fake'}
    rep = generate_report([ok, bad], audit, [], 1, False)
    assert rep.count('Status: confirmed') == 1 and rep.count('Status: unconfirmed inference') == 1
