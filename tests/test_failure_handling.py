import json
from sift_agent.audit import AuditLog
from sift_agent.agent import Agent
from sift_agent.rate_limiter import RateLimiter
from sift_agent.tools import process_output

BANNER = 'Volatility 3 Framework 2.28.2\n\nOffset\tProto\tPID\n'

# A crash after the header was printed is a failure, not an empty table
def test_crash_after_header_is_a_failure():
    msg, failed, _ = process_output(BANNER, 'Traceback...\nNotImplementedError: not supported: 5.1 15.2600!', 1)
    assert failed and 'exited with code 1' in msg and 'NotImplementedError' in msg
    assert 'No data rows were produced' in msg

# Rows printed before a crash are reported as partial
def test_partial_rows_before_crash_are_noted():
    msg, failed, _ = process_output(BANNER + '0x1\tTCP\t4\n0x2\tTCP\t8\n', 'boom', 1)
    assert failed and 'Partial output before the failure: 2 data rows' in msg

# stderr warnings with a zero exit code are not a failure
def test_warning_on_stderr_with_success_is_not_failure():
    _, failed, _ = process_output(BANNER + '0x1\tTCP\t4\n', 'WARNING something benign', 0)
    assert not failed

# The agent tells the model the call failed, and the audit log keeps stdout and stderr
def test_agent_reports_failed_plugin_as_data(tmp_path):
    audit = AuditLog(tmp_path / 'a.jsonl')
    class R:
        def run(self, plugin, ev):
            return 1, BANNER, 'NotImplementedError: unsupported'
    class L:
        n = 0
        def chat(self, messages, tools):
            L.n += 1
            if L.n == 1:
                return {'tool_calls': [{'name': 'windows.netscan', 'arguments': {}}]}
            return {'content': '[]', 'conclude': True}
    a = Agent(L(), R(), audit, RateLimiter(state_file=str(tmp_path / 'u.json')), 'e.raw', require_all_tools=False)
    a.run()
    entry = [json.loads(l) for l in open(tmp_path / 'a.jsonl') if 'tool_call_id' in l][0]
    raw = audit.read_raw(entry['tool_call_id'])
    assert 'NotImplementedError' in raw and 'Offset' in raw
