import pytest
from sift_agent.audit import AuditLog
from sift_agent.agent import Agent
from sift_agent.rate_limiter import RateLimiter
from sift_agent.report import generate_report

class R:
    def __init__(self):
        self.ran = []

    def run(self, plugin, ev):
        self.ran.append(plugin)
        return 0, 'PID\tName\n1\ta.exe', ''

def make(tmp_path, llm, **kw):
    return Agent(llm, R(), AuditLog(tmp_path / 'a.jsonl'), RateLimiter(state_file=str(tmp_path / 'u.json')), 'e.raw', **kw)

# A model that never stops asking for tools must still be stopped by the call cap
def test_run_stops_at_the_configured_cap(tmp_path):
    class L:
        def chat(self, messages, tools):
            return {'tool_calls': [{'name': 'windows.info', 'arguments': {}}]}
    a = make(tmp_path, L(), require_all_tools=False, max_calls=3)
    a.run()
    assert a.tool_calls_count == 3 and len(a.runner.ran) == 3

# The cap defaults to 15 when the caller does not choose one
def test_default_cap_is_fifteen(tmp_path):
    class L:
        def chat(self, messages, tools):
            return {'content': '[]', 'conclude': True}
    a = make(tmp_path, L())
    assert a.max_calls == 15
    assert a.runner is not None
    assert 'Calls used vs cap: 0 / 15' in a.build_report()

# The chosen cap reaches the report instead of a hardcoded 15
def test_report_states_the_chosen_cap(tmp_path):
    audit = AuditLog(tmp_path / 'a.jsonl')
    rep = generate_report([], audit, [], 2, False, calls_cap=4)
    assert 'Calls used vs cap: 2 / 4' in rep

# A cap below one makes no sense and is refused at construction
def test_cap_below_one_is_refused(tmp_path):
    class L:
        def chat(self, messages, tools):
            return {'content': '[]'}
    with pytest.raises(ValueError, match='max_calls'):
        make(tmp_path, L(), max_calls=0)

# The cap also bounds the nudge loop, so a stubborn model cannot be pushed past it
def test_nudge_respects_the_cap(tmp_path):
    class L:
        def chat(self, messages, tools):
            return {'content': '[]', 'conclude': True}
    a = make(tmp_path, L(), max_calls=1, max_nudges=5)
    # The cap is already used up, so no further nudge is sent even though plugins are missing
    a.tool_calls_count = 1
    assert a.nudge_if_early([]) is False
