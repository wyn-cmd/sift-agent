import json
from sift_agent.audit import AuditLog
from sift_agent.agent import Agent
from sift_agent.rate_limiter import RateLimiter
from sift_agent.gemini_client import GeminiClient

class R:
    def __init__(self):
        self.ran = []
    def run(self, plugin, ev):
        self.ran.append(plugin)
        return 0, 'PID Name\n1 a.exe', ''

def make(tmp_path, llm, **kw):
    return Agent(llm, R(), AuditLog(tmp_path / 'a.jsonl'), RateLimiter(state_file=str(tmp_path / 'u.json')), 'e.raw', **kw)

# A model that tries to stop after one tool is sent back until all four plugins have run
def test_early_stop_is_nudged_until_all_tools_run(tmp_path):
    class L:
        n = 0
        def chat(self, messages, tools):
            L.n += 1
            if L.n == 1:
                return {'tool_calls': [{'name': 'windows.pslist', 'arguments': {}}]}
            ran = {m['name'] for m in messages if m['role'] == 'tool'}
            nudged = any(m['role'] == 'user' and 'have not yet run' in m['content'] for m in messages)
            todo = [t for t in ['windows.info', 'windows.netscan', 'windows.cmdline'] if t not in ran]
            if nudged and todo:
                return {'tool_calls': [{'name': todo[0], 'arguments': {}}]}
            return {'content': '[]'}
    a = make(tmp_path, L())
    a.run()
    assert a.missing_tools() == [] and a.nudges >= 1
    assert sorted(a.runner.ran) == ['windows.cmdline', 'windows.info', 'windows.netscan', 'windows.pslist']

# A stubborn model is nudged at most max_nudges times, then the run ends and the gap is reported
def test_stubborn_model_is_capped_and_gap_reported(tmp_path):
    class L:
        def chat(self, messages, tools):
            return {'content': '[]', 'conclude': True}
    a = make(tmp_path, L(), max_nudges=2)
    a.run()
    assert a.nudges == 2 and len(a.missing_tools()) == 4
    assert 'Plugins never run: windows.cmdline' in a.build_report()

# The nudge can be switched off
def test_nudge_can_be_disabled(tmp_path):
    class L:
        def chat(self, messages, tools):
            return {'content': 'done', 'conclude': True}
    a = make(tmp_path, L(), require_all_tools=False)
    a.run()
    assert a.nudges == 0

# User turns must reach Gemini, otherwise the nudge is invisible to the model
def test_gemini_convert_keeps_user_nudge():
    _, contents = GeminiClient.convert([{'role': 'system', 'content': 's'},
                                        {'role': 'assistant', 'content': 'x'},
                                        {'role': 'user', 'content': 'You have not yet run: windows.info'}])
    assert 'You have not yet run' in contents[-1]['parts'][-1]['text']
