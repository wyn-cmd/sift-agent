import json
import pytest
from sift_agent.audit import AuditLog
from sift_agent.agent import Agent
from sift_agent.rate_limiter import RateLimiter, DailyLimitReached

class R:
    def run(self, plugin, ev):
        return 0, 'PID Name\n1 a.exe', ''

def make(tmp_path, llm, limiter=None, **kw):
    limiter = limiter or RateLimiter(state_file=str(tmp_path / 'u.json'), sleep=lambda s: None)
    return Agent(llm, R(), AuditLog(tmp_path / 'a.jsonl'), limiter, 'e.raw', require_all_tools=False, **kw), limiter

def events(tmp_path):
    return [json.loads(l) for l in open(tmp_path / 'a.jsonl')]

# The defaults match the limits observed at build time
def test_default_limits():
    rl = RateLimiter()
    assert (rl.rpm_limit, rl.tpm_limit, rl.rpd_limit) == (15, 250000, 500)

# Reaching the daily cap ends the run and never calls the model
def test_daily_cap_stops_the_run(tmp_path):
    rl = RateLimiter(rpd_limit=1, state_file=str(tmp_path / 'u.json'))
    rl.check_and_consume(100)
    with pytest.raises(DailyLimitReached):
        rl.check_and_consume(100)
    class L:
        called = 0
        def chat(self, messages, tools):
            L.called += 1
            return {'content': '[]', 'conclude': True}
    a, _ = make(tmp_path, L(), limiter=rl)
    a.run()
    assert L.called == 0
    assert any(e.get('event_type') == 'daily request limit reached' for e in events(tmp_path))

# A real 429 is waited out using the delay in the message, then retried
def test_429_is_retried_with_reported_delay(tmp_path):
    waits = []
    rl = RateLimiter(state_file=str(tmp_path / 'u.json'), sleep=waits.append)
    class L:
        n = 0
        def chat(self, messages, tools):
            L.n += 1
            if L.n == 1:
                raise RuntimeError('429 RESOURCE_EXHAUSTED. Please retry in 12.5s.')
            return {'content': '[]', 'conclude': True}
    a, _ = make(tmp_path, L(), limiter=rl)
    a.run()
    assert L.n == 2 and 13.5 in waits and a.rate_limit_approached
    assert any(e.get('event_type') == 'rate limited by API' for e in events(tmp_path))

# A 429 that never clears is raised after two retries, and other errors are not retried
def test_persistent_429_and_other_errors_propagate(tmp_path):
    class Always429:
        n = 0
        def chat(self, messages, tools):
            Always429.n += 1
            raise RuntimeError('429 RESOURCE_EXHAUSTED')
    a, _ = make(tmp_path, Always429())
    with pytest.raises(RuntimeError):
        a.run()
    assert Always429.n == 3
    class Boom:
        n = 0
        def chat(self, messages, tools):
            Boom.n += 1
            raise ValueError('bad request')
    b, _ = make(tmp_path, Boom())
    with pytest.raises(ValueError):
        b.run()
    assert Boom.n == 1
