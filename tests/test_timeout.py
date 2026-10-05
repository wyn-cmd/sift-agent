from sift_agent.tools import plugin_timeout

def test_default_and_override(monkeypatch):
    monkeypatch.delenv('SIFT_PLUGIN_TIMEOUT', raising=False)
    assert plugin_timeout() == 60
    monkeypatch.setenv('SIFT_PLUGIN_TIMEOUT', '300')
    assert plugin_timeout() == 300

def test_bad_values_fall_back(monkeypatch):
    for bad in ('abc', '0', '-5', ''):
        monkeypatch.setenv('SIFT_PLUGIN_TIMEOUT', bad)
        assert plugin_timeout() == 60
