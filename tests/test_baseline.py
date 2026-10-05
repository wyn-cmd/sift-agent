from runhelp import make_run
from sift_agent.baseline import baseline_from_run, load_baseline

def test_baseline_flags_unknown(tmp_path):
    run, _ = make_run(tmp_path / 'run')
    base = tmp_path / 'base.txt'
    base.write_text('# core\nSystem\nsmss.exe\nservices.exe # svc\n\n')
    assert load_baseline(base) == {'system', 'smss.exe', 'services.exe'}
    out = baseline_from_run(run, base)
    assert 'winlogon.exe: not in baseline (PIDs 600)' in out and 'smss.exe' not in out

def test_baseline_all_known_and_empty(tmp_path):
    run, _ = make_run(tmp_path / 'run')
    base = tmp_path / 'b.txt'
    base.write_text('system\nsmss.exe\nwinlogon.exe\nservices.exe\nsvchost.exe\n')
    assert baseline_from_run(run, base) == 'every process is in the baseline.'
    base.write_text('# nothing\n')
    try:
        baseline_from_run(run, base)
        assert False
    except ValueError:
        pass
