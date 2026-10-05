from runhelp import make_run, PSLIST
from sift_agent.procdiff import diff_runs

def test_diff_reports_new_missing_and_counts(tmp_path):
    a, _ = make_run(tmp_path / 'a')
    extra = PSLIST + "800\t650\tsvchost.exe\t0\t2012-01-01\tN/A\n900\t650\tevil.exe\t0\t2012-01-01\tN/A\n"
    b, _ = make_run(tmp_path / 'b', {'windows.pslist': extra.replace('smss.exe', 'smss2.exe')})
    out = diff_runs(a, b)
    assert 'only in A: smss.exe' in out and 'evil.exe' in out and 'smss2.exe' in out
    assert 'svchost.exe (1 vs 2)' in out

def test_diff_needs_pslist(tmp_path):
    a, _ = make_run(tmp_path / 'a')
    b, _ = make_run(tmp_path / 'b', {'windows.info': 'x'})
    try:
        diff_runs(a, b)
        assert False
    except ValueError:
        pass
