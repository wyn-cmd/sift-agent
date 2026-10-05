from runhelp import make_run, PSLIST
from sift_agent.hidden import hidden_from_run

SCAN = PSLIST + "666\t4\trootkit.exe\t0\t2012-01-01\tN/A\n777\t4\tdone.exe\t0\t2012-01-01\t2012-01-02\n"

def test_hidden_splits_running_and_ended(tmp_path):
    run, _ = make_run(tmp_path, {'windows.pslist': PSLIST, 'windows.psscan': SCAN})
    out = hidden_from_run(run)
    assert 'PID 666 rootkit.exe' in out and 'possibly hidden' in out
    assert 'PID 777 done.exe' in out and 'exited 2012-01-02' in out

def test_hidden_agreement(tmp_path):
    run, _ = make_run(tmp_path, {'windows.pslist': PSLIST, 'windows.psscan': PSLIST})
    assert hidden_from_run(run) == 'psscan and pslist agree.'

def test_hidden_requires_psscan(tmp_path):
    run, _ = make_run(tmp_path)
    try:
        hidden_from_run(run)
        assert False
    except ValueError:
        pass
