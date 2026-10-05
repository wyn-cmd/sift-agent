from runhelp import make_run
from sift_agent.lineage import lineage_from_run, lineage

def test_lineage_chain(tmp_path):
    run, _ = make_run(tmp_path)
    assert lineage_from_run(run, 700) == 'svchost.exe (700) <- services.exe (650) <- winlogon.exe (600) <- smss.exe (368) <- System (4)'

def test_lineage_missing_parent_and_loop():
    rows = [{'PID': '10', 'PPID': '99', 'ImageFileName': 'a.exe'},
            {'PID': '20', 'PPID': '21', 'ImageFileName': 'b.exe'}, {'PID': '21', 'PPID': '20', 'ImageFileName': 'c.exe'}]
    assert lineage(rows, 10).endswith('(parent PID 99 not in the list)')
    assert lineage(rows, 20).endswith('(loop)')

def test_lineage_unknown_pid(tmp_path):
    run, _ = make_run(tmp_path)
    try:
        lineage_from_run(run, 12345)
        assert False
    except ValueError as e:
        assert '12345' in str(e)
