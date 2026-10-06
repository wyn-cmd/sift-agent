from runhelp import make_run
from sift_agent.exits import exits_from_run

PS = ("PID\tPPID\tImageFileName\tCreateTime\tExitTime\n"
      "4\t0\tSystem\tN/A\tN/A\n"
      "10\t4\tquick.exe\t2012-07-22 02:40:00.000000 UTC\t2012-07-22 02:40:03.000000 UTC\n"
      "11\t4\tslow.exe\t2012-07-22 02:00:00.000000 UTC\t2012-07-22 03:00:00.000000 UTC\n"
      "12\t4\todd.exe\tN/A\t2012-07-22 03:00:00.000000 UTC\n")

def test_exits_sorted_and_marked(tmp_path):
    run, _ = make_run(tmp_path, {'windows.pslist': PS})
    lines = exits_from_run(run).splitlines()
    assert lines[0].startswith('PID 10 quick.exe: lived 3s (short)')
    assert lines[1].startswith('PID 11 slow.exe: lived 3600s,') and '(short)' not in lines[1]
    assert lines[2].startswith('PID 12 odd.exe: lifetime unknown')
    assert len(lines) == 3

def test_exits_threshold_and_none(tmp_path):
    run, _ = make_run(tmp_path, {'windows.pslist': PS})
    assert '(short)' not in exits_from_run(run, under=1).splitlines()[0]
    run2, _ = make_run(tmp_path / 'b')
    assert exits_from_run(run2) == 'no exited processes in the list.'
