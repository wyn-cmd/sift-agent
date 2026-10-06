from runhelp import make_run
from sift_agent.window import window_from_run

PS = ("PID\tPPID\tImageFileName\tCreateTime\n4\t0\tSystem\tN/A\n10\t4\ta.exe\t2012-07-22 02:40:00\n"
      "11\t4\tb.exe\t2012-07-22 02:43:00\n12\t4\tc.exe\t2012-07-23 01:00:00\n")

def test_window_selects_and_orders(tmp_path):
    run, _ = make_run(tmp_path, {'windows.pslist': PS})
    out = window_from_run(run, '2012-07-22 02:30', '2012-07-22 23:59')
    assert out.splitlines()[0].startswith('2012-07-22 02:40:00  PID 10 a.exe')
    assert 'c.exe' not in out and 'System' not in out and len(out.splitlines()) == 2

def test_window_handles_identical_timestamps(tmp_path):
    ps = "PID\tPPID\tImageFileName\tCreateTime\n11\t4\tb.exe\t2012-07-22 02:43:00\n10\t4\ta.exe\t2012-07-22 02:43:00\n"
    run, _ = make_run(tmp_path, {'windows.pslist': ps})
    out = window_from_run(run, '2012', '2013').splitlines()
    assert [l.split()[3] for l in out] == ['10', '11']

def test_window_empty_and_reversed(tmp_path):
    run, _ = make_run(tmp_path, {'windows.pslist': PS})
    assert window_from_run(run, '2013', '2014').startswith('no processes')
    try:
        window_from_run(run, '2014', '2013')
        assert False
    except ValueError:
        pass

def test_window_end_date_covers_the_whole_day(tmp_path):
    run, _ = make_run(tmp_path, {'windows.pslist': PS})
    out = window_from_run(run, '2012-07-22', '2012-07-22')
    assert 'a.exe' in out and 'b.exe' in out and 'c.exe' not in out

def test_window_minute_precision_end(tmp_path):
    run, _ = make_run(tmp_path, {'windows.pslist': PS})
    out = window_from_run(run, '2012-07-22 02:00', '2012-07-22 02:40')
    assert 'a.exe' in out and 'b.exe' not in out
