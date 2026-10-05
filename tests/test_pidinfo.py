from runhelp import make_run, PSLIST
from sift_agent.pidinfo import pidinfo_from_run

CMD = "PID\tProcess\tArgs\n700\tsvchost.exe\tC:\\Windows\\system32\\svchost.exe -k netsvcs\n"
NET = "Offset\tProto\tLocalAddr\tLocalPort\tForeignAddr\tForeignPort\tState\tPID\tOwner\tCreated\n0x1\tTCPv4\t10.0.0.2\t1\t8.8.8.8\t443\tESTABLISHED\t700\tsvchost.exe\tN/A\n"

def test_pidinfo_collects_everything(tmp_path):
    run, _ = make_run(tmp_path, {'windows.pslist': PSLIST, 'windows.cmdline': CMD, 'windows.netscan': NET})
    out = pidinfo_from_run(run, 700)
    assert 'process: svchost.exe (PID 700, parent 650' in out
    assert 'chain: svchost.exe (700) <- services.exe (650)' in out
    assert '-k netsvcs' in out and 'TCPv4 10.0.0.2:1 -> 8.8.8.8:443 ESTABLISHED' in out

def test_pidinfo_missing_data_and_pid(tmp_path):
    run, _ = make_run(tmp_path)
    out = pidinfo_from_run(run, 650)
    assert 'command line: not in this run' in out and 'sockets: none in this run' in out
    try:
        pidinfo_from_run(run, 9)
        assert False
    except ValueError:
        pass
