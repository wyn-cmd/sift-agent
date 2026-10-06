from runhelp import make_run
from sift_agent.ports import ports_from_run

HEAD = "Offset\tProto\tLocalAddr\tLocalPort\tForeignAddr\tForeignPort\tState\tPID\tOwner\tCreated\n"
NET = (HEAD +
       "0x1\tTCPv4\t10.0.0.2\t1050\t8.8.8.8\t8080\tESTABLISHED\t1640\tevil.exe\tN/A\n"
       "0x2\tTCPv4\t10.0.0.2\t1051\t1.1.1.1\t443\tESTABLISHED\t1700\tbrowser.exe\tN/A\n"
       "0x3\tTCPv4\t10.0.0.2\t1052\t1.1.1.1\t443\tESTABLISHED\t1700\tbrowser.exe\tN/A\n"
       "0x4\tTCPv4\t0.0.0.0\t135\t0.0.0.0\t0\tLISTENING\t900\tsvchost.exe\tN/A\n")

def test_ports_summary(tmp_path):
    run, _ = make_run(tmp_path, {'windows.netscan': NET})
    out = ports_from_run(run)
    assert 'listening: 135 (svchost.exe)' in out
    assert 'remote ports: 443 x2, 8080 x1' in out
    assert 'unusual remote ports: 8080 from evil.exe (PID 1640)' in out

def test_ports_without_network_rows(tmp_path):
    run, _ = make_run(tmp_path)
    assert ports_from_run(run).startswith('No network rows')
