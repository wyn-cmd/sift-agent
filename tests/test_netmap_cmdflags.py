from sift_agent.tables import parse_table
from sift_agent.netmap import build_netmap
from sift_agent.cmdflags import scan_cmdlines

# Sample network connection table data used for testing map generation.
NET = ("Offset\tProto\tLocalAddr\tLocalPort\tForeignAddr\tForeignPort\tState\tPID\tOwner\tCreated\n"
       "0x1\tTCPv4\t10.0.0.2\t1050\t8.8.8.8\t8080\tESTABLISHED\t1640\tevil.exe\tN/A\n"
       "0x2\tTCPv4\t10.0.0.2\t1051\t10.0.0.9\t445\tESTABLISHED\t4\tSystem\tN/A\n"
       "0x3\tTCPv4\t0.0.0.0\t135\t0.0.0.0\t0\tLISTENING\t900\tsvchost.exe\tN/A\n")

def test_netmap_flags_external_only():
    # Verify that external addresses are flagged correctly while local ones are not.
    out = build_netmap(parse_table(NET))
    assert 'to 8.8.8.8:8080 ESTABLISHED [external]' in out
    assert 'to 10.0.0.9:445 ESTABLISHED' in out
    assert 'to 10.0.0.9:445 ESTABLISHED [external]' not in out
    assert 'listens on 0.0.0.0:135' in out

def test_netmap_empty():
    # Ensure empty input yields the default fallback string.
    assert build_netmap([]).startswith('No network rows')

def test_cmdflags_detects_patterns():
    # Check process argument scanner flags suspicious execution patterns.
    rows = [{'PID': '1', 'Process': 'powershell.exe', 'Args': 'powershell -nop -w hidden -enc ' + 'QQ' * 20},
            {'PID': '2', 'Process': 'a.exe', 'Args': 'C:\\Users\\Public\\a.exe'},
            {'PID': '3', 'Process': 'notepad.exe', 'Args': 'notepad.exe notes.txt'}]
    found = scan_cmdlines(rows)
    reasons = {w for _, _, w, _ in found}
    assert 'encoded PowerShell command' in reasons and 'hidden window' in reasons
    assert 'runs from a temp or shared writable path' in reasons
    assert all(p != '3' for p, _, _, _ in found)

def test_netmap_ignores_failed_plugin_text():
    # Ensure traceback or plugin error text does not break network parsing.
    junk = "Offset\tProto\tLocalAddr\tLocalPort\n\n[stderr]\nTraceback (most recent call last):\n"
    assert build_netmap(parse_table(junk)).startswith('No network rows')
