from sift_agent.tables import parse_table

def test_crlf_lines():
    raw = "Volatility 3 Framework 2.28.2\r\n\r\nPID\tPPID\r\n4\t0\r\n"
    assert parse_table(raw) == [{'PID': '4', 'PPID': '0'}]

def test_stderr_section_is_not_data():
    raw = "PID\tPPID\n4\t0\n\n[stderr]\nWARNING something\tbad\n"
    assert parse_table(raw) == [{'PID': '4', 'PPID': '0'}]
