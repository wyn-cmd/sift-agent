from runhelp import make_run
from sift_agent.defang import defang_value, defang_from_run

def test_defang_value_forms():
    assert defang_value('http://evil.example.com/a.exe') == 'hxxp://evil[.]example[.]com/a[.]exe'
    assert defang_value('HTTPS://x.io') == 'hxxps://x[.]io'
    assert defang_value('8.8.8.8') == '8[.]8[.]8[.]8'
    assert defang_value('abc123') == 'abc123'

def test_defang_from_run(tmp_path):
    run, _ = make_run(tmp_path, {'windows.cmdline': "PID\tArgs\n1\tcurl http://evil.example.com/a 8.8.8.8\n"})
    out = defang_from_run(run)
    assert 'ip 8[.]8[.]8[.]8' in out and 'hxxp://evil[.]example[.]com' in out
    assert 'http://' not in out and '8.8.8.8' not in out

def test_defang_nothing(tmp_path):
    run, _ = make_run(tmp_path)
    assert defang_from_run(run) == 'no indicators found.'
