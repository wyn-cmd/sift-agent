from sift_agent.cmdflags import scan_cmdlines

def reasons(args):
    return {w for _, _, w, _ in scan_cmdlines([{'PID': '1', 'Process': 'x.exe', 'Args': args}])}

def test_tampering_accounts_and_persistence():
    assert 'backup, recovery or log tampering' in reasons('vssadmin delete shadows /all /quiet')
    assert 'backup, recovery or log tampering' in reasons('wevtutil cl Security')
    assert 'local account creation' in reasons('net user backdoor P@ss /add')
    assert 'local account creation' in reasons('net localgroup administrators backdoor /add')
    assert 'persistence setup' in reasons('schtasks /create /tn x /tr c:\\a.exe')
    assert 'persistence setup' in reasons('reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x')

def test_ordinary_commands_stay_quiet():
    assert reasons('net user') == set()
    assert reasons('schtasks /query') == set()
    assert reasons('notepad.exe notes.txt') == set()
