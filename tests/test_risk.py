import json
import pytest
from sift_agent.risk import risk_report, format_risk, risk_from_run

PSLIST = ('PID\tPPID\tImageFileName\tOffset(V)\tSessionId\tCreateTime\n'
          '4\t0\tSystem\t0x1\tN/A\tN/A\n'
          '368\t4\tsmss.exe\t0x2\tN/A\tN/A\n'
          '700\t368\tsvch0st.exe\t0x3\t0\t2012-07-22 02:42:35.000000 UTC\n'
          '900\t999\tsvchost.exe\t0x4\t0\tN/A\n'
          '1200\t700\tpowershell.exe\t0x5\t0\tN/A')
CMDLINE = ('PID\tProcess\tArgs\n'
           '1200\tpowershell.exe\tpowershell.exe -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACkA')
# three public remotes on one process, so the cap and the ordering are both exercised
NETSCAN = ('Offset\tProto\tLocalAddr\tLocalPort\tForeignAddr\tForeignPort\tState\tPID\tOwner\tCreated\n'
           '0x1\tTCPv4\t0.0.0.0\t999\t8.8.8.8\t4444\tESTABLISHED\t1200\t-\tN/A\n'
           '0x2\tTCPv4\t0.0.0.0\t999\t1.1.1.1\t80\tESTABLISHED\t1200\t-\tN/A\n'
           '0x3\tTCPv4\t0.0.0.0\t999\t9.9.9.9\t443\tESTABLISHED\t1200\t-\tN/A\n'
           '0x4\tTCPv4\t0.0.0.0\t999\t0.0.0.0\t0\tLISTENING\t1200\t-\tN/A\n'
           '0x5\tTCPv4\t10.0.0.5\t4444\t93.184.216.34\t80\tESTABLISHED\t900\t-\tN/A')
TOOLS = {'pslist': 'windows.pslist', 'cmdline': 'windows.cmdline', 'netscan': 'windows.netscan'}

def build(tmp_path, pslist=PSLIST, cmdline=CMDLINE, netscan=NETSCAN):
    run = tmp_path / 'run'
    raw = run / 'raw'
    raw.mkdir(parents=True)
    log = []
    for name, text in [('pslist', pslist), ('cmdline', cmdline), ('netscan', netscan)]:
        if text is None:
            continue
        (raw / f'{name}.txt').write_text(text, encoding='utf-8')
        log.append(json.dumps({'tool': TOOLS[name], 'raw_output_file': f'raw/{name}.txt'}))
    (run / 'audit.jsonl').write_text('\n'.join(log) + '\n', encoding='utf-8')
    return run

# The four checks in one table: an anomaly, a cmdflag, a public connection and a low listening port
def test_signals_are_fused_and_ranked(tmp_path):
    report = risk_report(build(tmp_path))
    assert [p['pid'] for p in report['processes']] == ['1200', '700', '900']
    assert [p['score'] for p in report['processes']] == [12, 5, 3]
    assert report['clean'] == 2

def test_reasons_name_the_signal(tmp_path):
    procs = {p['pid']: p for p in risk_report(build(tmp_path))['processes']}
    assert 'flagged command line: encoded PowerShell command' in procs['1200']['reasons']
    assert 'name is a script host or proxy binary' in procs['1200']['reasons']
    assert 'listening on port 999, below 1024 and not a routine port' in procs['1200']['reasons']
    assert 'rule anomaly: name imitates svchost.exe' in procs['700']['reasons']
    assert 'parent is not in the process list' in procs['900']['reasons']
    assert 'connection to public address 93.184.216.34' in procs['900']['reasons']

# The remote weight is capped at two addresses and picks them in a stable order
def test_public_connections_are_capped_and_ordered(tmp_path):
    reasons = {p['pid']: p['reasons'] for p in risk_report(build(tmp_path))['processes']}
    remotes = [r for r in reasons['1200'] if 'public address' in r]
    assert remotes == ['connection to public address 1.1.1.1', 'connection to public address 8.8.8.8']
    assert not any('9.9.9.9' in r for r in reasons['1200'])
    # a private address never counts
    assert not any('10.0.0.5' in r for r in reasons['900'])

def test_same_run_scores_identically_twice(tmp_path):
    first = risk_report(build(tmp_path / 'a'))
    second = risk_report(build(tmp_path / 'b'))
    assert first['processes'] == second['processes']

# Ties break on the numeric PID, so PID 9 is listed before PID 10
def test_ties_sort_by_numeric_pid(tmp_path):
    rows = ('PID\tPPID\tImageFileName\tSessionId\n'
            '10\t11\taaa.exe\t0\n'
            '9\t8\tbbb.exe\t0')
    report = risk_report(build(tmp_path, pslist=rows, cmdline=None, netscan=None))
    assert [p['pid'] for p in report['processes']] == ['9', '10']
    assert [p['score'] for p in report['processes']] == [2, 2]

# A run with no network or command line output still scores from the process list alone
def test_network_and_cmdline_are_optional(tmp_path):
    no_net = {p['pid']: p for p in risk_report(build(tmp_path / 'a', netscan=None))['processes']}
    assert no_net['1200']['score'] == 6
    no_cmd = {p['pid']: p for p in risk_report(build(tmp_path / 'b', cmdline=None))['processes']}
    assert no_cmd['1200']['score'] == 9
    assert 'name is a script host or proxy binary' in no_cmd['1200']['reasons']
    both = risk_report(build(tmp_path / 'c', cmdline=None, netscan=None))
    assert {p['pid']: p['score'] for p in both['processes']}['1200'] == 3
    assert both['clean'] == 2

def test_empty_pslist_is_refused(tmp_path):
    with pytest.raises(ValueError):
        risk_report(build(tmp_path, pslist='PID\tPPID\tImageFileName\n'))

def test_missing_audit_log_is_refused(tmp_path):
    (tmp_path / 'run').mkdir()
    with pytest.raises(FileNotFoundError):
        risk_report(tmp_path / 'run')

def test_format_and_wrapper_agree(tmp_path):
    run = build(tmp_path)
    text = risk_from_run(run)
    assert format_risk(risk_report(run)) == text
    assert 'SCORE 12 PID 1200 powershell.exe:' in text
    assert '2 of 5 processes scored 0' in text
