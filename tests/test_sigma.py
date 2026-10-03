import pytest
from pathlib import Path
from sift_agent.sigma import rules_from_run, format_sigma

yaml = pytest.importorskip('yaml')

def test_sigma_rules(tmp_path):
    run_dir = tmp_path / 'run'
    run_dir.mkdir()
    (run_dir / 'audit.jsonl').write_text('{"tool": "windows.cmdline", "raw_output_file": "cmd.txt"}')
    # PID|Process|Reason|Args: 1 encoded, 2 hidden, 3 proxy binary, 4 URL
    # Reason: encoded PowerShell command (high), hidden window (medium), script host or proxy binary (medium), URL in arguments (low)
    # PID\tProcess\tReason\tArgs
    # We must match the header expected by rows_for/parse_table
    (run_dir / 'cmd.txt').write_text('PID\tProcess\tReason\tArgs\n1\tpowershell.exe\tencoded PowerShell command\t-encodedcommand QkFTRTY0U1RSSU5HRklMTEVE\n2\thidden.exe\thidden window\t-windowstyle hidden\n3\tcmd.exe\tscript host or proxy binary\trundll32\n4\tcalc.exe\tURL in the arguments\thttps://evil.com')
    
    rules = rules_from_run(run_dir)
    assert len(rules) == 4
    
    # Check levels
    assert next(r for r in rules if 'encoded' in r['title'])['level'] == 'high'
    assert next(r for r in rules if 'hidden' in r['title'])['level'] == 'medium'
    assert next(r for r in rules if 'script host' in r['title'])['level'] == 'medium'
    assert next(r for r in rules if 'URL' in r['title'])['level'] == 'low'
    
    # Check logsource/detection structure
    rule = rules[0]
    assert rule['logsource']['category'] == 'process_creation'
    assert 'CommandLine|contains' in rule['detection']['selection']
    
    # Check yaml parsing
    yaml_output = format_sigma(rules)
    yaml_data = yaml.safe_load(yaml_output)
    assert len(yaml_data) == 4
    for i in range(4):
        assert yaml_data[i]['title'] == rules[i]['title']
        assert yaml_data[i]['level'] == rules[i]['level']

def test_cap_and_no_rules(tmp_path):
    # Cap 20
    run_dir_cap = tmp_path / 'run_cap'
    run_dir_cap.mkdir()
    (run_dir_cap / 'audit.jsonl').write_text('{"tool": "windows.cmdline", "raw_output_file": "cmd.txt"}')
    # Use unique Args for each row to avoid de-duplication
    # We must match the header expected by rows_for/parse_table
    content = 'PID\tProcess\tReason\tArgs\n' + '\n'.join([f'{i}\trundll32\tscript host or proxy binary\trundll32_{i}' for i in range(30)])
    (run_dir_cap / 'cmd.txt').write_text(content)
    rules = rules_from_run(run_dir_cap)
    assert len(rules) == 20
    
    # No flags
    run_dir_none = tmp_path / 'run_none'
    run_dir_none.mkdir()
    (run_dir_none / 'audit.jsonl').write_text('{"tool": "windows.cmdline", "raw_output_file": "cmd.txt"}')
    (run_dir_none / 'cmd.txt').write_text('PID\tProcess\tReason\tArgs\n1\tproc\tclean\tclean')
    rules = rules_from_run(run_dir_none)
    assert rules == []
    assert format_sigma(rules) == '# no rules were generated because no command line was flagged'
    
    # ValueError
    run_dir_val = tmp_path / 'run_val'
    run_dir_val.mkdir()
    (run_dir_val / 'audit.jsonl').write_text('{"tool": "windows.cmdline", "raw_output_file": "cmd.txt"}')
    (run_dir_val / 'cmd.txt').write_text('pid\tproc\treason\targs')
    with pytest.raises(ValueError):
        rules_from_run(run_dir_val)
