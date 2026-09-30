import json
import pytest
from sift_agent.audit import AuditLog
from sift_agent.guardrails import load_allowlist
from sift_agent.verify import verify_audit, head_hash
from sift_agent.tools import process_output
from sift_agent.dump import dump_and_hash, format_hash_section
from sift_agent.yarascan import load_rules, scan_file

PSLIST = 'PID\tPPID\tImageFileName\n1640\t1484\treader_sl.exe\n'

# The head hash pins the whole log: a full rewrite that keeps the chain valid is still caught
def test_expected_head_detects_rewrite(tmp_path):
    audit = AuditLog(tmp_path / 'audit.jsonl')
    audit.log_tool('windows.pslist', {}, 'a')
    head = head_hash(tmp_path / 'audit.jsonl')
    assert verify_audit(tmp_path / 'audit.jsonl', head)[0]
    audit.log_event('extra', {})
    assert not verify_audit(tmp_path / 'audit.jsonl', head)[0]

def test_extended_allowlist_is_valid():
    from pathlib import Path
    tools = load_allowlist(Path(__file__).resolve().parent.parent / 'sift_agent' / 'allowlist-extended.json')
    assert {'windows.malfind', 'windows.psscan', 'windows.psxview'} <= tools

# malfind blocks keep their original order; psxview rows hidden from a view are ranked first
def test_plugin_specific_processing():
    raw = 'Volatility 3 Framework 2\n\nPID\tProcess\n1\tsvchost.exe\n2\tsvchost.exe\n'
    assert process_output(raw, '', 0, 'windows.malfind')[0].splitlines()[1:] == ['1\tsvchost.exe', '2\tsvchost.exe']
    px = 'Offset\tName\tpslist\tpsscan\n0x1\tsvchost.exe\tTrue\tTrue\n0x2\tsvchost.exe\tFalse\tTrue\n'
    assert process_output(px, '', 0, 'windows.psxview')[0].splitlines()[1].startswith('0x2')

class YRunner:
    def dump_files(self, evidence, pid, out_dir):
        (__import__('pathlib').Path(out_dir) / 'file.0x1.0x2.ImageSectionObject.reader_sl.exe.img').write_bytes(b'MZ WSAStartup VirtualAllocEx WriteProcessMemory')
        return 0, '', ''

def test_yara_scan_in_dump_report(tmp_path):
    pytest.importorskip('yara')
    rules = load_rules(__import__('pathlib').Path(__file__).resolve().parent.parent / 'sift_agent' / 'rules')
    res = dump_and_hash(YRunner(), 'e', PSLIST, tmp_path / 'd', AuditLog(tmp_path / 'a.jsonl'), yara_rules=rules)
    assert res[0]['files'][0]['yara'] == ['Suspicious_Winsock_Downloader']
    assert 'YARA: Suspicious_Winsock_Downloader' in '\n'.join(format_hash_section(res))
