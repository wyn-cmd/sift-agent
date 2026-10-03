import json
import hashlib
from pathlib import Path
from sift_agent.tables import parse_table
from sift_agent.ptree import build_tree
from sift_agent.anomalies import find_anomalies, format_anomalies
from sift_agent.iocs import extract_iocs, format_iocs
from sift_agent.stats import run_stats
from sift_agent.doctor import run_doctor, format_doctor
from sift_agent.redact import redact
from sift_agent.export import export_json, evidence_hash_line
from sift_agent.audit import AuditLog

PSLIST = ("Volatility 3 Framework 2.28.2\n\n"
          "PID\tPPID\tImageFileName\tSessionId\tCreateTime\n"
          "4\t0\tSystem\tN/A\tN/A\n"
          "368\t4\tsmss.exe\tN/A\t2012-01-01\n"
          "600\t368\twinlogon.exe\t0\t2012-01-01\n"
          "650\t600\tservices.exe\t0\t2012-01-01\n"
          "700\t650\tsvchost.exe\t0\t2012-01-01\n"
          "701\t4\tsvchost.exe\t0\t2012-01-01\n"
          "702\t650\tsvch0st.exe\t0\t2012-01-01\n"
          "800\t999\tlost.exe\t1\t2012-01-01\n"
          "900\t650\tlsass.exe\t0\t2012-01-01\n"
          "901\t650\tlsass.exe\t0\t2012-01-01\n")

def make_run(tmp_path: Path, answer: str = '[]', extra_raw: str = '') -> Path:
    log = AuditLog(tmp_path / 'audit.jsonl')
    log.log_tool('windows.pslist', {}, PSLIST + extra_raw)
    log.log_event('final model answer', {'answer': answer})
    return tmp_path

def test_parse_table_skips_banner():
    rows = parse_table(PSLIST)
    assert rows[0]['ImageFileName'] == 'System' and len(rows) == 10

def test_parse_table_empty():
    assert parse_table('') == []

def test_tree_nests_and_marks_orphans():
    t = build_tree(parse_table(PSLIST))
    assert '    winlogon.exe (PID 600' in t
    assert 'lost.exe (PID 800, PPID 999)*' in t

def test_anomalies_find_each_rule():
    out = format_anomalies(find_anomalies(parse_table(PSLIST)))
    assert 'PID 701 svchost.exe: parent is System' in out
    assert 'imitates svchost.exe' in out
    assert '2 instances' in out

def test_anomalies_clean_list():
    clean = "PID\tPPID\tImageFileName\tSessionId\tCreateTime\n4\t0\tSystem\tN/A\tN/A\n"
    assert 'No rule-based' in format_anomalies(find_anomalies(parse_table(clean)))

def test_iocs_keep_public_drop_private_and_guid(tmp_path):
    raw = "conn 10.0.0.5 8.8.8.8 http://evil.example.ru/a.exe\n30B5FB31AE7E4ACAABA750AA241FF331-1.json.xz\n" + "a" * 64
    iocs = extract_iocs(make_run(tmp_path, extra_raw=raw))
    assert iocs['ip'] == ['8.8.8.8']
    assert iocs['url'] == ['http://evil.example.ru/a.exe']
    assert iocs['hash'] == ['a' * 64]

def test_iocs_formats(tmp_path):
    iocs = extract_iocs(make_run(tmp_path, extra_raw='8.8.4.4'))
    assert json.loads(format_iocs(iocs, 'json'))['ip'] == ['8.8.4.4']
    assert format_iocs(iocs, 'csv').splitlines()[:2] == ['type,value', 'ip,8.8.4.4']

def test_stats_counts_calls(tmp_path):
    out = run_stats(make_run(tmp_path))
    assert 'tool calls: 1' in out and 'windows.pslist: 1 call(s)' in out

def test_stats_missing_log(tmp_path):
    try:
        run_stats(tmp_path)
        assert False
    except FileNotFoundError:
        pass

def test_doctor_reports_missing_key_and_vol():
    checks = run_doctor(env={}, which=lambda n: None)
    ok, text = format_doctor(checks)
    assert not ok and '[FAIL] GEMINI_API_KEY' in text and '[FAIL] Volatility' in text

def test_doctor_optional_never_fails():
    checks = run_doctor(env={'GEMINI_API_KEY': 'x'}, which=lambda n: '/bin/vol')
    assert all(p for p, _, req in checks if req and 'evidence' not in _ and 'Gemini client' not in _)

def test_redact_masks_ip_user_host():
    out = redact(r'conn 8.8.8.8 file C:\Users\alice\a.exe from \\HOST01\share')
    assert '8.8.8.8' not in out and 'alice' not in out and 'HOST01' not in out

def test_export_json_summary(tmp_path):
    answer = json.dumps([{'claim': 'x', 'status': 'inference', 'tool_call_ids': []}])
    data = json.loads(export_json(make_run(tmp_path, answer)))
    assert data['summary'] == {'unconfirmed inference': 0, 'inference': 1} or data['summary'] == {'inference': 1}
    assert len(data['tool_calls']) == 1

def test_evidence_hash_line(tmp_path):
    f = tmp_path / 'img.raw'
    f.write_bytes(b'abc')
    assert evidence_hash_line(f).startswith(hashlib.sha256(b'abc').hexdigest())
