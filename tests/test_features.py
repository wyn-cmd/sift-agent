import io
import json
import urllib.error
from sift_agent.audit import AuditLog
from sift_agent.report import generate_report
from sift_agent.verify import verify_audit
from sift_agent.replay import replay
from sift_agent.dump import pick_pids, dump_and_hash, format_hash_section
from sift_agent.vt import VirusTotal

PSLIST = 'PID\tPPID\tImageFileName\n4\t0\tSystem\n1640\t1484\treader_sl.exe\n500\t4\tsmss.exe\n'

# Confidence is derived from how many different plugins back a verified claim
def test_confidence_from_independent_tools(tmp_path):
    audit = AuditLog(tmp_path / 'a.jsonl')
    c1 = audit.log_tool('windows.pslist', {}, PSLIST)
    c2 = audit.log_tool('windows.cmdline', {}, 'PID\tArgs\n1640\treader_sl.exe --x\n')
    one = {'claim': 'c', 'status': 'confirmed', 'tool_call_ids': [c1], 'excerpt': '1640 1484 reader_sl.exe', 'confidence': 'high'}
    two = {'claim': 'c', 'status': 'confirmed', 'tool_call_ids': [c1, c2], 'excerpt': '1640 1484 reader_sl.exe'}
    fake = {'claim': 'c', 'status': 'confirmed', 'tool_call_ids': [c1, c2], 'excerpt': 'nope'}
    rep = generate_report([one, two, fake], audit, [], 2, False)
    assert rep.count('Confidence: high') == 1 and rep.count('Confidence: medium') == 1 and rep.count('Confidence: low') == 1

def test_verify_audit_detects_tampering(tmp_path):
    audit = AuditLog(tmp_path / 'audit.jsonl')
    cid = audit.log_tool('windows.pslist', {}, PSLIST)
    assert verify_audit(tmp_path / 'audit.jsonl')[0]
    (tmp_path / 'raw' / f'{cid}.txt').write_text(PSLIST.replace('1640', '9999'))
    ok, lines = verify_audit(tmp_path / 'audit.jsonl')
    assert not ok and any('SHA-256 mismatch' in l for l in lines)
    (tmp_path / 'raw' / f'{cid}.txt').unlink()
    assert any('missing' in l for l in verify_audit(tmp_path / 'audit.jsonl')[1])

def test_replay_rebuilds_report(tmp_path):
    audit = AuditLog(tmp_path / 'audit.jsonl')
    cid = audit.log_tool('windows.pslist', {}, PSLIST)
    audit.log_event('final model answer', {'answer': json.dumps([{'claim': 'reader runs', 'status': 'confirmed', 'tool_call_ids': [cid], 'excerpt': '1640 1484 reader_sl.exe'}])})
    rep = replay(tmp_path)
    assert 'Status: confirmed' in rep and 'Confidence: medium' in rep and 'windows.netscan' in rep

def test_replay_without_answer_fails(tmp_path):
    AuditLog(tmp_path / 'audit.jsonl').log_tool('windows.pslist', {}, PSLIST)
    try:
        replay(tmp_path)
        assert False
    except ValueError:
        pass

def test_pick_pids_skips_system_names():
    assert pick_pids(PSLIST) == [(1640, 'reader_sl.exe')]

class DumpRunner:
    def dump(self, evidence, pid, out_dir):
        (__import__('pathlib').Path(out_dir) / f'pid.{pid}.0x1.dmp').write_bytes(b'MZ fake image')
        return 0, '', ''

class FakeResp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False

def test_dump_hash_and_virustotal(tmp_path):
    audit = AuditLog(tmp_path / 'audit.jsonl')
    body = {'data': {'attributes': {'last_analysis_stats': {'malicious': 7, 'suspicious': 0, 'harmless': 0, 'undetected': 60}}}}
    seen = []
    def opener(req, timeout=0):
        seen.append(req.full_url)
        return FakeResp(json.dumps(body).encode())
    vt = VirusTotal('k', min_interval=0, opener=opener)
    res = dump_and_hash(DumpRunner(), 'e', PSLIST, tmp_path / 'dumps', audit, vt)
    f = res[0]['files'][0]
    assert len(f['sha256']) == 64 and f['virustotal']['malicious'] == 7 and seen[0].endswith(f['sha256'])
    assert 'VirusTotal: 7 malicious' in '\n'.join(format_hash_section(res))
    assert any('process dump' in l for l in (tmp_path / 'audit.jsonl').read_text().splitlines())

def test_virustotal_404_and_rate_spacing():
    def nf(req, timeout=0):
        raise urllib.error.HTTPError(req.full_url, 404, 'nf', {}, None)
    naps = []
    t = [100.0]
    vt = VirusTotal('k', min_interval=15, opener=nf, clock=lambda: t[0], sleep=naps.append)
    assert vt.lookup('a' * 64)['found'] is False
    vt.lookup('b' * 64)
    assert naps and naps[0] == 15


# The hash chain catches an edited line, a deleted line and a reordered pair
def test_audit_chain_detects_line_edits(tmp_path):
    audit = AuditLog(tmp_path / 'audit.jsonl')
    for i in range(3):
        audit.log_tool('windows.pslist', {'n': i}, f'out {i}')
    log = tmp_path / 'audit.jsonl'
    good = log.read_text().splitlines()
    assert verify_audit(log)[0]
    log.write_text('\n'.join([good[0], good[1].replace('"n": 1', '"n": 9'), good[2]]) + '\n')
    assert any('line hash mismatch' in p for p in verify_audit(log)[1])
    log.write_text('\n'.join([good[0], good[2]]) + '\n')
    assert any('chain broken' in p for p in verify_audit(log)[1])
    log.write_text('\n'.join([good[0], good[2], good[1]]) + '\n')
    assert not verify_audit(log)[0]

# Lines from before the chain existed are reported, not failed
def test_verify_accepts_legacy_lines(tmp_path):
    import hashlib
    (tmp_path / 'raw').mkdir()
    (tmp_path / 'raw' / 'x.txt').write_text('hi')
    e = {'tool_call_id': 'x', 'raw_output_file': 'raw/x.txt', 'raw_output_len': 2, 'raw_output_sha256': hashlib.sha256(b'hi').hexdigest()}
    (tmp_path / 'audit.jsonl').write_text(json.dumps(e) + '\n')
    ok, lines = verify_audit(tmp_path / 'audit.jsonl')
    assert ok and any('no hash chain' in l for l in lines)

class BothRunner:
    def dump_files(self, evidence, pid, out_dir):
        (__import__('pathlib').Path(out_dir) / f'file.0x1.0x2.ImageSectionObject.reader_sl.exe.img').write_bytes(b'MZ img')
        (__import__('pathlib').Path(out_dir) / f'file.0x1.0x2.ImageSectionObject.kernel32.dll.img').write_bytes(b'MZ dll')
        return 0, '', ''
    def dump(self, evidence, pid, out_dir):
        raise AssertionError('fallback must not run when dumpfiles works')

# dumpfiles is preferred and only the process's own image is kept; a failing dumpfiles falls back
def test_dumpfiles_preferred_with_fallback(tmp_path):
    audit = AuditLog(tmp_path / 'audit.jsonl')
    res = dump_and_hash(BothRunner(), 'e', PSLIST, tmp_path / 'd1', audit)
    assert res[0]['method'] == 'windows.dumpfiles' and [f['file'] for f in res[0]['files']] == ['file.0x1.0x2.ImageSectionObject.reader_sl.exe.img']
    res = dump_and_hash(DumpRunner(), 'e', PSLIST, tmp_path / 'd2', audit)
    assert res[0]['method'] == 'windows.pslist --dump'
