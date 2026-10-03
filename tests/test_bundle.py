import json
import pytest
import zipfile
from pathlib import Path
from sift_agent.bundle import build_manifest, write_bundle

# tests the bundle module with a synthetic run directory
def test_bundle(tmp_path: Path):
    run_dir = tmp_path / 'run-1'
    run_dir.mkdir()
    
    # create audit.jsonl
    audit = run_dir / 'audit.jsonl'
    lines = [
        {"tool": "plugin.a", "tool_call_id": "1", "event_type": "call"},
        {"tool": "plugin.a", "tool_call_id": "2", "event_type": "call"},
        {"tool": "plugin.a", "event_type": "final model answer", "details": {"answer": "result"}},
        {"tool": "plugin.a", "event_type": "test", "tool_call_id": "3"}
    ]
    audit.write_text("\n".join(json.dumps(l) for l in lines))
    
    # create raw files
    raw_dir = run_dir / 'raw'
    raw_dir.mkdir()
    (raw_dir / '1').write_text('content1')
    (raw_dir / '2').write_text('content2')
    
    # test build_manifest counts
    m = build_manifest(run_dir)
    assert m['tool_calls'] == 4
    assert m['events'] == 4
    assert m['plugins']['plugin.a'] == 4
    
    # test file list sorted and hashes
    paths = [f['path'] for f in m['files']]
    assert sorted(paths) == paths
    assert any(f['path'] == 'audit.jsonl' for f in m['files'])
    
    # test evidence
    evidence = tmp_path / 'evidence.txt'
    evidence.write_text('evidence content')
    m_ev = build_manifest(run_dir, evidence=evidence)
    assert m_ev['evidence']['path'] == 'evidence.txt'
    
    # test write_bundle
    out_zip = tmp_path / 'bundle.zip'
    res = write_bundle(run_dir, out_zip, evidence=evidence)
    assert out_zip.exists()
    
    with zipfile.ZipFile(out_zip, 'r') as zf:
        names = zf.namelist()
        assert 'manifest.json' in names
        assert 'report.md' in names
        assert 'audit.jsonl' in names
        
        # compare manifest
        m_in = json.loads(zf.read('manifest.json').decode('utf-8'))
        assert m_in == m_ev
        
    # test redact
    out_zip_red = tmp_path / 'bundle_red.zip'
    res_red = write_bundle(run_dir, out_zip_red, redact_text=True)
    with zipfile.ZipFile(out_zip_red, 'r') as zf:
        report = zf.read('report.md').decode('utf-8')
        assert report.startswith("REDACTED\n")
        
    # test missing audit
    with pytest.raises(FileNotFoundError, match='no audit.jsonl in'):
        build_manifest(tmp_path / 'empty')
