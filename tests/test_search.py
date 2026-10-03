import pytest
import json
from pathlib import Path
from sift_agent.search import search_run, format_search

def test_search_basic(tmp_path):
    run_dir = tmp_path / 'run1'
    run_dir.mkdir()
    (run_dir / 'audit.jsonl').write_text(
        '{"tool": "plugin1", "raw_output_file": "out1.txt"}\n'
    )
    (run_dir / 'out1.txt').write_text('line1\nline2\nmatch\nline4')
    
    res = search_run(run_dir, 'match')
    assert len(res['hits']) == 1
    assert res['hits'][0]['line_no'] == 3
    assert res['hits'][0]['line'] == 'match'
    
def test_search_filters(tmp_path):
    run_dir = tmp_path / 'run1'
    run_dir.mkdir()
    (run_dir / 'audit.jsonl').write_text(
        '{"tool": "p1", "raw_output_file": "o1.txt"}\n'
        '{"tool": "p2", "raw_output_file": "o2.txt"}\n'
    )
    (run_dir / 'o1.txt').write_text('match')
    (run_dir / 'o2.txt').write_text('match')
    
    res = search_run(run_dir, 'match', plugins=['p1'])
    assert len(res['hits']) == 1
    assert res['hits'][0]['plugin'] == 'p1'

def test_search_errors(tmp_path):
    with pytest.raises(ValueError, match='empty pattern'):
        search_run(tmp_path, ' ')
    with pytest.raises(ValueError, match='bad pattern'):
        search_run(tmp_path, '(')
    with pytest.raises(FileNotFoundError):
        search_run(tmp_path, 'foo')