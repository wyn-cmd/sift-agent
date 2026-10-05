from runhelp import make_run
from sift_agent.stats import run_stats
from sift_agent.iocs import extract_iocs
from sift_agent.tables import rows_for
from sift_agent.export import export_json

def damage(run):
    with open(run / 'audit.jsonl', 'a') as f:
        f.write('{broken\n')

def test_offline_commands_skip_a_damaged_line(tmp_path):
    run, _ = make_run(tmp_path, answer='[]')
    damage(run)
    assert 'tool calls: 1' in run_stats(run)
    assert extract_iocs(run)['ip'] == []
    assert len(rows_for(run, 'windows.pslist')) == 5
    assert '"findings": []' in export_json(run)
