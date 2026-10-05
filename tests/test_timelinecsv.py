import csv
import io
from runhelp import make_run
from sift_agent.timelinecsv import timeline_csv

def test_csv_rows(tmp_path):
    run, ids = make_run(tmp_path)
    rows = list(csv.reader(io.StringIO(timeline_csv(run))))
    assert rows[0][:3] == ['ts', 'kind', 'name']
    assert rows[1][1:4] == ['tool', 'windows.pslist', ids['windows.pslist']]
    assert rows[2][1:3] == ['event', 'final model answer']

def test_csv_missing_log(tmp_path):
    try:
        timeline_csv(tmp_path)
        assert False
    except FileNotFoundError:
        pass
