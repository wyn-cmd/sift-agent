import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def run_help(*args):
    return subprocess.run([sys.executable, '-m', 'sift_agent', *args, '--help'], cwd=ROOT, capture_output=True, text=True)

# Every subcommand listed in the top level help must print its own usage and exit cleanly
def test_every_subcommand_has_working_help():
    top = run_help()
    assert top.returncode == 0
    names = re.search(r'\{([^}]+)\}', top.stdout).group(1).split(',')
    assert len(names) >= 20
    for name in names:
        r = run_help(name)
        assert r.returncode == 0 and 'usage:' in r.stdout, f'{name}: {r.stderr[-200:]}'

def test_offline_commands_say_what_is_missing(tmp_path):
    for name in ('summary', 'tree', 'ports', 'exits', 'defang'):
        r = subprocess.run([sys.executable, '-m', 'sift_agent', name, '--runs', str(tmp_path / 'nope')],
                           cwd=ROOT, capture_output=True, text=True)
        assert r.returncode != 0 and 'Traceback' not in r.stderr, f'{name}: {r.stderr[-200:]}'
