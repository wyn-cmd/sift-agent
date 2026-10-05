from pathlib import Path
from sift_agent.tables import rows_for

# Names in a baseline file, one per line, lowercase; blank lines and # comments are ignored
def load_baseline(path: Path) -> set[str]:
    names = set()
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        line = line.split('#', 1)[0].strip().lower()
        if line:
            names.add(line)
    return names

# Report process names that are not in the baseline of a known-good host
def baseline_from_run(runs_dir: Path, baseline_file: Path) -> str:
    rows = rows_for(runs_dir, 'windows.pslist')
    if not rows:
        raise ValueError('the run has no usable windows.pslist output')
    known = load_baseline(baseline_file)
    if not known:
        raise ValueError('the baseline file has no process names')
    seen = {}
    for r in rows:
        if r['ImageFileName'].lower() not in known:
            seen.setdefault(r['ImageFileName'], []).append(r['PID'])
    if not seen:
        return 'every process is in the baseline.'
    return '\n'.join(f"{n}: not in baseline (PIDs {', '.join(p)})" for n, p in sorted(seen.items()))
