from pathlib import Path
from sift_agent.tables import rows_for

# Draw the process tree from pslist rows. A process whose parent is missing becomes a root, which
# is itself worth noticing, so those roots are marked with a star.
def build_tree(rows: list[dict]) -> str:
    by_pid = {r['PID']: r for r in rows if r.get('PID')}
    kids: dict[str, list[str]] = {}
    roots = []
    for pid, r in by_pid.items():
        ppid = r.get('PPID', '')
        if ppid in by_pid and ppid != pid:
            kids.setdefault(ppid, []).append(pid)
        else:
            roots.append(pid)
    lines, seen = [], set()

    def walk(pid, depth):
        if pid in seen:
            return
        seen.add(pid)
        r = by_pid[pid]
        orphan = '*' if depth == 0 and r.get('PPID') not in ('0', '') else ''
        lines.append(f"{'  ' * depth}{r.get('ImageFileName', '?')} (PID {pid}, PPID {r.get('PPID', '?')}){orphan}")
        for c in sorted(kids.get(pid, []), key=lambda p: int(p) if p.isdigit() else 0):
            walk(c, depth + 1)

    for pid in sorted(roots, key=lambda p: int(p) if p.isdigit() else 0):
        walk(pid, 0)
    if any(l.endswith('*') for l in lines):
        lines.append('')
        lines.append('* parent process not in the list (exited, hidden or never scanned)')
    return '\n'.join(lines)

def tree_from_run(runs_dir: Path) -> str:
    rows = rows_for(runs_dir, 'windows.pslist')
    if not rows:
        raise ValueError('the run has no usable windows.pslist output')
    return build_tree(rows)
