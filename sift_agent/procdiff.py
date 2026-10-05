from pathlib import Path
from sift_agent.tables import rows_for

# Compare the process lists of two saved runs by image name, for example before and after an
# action or from two captures of the same host. PIDs change between boots, so names are the key.
def diff_runs(run_a: Path, run_b: Path) -> str:
    a, b = rows_for(run_a, 'windows.pslist'), rows_for(run_b, 'windows.pslist')
    if not a or not b:
        raise ValueError('both runs need usable windows.pslist output')
    names_a = {r['ImageFileName'].lower(): r for r in a}
    names_b = {r['ImageFileName'].lower(): r for r in b}
    only_a = sorted(set(names_a) - set(names_b))
    only_b = sorted(set(names_b) - set(names_a))
    count = lambda rows, n: sum(1 for r in rows if r['ImageFileName'].lower() == n)
    changed = sorted(n for n in set(names_a) & set(names_b) if count(a, n) != count(b, n))
    out = [f'processes: A {len(a)}, B {len(b)}']
    out.append('only in A: ' + (', '.join(only_a) or 'none'))
    out.append('only in B: ' + (', '.join(only_b) or 'none'))
    out.append('different instance count: ' + (', '.join(f'{n} ({count(a, n)} vs {count(b, n)})' for n in changed) or 'none'))
    return '\n'.join(out)
