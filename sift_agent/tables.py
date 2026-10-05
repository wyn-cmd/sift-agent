import json
from pathlib import Path

# Split a Volatility TSV table into dict rows keyed by the header, skipping the banner and blank lines
def parse_table(raw: str) -> list[dict]:
    rows = [l for l in raw.splitlines() if l.strip() and not l.startswith('Volatility 3 Framework')]
    if len(rows) < 2:
        return []
    header = [h.strip() for h in rows[0].split('\t')]
    out = []
    for line in rows[1:]:
        cols = line.split('\t')
        if len(cols) < len(header):
            cols += [''] * (len(header) - len(cols))
        out.append({h: c.strip() for h, c in zip(header, cols)})
    return out

# Load the raw output of every call of one plugin from a saved run, in log order
# Yield the dict entries of an audit log, skipping blank lines and lines that are not valid JSON,
# so one damaged line does not stop an offline command; verify-audit is where damage is reported
def iter_entries(log: Path):
    for line in Path(log).read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(e, dict):
            yield e

def raw_for(runs_dir: Path, plugin: str) -> list[str]:
    log = Path(runs_dir) / 'audit.jsonl'
    if not log.exists():
        raise FileNotFoundError(f'no audit.jsonl in {runs_dir}')
    out = []
    for line in log.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        if e.get('tool') == plugin and 'raw_output_file' in e:
            p = Path(runs_dir) / e['raw_output_file']
            if p.is_file():
                out.append(p.read_text(encoding='utf-8'))
    return out

# Convenience: parsed rows of the first successful call of a plugin, or an empty list
def rows_for(runs_dir: Path, plugin: str) -> list[dict]:
    for raw in raw_for(runs_dir, plugin):
        rows = parse_table(raw)
        if rows:
            return rows
    return []
