from pathlib import Path

# yara-python is optional: the rest of the tool works without it
def load_rules(path: Path):
    try:
        import yara
    except ImportError:
        raise RuntimeError('--yara needs the yara-python package (pip install yara-python)')
    path = Path(path)
    if path.is_dir():
        files = {p.stem: str(p) for p in sorted(path.glob('*.yar')) + sorted(path.glob('*.yara'))}
        if not files:
            raise ValueError(f'no .yar or .yara files in {path}')
        return yara.compile(filepaths=files)
    if not path.is_file():
        raise FileNotFoundError(f'YARA rules not found: {path}')
    return yara.compile(filepath=str(path))

# Names of the rules that match one dumped file
def scan_file(rules, path: Path) -> list[str]:
    return sorted({m.rule for m in rules.match(str(path))})
