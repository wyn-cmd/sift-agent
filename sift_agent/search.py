import re
import json
from pathlib import Path

def search_run(runs_dir: Path, pattern: str, plugins: list[str] | None = None, ignore_case: bool = False, context: int = 0, max_hits: int = 200) -> dict:
    if not pattern.strip():
        raise ValueError('empty pattern')
    try:
        regex = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    except re.error as e:
        raise ValueError(f'bad pattern: {e}')
    audit_path = runs_dir / 'audit.jsonl'
    if not audit_path.exists():
        raise FileNotFoundError(f'no audit.jsonl in {runs_dir}')
    
    hits = []
    files_scanned = 0
    lines_scanned = 0
    truncated = False
    
    with open(audit_path, 'r') as f:
        for line_json in f:
            # a blank separator or a half written line must not break the scan
            if not line_json.strip():
                continue
            entry = json.loads(line_json)
            if 'raw_output_file' not in entry:
                continue
            if plugins is not None and entry.get('tool') not in plugins:
                continue
            
            raw_file = runs_dir / entry['raw_output_file']
            if not raw_file.exists():
                continue
            files_scanned += 1
            
            with open(raw_file, 'r', errors='replace') as rf:
                lines = rf.readlines()
                for i, line in enumerate(lines):
                    lines_scanned += 1
                    if regex.search(line):
                        if len(hits) >= max_hits:
                            truncated = True
                            break
                        
                        start_ctx = max(0, i - context)
                        end_ctx = min(len(lines), i + context + 1)
                        
                        hit = {
                            'plugin': entry.get('tool', 'unknown'),
                            'file': entry['raw_output_file'],
                            'line_no': i + 1,
                            'line': line.strip()[:400],
                            'before': [l.strip()[:400] for l in lines[start_ctx:i]],
                            'after': [l.strip()[:400] for l in lines[i+1:end_ctx]]
                        }
                        hits.append(hit)
                if truncated:
                    break
                    
    return {
        'pattern': pattern,
        'plugins': plugins,
        'files_scanned': files_scanned,
        'lines_scanned': lines_scanned,
        'hits': hits,
        'truncated': truncated
    }

def format_search(result: dict) -> str:
    hits = result['hits']
    if not hits:
        return f"pattern '{result['pattern']}' found no matches in {result['files_scanned']} files"
    
    lines = [f"{len(hits)} hits in {result['files_scanned']} files"]
    for hit in hits:
        lines.append(f"{hit['plugin']} {hit['file']}:{hit['line_no']}: {hit['line']}")
        for line in hit['before']:
            lines.append(f"  | {line}")
        for line in hit['after']:
            lines.append(f"  | {line}")
    if result.get('truncated'):
        lines.append('hit limit was reached')
    return '\n'.join(lines)

def json_search(result: dict) -> str:
    return json.dumps(result, indent=2, sort_keys=True)