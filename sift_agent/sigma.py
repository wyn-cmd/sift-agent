import uuid
from pathlib import Path
from sift_agent.tables import rows_for
from sift_agent.cmdflags import scan_cmdlines

# returns a quoted scalar if it needs YAML escaping
def _yaml_scalar(v: str) -> str:
    v = str(v)
    if not v:
        return '""'
    
    # Needs quotes if leading/trailing whitespace or problematic chars or special sequences
    needs_quotes = (
        v.startswith((' ', '\t', '\n', '\r')) or v.endswith((' ', '\t', '\n', '\r')) or
        ': ' in v or v.endswith(':') or ' #' in v or '\n' in v or '\t' in v or
        v.startswith(('#', '-', '?', ':', '!', '&', '*', '>', '|', '%', '@', '`', '"', "'", '[', ']', '{', '}'))
    )
    
    if needs_quotes:
        # Escape backslashes and double quotes
        v = v.replace('\\', '\\\\').replace('"', '\\"')
        return f'"{v}"'
    return v

# Map reasons to severity levels
LEVEL_MAP = {
    'encoded PowerShell command': 'high',
    'download cradle': 'high',
    'hidden window': 'medium',
    'script host or proxy binary': 'medium',
    'runs from a temp or shared writable path': 'medium'
}

def rules_from_run(runs_dir: Path) -> list[dict]:
    # Extract rows using sift_agent.tables
    rows = list(rows_for(runs_dir, 'windows.cmdline'))
    if not rows:
        raise ValueError('the run has no usable windows.cmdline output')
    
    # Scan command lines
    flagged = scan_cmdlines(rows)
    
    rules = []
    seen = set()
    
    for pid, proc, reason, args in flagged:
        # Deduplication key
        key = (reason, args)
        if key in seen:
            continue
        if len(rules) >= 20:
            break
        
        # UUID generation
        uid_str = f"https://sift-agent.local/sigma/{reason}/{args}"
        rule_id = str(uuid.uuid5(uuid.NAMESPACE_URL, uid_str))
        
        # Determine level
        level = LEVEL_MAP.get(reason, 'low')
        
        # Detection logic
        selection = {'CommandLine|contains': args} if args else {'CommandLine|contains': proc}
        
        rule = {
            'title': f'Suspicious command line: {reason}',
            'id': rule_id,
            'status': 'experimental',
            'description': f'Process {proc} with PID {pid} executed a suspicious command. This is a lead for an analyst and not a verdict.',
            'references': ['sift-agent'],
            'tags': ['attack.execution'],
            'logsource': {'category': 'process_creation', 'product': 'windows'},
            'detection': {'selection': selection, 'condition': 'selection'},
            'falsepositives': ['Legitimate software can match the pattern.'],
            'level': level
        }
        
        rules.append(rule)
        seen.add(key)
        
    return rules

def format_sigma(rules: list[dict]) -> str:
    if not rules:
        return '# no rules were generated because no command line was flagged'
    
    yaml_lines = []
    keys = ['title', 'id', 'status', 'description', 'references', 'tags', 'logsource', 'detection', 'falsepositives', 'level']

    for rule in rules:
        # Every rule is one item of a top level list, so the first key carries the dash and
        # everything else in that rule sits two spaces in, with nested values two deeper again
        for k in keys:
            v = rule[k]
            pad = '- ' if k == keys[0] else '  '
            if isinstance(v, list):
                yaml_lines.append(f'{pad}{k}:')
                for item in v:
                    yaml_lines.append(f'{pad}  - {_yaml_scalar(item)}')
            elif isinstance(v, dict):
                yaml_lines.append(f'{pad}{k}:')
                for sk, sv in v.items():
                    if isinstance(sv, dict):
                        yaml_lines.append(f'{pad}  {sk}:')
                        for ssk, ssv in sv.items():
                            yaml_lines.append(f'{pad}    {ssk}: {_yaml_scalar(ssv)}')
                    else:
                        yaml_lines.append(f'{pad}  {sk}: {_yaml_scalar(sv)}')
            else:
                yaml_lines.append(f'{pad}{k}: {_yaml_scalar(v)}')
        yaml_lines.append('')
    
    return '\n'.join(yaml_lines).strip()

def sigma_from_run(runs_dir: Path) -> str:
    return format_sigma(rules_from_run(runs_dir))
