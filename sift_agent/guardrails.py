import json
import os
from pathlib import Path
# Evidence is locked to one directory: SIFT_EVIDENCE_DIR if set, otherwise ./evidence in the repo
EVIDENCE_DIR = Path(os.environ.get('SIFT_EVIDENCE_DIR') or Path(__file__).resolve().parent.parent / 'evidence').resolve()
# The approved tool list lives in allowlist.json beside this file; SIFT_ALLOWLIST can point elsewhere
ALLOWLIST_FILE = Path(os.environ.get('SIFT_ALLOWLIST') or Path(__file__).resolve().parent / 'allowlist.json')

def load_allowlist(path: Path = ALLOWLIST_FILE) -> set:
    tools = json.loads(Path(path).read_text(encoding='utf-8')).get('tools')
    if not isinstance(tools, list) or not tools or not all(isinstance(t, str) and t.startswith('windows.') for t in tools):
        raise ValueError('allowlist.json needs a non-empty "tools" list of windows.* plugin names')
    return set(tools)

ALLOWED_TOOLS = load_allowlist()

class ToolNotAllowed(Exception):
    pass

def validate_path(user_path: str) -> Path:
    target = (EVIDENCE_DIR / user_path).resolve()
    if not target.is_relative_to(EVIDENCE_DIR):
        raise ValueError('Traversal attempt')
    if not target.is_file():
        raise FileNotFoundError('File missing or not a file')
    return target

def check_tool(tool_name: str):
    if tool_name not in ALLOWED_TOOLS:
        raise ToolNotAllowed(f'{tool_name} not allowed')
