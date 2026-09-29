import os
from pathlib import Path
# Evidence is locked to one directory: SIFT_EVIDENCE_DIR if set, otherwise ./evidence in the repo
EVIDENCE_DIR = Path(os.environ.get('SIFT_EVIDENCE_DIR') or Path(__file__).resolve().parent.parent / 'evidence').resolve()
ALLOWED_TOOLS = {'windows.info', 'windows.pslist', 'windows.netscan', 'windows.cmdline'}

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
