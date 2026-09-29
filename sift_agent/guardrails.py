from pathlib import Path
# Lock evidence path
EVIDENCE_DIR = Path('/media/eurae/Hard Drive/github-repos/sift-agent/evidence').resolve()
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
