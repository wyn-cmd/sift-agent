import importlib.util
import os
import shutil
import sys
from pathlib import Path
from sift_agent.guardrails import EVIDENCE_DIR, ALLOWED_TOOLS

# Check the setup and return (ok, line) pairs; a failed required check makes the command exit non-zero
def run_doctor(env=None, which=shutil.which) -> list[tuple[bool, str, bool]]:
    env = os.environ if env is None else env
    checks = []
    checks.append((sys.version_info >= (3, 10), f'python {sys.version_info.major}.{sys.version_info.minor} (3.10 or newer needed)', True))
    checks.append((bool(which('vol') or which('vol3') or which('volatility3')), 'Volatility 3 command found (vol)', True))
    checks.append((bool(env.get('GEMINI_API_KEY')), 'GEMINI_API_KEY is set', True))
    checks.append((importlib.util.find_spec('google') is not None, 'Gemini client library importable', True))
    checks.append((Path(EVIDENCE_DIR).is_dir(), f'evidence directory exists ({EVIDENCE_DIR})', True))
    checks.append((bool(ALLOWED_TOOLS), f'allowlist loaded ({len(ALLOWED_TOOLS)} plugins)', True))
    checks.append((importlib.util.find_spec('yara') is not None, 'yara-python installed (optional, for --yara)', False))
    checks.append((bool(env.get('VT_API_KEY')), 'VT_API_KEY is set (optional, for --vt)', False))
    return checks

def format_doctor(checks) -> tuple[bool, str]:
    lines, ok = [], True
    for passed, text, required in checks:
        mark = 'ok  ' if passed else ('FAIL' if required else 'skip')
        lines.append(f'[{mark}] {text}')
        if required and not passed:
            ok = False
    return ok, '\n'.join(lines)
