import json
from pathlib import Path
from sift_agent.audit import AuditLog

PSLIST = ("Volatility 3 Framework 2.28.2\n\n"
          "PID\tPPID\tImageFileName\tSessionId\tCreateTime\tExitTime\n"
          "4\t0\tSystem\tN/A\tN/A\tN/A\n"
          "368\t4\tsmss.exe\tN/A\t2012-01-01\tN/A\n"
          "600\t368\twinlogon.exe\t0\t2012-01-01\tN/A\n"
          "650\t600\tservices.exe\t0\t2012-01-01\tN/A\n"
          "700\t650\tsvchost.exe\t0\t2012-01-01\tN/A\n")

# Build a saved run from {plugin: raw output}; returns (runs dir, {plugin: call id})
def make_run(tmp_path: Path, calls=None, answer='[]'):
    calls = {'windows.pslist': PSLIST} if calls is None else calls
    log = AuditLog(tmp_path / 'audit.jsonl')
    ids = {plugin: log.log_tool(plugin, {}, raw) for plugin, raw in calls.items()}
    log.log_event('final model answer', {'answer': answer})
    return tmp_path, ids
