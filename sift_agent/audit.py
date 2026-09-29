import json
import hashlib
from uuid import uuid4
from datetime import datetime, timezone
from pathlib import Path

class AuditLog:
    def __init__(self, log_path: Path):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        # Full raw plugin output lives here, one file per call, so nothing is lost to the log cap
        self.raw_dir = self.log_path.parent / 'raw'

    # Logs the raw plugin output hash and the processed view the model actually saw
    def log_tool(self, tool: str, args: dict, raw_output: str, processed_output: str | None = None) -> str:
        call_id = str(uuid4())
        if processed_output is None:
            processed_output = raw_output
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        (self.raw_dir / f'{call_id}.txt').write_text(raw_output, encoding='utf-8')
        entry = {
            'ts': datetime.now(timezone.utc).isoformat(),
            'tool_call_id': call_id,
            'tool': tool,
            'args': args,
            'raw_output_sha256': hashlib.sha256(raw_output.encode('utf-8')).hexdigest(),
            'raw_output_len': len(raw_output),
            'raw_output_file': f'raw/{call_id}.txt',
            'raw_output_head': raw_output[:2000],
            'processed_output_sha256': hashlib.sha256(processed_output.encode('utf-8')).hexdigest(),
            'output_truncated': processed_output[:2000]
        }
        with open(self.log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry) + '\n')
        return call_id

    def log_event(self, event_type: str, details: dict):
        entry = {
            'ts': datetime.now(timezone.utc).isoformat(),
            'event_type': event_type,
            'details': details
        }
        with open(self.log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry) + '\n')

    # Full raw output of a logged call, or None when the id or file is missing
    def read_raw(self, tool_call_id: str) -> str | None:
        if not tool_call_id or '/' in tool_call_id or '..' in tool_call_id:
            return None
        f = self.raw_dir / f'{tool_call_id}.txt'
        return f.read_text(encoding='utf-8') if f.exists() else None

    def lookup(self, tool_call_id: str) -> dict | None:
        if not self.log_path.exists():
            return None
        with open(self.log_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    if data.get('tool_call_id') == tool_call_id:
                        return data
                except json.JSONDecodeError:
                    continue
        return None
