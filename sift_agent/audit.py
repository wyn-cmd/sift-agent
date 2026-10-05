import json
import hashlib
from uuid import uuid4
from datetime import datetime, timezone
from pathlib import Path

GENESIS = '0' * 64

# Hash of one log entry, computed over its canonical JSON without the line_sha256 field itself
def entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != 'line_sha256'}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()

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
        self._append(entry)
        return call_id

    # Hash of the last entry already in the log, so each new line commits to the whole history
    def _last_hash(self) -> str:
        if not self.log_path.exists():
            return GENESIS
        last = GENESIS
        for line in self.log_path.read_text(encoding='utf-8').splitlines():
            if line.strip():
                try:
                    last = json.loads(line).get('line_sha256') or entry_hash(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return last

    # Every line stores the previous line's hash and its own, forming a hash chain
    def _append(self, entry: dict):
        entry['prev_sha256'] = self._last_hash()
        entry['line_sha256'] = entry_hash(entry)
        with open(self.log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry) + '\n')

    def log_event(self, event_type: str, details: dict):
        entry = {
            'ts': datetime.now(timezone.utc).isoformat(),
            'event_type': event_type,
            'details': details
        }
        self._append(entry)

    # Full raw output of a logged call, or None when the id or file is missing
    def read_raw(self, tool_call_id: str) -> str | None:
        if not tool_call_id or '/' in tool_call_id or '..' in tool_call_id:
            return None
        f = self.raw_dir / f'{tool_call_id}.txt'
        return f.read_text(encoding='utf-8') if f.exists() else None

    # Entries are indexed by call id, and the index is rebuilt only when the file size or mtime changes,
    # so validating many findings does not re-read the whole log once per cited id
    def lookup(self, tool_call_id: str) -> dict | None:
        if not self.log_path.exists():
            return None
        st = self.log_path.stat()
        key = (st.st_mtime_ns, st.st_size)
        if getattr(self, '_idx_key', None) != key:
            idx = {}
            for line in self.log_path.read_text(encoding='utf-8').splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if 'tool_call_id' in data:
                    idx.setdefault(data['tool_call_id'], data)
            self._idx, self._idx_key = idx, key
        return self._idx.get(tool_call_id)
