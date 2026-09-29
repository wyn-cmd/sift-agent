import json
import time
from datetime import datetime, timezone
from pathlib import Path

# Raised when the persisted daily request count reaches its cap
class DailyLimitReached(RuntimeError):
    pass

# Defaults are the free tier limits observed on the author's account at build time, not a
# published guarantee, so real 429 responses are also handled by the agent loop
class RateLimiter:
    def __init__(self, rpm_limit: int = 15, tpm_limit: int = 250000, rpd_limit: int = 500, state_file: str = 'api_usage.json', clock=time.time, sleep=time.sleep):
        self.rpm_limit = rpm_limit
        self.tpm_limit = tpm_limit
        self.rpd_limit = rpd_limit
        self.state_file = Path(state_file)
        self.clock = clock
        self.sleep = sleep
        self.tokens_rpm = float(rpm_limit)
        self.tokens_tpm = float(tpm_limit)
        self.last_update = self.clock()

    def _refill(self):
        now = self.clock()
        elapsed = now - self.last_update
        if elapsed > 0:
            self.tokens_rpm = min(float(self.rpm_limit), self.tokens_rpm + elapsed * (self.rpm_limit / 60.0))
            self.tokens_tpm = min(float(self.tpm_limit), self.tokens_tpm + elapsed * (self.tpm_limit / 60.0))
            self.last_update = now

    def check_and_consume(self, estimated_tokens: int = 1000):
        self._refill()
        while self.tokens_rpm < 1.0 or self.tokens_tpm < estimated_tokens:
            self.sleep(0.1)
            self._refill()
        self.tokens_rpm -= 1.0
        self.tokens_tpm -= float(estimated_tokens)
        self._update_rpd()

    def _update_rpd(self):
        today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        data = {}
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except Exception:
                data = {}
        current_count = data.get(today, 0)
        if current_count >= self.rpd_limit:
            raise DailyLimitReached('RPD limit reached')
        data[today] = current_count + 1
        try:
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(data, f)
        except Exception:
            pass

    def back_off(self, retry_delay: float):
        self.sleep(retry_delay)
        self._refill()
