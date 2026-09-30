import json
import os
import time
import urllib.error
import urllib.request

VT_URL = 'https://www.virustotal.com/api/v3/files/'

# Looks up SHA-256 hashes on VirusTotal. The free tier allows 4 requests a minute, so calls are
# spaced by min_interval seconds. The key is read only from the VT_API_KEY environment variable.
class VirusTotal:
    def __init__(self, api_key: str, min_interval: float = 15.5, opener=urllib.request.urlopen, clock=time.time, sleep=time.sleep):
        self.api_key = api_key
        self.min_interval = min_interval
        self.opener = opener
        self.clock = clock
        self.sleep = sleep
        self.last_call = None

    @classmethod
    def from_env(cls, **kw):
        key = os.environ.get('VT_API_KEY')
        return cls(key, **kw) if key else None

    # Returns a small dict: found True/False with detection counts, or an error string
    def lookup(self, sha256: str) -> dict:
        if self.last_call is not None:
            wait = self.min_interval - (self.clock() - self.last_call)
            if wait > 0:
                self.sleep(wait)
        self.last_call = self.clock()
        req = urllib.request.Request(VT_URL + sha256, headers={'x-apikey': self.api_key})
        try:
            with self.opener(req, timeout=20) as resp:
                data = json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {'sha256': sha256, 'found': False}
            return {'sha256': sha256, 'error': f'HTTP {e.code}'}
        except Exception as e:
            return {'sha256': sha256, 'error': str(e)[:200]}
        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        return {'sha256': sha256, 'found': True, 'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0), 'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'link': 'https://www.virustotal.com/gui/file/' + sha256}
