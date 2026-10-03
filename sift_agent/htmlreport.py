import html
import json
from datetime import datetime, timezone
from pathlib import Path
from sift_agent.verify import head_hash
from sift_agent.compare import load_findings
from sift_agent.redact import redact
from sift_agent.ptree import tree_from_run
from sift_agent.anomalies import anomalies_from_run
from sift_agent.netmap import netmap_from_run
from sift_agent.cmdflags import cmdflags_from_run
from sift_agent.iocs import extract_iocs, format_iocs
from sift_agent.risk import risk_from_run
from sift_agent.injection import scan_runs, format_injection

# One dark theme, no script and no external asset, so the page opens from a USB stick
STYLE = (
    'body { background: #14161a; color: #d7dae0; font-family: system-ui, sans-serif; line-height: 1.6; '
    'margin: 0 auto; max-width: 62rem; padding: 2rem 1.5rem; }'
    'h1 { color: #c9a0ff; margin-bottom: 0.2rem; }'
    'h2 { color: #8ab4f8; border-bottom: 1px solid #2a2f38; padding-bottom: 0.3rem; margin-top: 2.2rem; }'
    'pre { background: #1c2027; padding: 0.8rem 1rem; border-radius: 6px; overflow-x: auto; '
    'font-family: ui-monospace, monospace; font-size: 0.85rem; white-space: pre-wrap; }'
    '.finding { background: #1a1e25; border-left: 4px solid #6b7280; padding: 0.4rem 1rem; margin: 1rem 0; }'
    '.confirmed { border-left-color: #34d399; }'
    '.inference { border-left-color: #fbbf24; }'
    '.unconfirmed { border-left-color: #f87171; }'
    '.muted { color: #8b93a1; font-size: 0.9rem; }'
)

# A verified claim, a plain inference and a downgraded claim each get their own accent
def _status_class(status: str) -> str:
    if status == 'confirmed':
        return 'confirmed'
    if status.startswith('unconfirmed'):
        return 'unconfirmed'
    return 'inference'

def _masked(text: str, redact_text: bool) -> str:
    return redact(text) if redact_text else text

# Calls per plugin, how many of each failed, the event count and the audit head hash
def _call_summary(runs_dir: Path) -> str:
    log = Path(runs_dir) / 'audit.jsonl'
    if not log.is_file():
        raise FileNotFoundError(f'no audit.jsonl in {runs_dir}')
    calls: dict = {}
    from_events: dict = {}
    from_stderr: dict = {}
    events = 0
    for line in log.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        if 'event_type' in e:
            events += 1
            if e['event_type'] == 'tool call failed':
                name = e.get('details', {}).get('tool', 'unknown')
                from_events[name] = from_events.get(name, 0) + 1
        if 'tool' in e:
            name = e['tool']
            calls[name] = calls.get(name, 0) + 1
            raw = Path(runs_dir) / e.get('raw_output_file', '')
            if raw.is_file() and '[stderr]' in raw.read_text(encoding='utf-8'):
                from_stderr[name] = from_stderr.get(name, 0) + 1
    # Failures are logged as events from this version on; an older run only has the stderr
    # marker the runner leaves behind, so fall back to counting that
    broken = from_events if from_events else from_stderr
    out = [f'tool calls: {sum(calls.values())}', f'events: {events}', f'audit head hash: {head_hash(log)}']
    for name in sorted(calls):
        out.append(f'  {name}: {calls[name]} call(s), {broken.get(name, 0)} failed')
    return '\n'.join(out)

# A helper can legitimately have nothing to say about a run, so a missing section becomes a
# note line and the rest of the page is still written
def _section(lines: list, heading: str, build, redact_text: bool):
    lines.append(f'<h2>{html.escape(heading)}</h2>')
    try:
        lines.append(f'<pre>{html.escape(_masked(build(), redact_text))}</pre>')
    except (FileNotFoundError, ValueError, KeyError) as e:
        lines.append(f'<p class="muted">not available in this run: {html.escape(str(e))}</p>')

def build_html(runs_dir: Path, title: str | None = None, redact_text: bool = False, created: str | None = None) -> str:
    runs_dir = Path(runs_dir)
    heading = title or f'sift-agent report for {runs_dir.name}'
    stamp = created or datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    lines = ['<!DOCTYPE html>', '<html lang="en">', '<head>', '<meta charset="utf-8">',
             f'<title>{html.escape(heading)}</title>', f'<style>{STYLE}</style>', '</head>', '<body>',
             f'<h1>{html.escape(heading)}</h1>',
             f'<p class="muted">Generated: {html.escape(stamp)}</p>']
    _section(lines, 'Run Summary', lambda: _call_summary(runs_dir), redact_text)

    lines.append('<h2>Findings</h2>')
    try:
        findings = load_findings(runs_dir)
    except (FileNotFoundError, ValueError) as e:
        findings = []
        lines.append(f'<p class="muted">not available in this run: {html.escape(str(e))}</p>')
    for f in findings:
        status = str(f.get('status', 'inference'))
        confidence = str(f.get('confidence', 'unknown'))
        claim = str(f.get('claim', ''))
        excerpt = str(f.get('excerpt', ''))
        reason = str(f.get('reason', ''))
        ids = ', '.join(str(i) for i in f.get('tool_call_ids', [])) or 'none cited'
        lines.append('<div class="finding ' + _status_class(status) + '">')
        lines.append('<p><strong>' + html.escape(status) + '</strong> <span class="muted">confidence '
                     + html.escape(confidence) + '</span></p>')
        lines.append('<p>' + html.escape(_masked(claim, redact_text)) + '</p>')
        lines.append('<p class="muted">tool call ids: ' + html.escape(ids) + '</p>')
        lines.append('<pre>' + html.escape(_masked(excerpt, redact_text)) + '</pre>')
        if reason:
            lines.append('<p class="muted">model reason: ' + html.escape(_masked(reason, redact_text)) + '</p>')
        lines.append('</div>')
    if not findings:
        lines.append('<p class="muted">No findings in this run.</p>')

    for heading_text, build in [('Process Tree', lambda: tree_from_run(runs_dir)),
                                ('Rule Based Anomalies', lambda: anomalies_from_run(runs_dir)),
                                ('Risk Ranking', lambda: risk_from_run(runs_dir)),
                                ('Network Map', lambda: netmap_from_run(runs_dir)),
                                ('Flagged Command Lines', lambda: cmdflags_from_run(runs_dir)),
                                ('Indicators', lambda: format_iocs(extract_iocs(runs_dir))),
                                ('Prompt Injection Scan', lambda: format_injection(scan_runs(runs_dir)))]:
        _section(lines, heading_text, build, redact_text)

    lines.extend(['</body>', '</html>'])
    return '\n'.join(lines) + '\n'

def write_html(runs_dir: Path, out: Path, title: str | None = None, redact_text: bool = False) -> str:
    Path(out).write_text(build_html(runs_dir, title, redact_text), encoding='utf-8')
    return str(out)
