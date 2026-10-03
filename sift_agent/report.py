import json
import re
from typing import List, Dict, Any
from sift_agent.audit import AuditLog

# Check every finding against the audit log and raw outputs; also used by replay, timeline and compare
def validate_findings(findings: List[Dict[str, Any]], audit_log: AuditLog) -> List[Dict[str, Any]]:
    validated_findings = []
    for f in findings:
        claim = f.get('claim', '')
        status = f.get('status', 'inference')
        tool_call_ids = f.get('tool_call_ids', [])
        excerpt = f.get('excerpt', '')

        # Check if all cited tool call IDs exist in audit log
        all_exist = True
        if status == 'confirmed':
            if not tool_call_ids:
                status = 'unconfirmed inference'
            else:
                for cid in tool_call_ids:
                    if not audit_log.lookup(cid):
                        all_exist = False
                        break
                if not all_exist:
                    status = 'unconfirmed inference'
                # A confirmed claim must quote text that really appears in a cited raw output
                elif not excerpt.strip():
                    status = 'unconfirmed inference'
                else:
                    norm = lambda t: re.sub(r'\s+', ' ', t).strip().lower()
                    raws = [audit_log.read_raw(cid) or '' for cid in tool_call_ids]
                    # Each excerpt line must appear verbatim in a cited output; rows need not be adjacent
                    lines = [norm(x) for x in excerpt.splitlines() if x.strip()]
                    if not all(any(l in norm(r) for r in raws) for l in lines):
                        status = 'unconfirmed inference'

        # Confidence comes from the evidence, not the model: a verified claim backed by two or more
        # different plugins is high, one plugin is medium, anything unverified is low
        if status != 'confirmed':
            conf = 'low'
        else:
            tools = {(audit_log.lookup(cid) or {}).get('tool') for cid in tool_call_ids}
            conf = 'high' if len(tools) >= 2 else 'medium'

        validated_findings.append({
            'confidence': conf,
            'claim': claim,
            'status': status,
            'tool_call_ids': tool_call_ids,
            'excerpt': excerpt,
            'assessment': f.get('assessment', ''),
            'reason': f.get('reason', '')
        })

    return validated_findings

def generate_report(findings: List[Dict[str, Any]], audit_log: AuditLog, truncated_plugins: List[str], calls_used: int, rate_limit_approached: bool, plugins_not_run: List[str] | None = None, extra_sections: List[str] | None = None, calls_cap: int = 15) -> str:
    validated_findings = validate_findings(findings, audit_log)
    report_lines = ['# DFIR Investigation Report', '', '## Findings']
    for vf in validated_findings:
        report_lines.append(f"- Claim: {vf['claim']}")
        report_lines.append(f"  Status: {vf['status']}")
        report_lines.append(f"  Confidence: {vf['confidence']}")
        report_lines.append(f"  Tool Call IDs: {', '.join(vf['tool_call_ids'])}")
        report_lines.append(f"  Excerpt: {vf['excerpt']}")
        # The assessment is the model's judgment, so it is labelled as such and never as confirmed fact
        if vf['assessment']:
            report_lines.append(f"  Assessment (model judgment): {vf['assessment']}. {vf['reason']}".rstrip())
        report_lines.append('')

    report_lines.extend([
        '## Limitations',
        f"- Truncated plugins: {', '.join(truncated_plugins) if truncated_plugins else 'None'}",
        f"- Calls used vs cap: {calls_used} / {calls_cap}",
        f"- Plugins never run: {', '.join(plugins_not_run) if plugins_not_run else 'None'}",
        f"- Rate limit approached: {'Yes' if rate_limit_approached else 'No'}"
    ])

    if extra_sections:
        report_lines.append('')
        report_lines.extend(extra_sections)

    return '\n'.join(report_lines)


# Pull the JSON findings list out of the model's final answer, tolerating code fences and prose.
# Anything unparseable becomes one unconfirmed inference so the text is never silently dropped.
def parse_findings(answer: str) -> List[Dict[str, Any]]:
    text = answer.strip()
    fence = re.search(r'```(?:json)?\s*(.*?)```', text, re.DOTALL)
    candidates = [fence.group(1)] if fence else []
    start, end = text.find('['), text.rfind(']')
    if start != -1 and end > start:
        candidates.append(text[start:end + 1])
    for c in candidates:
        try:
            data = json.loads(c)
        except json.JSONDecodeError:
            continue
        if isinstance(data, list) and all(isinstance(x, dict) for x in data):
            return [{'claim': str(x.get('claim', '')),
                     'status': str(x.get('status', 'inference')),
                     'tool_call_ids': [str(i) for i in x.get('tool_call_ids', []) if isinstance(i, str)],
                     'excerpt': str(x.get('excerpt', '')),
                     'assessment': str(x.get('assessment', '')).lower() if str(x.get('assessment', '')).lower() in ('anomalous', 'expected', 'unclear') else '',
                     'reason': str(x.get('reason', ''))} for x in data]
    return [{'claim': text[:1500], 'status': 'unconfirmed inference', 'tool_call_ids': [], 'excerpt': ''}]
