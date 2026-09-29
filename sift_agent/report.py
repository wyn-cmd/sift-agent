import json
from typing import List, Dict, Any
from sift_agent.audit import AuditLog

def generate_report(findings: List[Dict[str, Any]], audit_log: AuditLog, truncated_plugins: List[str], calls_used: int, rate_limit_approached: bool) -> str:
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

        validated_findings.append({
            'claim': claim,
            'status': status,
            'tool_call_ids': tool_call_ids,
            'excerpt': excerpt
        })

    report_lines = ['# DFIR Investigation Report', '', '## Findings']
    for vf in validated_findings:
        report_lines.append(f"- Claim: {vf['claim']}")
        report_lines.append(f"  Status: {vf['status']}")
        report_lines.append(f"  Tool Call IDs: {', '.join(vf['tool_call_ids'])}")
        report_lines.append(f"  Excerpt: {vf['excerpt']}")
        report_lines.append('')

    report_lines.extend([
        '## Limitations',
        f"- Truncated plugins: {', '.join(truncated_plugins) if truncated_plugins else 'None'}",
        f"- Calls used vs cap: {calls_used} / 15",
        f"- Rate limit approached: {'Yes' if rate_limit_approached else 'No'}"
    ])

    return '\n'.join(report_lines)
