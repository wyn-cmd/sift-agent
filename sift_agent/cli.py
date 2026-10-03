import os
import sys
import argparse
from pathlib import Path
from sift_agent.guardrails import validate_path
from sift_agent.audit import AuditLog
from sift_agent.tools import SubprocessRunner
from sift_agent.rate_limiter import RateLimiter
from sift_agent.agent import Agent
from sift_agent.gemini_client import GeminiClient
from sift_agent.report import generate_report
from sift_agent.verify import verify_audit
from sift_agent.replay import replay
from sift_agent.vt import VirusTotal
from sift_agent.verify import head_hash
from sift_agent.yarascan import load_rules
from sift_agent.timeline import build_timeline
from sift_agent.compare import compare_runs
from sift_agent.ptree import tree_from_run
from sift_agent.anomalies import anomalies_from_run
from sift_agent.iocs import extract_iocs, format_iocs
from sift_agent.stats import run_stats
from sift_agent.doctor import run_doctor, format_doctor
from sift_agent.redact import redact
from sift_agent.export import export_json, evidence_hash_line

def main():
    parser = argparse.ArgumentParser(description='Sift Agent CLI')
    subparsers = parser.add_subparsers(dest='command')

    run_parser = subparsers.add_parser('run')
    run_parser.add_argument('--evidence', required=True, help='Path to evidence file')
    run_parser.add_argument('--model', default='gemini-3.5-flash-lite', help='Gemini model name')

    run_parser.add_argument('--runs', default='runs', help='Directory for audit.jsonl, raw/ and dumps/')
    run_parser.add_argument('--dump-hash', action='store_true', help='Dump the most suspicious processes, SHA-256 the images and list the hashes')
    run_parser.add_argument('--yara', metavar='RULES', help='Scan dumped images with a YARA rules file or directory (needs yara-python, implies --dump-hash)')
    run_parser.add_argument('--vt', action='store_true', help='Look the dumped hashes up on VirusTotal (needs VT_API_KEY, implies --dump-hash)')

    verify_parser = subparsers.add_parser('verify-audit', help='Check the raw outputs in a runs directory against the audit log')
    verify_parser.add_argument('--expect-head', help='Head hash you recorded after the run; fails if the log no longer ends at it')
    verify_parser.add_argument('--runs', default='runs', help='Directory holding audit.jsonl and raw/')

    replay_parser = subparsers.add_parser('replay', help='Rebuild the report from a saved run without a model or Volatility')
    replay_parser.add_argument('--runs', default='runs', help='Directory holding audit.jsonl and raw/')

    timeline_parser = subparsers.add_parser('timeline', help='Write a static HTML timeline of a saved run')
    timeline_parser.add_argument('--runs', default='runs')
    timeline_parser.add_argument('--out', default='timeline.html')

    compare_parser = subparsers.add_parser('compare', help='Diff the confirmed claims of two saved runs')
    compare_parser.add_argument('run_a')
    compare_parser.add_argument('run_b')

    replay_parser.add_argument('--redact', action='store_true', help='Mask IP addresses, user names and host names in the report')
    replay_parser.add_argument('--out', help='Write the report to this file instead of printing it')
    replay_parser.add_argument('--extras', action='store_true', help='Append the process tree and rule-based anomalies')

    for name, text in (('tree', 'Print the process tree of a saved run'), ('anomalies', 'Rule-based process checks on a saved run (no model)'),
                       ('stats', 'Summarise the calls, sizes and duration of a saved run'), ('export-json', 'Print validated findings as JSON')):
        p = subparsers.add_parser(name, help=text)
        p.add_argument('--runs', default='runs')
    iocs_parser = subparsers.add_parser('iocs', help='List IPs, URLs, domains and hashes found in the raw outputs of a saved run')
    iocs_parser.add_argument('--runs', default='runs')
    iocs_parser.add_argument('--format', choices=['text', 'json', 'csv'], default='text')
    subparsers.add_parser('doctor', help='Check that Volatility, the API key and the evidence directory are ready')
    hash_parser = subparsers.add_parser('hash-evidence', help='Print the SHA-256 of an evidence file')
    hash_parser.add_argument('--evidence', required=True)

    args = parser.parse_args()
    if args.command == 'doctor':
        ok, text = format_doctor(run_doctor())
        print(text)
        sys.exit(0 if ok else 1)
    if args.command == 'hash-evidence':
        try:
            print(evidence_hash_line(validate_path(args.evidence)))
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return
    simple = {'tree': tree_from_run, 'anomalies': anomalies_from_run, 'stats': run_stats, 'export-json': export_json,
              'iocs': lambda r: format_iocs(extract_iocs(r), getattr(args, 'format', 'text'))}
    if args.command in simple:
        try:
            print(simple[args.command](Path(args.runs)))
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return
    if args.command == 'timeline':
        try:
            Path(args.out).write_text(build_timeline(Path(args.runs)), encoding='utf-8')
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        print(f'Wrote {args.out}')
        return
    if args.command == 'compare':
        try:
            print(compare_runs(Path(args.run_a), Path(args.run_b)))
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return
    if args.command == 'verify-audit':
        ok, lines = verify_audit(Path(args.runs) / 'audit.jsonl', args.expect_head)
        if (Path(args.runs) / 'audit.jsonl').exists():
            lines.append(f"head hash: {head_hash(Path(args.runs) / 'audit.jsonl')}")
        print('\n'.join(lines))
        print('OK: audit log matches the raw outputs' if ok else 'FAILED: audit log does not match the raw outputs')
        sys.exit(0 if ok else 1)
    if args.command == 'replay':
        try:
            text = replay(Path(args.runs))
            if args.extras:
                text += '\n\n## Process tree\n' + tree_from_run(Path(args.runs)) + '\n\n## Rule-based anomalies\n' + anomalies_from_run(Path(args.runs))
            if args.redact:
                text = redact(text)
            if args.out:
                Path(args.out).write_text(text + '\n', encoding='utf-8')
                print(f'Wrote {args.out}')
            else:
                print(text)
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return
    if args.command == 'run':
        try:
            ev_path = validate_path(args.evidence)
        except Exception as e:
            print(f"Error validating evidence path: {e}", file=sys.stderr)
            sys.exit(1)

        api_key = os.environ.get('GEMINI_API_KEY')
        if not api_key:
            print("Error: the GEMINI_API_KEY environment variable is not set. The key is read only from the environment.", file=sys.stderr)
            sys.exit(1)

        audit_log = AuditLog(Path(args.runs) / 'audit.jsonl')
        rate_limiter = RateLimiter(state_file='api_usage.json')
        runner = SubprocessRunner()
        
        try:
            llm = GeminiClient(args.model)
        except Exception as e:
            print(f"Error initializing Gemini client: {e}", file=sys.stderr)
            sys.exit(1)

        vt = None
        if args.vt:
            vt = VirusTotal.from_env()
            if vt is None:
                print("Error: --vt needs the VT_API_KEY environment variable.", file=sys.stderr)
                sys.exit(1)
        dump_dir = Path(args.runs) / 'dumps' if (args.dump_hash or args.vt or args.yara) else None
        yara_rules = None
        if args.yara:
            try:
                yara_rules = load_rules(Path(args.yara))
            except Exception as e:
                print(f"Error loading YARA rules: {e}", file=sys.stderr)
                sys.exit(1)
        agent = Agent(llm, runner, audit_log, rate_limiter, str(ev_path), dump_dir=dump_dir, vt=vt, yara_rules=yara_rules)
        # Surface API failures as a clean error and log them instead of a traceback
        try:
            final_answer = agent.build_report()
        except Exception as e:
            audit_log.log_event('agent run failed', {'error': str(e)[:500]})
            print(f"Error during investigation: {str(e)[:300]}", file=sys.stderr)
            sys.exit(2)
        print(final_answer)
        # Note this value somewhere outside the run directory to make later tampering detectable
        print(f"Audit log head hash: {head_hash(Path(args.runs) / 'audit.jsonl')}", file=sys.stderr)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
