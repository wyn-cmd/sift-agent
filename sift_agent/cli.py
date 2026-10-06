import os
from sift_agent import __version__
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
from sift_agent.defang import defang_from_run
from sift_agent.exits import exits_from_run
from sift_agent.ports import ports_from_run
from sift_agent.baseline import baseline_from_run
from sift_agent.pidinfo import pidinfo_from_run
from sift_agent.window import window_from_run
from sift_agent.timelinecsv import timeline_csv
from sift_agent.lineage import lineage_from_run
from sift_agent.hidden import hidden_from_run
from sift_agent.procdiff import diff_runs
from sift_agent.summary import run_summary
from sift_agent.netmap import netmap_from_run
from sift_agent.cmdflags import cmdflags_from_run
from sift_agent.export import export_json, evidence_hash_line
from sift_agent.search import search_run, format_search, json_search
from sift_agent.risk import risk_report, format_risk
from sift_agent.injection import scan_runs, format_injection
from sift_agent.stix import stix_from_run
from sift_agent.sigma import sigma_from_run
from sift_agent.htmlreport import write_html
from sift_agent.bundle import write_bundle
import json

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
    run_parser.add_argument('--max-calls', type=int, default=15, help='Tool call cap for this run (default 15)')
    run_parser.add_argument('--max-nudges', type=int, default=3, help='How often to push a model that tries to stop early (default 3)')

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
                       ('netmap', 'Group network connections by owning process, flagging external addresses'), ('cmdflags', 'Flag unusual command lines in a saved run'), ('stats', 'Summarise the calls, sizes and duration of a saved run'), ('export-json', 'Print validated findings as JSON')):
        p = subparsers.add_parser(name, help=text)
        p.add_argument('--runs', default='runs')
    iocs_parser = subparsers.add_parser('iocs', help='List IPs, URLs, domains and hashes found in the raw outputs of a saved run')
    iocs_parser.add_argument('--runs', default='runs')
    iocs_parser.add_argument('--format', choices=['text', 'json', 'csv'], default='text')

    search_parser = subparsers.add_parser('search', help='Search the raw plugin outputs of a saved run with a regular expression')
    search_parser.add_argument('pattern')
    search_parser.add_argument('--runs', default='runs')
    search_parser.add_argument('--plugin', action='append', dest='plugins', help='Search only this plugin, repeat for several')
    search_parser.add_argument('-i', '--ignore-case', action='store_true', help='Case insensitive match')
    search_parser.add_argument('-C', '--context', type=int, default=0, help='Lines of context to show around each hit')
    search_parser.add_argument('--max-hits', type=int, default=200, help='Stop after this many hits (default 200)')
    search_parser.add_argument('--json', action='store_true', help='Print the hits as JSON')

    risk_parser = subparsers.add_parser('risk', help='Rank processes by one score fused from the rule-based checks')
    risk_parser.add_argument('--runs', default='runs')
    risk_parser.add_argument('--json', action='store_true', help='Print the scored processes as JSON')

    injection_parser = subparsers.add_parser('injection', help='Flag raw output that looks like prompt injection aimed at the model')
    injection_parser.add_argument('--runs', default='runs')
    injection_parser.add_argument('--json', action='store_true', help='Print the findings as JSON')

    stix_parser = subparsers.add_parser('stix', help='Export the indicators of a saved run as a STIX 2.1 bundle')
    stix_parser.add_argument('--runs', default='runs')
    stix_parser.add_argument('--created', help='Fixed timestamp to use instead of now, for reproducible output')
    stix_parser.add_argument('--out', help='Write to this file instead of printing')

    sigma_parser = subparsers.add_parser('sigma', help='Turn the flagged command lines of a saved run into Sigma rules')
    sigma_parser.add_argument('--runs', default='runs')
    sigma_parser.add_argument('--out', help='Write to this file instead of printing')

    html_parser = subparsers.add_parser('html-report', help='Write one self contained HTML page for a saved run')
    html_parser.add_argument('--runs', default='runs')
    html_parser.add_argument('--out', default='report.html')
    html_parser.add_argument('--title', help='Heading to use instead of the run directory name')
    html_parser.add_argument('--redact', action='store_true', help='Mask IP addresses, user names and host names')

    bundle_parser = subparsers.add_parser('bundle', help='Package a saved run into one zip with a hash manifest')
    bundle_parser.add_argument('--runs', default='runs')
    bundle_parser.add_argument('--out', help='Zip to write (default: the run directory name plus -bundle.zip)')
    bundle_parser.add_argument('--evidence', help='Evidence image to hash into the manifest, relative to the evidence directory')
    bundle_parser.add_argument('--redact', action='store_true', help='Redact the copy of the report inside the bundle')
    p = subparsers.add_parser('summary', help='Counts of findings, confidence and anomalies for a saved run')
    p.add_argument('--json', action='store_true', help='Print the counts as a JSON object')
    p.add_argument('--runs', default='runs')
    p = subparsers.add_parser('procdiff', help='Compare the process names of two saved runs')
    p.add_argument('run_a')
    p.add_argument('run_b')
    p = subparsers.add_parser('hidden', help='Compare windows.psscan with windows.pslist to find unlisted processes')
    p.add_argument('--runs', default='runs')
    p = subparsers.add_parser('lineage', help='Print the parent chain of one PID')
    p.add_argument('--runs', default='runs')
    p.add_argument('--pid', type=int, required=True)
    p = subparsers.add_parser('timeline-csv', help='Print every audit entry as CSV')
    p.add_argument('--runs', default='runs')
    p = subparsers.add_parser('window', help='List processes created between two timestamps')
    p.add_argument('--runs', default='runs')
    p.add_argument('--start', required=True)
    p.add_argument('--end', required=True)
    p = subparsers.add_parser('pidinfo', help='Show process row, command line, sockets and parent chain for one PID')
    p.add_argument('--runs', default='runs')
    p.add_argument('--pid', type=int, required=True)
    p = subparsers.add_parser('baseline', help='List processes that are not in a baseline file of known-good names')
    p.add_argument('--runs', default='runs')
    p.add_argument('--names', help='Text file with one known-good process name per line; the bundled core Windows list is used if omitted')
    p = subparsers.add_parser('ports', help='Summarise listening and remote ports from netscan and netstat')
    p.add_argument('--runs', default='runs')
    p = subparsers.add_parser('exits', help='List processes that have already exited, shortest lifetime first')
    p.add_argument('--runs', default='runs')
    p.add_argument('--under', type=float, default=60.0, help='Lifetime in seconds below which a process is marked short')
    p = subparsers.add_parser('defang', help='Print the indicators of a saved run in defanged form')
    p.add_argument('--runs', default='runs')
    subparsers.add_parser('doctor', help='Check that Volatility, the API key and the evidence directory are ready')
    hash_parser = subparsers.add_parser('hash-evidence', help='Print the SHA-256 of an evidence file')
    hash_parser.add_argument('--evidence', required=True)

    parser.add_argument('--version', action='version', version=f'sift-agent {__version__}')
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
    if args.command == 'summary':
        try:
            print(run_summary(Path(args.runs), args.json))
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return
    if args.command == 'procdiff':
        try:
            print(diff_runs(Path(args.run_a), Path(args.run_b)))
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return
    if args.command == 'hidden':
        try:
            print(hidden_from_run(Path(args.runs)))
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return
    if args.command == 'lineage':
        try:
            print(lineage_from_run(Path(args.runs), args.pid))
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return
    if args.command == 'timeline-csv':
        try:
            print(timeline_csv(Path(args.runs)))
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return
    if args.command == 'window':
        try:
            print(window_from_run(Path(args.runs), args.start, args.end))
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return
    if args.command == 'pidinfo':
        try:
            print(pidinfo_from_run(Path(args.runs), args.pid))
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return
    if args.command == 'baseline':
        try:
            print(baseline_from_run(Path(args.runs), Path(args.names) if args.names else None))
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return
    if args.command == 'ports':
        try:
            print(ports_from_run(Path(args.runs)))
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return
    if args.command == 'exits':
        try:
            print(exits_from_run(Path(args.runs), args.under))
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return
    if args.command == 'defang':
        try:
            print(defang_from_run(Path(args.runs)))
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return
    simple = {'tree': tree_from_run, 'anomalies': anomalies_from_run, 'stats': run_stats, 'netmap': netmap_from_run, 'cmdflags': cmdflags_from_run, 'export-json': export_json,
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
    if args.command == 'search':
        try:
            result = search_run(Path(args.runs), args.pattern, plugins=args.plugins, ignore_case=args.ignore_case,
                                context=args.context, max_hits=args.max_hits)
            print(json_search(result) if args.json else format_search(result))
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return
    if args.command == 'risk':
        try:
            report = risk_report(Path(args.runs))
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        print(json.dumps(report, indent=2) if args.json else format_risk(report))
        return
    if args.command == 'injection':
        try:
            found = scan_runs(Path(args.runs))
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        print(json.dumps(found, indent=2) if args.json else format_injection(found))
        return
    if args.command in ('stix', 'sigma'):
        try:
            text = stix_from_run(Path(args.runs), args.created) if args.command == 'stix' else sigma_from_run(Path(args.runs))
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        if args.out:
            Path(args.out).write_text(text + '\n', encoding='utf-8')
            print(f'Wrote {args.out}')
        else:
            print(text)
        return
    if args.command == 'html-report':
        try:
            out = write_html(Path(args.runs), Path(args.out), args.title, args.redact)
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        print(f'Wrote {out}')
        return
    if args.command == 'bundle':
        try:
            evidence = validate_path(args.evidence) if args.evidence else None
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        out = Path(args.out) if args.out else Path(f'{Path(args.runs).name}-bundle.zip')
        try:
            info = write_bundle(Path(args.runs), out, evidence, args.redact)
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"Wrote {info['out']} ({info['bytes']} bytes, {len(info['entries'])} entries)")
        print(f"manifest sha256: {info['manifest_sha256']}")
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
        agent = Agent(llm, runner, audit_log, rate_limiter, str(ev_path), dump_dir=dump_dir, vt=vt, yara_rules=yara_rules,
                      max_calls=args.max_calls, max_nudges=args.max_nudges)
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
