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

def main():
    parser = argparse.ArgumentParser(description='Sift Agent CLI')
    subparsers = parser.add_subparsers(dest='command')

    run_parser = subparsers.add_parser('run')
    run_parser.add_argument('--evidence', required=True, help='Path to evidence file')
    run_parser.add_argument('--model', default='gemini-2.5-flash-lite', help='Gemini model name')

    args = parser.parse_args()
    if args.command == 'run':
        try:
            ev_path = validate_path(args.evidence)
        except Exception as e:
            print(f"Error validating evidence path: {e}", file=sys.stderr)
            sys.exit(1)

        api_key = os.environ.get('GEMINI_API_KEY')
        if not api_key:
            print("Error: GEMINI_API_KEY environment variable never read from file, must be in env", file=sys.stderr)
            sys.exit(1)

        audit_log = AuditLog(Path('runs/audit.jsonl'))
        rate_limiter = RateLimiter(state_file='api_usage.json')
        runner = SubprocessRunner()
        
        try:
            llm = GeminiClient(args.model)
        except Exception as e:
            print(f"Error initializing Gemini client: {e}", file=sys.stderr)
            sys.exit(1)

        agent = Agent(llm, runner, audit_log, rate_limiter, str(ev_path))
        # Surface API failures as a clean error and log them instead of a traceback
        try:
            final_answer = agent.build_report()
        except Exception as e:
            audit_log.log_event('agent run failed', {'error': str(e)[:500]})
            print(f"Error during investigation: {str(e)[:300]}", file=sys.stderr)
            sys.exit(2)
        print(final_answer)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
