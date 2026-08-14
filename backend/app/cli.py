from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.core.scope import ScopeViolation
from app.services.authorized_scan import AuthorizationError, AuthorizedScanService, AuthorizedScope


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="red",
        description="RedPath authorized reconnaissance and vulnerability-correlation CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Run a scope-bound reconnaissance plan or authorized execution")
    scan.add_argument("target", help="Single IPv4 or IPv6 address inside the approved CIDR scope")
    scan.add_argument("--scope-file", required=True, type=Path, help="Approved JSON scope file")
    scan.add_argument("--authorization-id", required=True, help="Written authorization or ticket identifier")
    scan.add_argument("--operator", required=True, help="Approved operator identifier")
    scan.add_argument("--profile", choices=("safe", "service_inventory"), default="service_inventory")
    scan.add_argument("--web-base-url", help="Optional approved HTTP(S) origin for bounded content inventory")
    scan.add_argument(
        "--execute",
        action="store_true",
        help="Execute approved TCP-connect and bounded web inventory; default is dry-run",
    )
    scan.add_argument("--audit-file", type=Path, default=Path(".redpath-audit.jsonl"))
    scan.add_argument("--report-file", type=Path, help="Optional JSON report path")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        scope = AuthorizedScope.from_file(args.scope_file)
        service = AuthorizedScanService(scope)
        report = service.run(
            args.target,
            authorization_id=args.authorization_id,
            operator=args.operator,
            execute=args.execute,
            profile=args.profile,
            web_base_url=args.web_base_url,
            audit_file=args.audit_file,
        )
    except (AuthorizationError, ScopeViolation, ValueError) as exc:
        parser.error(str(exc))
    payload = report.as_dict()
    encoded = json.dumps(payload, indent=2, sort_keys=True)
    if args.report_file:
        args.report_file.parent.mkdir(parents=True, exist_ok=True)
        args.report_file.write_text(encoded + "\n", encoding="utf-8")
        args.report_file.chmod(0o600)
    print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
