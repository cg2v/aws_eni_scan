#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from aws_org_scan import (
    AccountInfo,
    assume_role_credentials,
    discover_enabled_regions,
    format_aws_error,
    list_active_accounts,
    make_client,
)
from eni_search import search_network_interfaces
from reporting import print_summary, write_json_report


def parse_csv_arg(raw: str | None) -> set[str]:
    if not raw:
        return set()
    return {item.strip() for item in raw.split(",") if item.strip()}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan AWS Organization accounts for ENIs by public IP or name/description.",
    )
    query_group = parser.add_mutually_exclusive_group(required=True)
    query_group.add_argument("--public-ip", help="Public IPv4 address to find on ENIs")
    query_group.add_argument("--eni-name", help="ENI Name tag value to search")
    query_group.add_argument("--description", help="ENI description value to search")

    parser.add_argument(
        "--role-name",
        default="OrganizationAccountAccessRole",
        help="Role name to assume in each member account",
    )
    parser.add_argument("--external-id", help="Optional external ID for AssumeRole")

    parser.add_argument(
        "--include-accounts",
        help="Comma-separated account IDs to include",
    )
    parser.add_argument(
        "--exclude-accounts",
        help="Comma-separated account IDs to exclude",
    )

    parser.add_argument(
        "--regions",
        default="all-enabled",
        help="all-enabled (default) or comma-separated explicit region list",
    )
    parser.add_argument(
        "--exclude-regions",
        help="Comma-separated regions to exclude",
    )

    parser.add_argument(
        "--match-mode",
        choices=["exact", "contains", "regex"],
        default="exact",
        help="Match mode for --eni-name/--description (default: exact)",
    )
    parser.add_argument(
        "--case-sensitive",
        action="store_true",
        help="Use case-sensitive matching for name/description",
    )

    parser.add_argument("--account-concurrency", type=int, default=8)
    parser.add_argument("--region-concurrency", type=int, default=5)
    parser.add_argument("--max-retries", type=int, default=4)
    parser.add_argument("--request-timeout-seconds", type=int, default=20)

    parser.add_argument(
        "--output-file",
        default="eni_scan_report.json",
        help="Path for JSON report output",
    )
    parser.add_argument(
        "--fail-on-partial",
        action="store_true",
        help="Exit with code 1 if any account/region errors occurred",
    )
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args(argv)

    if args.public_ip:
        try:
            parsed = ipaddress.ip_address(args.public_ip)
        except ValueError as exc:
            raise SystemExit(f"Invalid --public-ip value: {args.public_ip}") from exc
        if parsed.version != 4:
            raise SystemExit("--public-ip must be an IPv4 address")

    if args.match_mode == "regex":
        probe = args.eni_name or args.description
        if probe:
            try:
                re.compile(probe)
            except re.error as exc:
                raise SystemExit(f"Invalid regex in query value: {exc}") from exc

    if args.account_concurrency < 1 or args.region_concurrency < 1:
        raise SystemExit("Concurrency values must be >= 1")

    if args.max_retries < 0:
        raise SystemExit("--max-retries must be >= 0")

    return args


def determine_query(args: argparse.Namespace) -> tuple[str, str]:
    if args.public_ip:
        return "public_ip", args.public_ip
    if args.eni_name:
        return "eni_name", args.eni_name
    if args.description:
        return "description", args.description
    raise RuntimeError("No query mode selected")


def build_targets(
    accounts: list[AccountInfo],
    include_accounts: set[str],
    exclude_accounts: set[str],
) -> list[AccountInfo]:
    output = []
    for account in accounts:
        if include_accounts and account.account_id not in include_accounts:
            continue
        if account.account_id in exclude_accounts:
            continue
        output.append(account)
    return output


def current_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def run_scan(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    started_at = current_utc_iso()
    query_mode, query_value = determine_query(args)

    include_accounts = parse_csv_arg(args.include_accounts)
    exclude_accounts = parse_csv_arg(args.exclude_accounts)
    exclude_regions = parse_csv_arg(args.exclude_regions)

    explicit_regions: list[str] | None
    if args.regions.strip().lower() == "all-enabled":
        explicit_regions = None
    else:
        explicit_regions = [r.strip() for r in args.regions.split(",") if r.strip()]
        if not explicit_regions:
            raise SystemExit("--regions must be 'all-enabled' or a non-empty CSV list")

    org_client = make_client("organizations", timeout_seconds=args.request_timeout_seconds)
    all_accounts = list_active_accounts(org_client, max_retries=args.max_retries)
    target_accounts = build_targets(all_accounts, include_accounts, exclude_accounts)

    if not target_accounts:
        raise SystemExit("No ACTIVE target accounts after filters")

    matches: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    coverage = {
        "target_accounts": len(target_accounts),
        "scanned_accounts": 0,
        "target_account_regions": 0,
        "scanned_account_regions": 0,
        "skipped_account_regions": 0,
    }

    def scan_region(
        account: AccountInfo,
        credentials: dict[str, str],
        region: str,
        seen_at: str,
    ) -> tuple[list[dict[str, Any]], dict[str, Any] | None, bool]:
        try:
            ec2_client = make_client(
                "ec2",
                region_name=region,
                credentials=credentials,
                timeout_seconds=args.request_timeout_seconds,
            )
            region_matches = search_network_interfaces(
                ec2_client=ec2_client,
                account_id=account.account_id,
                account_name=account.account_name,
                region=region,
                query_mode=query_mode,
                query_value=query_value,
                match_mode=args.match_mode,
                case_sensitive=args.case_sensitive,
                seen_at=seen_at,
                max_retries=args.max_retries,
            )
            return region_matches, None, True
        except Exception as exc:  # noqa: BLE001
            code, message = format_aws_error(exc)
            error_item = {
                "scope": "region",
                "account_id": account.account_id,
                "region": region,
                "stage": "describe_enis",
                "error_code": code,
                "error_message": message,
                "retry_count": args.max_retries,
                "terminal": True,
            }
            return [], error_item, False

    def scan_account(account: AccountInfo) -> dict[str, Any]:
        account_result = {
            "matches": [],
            "errors": [],
            "target_regions": 0,
            "scanned_regions": 0,
            "skipped_regions": 0,
            "account_scanned": False,
        }

        session_name = f"eni-scan-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        try:
            credentials = assume_role_credentials(
                account_id=account.account_id,
                role_name=args.role_name,
                external_id=args.external_id,
                session_name=session_name,
                timeout_seconds=args.request_timeout_seconds,
                max_retries=args.max_retries,
            )
        except Exception as exc:  # noqa: BLE001
            code, message = format_aws_error(exc)
            account_result["errors"].append(
                {
                    "scope": "account",
                    "account_id": account.account_id,
                    "region": None,
                    "stage": "assume_role",
                    "error_code": code,
                    "error_message": message,
                    "retry_count": args.max_retries,
                    "terminal": True,
                }
            )
            return account_result

        if explicit_regions is None:
            try:
                discovered_regions = discover_enabled_regions(
                    credentials=credentials,
                    timeout_seconds=args.request_timeout_seconds,
                    max_retries=args.max_retries,
                )
            except Exception as exc:  # noqa: BLE001
                code, message = format_aws_error(exc)
                account_result["errors"].append(
                    {
                        "scope": "account",
                        "account_id": account.account_id,
                        "region": None,
                        "stage": "describe_regions",
                        "error_code": code,
                        "error_message": message,
                        "retry_count": args.max_retries,
                        "terminal": True,
                    }
                )
                return account_result
        else:
            discovered_regions = explicit_regions

        scan_regions: list[str] = []
        for region in discovered_regions:
            if region in exclude_regions:
                account_result["skipped_regions"] += 1
                continue
            scan_regions.append(region)

        account_result["target_regions"] = len(scan_regions)
        if not scan_regions:
            return account_result

        seen_at = current_utc_iso()

        with ThreadPoolExecutor(max_workers=args.region_concurrency) as region_pool:
            futures = [
                region_pool.submit(scan_region, account, credentials, region, seen_at)
                for region in scan_regions
            ]
            for future in as_completed(futures):
                region_matches, region_error, ok = future.result()
                if ok:
                    account_result["scanned_regions"] += 1
                    account_result["matches"].extend(region_matches)
                elif region_error:
                    account_result["errors"].append(region_error)

        account_result["account_scanned"] = account_result["scanned_regions"] > 0
        return account_result

    with ThreadPoolExecutor(max_workers=args.account_concurrency) as account_pool:
        future_to_account = {
            account_pool.submit(scan_account, account): account for account in target_accounts
        }
        for future in as_completed(future_to_account):
            account = future_to_account[future]
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001
                code, message = format_aws_error(exc)
                errors.append(
                    {
                        "scope": "account",
                        "account_id": account.account_id,
                        "region": None,
                        "stage": "account_scan",
                        "error_code": code,
                        "error_message": message,
                        "retry_count": args.max_retries,
                        "terminal": True,
                    }
                )
                continue

            matches.extend(result["matches"])
            errors.extend(result["errors"])
            coverage["target_account_regions"] += result["target_regions"]
            coverage["scanned_account_regions"] += result["scanned_regions"]
            coverage["skipped_account_regions"] += result["skipped_regions"]
            if result["account_scanned"]:
                coverage["scanned_accounts"] += 1

            if args.verbose:
                print(
                    "account"
                    f" {account.account_id}"
                    f" regions={result['scanned_regions']}/{result['target_regions']}"
                    f" matches={len(result['matches'])}"
                    f" errors={len(result['errors'])}"
                )

    finished_at = current_utc_iso()

    if coverage["scanned_account_regions"] == 0:
        status = "failed"
        exit_code = 1
    elif errors:
        status = "partial_success"
        exit_code = 1 if args.fail_on_partial else 2
    else:
        status = "success"
        exit_code = 0

    report = {
        "query": {
            "mode": query_mode,
            "value": query_value,
            "match_mode": args.match_mode,
            "case_sensitive": bool(args.case_sensitive),
            "started_at": started_at,
            "finished_at": finished_at,
        },
        "coverage": coverage,
        "matches": matches,
        "errors": errors,
        "status": status,
    }

    return report, exit_code


def main(argv: list[str]) -> int:
    try:
        args = parse_args(argv)
        report, exit_code = run_scan(args)
        write_json_report(report, args.output_file)
        print_summary(report, args.output_file)
        return exit_code
    except ClientError as exc:
        code, message = exc.response.get("Error", {}).get("Code", "ClientError"), exc.response.get(
            "Error", {}
        ).get("Message", str(exc))
        print(f"fatal AWS client error: {code}: {message}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        print(f"fatal error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
