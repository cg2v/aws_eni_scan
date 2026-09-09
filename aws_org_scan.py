from __future__ import annotations
# pylint: disable=broad-exception-caught

import random
import time
from dataclasses import dataclass
from typing import Any, Callable

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, EndpointConnectionError


RETRIABLE_ERROR_CODES = {
    "RequestLimitExceeded",
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
    "ServiceUnavailable",
    "InternalError",
    "InternalFailure",
    "PriorRequestNotComplete",
    "RequestTimeout",
}


@dataclass(frozen=True)
class AccountInfo:
    account_id: str
    account_name: str


def make_client(
    service_name: str,
    region_name: str | None = None,
    credentials: dict[str, str] | None = None,
    timeout_seconds: int = 20,
):
    config = Config(
        retries={"max_attempts": 1, "mode": "standard"},
        read_timeout=timeout_seconds,
        connect_timeout=timeout_seconds,
    )
    kwargs: dict[str, Any] = {"service_name": service_name, "config": config}
    if region_name:
        kwargs["region_name"] = region_name

    if credentials:
        kwargs["aws_access_key_id"] = credentials["AccessKeyId"]
        kwargs["aws_secret_access_key"] = credentials["SecretAccessKey"]
        kwargs["aws_session_token"] = credentials["SessionToken"]

    return boto3.client(**kwargs)


def is_retriable_exception(exc: Exception) -> bool:
    if isinstance(exc, EndpointConnectionError):
        return True
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        status_code = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
        return code in RETRIABLE_ERROR_CODES or status_code >= 500
    return False


def call_with_retries(
    fn: Callable[..., Any],
    *args: Any,
    max_retries: int = 4,
    base_delay_seconds: float = 0.4,
    **kwargs: Any,
) -> Any:
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return fn(*args, **kwargs)
        except (ClientError, EndpointConnectionError, BotoCoreError) as exc:
            last_exc = exc
            if attempt >= max_retries or not is_retriable_exception(exc):
                raise
            sleep_s = base_delay_seconds * (2**attempt)
            sleep_s = random.uniform(0, sleep_s)
            time.sleep(sleep_s)
    raise RuntimeError("retry loop exhausted") from last_exc


def list_active_accounts(org_client: Any, max_retries: int) -> list[AccountInfo]:
    paginator = org_client.get_paginator("list_accounts")
    accounts: list[AccountInfo] = []

    page_iterator = call_with_retries(
        paginator.paginate,
        max_retries=max_retries,
    )
    for page in page_iterator:
        for account in page.get("Accounts", []):
            if account.get("Status") == "ACTIVE":
                accounts.append(
                    AccountInfo(
                        account_id=account["Id"],
                        account_name=account.get("Name", ""),
                    )
                )

    return accounts


def list_child_ous(org_client: Any, parent_id: str, max_retries: int) -> list[str]:
    paginator = org_client.get_paginator("list_organizational_units_for_parent")
    page_iterator = call_with_retries(
        paginator.paginate,
        ParentId=parent_id,
        max_retries=max_retries,
    )

    ou_ids: list[str] = []
    for page in page_iterator:
        for ou in page.get("OrganizationalUnits", []):
            ou_id = ou.get("Id")
            if ou_id:
                ou_ids.append(ou_id)
    return ou_ids


def list_active_accounts_for_parent(
    org_client: Any,
    parent_id: str,
    max_retries: int,
) -> list[AccountInfo]:
    paginator = org_client.get_paginator("list_accounts_for_parent")
    page_iterator = call_with_retries(
        paginator.paginate,
        ParentId=parent_id,
        max_retries=max_retries,
    )

    accounts: list[AccountInfo] = []
    for page in page_iterator:
        for account in page.get("Accounts", []):
            if account.get("Status") == "ACTIVE":
                accounts.append(
                    AccountInfo(
                        account_id=account["Id"],
                        account_name=account.get("Name", ""),
                    )
                )
    return accounts


def list_active_accounts_for_ou_scope(
    org_client: Any,
    ou_or_root_ids: list[str],
    max_retries: int,
) -> list[AccountInfo]:
    visited_parents: set[str] = set()
    dedup_accounts: dict[str, AccountInfo] = {}

    def walk_parent(parent_id: str) -> None:
        if parent_id in visited_parents:
            return
        visited_parents.add(parent_id)

        for account in list_active_accounts_for_parent(org_client, parent_id, max_retries):
            dedup_accounts[account.account_id] = account

        for child_ou_id in list_child_ous(org_client, parent_id, max_retries):
            walk_parent(child_ou_id)

    for parent_id in ou_or_root_ids:
        walk_parent(parent_id)

    return sorted(dedup_accounts.values(), key=lambda a: a.account_id)


def assume_role_credentials(
    account_id: str,
    role_name: str,
    external_id: str | None,
    session_name: str,
    timeout_seconds: int,
    max_retries: int,
) -> dict[str, str]:
    sts_client = make_client("sts", timeout_seconds=timeout_seconds)
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    assume_args: dict[str, Any] = {
        "RoleArn": role_arn,
        "RoleSessionName": session_name,
    }
    if external_id:
        assume_args["ExternalId"] = external_id

    response = call_with_retries(
        sts_client.assume_role,
        max_retries=max_retries,
        **assume_args,
    )
    return response["Credentials"]


def discover_enabled_regions(
    credentials: dict[str, str],
    timeout_seconds: int,
    max_retries: int,
) -> list[str]:
    ec2_client = make_client(
        "ec2",
        region_name="us-east-1",
        credentials=credentials,
        timeout_seconds=timeout_seconds,
    )
    response = call_with_retries(
        ec2_client.describe_regions,
        AllRegions=True,
        max_retries=max_retries,
    )

    regions: list[str] = []
    for region in response.get("Regions", []):
        status = region.get("OptInStatus", "")
        if status in {"opt-in-not-required", "opted-in"}:
            region_name = region.get("RegionName")
            if region_name:
                regions.append(region_name)

    return sorted(regions)


def format_aws_error(exc: Exception) -> tuple[str, str]:
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {})
        return error.get("Code", "ClientError"), error.get("Message", str(exc))
    return exc.__class__.__name__, str(exc)
