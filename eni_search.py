from __future__ import annotations

import re
from typing import Any

from aws_org_scan import call_with_retries


def _normalize_text(value: str, case_sensitive: bool) -> str:
    return value if case_sensitive else value.lower()


def text_matches(
    candidate: str,
    wanted: str,
    match_mode: str,
    case_sensitive: bool,
) -> bool:
    left = _normalize_text(candidate, case_sensitive)
    right = _normalize_text(wanted, case_sensitive)

    if match_mode == "exact":
        return left == right
    if match_mode == "contains":
        return right in left
    if match_mode == "regex":
        flags = 0 if case_sensitive else re.IGNORECASE
        return re.search(wanted, candidate, flags=flags) is not None
    raise ValueError(f"Unsupported match mode: {match_mode}")


def extract_public_ips(eni: dict[str, Any]) -> list[str]:
    public_ips: set[str] = set()

    for private_ip in eni.get("PrivateIpAddresses", []):
        association = private_ip.get("Association", {})
        public_ip = association.get("PublicIp")
        if public_ip:
            public_ips.add(public_ip)

    association = eni.get("Association", {})
    eni_level_public_ip = association.get("PublicIp")
    if eni_level_public_ip:
        public_ips.add(eni_level_public_ip)

    return sorted(public_ips)


def extract_private_ips(eni: dict[str, Any]) -> list[str]:
    private_ips = []
    for private_ip in eni.get("PrivateIpAddresses", []):
        value = private_ip.get("PrivateIpAddress")
        if value:
            private_ips.append(value)
    return sorted(set(private_ips))


def match_eni(
    eni: dict[str, Any],
    query_mode: str,
    query_value: str,
    match_mode: str,
    case_sensitive: bool,
) -> bool:
    if query_mode == "public_ip":
        return query_value in extract_public_ips(eni)

    if query_mode == "eni_name":
        tag_name = ""
        for tag in eni.get("TagSet", []):
            if tag.get("Key") == "Name":
                tag_name = tag.get("Value", "")
                break
        return text_matches(tag_name, query_value, match_mode, case_sensitive)

    if query_mode == "description":
        description = eni.get("Description", "")
        return text_matches(description, query_value, match_mode, case_sensitive)

    raise ValueError(f"Unsupported query mode: {query_mode}")


def build_ec2_filters(query_mode: str, query_value: str) -> list[dict[str, Any]]:
    if query_mode == "public_ip":
        return [{"Name": "addresses.association.public-ip", "Values": [query_value]}]
    if query_mode == "eni_name":
        return [{"Name": "tag:Name", "Values": [query_value]}]
    if query_mode == "description":
        return [{"Name": "description", "Values": [query_value]}]
    raise ValueError(f"Unsupported query mode: {query_mode}")


def normalize_match(
    eni: dict[str, Any],
    account_id: str,
    account_name: str,
    region: str,
    seen_at: str,
) -> dict[str, Any]:
    attachment = eni.get("Attachment", {})
    tag_name = ""
    for tag in eni.get("TagSet", []):
        if tag.get("Key") == "Name":
            tag_name = tag.get("Value", "")
            break

    return {
        "account_id": account_id,
        "account_name": account_name,
        "region": region,
        "network_interface_id": eni.get("NetworkInterfaceId", ""),
        "interface_type": eni.get("InterfaceType", ""),
        "status": eni.get("Status", ""),
        "description": eni.get("Description", ""),
        "tag_name": tag_name,
        "vpc_id": eni.get("VpcId", ""),
        "subnet_id": eni.get("SubnetId", ""),
        "private_ips": extract_private_ips(eni),
        "public_ips": extract_public_ips(eni),
        "requester_managed": bool(eni.get("RequesterManaged", False)),
        "attachment_instance_id": attachment.get("InstanceId", ""),
        "attachment_status": attachment.get("Status", ""),
        "owner_id": eni.get("OwnerId", ""),
        "seen_at": seen_at,
    }


def search_network_interfaces(
    ec2_client: Any,
    account_id: str,
    account_name: str,
    region: str,
    query_mode: str,
    query_value: str,
    match_mode: str,
    case_sensitive: bool,
    seen_at: str,
    max_retries: int,
) -> list[dict[str, Any]]:
    filters = build_ec2_filters(query_mode, query_value)
    paginator = ec2_client.get_paginator("describe_network_interfaces")
    page_iterator = call_with_retries(
        paginator.paginate,
        Filters=filters,
        PaginationConfig={"PageSize": 1000},
        max_retries=max_retries,
    )

    matches: list[dict[str, Any]] = []
    for page in page_iterator:
        for eni in page.get("NetworkInterfaces", []):
            if match_eni(eni, query_mode, query_value, match_mode, case_sensitive):
                matches.append(
                    normalize_match(
                        eni=eni,
                        account_id=account_id,
                        account_name=account_name,
                        region=region,
                        seen_at=seen_at,
                    )
                )

    return matches
