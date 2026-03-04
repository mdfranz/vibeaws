# /// script
# dependencies = ["boto3", "rich"]
# ///
from __future__ import annotations

from typing import Callable

import boto3
from rich.console import Console


def discover_global(
    session: boto3.Session,
    account_id: str,
    account_dir: str,
    write_json: Callable,
    paginate: Callable,
    safe_api_call: Callable,
    verbose: bool,
    console: Console,
):
    if verbose: console.print("  [blue]Scanning Global Services...[/]")

    # S3
    if verbose: console.print("    [dim]Scanning S3...[/]")
    s3 = session.client("s3")
    buckets = safe_api_call("s3", "list_buckets", s3.list_buckets)
    if buckets:
        write_json(account_dir, "global", "s3", "buckets.json", buckets)

    # IAM
    if verbose: console.print("    [dim]Scanning IAM...[/]")
    iam = session.client("iam")
    for op, key, filename in [
        ("list_users", "Users", "users.json"),
        ("list_roles", "Roles", "roles.json"),
        ("list_policies", "Policies", "policies.json"),
    ]:
        kwargs = {}
        if op == "list_policies":
            kwargs["Scope"] = "Local"
        data = paginate(iam, op, key, **kwargs)
        if data:
            write_json(account_dir, "global", "iam", filename, {key: data})

    # Route53
    if verbose: console.print("    [dim]Scanning Route53...[/]")
    r53 = session.client("route53")

    zones = paginate(r53, "list_hosted_zones", "HostedZones")
    if zones:
        write_json(
            account_dir,
            "global",
            "route53",
            "hosted_zones.json",
            {"HostedZones": zones},
        )
        for zone in zones:
            zid = zone["Id"].split("/")[-1]
            recs = paginate(
                r53, "list_resource_record_sets", "ResourceRecordSets", HostedZoneId=zid
            )
            if recs:
                write_json(
                    account_dir,
                    "global",
                    "route53",
                    f"records_{zid}.json",
                    {"ResourceRecordSets": recs},
                )
