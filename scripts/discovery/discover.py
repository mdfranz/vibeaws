#!/usr/bin/env python3
"""AWS discovery tool using boto3.

Outputs JSON only, preserving existing results layout under scripts/discovery/results.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


DEFAULT_CLOUDTRAIL_BUCKET = "your-cloudtrail-bucket"
DEFAULT_ACCOUNT_ID = "123456789012"
DEFAULT_OUTPUT_DIR = "scripts/discovery/results"
DEFAULT_LOG_FILE = "discovery.log"
DEFAULT_MAX_WORKERS = 4


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AWS resource discovery (boto3)")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument(
        "--regions",
        help="Comma-separated regions to scan (overrides CloudTrail/active discovery)",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=DEFAULT_MAX_WORKERS,
        help="Max concurrent regional workers (default: %(default)s)",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help="Output directory (default: %(default)s)",
    )
    parser.add_argument(
        "--log-file",
        help="Log file path (default: <output-dir>/discovery.log)",
    )
    parser.add_argument(
        "--cloudtrail-bucket",
        default=DEFAULT_CLOUDTRAIL_BUCKET,
        help="CloudTrail bucket name (default: %(default)s)",
    )
    parser.add_argument(
        "--account-id",
        default=DEFAULT_ACCOUNT_ID,
        help="AWS account ID for CloudTrail prefix (default: %(default)s)",
    )
    parser.add_argument(
        "--cloudtrail-prefix",
        help="CloudTrail prefix override (default: AWSLogs/<account-id>/CloudTrail/)",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Fail fast on first error (default: continue)",
    )
    return parser.parse_args()


def make_session(profile: Optional[str]) -> boto3.Session:
    if profile:
        return boto3.Session(profile_name=profile)
    return boto3.Session()


def make_config() -> Config:
    return Config(retries={"mode": "standard", "max_attempts": 10})


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_json(path: str, obj: Any) -> None:
    ensure_dir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, default=str)


_LOG_FILE = None


def init_log_file(path: str) -> None:
    global _LOG_FILE
    ensure_dir(os.path.dirname(path))
    _LOG_FILE = open(path, "a", encoding="utf-8")


def _write_log_line(line: str) -> None:
    if _LOG_FILE:
        _LOG_FILE.write(line + "\n")
        _LOG_FILE.flush()


def log(msg: str) -> None:
    print(msg, flush=True)
    _write_log_line(msg)


def log_error(msg: str) -> None:
    line = f"ERROR: {msg}"
    print(line, file=sys.stderr, flush=True)
    _write_log_line(line)


def safe_call(name: str, fn, fail_fast: bool) -> Optional[Any]:
    try:
        return fn()
    except (ClientError, BotoCoreError, Exception) as exc:
        log_error(f"{name}: {exc}")
        if fail_fast:
            raise
        return None


def paginate(client, op_name: str, result_key: str, **kwargs) -> List[Any]:
    paginator = client.get_paginator(op_name)
    items: List[Any] = []
    for page in paginator.paginate(**kwargs):
        items.extend(page.get(result_key, []))
    return items


def get_enabled_regions(session: boto3.Session, config: Config) -> Set[str]:
    ec2 = session.client("ec2", region_name="us-east-1", config=config)
    resp = ec2.describe_regions(AllRegions=True)
    regions = set()
    for r in resp.get("Regions", []):
        if r.get("OptInStatus") != "not-opted-in":
            name = r.get("RegionName")
            if name:
                regions.add(name)
    return regions


def get_cloudtrail_regions(
    session: boto3.Session,
    config: Config,
    bucket: str,
    prefix: str,
) -> Set[str]:
    s3 = session.client("s3", config=config)
    regions: Set[str] = set()
    continuation_token: Optional[str] = None

    while True:
        params: Dict[str, Any] = {
            "Bucket": bucket,
            "Prefix": prefix,
            "Delimiter": "/",
        }
        if continuation_token:
            params["ContinuationToken"] = continuation_token
        resp = s3.list_objects_v2(**params)
        for cp in resp.get("CommonPrefixes", []):
            pfx = cp.get("Prefix", "")
            # Prefix format: AWSLogs/<account>/CloudTrail/<region>/
            parts = pfx.strip("/").split("/")
            if parts:
                region = parts[-1]
                if region:
                    regions.add(region)
        if resp.get("IsTruncated"):
            continuation_token = resp.get("NextContinuationToken")
        else:
            break
    return regions


def get_active_regions(
    session: boto3.Session,
    config: Config,
    bucket: str,
    account_id: str,
    prefix_override: Optional[str],
    fail_fast: bool,
) -> List[str]:
    prefix = prefix_override or f"AWSLogs/{account_id}/CloudTrail/"

    cloudtrail_regions = safe_call(
        "cloudtrail_regions",
        lambda: get_cloudtrail_regions(session, config, bucket, prefix),
        fail_fast,
    )
    if cloudtrail_regions is None:
        cloudtrail_regions = set()

    enabled_regions = safe_call(
        "enabled_regions",
        lambda: get_enabled_regions(session, config),
        fail_fast,
    )
    if enabled_regions is None:
        enabled_regions = set()

    active = sorted(cloudtrail_regions & enabled_regions)
    if not active:
        log("No overlapping enabled regions found with CloudTrail logs. Defaulting to us-east-1.")
        active = ["us-east-1"]

    return active


def write_active_regions(path: str, regions: Iterable[str]) -> None:
    ensure_dir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as f:
        f.write(" ".join(regions).strip() + "\n")


def discover_s3(session: boto3.Session, config: Config, output_dir: str, fail_fast: bool) -> None:
    s3 = session.client("s3", config=config)
    buckets = safe_call("s3_list_buckets", s3.list_buckets, fail_fast)
    if buckets is None:
        return
    write_json(os.path.join(output_dir, "global", "s3_buckets.json"), buckets)


def discover_iam(session: boto3.Session, config: Config, output_dir: str, fail_fast: bool) -> None:
    iam = session.client("iam", config=config)

    def users():
        return {"Users": paginate(iam, "list_users", "Users")}

    def roles():
        return {"Roles": paginate(iam, "list_roles", "Roles")}

    users_resp = safe_call("iam_list_users", users, fail_fast)
    if users_resp is not None:
        write_json(os.path.join(output_dir, "global", "iam_users.json"), users_resp)

    roles_resp = safe_call("iam_list_roles", roles, fail_fast)
    if roles_resp is not None:
        write_json(os.path.join(output_dir, "global", "iam_roles.json"), roles_resp)


def discover_route53(session: boto3.Session, config: Config, output_dir: str, fail_fast: bool) -> None:
    r53 = session.client("route53", config=config)

    def zones():
        return {"HostedZones": paginate(r53, "list_hosted_zones", "HostedZones")}

    zones_resp = safe_call("route53_list_zones", zones, fail_fast)
    if zones_resp is not None:
        write_json(os.path.join(output_dir, "global", "route53_hosted_zones.json"), zones_resp)

        # For each zone, fetch record sets
        for zone in zones_resp.get("HostedZones", []):
            zone_id = zone.get("Id", "").split("/")[-1]
            if not zone_id:
                continue

            def records(zid=zone_id):
                return {"ResourceRecordSets": paginate(r53, "list_resource_record_sets", "ResourceRecordSets", HostedZoneId=zid)}

            recs_resp = safe_call(f"route53_records:{zone_id}", records, fail_fast)
            if recs_resp is not None:
                write_json(os.path.join(output_dir, "global", f"route53_records_{zone_id}.json"), recs_resp)


def discover_ec2(region: str, session: boto3.Session, config: Config) -> Dict[str, Any]:
    ec2 = session.client("ec2", region_name=region, config=config)
    return {
        "Reservations": paginate(ec2, "describe_instances", "Reservations"),
    }


def discover_volumes(region: str, session: boto3.Session, config: Config) -> Dict[str, Any]:
    ec2 = session.client("ec2", region_name=region, config=config)
    return {
        "Volumes": paginate(ec2, "describe_volumes", "Volumes"),
    }


def discover_lambda(region: str, session: boto3.Session, config: Config) -> Dict[str, Any]:
    lam = session.client("lambda", region_name=region, config=config)
    return {
        "Functions": paginate(lam, "list_functions", "Functions"),
    }


def discover_vpcs(region: str, session: boto3.Session, config: Config) -> Dict[str, Any]:
    ec2 = session.client("ec2", region_name=region, config=config)
    return {
        "Vpcs": paginate(ec2, "describe_vpcs", "Vpcs"),
    }


def discover_subnets(region: str, session: boto3.Session, config: Config) -> Dict[str, Any]:
    ec2 = session.client("ec2", region_name=region, config=config)
    return {
        "Subnets": paginate(ec2, "describe_subnets", "Subnets"),
    }


def discover_rds(region: str, session: boto3.Session, config: Config) -> Dict[str, Any]:
    rds = session.client("rds", region_name=region, config=config)
    return {
        "DBInstances": paginate(rds, "describe_db_instances", "DBInstances"),
    }


def discover_cloudwatch_logs(region: str, session: boto3.Session, config: Config) -> Dict[str, Any]:
    logs = session.client("logs", region_name=region, config=config)
    return {
        "logGroups": paginate(logs, "describe_log_groups", "logGroups"),
    }


def discover_cloudwatch_metrics(region: str, session: boto3.Session, config: Config) -> Dict[str, Any]:
    cw = session.client("cloudwatch", region_name=region, config=config)
    metrics: List[Any] = []
    paginator = cw.get_paginator("list_metrics")
    for page in paginator.paginate():
        page_metrics = page.get("Metrics", [])
        metrics.extend(page_metrics)
        if len(metrics) >= 20:
            metrics = metrics[:20]
            break
    return {"Metrics": metrics}


def discover_region(
    region: str,
    session: boto3.Session,
    config: Config,
    output_dir: str,
    fail_fast: bool,
) -> None:
    region_dir = os.path.join(output_dir, "regions", region)

    ec2_instances = safe_call(
        f"ec2_instances:{region}",
        lambda: discover_ec2(region, session, config),
        fail_fast,
    )
    if ec2_instances is not None:
        write_json(os.path.join(region_dir, "ec2_instances.json"), ec2_instances)

    ec2_volumes = safe_call(
        f"ec2_volumes:{region}",
        lambda: discover_volumes(region, session, config),
        fail_fast,
    )
    if ec2_volumes is not None:
        write_json(os.path.join(region_dir, "ec2_volumes.json"), ec2_volumes)

    lambda_functions = safe_call(
        f"lambda_functions:{region}",
        lambda: discover_lambda(region, session, config),
        fail_fast,
    )
    if lambda_functions is not None:
        write_json(os.path.join(region_dir, "lambda_functions.json"), lambda_functions)

    vpcs = safe_call(
        f"vpcs:{region}",
        lambda: discover_vpcs(region, session, config),
        fail_fast,
    )
    if vpcs is not None:
        write_json(os.path.join(region_dir, "vpcs.json"), vpcs)

    subnets = safe_call(
        f"subnets:{region}",
        lambda: discover_subnets(region, session, config),
        fail_fast,
    )
    if subnets is not None:
        write_json(os.path.join(region_dir, "subnets.json"), subnets)

    rds_instances = safe_call(
        f"rds_instances:{region}",
        lambda: discover_rds(region, session, config),
        fail_fast,
    )
    if rds_instances is not None:
        write_json(os.path.join(region_dir, "rds_instances.json"), rds_instances)

    cw_log_groups = safe_call(
        f"cloudwatch_log_groups:{region}",
        lambda: discover_cloudwatch_logs(region, session, config),
        fail_fast,
    )
    if cw_log_groups is not None:
        write_json(os.path.join(region_dir, "cloudwatch_log_groups.json"), cw_log_groups)

    cw_metrics = safe_call(
        f"cloudwatch_metrics:{region}",
        lambda: discover_cloudwatch_metrics(region, session, config),
        fail_fast,
    )
    if cw_metrics is not None:
        write_json(os.path.join(region_dir, "cloudwatch_metrics.json"), cw_metrics)


def parse_regions_arg(regions_arg: Optional[str]) -> Optional[List[str]]:
    if not regions_arg:
        return None
    regions = [r.strip() for r in regions_arg.split(",") if r.strip()]
    return regions or None


def main() -> int:
    args = parse_args()

    session = make_session(args.profile)
    config = make_config()

    log_path = args.log_file or os.path.join(args.output_dir, DEFAULT_LOG_FILE)
    init_log_file(log_path)

    log("Starting AWS Resource Discovery...")
    log(f"Account ID: {args.account_id}")
    log("==================================")

    # Update output directory to include account ID
    account_output_dir = os.path.join(args.output_dir, args.account_id)
    ensure_dir(account_output_dir)

    regions = parse_regions_arg(args.regions)
    if regions:
        enabled_regions = safe_call(
            "enabled_regions",
            lambda: get_enabled_regions(session, config),
            args.fail_fast,
        )
        if enabled_regions:
            regions = [r for r in regions if r in enabled_regions]
        if not regions:
            log("No valid regions after filtering; defaulting to us-east-1.")
            regions = ["us-east-1"]
    else:
        regions = get_active_regions(
            session,
            config,
            args.cloudtrail_bucket,
            args.account_id,
            args.cloudtrail_prefix,
            args.fail_fast,
        )

    write_active_regions("scripts/discovery/active_regions.txt", regions)

    log("Discovering global services...")
    discover_s3(session, config, account_output_dir, args.fail_fast)
    discover_iam(session, config, account_output_dir, args.fail_fast)
    discover_route53(session, config, account_output_dir, args.fail_fast)

    log(f"Discovering regional services in {len(regions)} regions...")
    if args.max_workers <= 1 or len(regions) == 1:
        for region in regions:
            log(f"=== Region: {region} ===")
            discover_region(region, session, config, account_output_dir, args.fail_fast)
    else:
        with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
            futures = {
                executor.submit(
                    discover_region, region, session, config, account_output_dir, args.fail_fast
                ): region
                for region in regions
            }
            for future in as_completed(futures):
                region = futures[future]
                try:
                    future.result()
                    log(f"=== Region complete: {region} ===")
                except Exception as exc:
                    log_error(f"region_failed:{region}: {exc}")
                    if args.fail_fast:
                        raise

    log("==================================")
    log("Discovery Complete.")
    log(f"All results are stored in {account_output_dir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
