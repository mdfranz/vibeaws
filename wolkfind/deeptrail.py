# /// script
# dependencies = ["rich"]
# ///
from __future__ import annotations

import gzip
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import boto3
from rich.console import Console


def get_trail_config(session: boto3.Session, console: Console, verbose: bool) -> Optional[Tuple[str, str]]:
    ct = session.client("cloudtrail", region_name="us-east-1")
    trails = ct.describe_trails().get("trailList", [])
    if not trails:
        return None
    trail = trails[0]
    if verbose:
        console.print(
            f"[dim blue]Using Trail: {trail['Name']} (S3: {trail['S3BucketName']})[/]"
        )
    return trail.get("S3BucketName"), trail.get("S3KeyPrefix", "")


def download_trail_samples(
    session: boto3.Session,
    account_id: str,
    account_dir: str,
    region: str,
    bucket: str,
    prefix: str,
    days: int,
    verbose: bool,
    console: Console,
    safe_api_call,
) -> List[str]:
    s3 = session.client("s3")
    now = datetime.now(timezone.utc)
    downloaded: List[str] = []
    cache_dir = os.path.join(account_dir, region, "cache", "cloudtrail")
    os.makedirs(cache_dir, exist_ok=True)

    for i in range(days):
        dt = now - timedelta(days=i)
        day_prefix = (
            f"{prefix}/AWSLogs/{account_id}/CloudTrail/{region}/"
            f"{dt.year}/{dt.month:02d}/{dt.day:02d}/"
        )
        if prefix == "":
            day_prefix = day_prefix[1:]

        objs = s3.list_objects_v2(Bucket=bucket, Prefix=day_prefix, MaxKeys=5).get(
            "Contents", []
        )
        if not objs:
            continue
        obj = objs[0]
        key = obj["Key"]
        fname = key.split("/")[-1]
        local_path = os.path.join(cache_dir, fname)
        if not os.path.exists(local_path):
            if verbose:
                console.print(
                    f"  [dim green]Downloading sample for {dt.strftime('%Y-%m-%d')}...[/]"
                )
            safe_api_call("s3", "download_file", s3.download_file, bucket, key, local_path)
        if os.path.exists(local_path):
            downloaded.append(local_path)
    return downloaded


def parse_trail_events(file_paths: List[str]) -> List[Dict]:
    events: List[Dict] = []
    for path in file_paths:
        try:
            with gzip.open(path, "rb") as f:
                data = json.load(f)
                events.extend(data.get("Records", []))
        except Exception:
            continue
    return events
