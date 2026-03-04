# /// script
# dependencies = ["boto3", "click", "rich"]
# ///
import json
import os
import sys
import gzip
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Callable

import boto3
import click
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree

# Constants
DEFAULT_OUTPUT_DIR = "scripts/discovery/results"
DEFAULT_MAX_WORKERS = 10
LOOKUP_DAYS = 90
TRAIL_DISCOVERY_DAYS = 30 
BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})

console = Console()

SCANNED_SERVICES = {
    "ec2.amazonaws.com", "rds.amazonaws.com", "lambda.amazonaws.com", 
    "s3.amazonaws.com", "iam.amazonaws.com", "route53.amazonaws.com",
    "sqs.amazonaws.com", "dynamodb.amazonaws.com", "logs.amazonaws.com",
    "autoscaling.amazonaws.com", "elasticloadbalancing.amazonaws.com",
    "eks.amazonaws.com", "sns.amazonaws.com", "elasticfilesystem.amazonaws.com",
    "cloudtrail.amazonaws.com", "sts.amazonaws.com" # Added these to known
}

class AWSDiscovery:
    def __init__(self, profile: Optional[str] = None, output_dir: str = DEFAULT_OUTPUT_DIR, verbose: bool = False):
        self.session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.output_dir = output_dir
        self.verbose = verbose
        try:
            self.account_id = self.session.client("sts").get_caller_identity()["Account"]
        except Exception as e:
            console.print(f"[bold red]Critical Error:[/] Could not retrieve account identity. ({e})")
            sys.exit(1)
            
        self.account_dir = os.path.join(self.output_dir, self.account_id)
        os.makedirs(self.account_dir, exist_ok=True)

    def _get_path(self, region: str, service: str, filename: str) -> str:
        return os.path.join(self.account_dir, region, service, filename)

    def _ensure_dir(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def _write_json(self, path: str, data: Any):
        self._ensure_dir(path)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def _safe_api_call(self, service: str, op_name: str, fn: Callable, *args, **kwargs) -> Optional[Any]:
        try:
            return fn(*args, **kwargs)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if code not in ["AccessDenied", "UnauthorizedOperation", "AccessDeniedException", "404", "NoSuchKey"]:
                if self.verbose: console.print(f"  [dim red]! {service}:{op_name} error: {code}[/]")
        except Exception as e:
            if self.verbose: console.print(f"  [dim red]! {service}:{op_name} unexpected: {e}[/]")
        return None

    def _paginate(self, client, op_name: str, result_key: str, **kwargs) -> List[Any]:
        service_name = client.meta.service_model.service_name
        if client.can_paginate(op_name):
            paginator = client.get_paginator(op_name)
            def run_pagination():
                items = []
                for page in paginator.paginate(**kwargs):
                    items.extend(page.get(result_key, []))
                return items
            res = self._safe_api_call(service_name, op_name, run_pagination)
            return res if res is not None else []
        else:
            method = getattr(client, op_name)
            res = self._safe_api_call(service_name, op_name, method, **kwargs)
            return res.get(result_key, []) if res is not None else []

    def _get_trail_config(self) -> Optional[Tuple[str, str]]:
        ct = self.session.client("cloudtrail", region_name="us-east-1")
        trails = ct.describe_trails().get("trailList", [])
        if not trails: return None
        t = trails[0]
        if self.verbose: console.print(f"[dim blue]Using Trail: {t['Name']} (S3: {t['S3BucketName']})[/]")
        return t.get("S3BucketName"), t.get("S3KeyPrefix", "")

    def _download_trail_samples(self, region: str, bucket: str, prefix: str, days: int):
        s3 = self.session.client("s3")
        now = datetime.now(timezone.utc)
        downloaded = []
        cache_dir = os.path.join(self.account_dir, region, "cache", "cloudtrail")
        os.makedirs(cache_dir, exist_ok=True)

        for i in range(days):
            dt = now - timedelta(days=i)
            day_prefix = f"{prefix}/AWSLogs/{self.account_id}/CloudTrail/{region}/{dt.year}/{dt.month:02d}/{dt.day:02d}/"
            if prefix == "": day_prefix = day_prefix[1:]
            
            objs = s3.list_objects_v2(Bucket=bucket, Prefix=day_prefix, MaxKeys=5).get("Contents", [])
            if objs:
                obj = objs[0]
                key = obj["Key"]
                fname = key.split("/")[-1]
                local_path = os.path.join(cache_dir, fname)
                if not os.path.exists(local_path):
                    if self.verbose: console.print(f"  [dim green]Downloading sample for {dt.strftime('%Y-%m-%d')}...[/]")
                    self._safe_api_call("s3", "download_file", s3.download_file, bucket, key, local_path)
                if os.path.exists(local_path):
                    downloaded.append(local_path)
        return downloaded

    def _parse_trail_events(self, file_paths: List[str]) -> List[Dict]:
        events = []
        for path in file_paths:
            try:
                with gzip.open(path, "rb") as f:
                    data = json.load(f)
                    events.extend(data.get("Records", []))
            except Exception: continue
        return events

    def get_active_regions(self) -> List[str]:
        ec2 = self.session.client("ec2", region_name="us-east-1")
        resp = self._safe_api_call("ec2", "describe_regions", ec2.describe_regions)
        return [r["RegionName"] for r in resp.get("Regions", [])] if resp else ["us-east-1"]

    def discover_region(self, region: str, deeptrail: bool = False, trail_days: int = 30):
        def get_client(service): return self.session.client(service, region_name=region, config=BOTO_CONFIG)
        clients = {s: get_client(s if s != "lam" else "lambda") for s in ["ec2", "rds", "lam", "dynamodb", "sqs", "cloudtrail"]}
        
        discovery_map = {"ec2": {"vpcs.json": ("describe_vpcs", "Vpcs")}, "sqs": {"queues.json": ("list_queues", "QueueUrls")}, "dynamodb": {"tables.json": ("list_tables", "TableNames")}}
        for svc, files in discovery_map.items():
            client = clients[svc]
            for filename, (op, key) in files.items():
                data = self._paginate(client, op, key)
                if data: self._write_json(self._get_path(region, svc, filename), {key: data})

        if deeptrail:
            config = self._get_trail_config()
            if config:
                bucket, prefix = config
                files = self._download_trail_samples(region, bucket, prefix, trail_days)
                if files:
                    events = self._parse_trail_events(files)
                    self._write_json(self._get_path(region, "cloudtrail", "discovery_events.json"), {"Records": events})
                    if self.verbose: console.print(f"  [dim blue]Parsed {len(events)} events for discovery.[/]")
        
        return region

    def run(self, regions: List[str], max_workers: int, deeptrail: bool = False, trail_months: int = 1):
        trail_days = trail_months * 30
        console.print(Panel(f"[bold blue]AWS Discovery: {self.account_id}[/]\nRegions: {len(regions)} | DeepTrail Months: {trail_months} ({trail_days}d)"))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.discover_region, r, deeptrail, trail_days): r for r in regions}
            for future in as_completed(futures):
                region = futures[future]
                future.result()
                console.print(f"  [green]✓[/] {region}")

def load_json(path: str) -> Dict[str, Any]:
    if not os.path.exists(path): return {}
    with open(path, "r") as f: return json.load(f)

def generate_discovery_report(output_dir: str):
    accounts = [d for d in os.listdir(output_dir) if os.path.isdir(os.path.join(output_dir, d)) and d.isdigit()]
    for account_id in accounts:
        acc_dir = os.path.join(output_dir, account_id)
        regions = [d for d in os.listdir(acc_dir) if os.path.isdir(os.path.join(acc_dir, d)) and d != "global"]
        
        for region in sorted(regions):
            r_path = os.path.join(acc_dir, region)
            events = load_json(os.path.join(r_path, "cloudtrail/discovery_events.json")).get("Records", [])
            if not events: continue
            
            unmapped = {}
            for ev in events:
                src = ev.get("eventSource")
                if src and src not in SCANNED_SERVICES:
                    if src not in unmapped: unmapped[src] = set()
                    unmapped[src].add(ev.get("eventName"))
            
            if unmapped:
                tree = Tree(f"[bold cyan]Discovery via CloudTrail: {region}[/]")
                node = tree.add("[bold yellow]Unmapped Service Activity Detected[/]")
                for src, actions in sorted(unmapped.items()):
                    svc_node = node.add(f"[bold white]{src}[/]")
                    for action in sorted(list(actions))[:10]:
                        svc_node.add(f"[dim]{action}[/]")
                console.print(tree)

@click.group()
def cli(): pass

@cli.command()
@click.option("--region", help="Comma-separated regions")
@click.option("--deeptrail", is_flag=True)
@click.option("--trail-months", default=1, type=int, help="Number of months to sample")
@click.option("--verbose", is_flag=True, help="Show detailed discovery activity")
def discover(region, deeptrail, trail_months, verbose):
    discovery = AWSDiscovery(verbose=verbose)
    regions = [r.strip() for r in region.split(",")] if region else discovery.get_active_regions()
    discovery.run(regions, DEFAULT_MAX_WORKERS, deeptrail, trail_months)
    generate_discovery_report(discovery.output_dir)

@cli.command()
def report():
    generate_discovery_report(DEFAULT_OUTPUT_DIR)

if __name__ == "__main__": cli()
