# /// script
# dependencies = ["boto3", "click", "rich"]
# ///
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, List, Optional, Callable

import boto3
import click
from botocore.exceptions import ClientError, EndpointConnectionError
from rich.console import Console
from rich.panel import Panel

from discovery_config import DEFAULT_MAX_WORKERS, DEFAULT_OUTPUT_DIR
from discovery_global import discover_global as discover_global_impl
from discovery_regional import discover_region as discover_region_impl
from report import generate_discovery_report

console = Console()

class AWSDiscovery:
    def __init__(self, profile: Optional[str] = None, role_arn: Optional[str] = None, output_dir: str = DEFAULT_OUTPUT_DIR, verbose: bool = False):
        self.session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.output_dir = output_dir
        self.verbose = verbose

        if role_arn:
            if self.verbose: console.print(f"  [dim]Assuming role: {role_arn}...[/]")
            sts = self.session.client("sts")
            try:
                assumed_role = sts.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName="WolkfindDiscoverySession"
                )
                creds = assumed_role["Credentials"]
                self.session = boto3.Session(
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"]
                )
            except Exception as e:
                console.print(f"[bold red]Critical Error:[/] Could not assume role {role_arn}. ({e})")
                sys.exit(1)

        try:
            self.account_id = self.session.client("sts").get_caller_identity()["Account"]
        except Exception as e:
            console.print(f"[bold red]Critical Error:[/] Could not retrieve account identity. Check credentials. ({e})")
            sys.exit(1)
            
        self.account_dir = os.path.join(self.output_dir, self.account_id)
        os.makedirs(self.account_dir, exist_ok=True)

    def _ensure_dir(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def _write_json(self, account_dir: str, region: str, service: str, filename: str, data: Any):
        path = os.path.join(account_dir, region, service, filename)
        self._ensure_dir(path)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def _safe_api_call(self, service: str, op_name: str, fn: Callable, *args, **kwargs) -> Optional[Any]:
        try:
            return fn(*args, **kwargs)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if code not in ["AccessDenied", "UnauthorizedOperation", "AccessDeniedException", "404", "NoSuchKey", "UnrecognizedClientException", "InvalidAccessException"]:
                if self.verbose: console.print(f"  [dim red]! {service}:{op_name} error: {code}[/]")
        except EndpointConnectionError:
            # Expected when service is not available in a region
            return None
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
            if res is None: return []
            return res.get(result_key, []) if isinstance(res, dict) else []

    def discover_global(self):
        discover_global_impl(
            self.session,
            self.account_id,
            self.account_dir,
            self._write_json,
            self._paginate,
            self._safe_api_call,
            self.verbose,
            console,
        )

    def get_active_regions(self) -> List[str]:
        ec2 = self.session.client("ec2", region_name="us-east-1")
        resp = self._safe_api_call("ec2", "describe_regions", ec2.describe_regions)
        return [r["RegionName"] for r in resp.get("Regions", [])] if resp else ["us-east-1"]

    def discover_region(self, region: str, deeptrail: bool = False, trail_days: int = 30):
        return discover_region_impl(
            self.session,
            self.account_id,
            self.account_dir,
            region,
            self._write_json,
            self._paginate,
            self._safe_api_call,
            self.verbose,
            console,
            deeptrail=deeptrail,
            trail_days=trail_days,
        )

    def run(self, regions: List[str], max_workers: int, deeptrail: bool = False, trail_months: int = 1):
        trail_days = trail_months * 30
        panel_text = f"[bold blue]AWS Discovery: {self.account_id}[/]\nRegions: {len(regions)}"
        if deeptrail:
            panel_text += f" | DeepTrail Months: {trail_months} ({trail_days}d)"
        console.print(Panel(panel_text))
        self.discover_global()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.discover_region, r, deeptrail, trail_days): r for r in regions}
            for future in as_completed(futures):
                region = futures[future]
                future.result()
                console.print(f"  [green]✓[/] {region}")


@click.group()
def cli(): pass

@cli.command()
@click.option("--region", help="Comma-separated regions")
@click.option("--role-arn", help="AWS Role ARN to assume")
@click.option("--deeptrail", is_flag=True)
@click.option("--trail-months", default=1, type=int)
@click.option("--detailed", is_flag=True)
@click.option("--verbose", is_flag=True)
def discover(region, role_arn, deeptrail, trail_months, detailed, verbose):
    discovery = AWSDiscovery(role_arn=role_arn, verbose=verbose)
    regions = [r.strip() for r in region.split(",")] if region else discovery.get_active_regions()
    discovery.run(regions, DEFAULT_MAX_WORKERS, deeptrail, trail_months)
    generate_discovery_report(discovery.output_dir, detailed)

@cli.command()
@click.option("--output-dir", default=DEFAULT_OUTPUT_DIR)
@click.option("--detailed", is_flag=True)
@click.option("--verbose", is_flag=True)
def report(output_dir, detailed, verbose):
    generate_discovery_report(output_dir, detailed)

if __name__ == "__main__": cli()
