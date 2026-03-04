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
    "cloudtrail.amazonaws.com", "sts.amazonaws.com", "cloudformation.amazonaws.com",
    "wafv2.amazonaws.com", "kms.amazonaws.com", "ssm.amazonaws.com",
    "apigateway.amazonaws.com", "workspaces.amazonaws.com", "ecr.amazonaws.com",
    "guardduty.amazonaws.com", "securityhub.amazonaws.com", "amplify.amazonaws.com",
    "ecs.amazonaws.com", "elb.amazonaws.com", "elbv2.amazonaws.com",
    "waf-regional.amazonaws.com", "internetmonitor.amazonaws.com", "ssm-quicksetup.amazonaws.com",
    "notifications.amazonaws.com", "bedrock.amazonaws.com", "ds.amazonaws.com",
    "sso.amazonaws.com", "resource-explorer-2.amazonaws.com", "monitoring.amazonaws.com",
    "resource-groups.amazonaws.com", "servicecatalog-appregistry.amazonaws.com",
    "tagging.amazonaws.com", "oam.amazonaws.com", "application-insights.amazonaws.com",
    "athena.amazonaws.com", "events.amazonaws.com", "backup.amazonaws.com",
    "codebuild.amazonaws.com", "config.amazonaws.com", "redshift.amazonaws.com",
    "sagemaker.amazonaws.com", "access-analyzer.amazonaws.com", "cognito-idp.amazonaws.com",
    "es.amazonaws.com", "servicediscovery.amazonaws.com", "opensearch.amazonaws.com",
    "appconfig.amazonaws.com", "apprunner.amazonaws.com", "appstream.amazonaws.com",
    "firehose.amazonaws.com", "imagebuilder.amazonaws.com", "codepipeline.amazonaws.com",
    "detective.amazonaws.com", "macie2.amazonaws.com", "signin.amazonaws.com",
    "q.amazonaws.com"
}

class AWSDiscovery:
    def __init__(self, profile: Optional[str] = None, output_dir: str = DEFAULT_OUTPUT_DIR, verbose: bool = False):
        self.session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.output_dir = output_dir
        self.verbose = verbose
        try:
            self.account_id = self.session.client("sts").get_caller_identity()["Account"]
        except Exception as e:
            console.print(f"[bold red]Critical Error:[/] Could not retrieve account identity. Check credentials. ({e})")
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
            if code not in ["AccessDenied", "UnauthorizedOperation", "AccessDeniedException", "404", "NoSuchKey", "UnrecognizedClientException", "InvalidAccessException"]:
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
            if res is None: return []
            return res.get(result_key, []) if isinstance(res, dict) else []

    def discover_global(self):
        if self.verbose: console.print("  [blue]Scanning Global Services...[/]")
        # S3
        s3 = self.session.client("s3")
        buckets = self._safe_api_call("s3", "list_buckets", s3.list_buckets)
        if buckets: self._write_json(self._get_path("global", "s3", "buckets.json"), buckets)
        
        # IAM
        iam = self.session.client("iam")
        for op, key, filename in [("list_users", "Users", "users.json"), ("list_roles", "Roles", "roles.json"), ("list_policies", "Policies", "policies.json")]:
            kwargs = {}
            if op == "list_policies": kwargs['Scope'] = 'Local'
            data = self._paginate(iam, op, key, **kwargs)
            if data: self._write_json(self._get_path("global", "iam", filename), {key: data})
            
        # Route53
        r53 = self.session.client("route53")
        zones = self._paginate(r53, "list_hosted_zones", "HostedZones")
        if zones:
            self._write_json(self._get_path("global", "route53", "hosted_zones.json"), {"HostedZones": zones})
            for zone in zones:
                zid = zone["Id"].split("/")[-1]
                recs = self._paginate(r53, "list_resource_record_sets", "ResourceRecordSets", HostedZoneId=zid)
                if recs: self._write_json(self._get_path("global", "route53", f"records_{zid}.json"), {"ResourceRecordSets": recs})

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
        discovery_map = {
            "ec2": {"vpcs.json": ("describe_vpcs", "Vpcs"), "subnets.json": ("describe_subnets", "Subnets"), "instances.json": ("describe_instances", "Reservations"), "volumes.json": ("describe_volumes", "Volumes"), "security_groups.json": ("describe_security_groups", "SecurityGroups")},
            "rds": {"instances.json": ("describe_db_instances", "DBInstances")},
            "lambda": {"functions.json": ("list_functions", "Functions")},
            "dynamodb": {"tables.json": ("list_tables", "TableNames")},
            "sqs": {"queues.json": ("list_queues", "QueueUrls")},
            "sns": {"topics.json": ("list_topics", "Topics")},
            "logs": {"log_groups.json": ("describe_log_groups", "logGroups")},
            "cloudformation": {"stacks.json": ("describe_stacks", "Stacks")},
            "kms": {"keys.json": ("list_keys", "Keys")},
            "ssm": {"parameters.json": ("describe_parameters", "Parameters")},
            "apigateway": {"rest_apis.json": ("get_rest_apis", "items")},
            "apigatewayv2": {"apis.json": ("get_apis", "Items")},
            "workspaces": {"workspaces.json": ("describe_workspaces", "Workspaces")},
            "ecr": {"repositories.json": ("describe_repositories", "repositories")},
            "guardduty": {"detectors.json": ("list_detectors", "DetectorIds")},
            "securityhub": {"hub.json": ("describe_hub", "HubArn")},
            "amplify": {"apps.json": ("list_apps", "apps")},
            "eks": {"clusters.json": ("list_clusters", "clusters")},
            "ecs": {"clusters.json": ("list_clusters", "clusterArns")},
            "elb": {"load_balancers.json": ("describe_load_balancers", "LoadBalancerDescriptions")},
            "elbv2": {"load_balancers.json": ("describe_load_balancers", "LoadBalancers")},
            "autoscaling": {"groups.json": ("describe_auto_scaling_groups", "AutoScalingGroups")},
            "waf-regional": {"web_acls.json": ("list_web_acls", "WebACLs")},
            "internetmonitor": {"monitors.json": ("list_monitors", "Monitors")},
            "resourcegroupstaggingapi": {"resources.json": ("get_resources", "ResourceTagMappingList")},
            "athena": {"workgroups.json": ("list_work_groups", "WorkGroups")},
            "events": {"rules.json": ("list_rules", "Rules")},
            "backup": {"vaults.json": ("list_backup_vaults", "BackupVaultList")},
            "codebuild": {"projects.json": ("list_projects", "projects")},
            "config": {"rules.json": ("describe_config_rules", "ConfigRules")},
            "redshift": {"clusters.json": ("describe_clusters", "Clusters")},
            "sagemaker": {"notebooks.json": ("list_notebook_instances", "NotebookInstances")},
            "accessanalyzer": {"analyzers.json": ("list_analyzers", "analyzers")},
            "cognito-idp": {"user_pools.json": ("list_user_pools", "UserPools")},
            "opensearch": {"domains.json": ("list_domain_names", "DomainNames")},
            "servicediscovery": {"namespaces.json": ("list_namespaces", "Namespaces")},
            "appconfig": {"applications.json": ("list_applications", "Items")},
            "apprunner": {"vpc_connectors.json": ("list_vpc_connectors", "VpcConnectors")},
            "firehose": {"delivery_streams.json": ("list_delivery_streams", "DeliveryStreamNames")},
            "imagebuilder": {"recipes.json": ("list_container_recipes", "containerRecipeSummaryList")},
            "codepipeline": {"pipelines.json": ("list_pipelines", "pipelines")},
            "detective": {"graphs.json": ("list_graphs", "GraphList")},
            "macie2": {"session.json": ("get_macie_session", "status")}
        }

        for svc, files in discovery_map.items():
            try:
                client = self.session.client(svc, region_name=region, config=BOTO_CONFIG)
                for filename, (op, key) in files.items():
                    kwargs = {}
                    if svc == "cognito-idp" and op == "list_user_pools": kwargs['MaxResults'] = 60
                    data = self._paginate(client, op, key, **kwargs)
                    if data: self._write_json(self._get_path(region, svc, filename), {key: data})
            except Exception as e:
                if self.verbose: console.print(f"  [dim red]! {svc} connection failed in {region}: {e}[/]")

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
        self.discover_global()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.discover_region, r, deeptrail, trail_days): r for r in regions}
            for future in as_completed(futures):
                region = futures[future]
                future.result()
                console.print(f"  [green]✓[/] {region}")

def load_json(path: str) -> Dict[str, Any]:
    if not os.path.exists(path): return {}
    with open(path, "r") as f: return json.load(f)

def extract_identifiers(acc_dir: str, region: str) -> Set[str]:
    """Scans all JSON files in a region to extract unique resource IDs/Names."""
    ids = set()
    r_path = os.path.join(acc_dir, region)
    if not os.path.exists(r_path): return ids
    
    for root, _, files in os.walk(r_path):
        for f in files:
            if f.endswith(".json") and f != "discovery_events.json":
                data = load_json(os.path.join(root, f))
                # Deep traverse values to find strings that look like AWS identifiers
                def find_strings(obj):
                    if isinstance(obj, str): 
                        if len(obj) > 5: ids.add(obj) # Heuristic for IDs/Names
                    elif isinstance(obj, list):
                        for item in obj: find_strings(item)
                    elif isinstance(obj, dict):
                        for v in obj.values(): find_strings(v)
                find_strings(data)
    return ids

def generate_discovery_report(output_dir: str, detailed: bool = False):
    accounts = [d for d in os.listdir(output_dir) if os.path.isdir(os.path.join(output_dir, d)) and d.isdigit()]
    for account_id in accounts:
        acc_dir = os.path.join(output_dir, account_id)
        console.print(Panel(f"[bold blue]Discovery Report: Account {account_id}[/]"))
        
        regions = sorted([d for d in os.listdir(acc_dir) if os.path.isdir(os.path.join(acc_dir, d)) and d != "global"])
        
        table = Table(title="Regional Resource Summary")
        table.add_column("Region", style="magenta")
        table.add_column("VPCs", justify="right")
        table.add_column("EC2", justify="right")
        table.add_column("Lambda", justify="right")
        table.add_column("Data (SQS/DDB)", justify="right")
        table.add_column("S3/IAM (Global)", justify="right")

        s3_data = load_json(os.path.join(acc_dir, "global", "s3", "buckets.json")).get("Buckets", [])
        iam_roles = load_json(os.path.join(acc_dir, "global", "iam", "roles.json")).get("Roles", [])

        if detailed:
            tree = Tree(f"[bold white]Account {account_id} Detail[/]")
            g_node = tree.add("[bold blue]Global Resources[/]")
            if s3_data:
                s3_node = g_node.add("S3 Buckets")
                for b in s3_data: s3_node.add(b.get("Name"))
            if iam_roles:
                iam_node = g_node.add("IAM Roles")
                for r in iam_roles[:20]: iam_node.add(r.get("RoleName"))
                if len(iam_roles) > 20: iam_node.add(f"... and {len(iam_roles)-20} more")

        for region in regions:
            r_path = os.path.join(acc_dir, region)
            vpcs = load_json(os.path.join(r_path, "ec2", "vpcs.json")).get("Vpcs", [])
            ec2_res = load_json(os.path.join(r_path, "ec2", "instances.json")).get("Reservations", [])
            instances = [i for r in ec2_res for i in r.get("Instances", [])]
            lambdas = load_json(os.path.join(r_path, "lambda", "functions.json")).get("Functions", [])
            sqs = load_json(os.path.join(r_path, "sqs", "queues.json")).get("QueueUrls", [])
            ddb = load_json(os.path.join(r_path, "dynamodb", "tables.json")).get("TableNames", [])
            
            if any([vpcs, instances, lambdas, sqs, ddb]):
                table.add_row(region, str(len(vpcs)), str(len(instances)), str(len(lambdas)), f"SQS:{len(sqs)}, DDB:{len(ddb)}", "-")
                if detailed:
                    r_node = tree.add(f"[bold magenta]{region}[/]")
                    v_node = r_node.add(f"VPCs ({len(vpcs)})")
                    for v in vpcs: v_node.add(v.get("VpcId"))
                    if instances:
                        i_node = r_node.add(f"EC2 Instances ({len(instances)})")
                        for i in instances: i_node.add(i.get("InstanceId"))
                    if lambdas:
                        l_node = r_node.add(f"Lambdas ({len(lambdas)})")
                        for l in lambdas: l_node.add(l.get("FunctionName"))
                    if sqs:
                        s_node = r_node.add(f"SQS Queues ({len(sqs)})")
                        for q in sqs: s_node.add(q.split("/")[-1])
                    if ddb:
                        d_node = r_node.add(f"DynamoDB Tables ({len(ddb)})")
                        for t in ddb: d_node.add(t)
        
        table.add_row("global", "-", "-", "-", "-", "-", f"S3:{len(s3_data)}, IAM:{len(iam_roles)}")
        console.print(table)
        if detailed: console.print(tree)

        # Deep Discovery Filtering
        for region in regions:
            r_path = os.path.join(acc_dir, region)
            events = load_json(os.path.join(r_path, "cloudtrail", "discovery_events.json")).get("Records", [])
            if not events: continue
            
            # Step 1: Identify what ACTUALLY exists in this account/region
            existing_ids = extract_identifiers(acc_dir, region)
            # Add global IDs for cross-region matching
            for b in s3_data: existing_ids.add(b.get("Name"))
            for r in iam_roles: existing_ids.add(r.get("RoleName"))

            unmapped = {}
            for ev in events:
                src = ev.get("eventSource")
                if src and src not in SCANNED_SERVICES:
                    # Step 2: Check if this unmapped event mentions an EXISTING resource
                    ev_str = json.dumps(ev)
                    has_existing = any(eid in ev_str for eid in existing_ids)
                    
                    if has_existing:
                        if src not in unmapped: unmapped[src] = set()
                        unmapped[src].add(ev.get("eventName"))
            
            if unmapped:
                utree = Tree(f"[bold cyan]Deep Discovery Finding: {region}[/]")
                node = utree.add("[bold yellow]Unmapped Services Touching Existing Resources[/]")
                for src, actions in sorted(unmapped.items()):
                    svc_node = node.add(f"[bold white]{src}[/]")
                    for action in sorted(list(actions))[:5]: svc_node.add(f"[dim]{action}[/]")
                console.print(utree)

@click.group()
def cli(): pass

@cli.command()
@click.option("--region", help="Comma-separated regions")
@click.option("--deeptrail", is_flag=True)
@click.option("--trail-months", default=1, type=int)
@click.option("--detailed", is_flag=True)
@click.option("--verbose", is_flag=True)
def discover(region, deeptrail, trail_months, detailed, verbose):
    discovery = AWSDiscovery(verbose=verbose)
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
