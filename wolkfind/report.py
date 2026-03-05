# /// script
# dependencies = ["rich"]
# ///
from __future__ import annotations

import json
import os
from typing import Any, Dict, Set, List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich import box

from discovery_config import SCANNED_SERVICES

SERVICE_NAMES = {
    "EC2": "Compute (EC2)",
    "Lambda": "Lambda",
    "EKS": "EKS Clusters",
    "ECS": "ECS Clusters",
    "ASG": "Auto Scaling",
    "VPC": "VPCs",
    "Subnet": "Subnets",
    "ELB": "Load Balancers",
    "NAT": "NAT Gateways",
    "EFS": "EFS",
    "ECR": "ECR Repos",
    "Backup": "Backup Vaults",
    "WAF": "WAF ACLs",
    "KMS": "KMS Keys",
    "GuardDuty": "GuardDuty",
    "SecHub": "Security Hub",
    "DDB": "DynamoDB",
    "SQS": "SQS Queues",
    "SNS": "SNS Topics",
    "RDS": "RDS Instances",
    "Redshift": "Redshift",
    "CFN": "CloudFormation",
    "SSM": "SSM Params",
    "APG": "API Gateways",
    "DMS": "DMS Certs",
    "DataSync": "DataSync Locs",
    "RolesAny": "RolesAny Profiles",
    "DataBrew": "DataBrew Recipes",
    "Deadline": "Deadline Farms",
}

REGION_SHORT = {
    "us-east-1": "use1", "us-east-2": "use2", "us-west-1": "usw1", "us-west-2": "usw2",
    "af-south-1": "afs1", "ap-east-1": "ape1", "ap-south-1": "aps1", "ap-northeast-3": "apn3",
    "ap-northeast-2": "apn2", "ap-northeast-1": "apn1", "ap-southeast-1": "apse1",
    "ap-southeast-2": "apse2", "ca-central-1": "cac1", "eu-central-1": "euc1",
    "eu-west-1": "euw1", "eu-west-2": "euw2", "eu-south-1": "eus1", "eu-west-3": "euw3",
    "eu-north-1": "eun1", "me-south-1": "mes1", "sa-east-1": "sae1",
}

def shorten_region(r: str) -> str:
    return REGION_SHORT.get(r, r)

def load_json(path: str) -> Dict[str, Any]:
    if not os.path.exists(path): return {}
    try:
        with open(path, "r") as f: return json.load(f)
    except Exception: return {}

SVC_DATE_FIELD = {
    "EC2": "LaunchTime",
    "Lambda": "LastModified",
    "ECR": "createdAt",
    "Backup": "CreationDate",
    "RDS": "InstanceCreateTime",
    "CFN": "CreationTime",
    "SSM": "LastModifiedDate",
    "DDB": "CreationDateTime",
    "SQS": "CreatedDate",
    "KMS": "CreationDate",
}


def get_res_id(item: Any) -> str:
    """Heuristic to extract the best ID/Name from an AWS resource object."""
    if isinstance(item, str): return item
    for key in ["AliasName", "repositoryArn", "BackupVaultArn", "VpcId", "InstanceId", "FunctionName", "DBInstanceIdentifier", "TableName", "QueueUrl", "TopicArn", "StackName", "KeyId", "RepositoryName", "ClusterName", "FileSystemId", "Id", "Name"]:
        if key in item:
            val = item[key]
            if key == "QueueUrl": return val.split("/")[-1]
            if key == "TopicArn": return val.split(":")[-1]
            return str(val)
    return str(item)

def extract_identifiers(acc_dir: str, region: str) -> Set[str]:
    ids: Set[str] = set()
    r_path = os.path.join(acc_dir, region)
    if not os.path.exists(r_path): return ids
    for root, _, files in os.walk(r_path):
        for fname in files:
            if fname.endswith(".json") and fname != "discovery_events.json":
                data = load_json(os.path.join(root, fname))
                def find_strings(obj):
                    if isinstance(obj, str): 
                        if len(obj) > 5: ids.add(obj)
                    elif isinstance(obj, list):
                        for item in obj: find_strings(item)
                    elif isinstance(obj, dict):
                        for v in obj.values(): find_strings(v)
                find_strings(data)
    return ids

def generate_discovery_report(output_dir: str, detailed: bool = False, console: Console | None = None):
    console = console or Console()
    accounts = [d for d in os.listdir(output_dir) if os.path.isdir(os.path.join(output_dir, d)) and d.isdigit()]
    
    for account_id in accounts:
        acc_dir = os.path.join(output_dir, account_id)
        console.print("\n")
        console.print(Panel(f"[bold white]AWS ACCOUNT DISCOVERY: {account_id}[/]", border_style="bold blue", padding=(1, 2)))

        # --- Global Services ---
        s3_buckets = load_json(os.path.join(acc_dir, "global", "s3", "buckets.json")).get("Buckets", [])
        iam_roles = load_json(os.path.join(acc_dir, "global", "iam", "roles.json")).get("Roles", [])
        iam_users = load_json(os.path.join(acc_dir, "global", "iam", "users.json")).get("Users", [])
        iam_policies = load_json(os.path.join(acc_dir, "global", "iam", "policies.json")).get("Policies", [])
        r53_zones = load_json(os.path.join(acc_dir, "global", "route53", "hosted_zones.json")).get("HostedZones", [])

        console.print(Panel(
            f"S3 Buckets: [bold]{len(s3_buckets)}[/] | Route53 Zones: [bold]{len(r53_zones)}[/]\n"
            f"IAM Identity: [bold]{len(iam_users)}[/] Users, [bold]{len(iam_roles)}[/] Roles, [bold]{len(iam_policies)}[/] Policies",
            title="[bold blue]Global Services[/]", border_style="blue", expand=False, padding=(0, 2)
        ))
        console.print("")

        # --- Regional Services Data Gathering ---
        # Strictly filter for AWS region patterns (e.g., us-east-1, ap-northeast-2)
        regions = sorted([
            d for d in os.listdir(acc_dir)
            if os.path.isdir(os.path.join(acc_dir, d)) 
            and "-" in d and len(d) >= 7
        ])
        region_data = []
        for region in regions:
            r_path = os.path.join(acc_dir, region)
            def get_r(svc, fname, key): return load_json(os.path.join(r_path, svc, fname)).get(key, [])

            ec2_res = get_r("ec2", "instances.json", "Reservations")
            instances = [i for res in ec2_res for i in res.get("Instances", [])]
            lambdas = get_r("lambda", "functions.json", "Functions")
            vpcs = get_r("ec2", "vpcs.json", "Vpcs")
            subnets = get_r("ec2", "subnets.json", "Subnets")
            _ddb_raw = load_json(os.path.join(r_path, "dynamodb", "tables.json"))
            ddb = _ddb_raw.get("Tables") or [{"TableName": n} for n in _ddb_raw.get("TableNames", [])]
            _sqs_raw = load_json(os.path.join(r_path, "sqs", "queues.json"))
            sqs = _sqs_raw.get("Queues") or [{"QueueUrl": u} for u in _sqs_raw.get("QueueUrls", [])]
            sns = get_r("sns", "topics.json", "Topics")
            rds = get_r("rds", "instances.json", "DBInstances")
            kms = get_r("kms", "keys.json", "Aliases")
            cfn = get_r("cloudformation", "stacks.json", "Stacks")
            ssm = get_r("ssm", "parameters.json", "Parameters")
            ecr = get_r("ecr", "repositories.json", "repositories")
            bak = get_r("backup", "vaults.json", "BackupVaultList")
            dms = get_r("dms", "certificates.json", "Certificates")
            dsync = get_r("datasync", "locations.json", "Locations")
            rany = get_r("rolesanywhere", "profiles.json", "profiles")
            dbrew = get_r("databrew", "recipes.json", "Recipes")
            dl = get_r("deadline", "farms.json", "farms")

            region_data.append({
                "region": region,
                "Compute": {"EC2": instances, "Lambda": lambdas},
                "Network": {"VPC": vpcs, "Subnet": subnets},
                "Storage": {"ECR": ecr, "Backup": bak},
                "Security": {"KMS": kms, "DMS": dms, "RolesAny": rany},
                "Data": {"DDB": ddb, "SQS": sqs, "SNS": sns, "RDS": rds, "DataSync": dsync, "DataBrew": dbrew},
                "Apps": {"CFN": cfn, "SSM": ssm, "Deadline": dl}
            })

        # --- Summary Tables ---
        for cat_name, cat_color in [("Compute", "green"), ("Network", "blue"), ("Storage", "cyan"), ("Security", "red"), ("Data", "yellow"), ("Apps", "white")]:
            active_rds = [rd for rd in region_data if any(rd[cat_name].values())]
            if not active_rds: continue
            console.print(f"[bold {cat_color}]{cat_name} Resources[/]")
            table = Table(box=box.ROUNDED, border_style=cat_color, header_style=f"bold {cat_color}")
            table.add_column("Service", style="bold white", width=25)
            for rd in active_rds: table.add_column(shorten_region(rd["region"]), justify="right", style=cat_color)
            
            for svc_key in region_data[0][cat_name].keys():
                row = [SERVICE_NAMES.get(svc_key, svc_key)]
                for rd in active_rds:
                    cnt = len(rd[cat_name][svc_key])
                    row.append(str(cnt) if cnt else "-")
                if any(len(rd[cat_name][svc_key]) for rd in active_rds): table.add_row(*row)
            console.print(table)
            console.print("")

        # --- Detailed Tree ---
        if detailed:
            tree = Tree(f"[bold white]Account {account_id} Detailed Map[/]")
            g_node = tree.add("[bold blue]Global Resources[/]")
            if s3_buckets:
                s3_node = g_node.add("S3 Buckets")
                for b in s3_buckets:
                    d = str(b.get("CreationDate", ""))[:10]
                    s3_node.add(f"[dim]{b.get('Name')}{f' ({d})' if d else ''}[/]")
            if iam_roles:
                iam_node = g_node.add("IAM Roles")
                for r in iam_roles:
                    d = str(r.get("CreateDate", ""))[:10]
                    iam_node.add(f"[dim]{r.get('RoleName')}{f' ({d})' if d else ''}[/]")
            
            for rd in region_data:
                r_node = tree.add(f"[bold magenta]{rd['region']}[/]")
                for cat_key in ["Compute", "Network", "Storage", "Security", "Data", "Apps"]:
                    stats = rd[cat_key]
                    if any(stats.values()):
                        c_node = r_node.add(f"[bold {cat_key.lower()}]{cat_key}[/]")
                        
                        if cat_key == "Network":
                            vpcs = stats.get("VPC", [])
                            subnets = stats.get("Subnet", [])
                            if vpcs:
                                v_node = c_node.add(f"VPCs ({len(vpcs)})")
                                for v in vpcs:
                                    v_id = v.get("VpcId")
                                    vp_node = v_node.add(v_id)
                                    v_subnets = [s for s in subnets if s.get("VpcId") == v_id]
                                    if v_subnets:
                                        s_node = vp_node.add(f"Subnets ({len(v_subnets)})")
                                        for sub in v_subnets:
                                            s_node.add(f"[dim]{sub.get('SubnetId')} ({sub.get('CidrBlock')})[/]")
                            continue

                        for svc_key, resources in stats.items():
                            if resources:
                                svc_name = SERVICE_NAMES.get(svc_key, svc_key)
                                date_field = SVC_DATE_FIELD.get(svc_key)
                                s_node = c_node.add(f"{svc_name} ({len(resources)})")
                                for res in resources:
                                    rid = get_res_id(res)
                                    d = str(res.get(date_field, ""))[:10] if date_field and isinstance(res, dict) else ""
                                    s_node.add(f"[dim]{rid}{f' ({d})' if d else ''}[/]")
            console.print(tree)
            console.print("")

        # --- Deep Discovery Filtering ---
        if detailed:
            for region in regions:
                r_path = os.path.join(acc_dir, region)
                events = load_json(os.path.join(r_path, "cloudtrail", "discovery_events.json")).get("Records", [])
                if not events: continue
                existing_ids = extract_identifiers(acc_dir, region)
                for b in s3_buckets: existing_ids.add(b.get("Name"))
                for r in iam_roles: existing_ids.add(r.get("RoleName"))
                unmapped = {}
                for ev in events:
                    src = ev.get("eventSource")
                    if src and src not in SCANNED_SERVICES:
                        ev_str = json.dumps(ev)
                        if any(eid in ev_str for eid in existing_ids):
                            if src not in unmapped: unmapped[src] = set()
                            unmapped[src].add(ev.get("eventName"))
                if unmapped:
                    utree = Tree(f"[bold cyan]Deep Discovery: {region}[/]", guide_style="yellow")
                    node = utree.add("[bold yellow]Unmapped Services Touching Existing Resources[/]")
                    for src, actions in sorted(unmapped.items()):
                        svc_node = node.add(f"[bold white]{src}[/]")
                        for action in sorted(list(actions))[:5]: svc_node.add(f"[dim]{action}[/]")
                    console.print(utree)
                    console.print("")
