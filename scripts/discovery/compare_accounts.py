#!/usr/bin/env python3
import json
import os
import glob
from typing import Dict, Any, List

def load_json(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception:
        return {}

def count_resources(data: Dict[str, Any], key: str) -> int:
    if not data: return 0
    items = data.get(key, [])
    return len(items)

def get_account_summary(account_id: str, base_dir: str) -> Dict[str, Any]:
    acc_dir = os.path.join(base_dir, account_id)
    summary = {
        "account_id": account_id,
        "s3_buckets": count_resources(load_json(os.path.join(acc_dir, "global/s3_buckets.json")), "Buckets"),
        "iam_roles": count_resources(load_json(os.path.join(acc_dir, "global/iam_roles.json")), "Roles"),
        "route53_zones": count_resources(load_json(os.path.join(acc_dir, "global/route53_hosted_zones.json")), "HostedZones"),
        "regions": {}
    }

    region_dirs = glob.glob(os.path.join(acc_dir, "regions/*"))
    for r_dir in region_dirs:
        region = os.path.basename(r_dir)
        reg_data = {
            "vpcs": count_resources(load_json(os.path.join(r_dir, "vpcs.json")), "Vpcs"),
            "instances": 0,
            "lambdas": count_resources(load_json(os.path.join(r_dir, "lambda_functions.json")), "Functions"),
            "rds": count_resources(load_json(os.path.join(r_dir, "rds_instances.json")), "DBInstances"),
        }
        
        # EC2 Instances are nested in Reservations
        ec2_data = load_json(os.path.join(r_dir, "ec2_instances.json"))
        for res in ec2_data.get("Reservations", []):
            reg_data["instances"] += len(res.get("Instances", []))
            
        if any(v > 0 for v in reg_data.values()):
            summary["regions"][region] = reg_data
            
    return summary

def main():
    base_results = "scripts/discovery/results"
    # Filter for directories that look like account IDs (all digits)
    accounts = [d for d in os.listdir(base_results) if os.path.isdir(os.path.join(base_results, d)) and d.isdigit()]
    
    summaries = [get_account_summary(acc, base_results) for acc in accounts]
    
    print(f"{'Account ID':<15} | {'S3':<5} | {'IAM':<5} | {'R53':<5} | {'Active Regions'}")
    print("-" * 75)
    for s in summaries:
        active_regions = ", ".join(s["regions"].keys()) if s["regions"] else "None"
        print(f"{s['account_id']:<15} | {s['s3_buckets']:<5} | {s['iam_roles']:<5} | {s['route53_zones']:<5} | {active_regions}")
        
    print("\nRegional Breakdown (Active Resources Only):")
    for s in summaries:
        print(f"\nAccount: {s['account_id']}")
        if not s["regions"]:
            print("  No active regional resources found.")
            continue
        # Sort regions for consistent output
        for reg in sorted(s["regions"].keys()):
            data = s["regions"][reg]
            res_str = f"VPCs: {data['vpcs']}, EC2: {data['instances']}, Lambda: {data['lambdas']}, RDS: {data['rds']}"
            print(f"  {reg:<15}: {res_str}")

if __name__ == "__main__":
    main()
