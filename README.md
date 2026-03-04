# AWS Discovery Tool

A consolidated, high-performance AWS resource discovery and audit tool built with Python, `boto3`, and `rich`. This tool provides a multi-layered view of your AWS environment, from static infrastructure counts to 90-day activity metrics and long-term service discovery via CloudTrail.

## Key Features

- **Consolidated CLI:** Replaces multiple shell and Python scripts with a single `aws_discovery.py` tool.
- **Robust Pagination:** Unified helper handles all AWS API interactions, ensuring complete data collection in large accounts.
- **Granular Error Handling:** Gracefully handles `AccessDenied` and other API errors without halting the discovery process.
- **Multi-Layered Audit:**
    - **Infrastructure Scan:** Static discovery of VPCs, EC2, RDS, Lambda, SQS, and DynamoDB.
    - **Activity Monitoring:** Queries 90 days of CloudWatch metrics to identify "stale" or unused resources.
    - **Temporal Discovery (`--deeptrail`):** Samples months of CloudTrail logs from S3 to identify active services not included in the static scan.
- **Rich Reporting:**
    - **Summary First:** High-level executive summaries and regional breakdown tables.
    - **Detailed View (`--detailed`):** Hierarchical tree view of individual resource names (via tags) and IDs.
- **Zero-Install Portability:** Optimized for execution with `uv` and includes inline dependency metadata.

## Prerequisites

- **Python 3.10+**
- **`uv`** (recommended) or `pip`
- **AWS Credentials:** Configured via environment variables (`AWS_ACCESS_KEY_ID`, etc.) or local profiles.

## Usage

### 1. Basic Discovery
Scan all enabled regions for standard resources:
```bash
uv run scripts/discovery/aws_discovery.py discover
```

### 2. Deep Audit & Service Discovery
Scan a specific region, sample 3 months of CloudTrail logs to find unmapped services, and show verbose progress:
```bash
uv run scripts/discovery/aws_discovery.py discover --region us-east-1 --deeptrail --trail-months 3 --verbose
```

### 3. Detailed Reporting
Generate a detailed report from previously saved discovery results, showing individual resource names and "Last Active" timestamps:
```bash
uv run scripts/discovery/aws_discovery.py report --detailed
```

## Output Structure

Results are stored in a hierarchical JSON format suitable for machine processing and long-term archiving:

```text
scripts/discovery/results/
└── <account_id>/
    ├── global/
    │   └── s3/buckets.json
    └── <region>/
        ├── ec2/vpcs.json
        ├── sqs/sqs_enriched.json        # Includes activity metrics
        ├── dynamodb/tables_enriched.json # Includes activity metrics
        └── cloudtrail/discovery_events.json
```

## Implementation Details

- **CloudWatch Integration:** Specifically targets `ConsumedReadCapacityUnits` (DynamoDB) and `NumberOfMessagesSent` (SQS) to detect real-world usage.
- **Temporal Sampling:** Sparse daily sampling of CloudTrail S3 archives to maximize discovery coverage while minimizing S3 GET costs and local storage.
- **Parallelization:** Uses `ThreadPoolExecutor` for concurrent regional scanning.

---
*Maintained as part of the AWS Discovery Work Log.*
