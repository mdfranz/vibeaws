# AWS Discovery Tool (Wolkfind)

A consolidated, high-performance AWS resource discovery and audit tool built with Python, `boto3`, and `rich`. This tool provides a multi-layered view of your AWS environment, from static infrastructure counts to 90-day activity metrics and long-term service discovery via CloudTrail.

## Key Features

- **Consolidated CLI:** Single entry point via `wolkfind/aws_discovery.py` for all discovery and reporting tasks.
- **Multi-Account Discovery:** Support for assuming one or more cross-account roles via `--role-arn`.
- **Robust Pagination:** Unified helper handles all AWS API interactions, ensuring complete data collection in large accounts.
- **Granular Error Handling:** Gracefully handles `AccessDenied` and other API errors without halting the discovery process.
- **Multi-Layered Audit:**
    - **Infrastructure Scan:** Static discovery across 50+ AWS services (EC2, RDS, Lambda, SQS, DynamoDB, DMS, DataSync, etc.).
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
Scan all enabled regions for standard resources in the current account:
```bash
uv run wolkfind/aws_discovery.py discover
```

### 2. Multi-Account Discovery
Assume one or more roles to scan multiple accounts sequentially:
```bash
uv run wolkfind/aws_discovery.py discover --role-arn arn:aws:iam::123456789012:role/AuditRole,arn:aws:iam::987654321098:role/AuditRole
```

### 3. Deep Audit & Service Discovery
Scan a specific region, sample 3 months of CloudTrail logs to find unmapped services, and show verbose progress:
```bash
uv run wolkfind/aws_discovery.py discover --region us-east-1 --deeptrail --trail-months 3 --verbose
```

### 4. Detailed Reporting
Generate a detailed report from previously saved discovery results:
```bash
uv run wolkfind/aws_discovery.py report --detailed
```

## Output Structure

Results are stored in a hierarchical JSON format organized by account and region:

```text
wolkfind/results/
└── <account_id>/
    ├── global/
    │   ├── iam/roles.json
    │   └── s3/buckets.json
    └── <region>/
        ├── ec2/vpcs.json
        ├── sqs/queues.json
        ├── dynamodb/tables.json
        └── cloudtrail/discovery_events.json
```

## Implementation Details

- **CloudWatch Integration:** Specifically targets `ConsumedReadCapacityUnits` (DynamoDB) and `NumberOfMessagesSent` (SQS) to detect real-world usage.
- **Temporal Sampling:** Sparse daily sampling of CloudTrail S3 archives to maximize discovery coverage while minimizing S3 GET costs and local storage.
- **Parallelization:** Uses `ThreadPoolExecutor` for concurrent regional scanning.

---
*Maintained as part of the AWS Discovery Work Log.*
