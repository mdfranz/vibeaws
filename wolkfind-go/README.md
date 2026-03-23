# wolkfind

`wolkfind` is a high-performance AWS resource discovery and reporting tool written in Go. It is designed to provide a comprehensive view of assets across multiple AWS accounts and regions, including deep analysis of CloudTrail logs to identify active but unmapped resources.

## Key Features

- **Multi-Region Scanning**: Automatically discovers active regions and performs parallelized scans using Go routines.
- **Global Service Discovery**: Scans global AWS services including IAM, S3, and Route53.
- **DeepTrail Analysis**: Samples CloudTrail logs stored in S3 to identify resource activity and unmapped service usage.
- **Automated Reporting**: Generates summarized and detailed reports directly in the terminal, including a categorized view of resources (Compute, Network, Storage, Security, Data, Apps).
- **Stale Resource Identification**: Identifies potentially unused resources such as stopped EC2 instances, unattached EBS volumes, and old snapshots.
- **Role Assumption**: Supports assuming IAM roles to scan multiple accounts from a single execution.

## 3rd Party Packages

The project relies on several key open-source packages:

1.  **[AWS SDK for Go v2](https://github.com/aws/aws-sdk-go-v2)**: The foundational library for all AWS API interactions. `wolkfind` utilizes dozens of service-specific clients to gather resource data.
2.  **[pterm](https://github.com/pterm/pterm)**: Used for creating a rich, interactive terminal UI. It provides the headers, tables, progress indicators, and tree views that make the discovery results easy to read.
3.  **[urfave/cli/v2](https://github.com/urfave/cli/v2)**: A robust framework for building command-line applications in Go, handling command routing, flag parsing, and help documentation.

## Installation

To build and install `wolkfind` to your local bin directory:

```bash
make install
```

## Usage

### Discover Resources

Scan an account (optionally assuming a role) and save results to the `results/` directory:

```bash
./wolkfind discover --region us-east-1,us-west-2 --deeptrail --verbose
```

### Generate Reports

Generate a summary report from previously discovered data:

```bash
./wolkfind report --detailed --stale
```

## Configuration

Default settings such as the output directory and maximum worker threads can be adjusted in `pkg/config/config.go`.
