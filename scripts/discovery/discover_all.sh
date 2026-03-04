#!/bin/bash
# Master Discovery Script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ensure active_regions.txt exists, or generate it
if [ ! -f "$SCRIPT_DIR/active_regions.txt" ]; then
    bash "$SCRIPT_DIR/get_active_regions.sh"
fi

ACTIVE_REGIONS=$(cat "$SCRIPT_DIR/active_regions.txt")

echo "Starting AWS Resource Discovery..."
echo "=================================="

# S3 is global
bash "$SCRIPT_DIR/discover_s3.sh"

# IAM is global
bash "$SCRIPT_DIR/discover_iam.sh"

# Regional services
for REGION in $ACTIVE_REGIONS; do
    echo "=== Region: $REGION ==="
    bash "$SCRIPT_DIR/discover_ec2.sh" "$REGION"
    bash "$SCRIPT_DIR/discover_lambda.sh" "$REGION"
    bash "$SCRIPT_DIR/discover_vpc.sh" "$REGION"
    bash "$SCRIPT_DIR/discover_rds.sh" "$REGION"
    bash "$SCRIPT_DIR/discover_cloudwatch.sh" "$REGION"
done

echo "=================================="
echo "Discovery Complete."
echo "All results are stored in scripts/discovery/results/"
