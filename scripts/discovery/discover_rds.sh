#!/bin/bash
REGION=$1
if [ -z "$REGION" ]; then
    echo "No region provided, skipping RDS discovery."
    exit 1
fi

OUTPUT_DIR="scripts/discovery/results/regions/$REGION"
mkdir -p "$OUTPUT_DIR"

echo "--- RDS Instances in $REGION ---"
aws rds describe-db-instances --region "$REGION" --query 'DBInstances[*].[DBInstanceIdentifier, DBInstanceClass, Engine, DBInstanceStatus]' --output table | tee "$OUTPUT_DIR/rds_instances.txt"
aws rds describe-db-instances --region "$REGION" --output json > "$OUTPUT_DIR/rds_instances.json"

echo "Results saved to $OUTPUT_DIR/rds_*"
