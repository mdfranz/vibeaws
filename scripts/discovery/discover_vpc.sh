#!/bin/bash
REGION=$1
if [ -z "$REGION" ]; then
    echo "No region provided, skipping VPC discovery."
    exit 1
fi

OUTPUT_DIR="scripts/discovery/results/regions/$REGION"
mkdir -p "$OUTPUT_DIR"

echo "--- VPCs in $REGION ---"
aws ec2 describe-vpcs --region "$REGION" --query 'Vpcs[*].[VpcId, CidrBlock, IsDefault, State]' --output table | tee "$OUTPUT_DIR/vpcs.txt"
aws ec2 describe-vpcs --region "$REGION" --output json > "$OUTPUT_DIR/vpcs.json"

echo "--- Subnets in $REGION ---"
aws ec2 describe-subnets --region "$REGION" --query 'Subnets[*].[SubnetId, VpcId, CidrBlock, AvailabilityZone]' --output table | tee "$OUTPUT_DIR/subnets.txt"
aws ec2 describe-subnets --region "$REGION" --output json > "$OUTPUT_DIR/subnets.json"

echo "Results saved to $OUTPUT_DIR/vpc_* and subnets_*"
