#!/bin/bash
REGION=$1
if [ -z "$REGION" ]; then
    echo "No region provided, skipping EC2 discovery."
    exit 1
fi

OUTPUT_DIR="scripts/discovery/results/regions/$REGION"
mkdir -p "$OUTPUT_DIR"

echo "--- EC2 Instances in $REGION ---"
aws ec2 describe-instances --region "$REGION" --query 'Reservations[*].Instances[*].[InstanceId, State.Name, InstanceType, LaunchTime]' --output table | tee "$OUTPUT_DIR/ec2_instances.txt"
aws ec2 describe-instances --region "$REGION" --output json > "$OUTPUT_DIR/ec2_instances.json"

echo "--- EC2 EBS Volumes in $REGION ---"
aws ec2 describe-volumes --region "$REGION" --query 'Volumes[*].[VolumeId, Size, State, AvailabilityZone]' --output table | tee "$OUTPUT_DIR/ec2_volumes.txt"
aws ec2 describe-volumes --region "$REGION" --output json > "$OUTPUT_DIR/ec2_volumes.json"

echo "Results saved to $OUTPUT_DIR/ec2_*"
