#!/bin/bash
REGION=$1
if [ -z "$REGION" ]; then
    echo "No region provided, skipping CloudWatch discovery."
    exit 1
fi

OUTPUT_DIR="scripts/discovery/results/regions/$REGION"
mkdir -p "$OUTPUT_DIR"

echo "--- CloudWatch Log Groups in $REGION ---"
aws logs describe-log-groups --region "$REGION" --query 'logGroups[*].[logGroupName, creationTime, storedBytes]' --output table | tee "$OUTPUT_DIR/cloudwatch_log_groups.txt"
aws logs describe-log-groups --region "$REGION" --output json > "$OUTPUT_DIR/cloudwatch_log_groups.json"

echo "--- CloudWatch Metrics (Top 20) in $REGION ---"
aws cloudwatch list-metrics --region "$REGION" --query 'Metrics[:20].[Namespace, MetricName]' --output table | tee "$OUTPUT_DIR/cloudwatch_metrics.txt"
aws cloudwatch list-metrics --region "$REGION" --output json > "$OUTPUT_DIR/cloudwatch_metrics.json"

echo "Results saved to $OUTPUT_DIR/cloudwatch_*"
