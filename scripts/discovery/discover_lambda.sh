#!/bin/bash
REGION=$1
if [ -z "$REGION" ]; then
    echo "No region provided, skipping Lambda discovery."
    exit 1
fi

OUTPUT_DIR="scripts/discovery/results/regions/$REGION"
mkdir -p "$OUTPUT_DIR"

echo "--- Lambda Functions in $REGION ---"
aws lambda list-functions --region "$REGION" --query 'Functions[*].[FunctionName, Runtime, LastModified]' --output table | tee "$OUTPUT_DIR/lambda_functions.txt"
aws lambda list-functions --region "$REGION" --output json > "$OUTPUT_DIR/lambda_functions.json"

echo "Results saved to $OUTPUT_DIR/lambda_*"
