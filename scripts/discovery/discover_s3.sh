#!/bin/bash
# Discover S3 Buckets
OUTPUT_DIR="scripts/discovery/results/global"
mkdir -p "$OUTPUT_DIR"

echo "--- S3 Buckets ---"
aws s3api list-buckets --query 'Buckets[*].[Name, CreationDate]' --output table | tee "$OUTPUT_DIR/s3_buckets.txt"
aws s3api list-buckets --output json > "$OUTPUT_DIR/s3_buckets.json"
echo "Results saved to $OUTPUT_DIR/s3_buckets.txt and .json"
