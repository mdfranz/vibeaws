#!/bin/bash
# Discover IAM Users and Roles
OUTPUT_DIR="scripts/discovery/results/global"
mkdir -p "$OUTPUT_DIR"

echo "--- IAM Users ---"
aws iam list-users --query 'Users[*].[UserName, CreateDate]' --output table | tee "$OUTPUT_DIR/iam_users.txt" 2>/dev/null || echo "Access Denied to list IAM Users"
aws iam list-users --output json > "$OUTPUT_DIR/iam_users.json" 2>/dev/null

echo "--- IAM Roles ---"
aws iam list-roles --query 'Roles[*].[RoleName, CreateDate]' --output table | tee "$OUTPUT_DIR/iam_roles.txt"
aws iam list-roles --output json > "$OUTPUT_DIR/iam_roles.json"

echo "Results saved to $OUTPUT_DIR/iam_*"
