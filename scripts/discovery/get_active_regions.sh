#!/bin/bash
# Identify active regions based on CloudTrail logs and other indicators

BUCKET="aws-cloudtrail-logs-647303185053-0e33cf25"
ACCOUNT_ID="647303185053"
PREFIX="AWSLogs/$ACCOUNT_ID/CloudTrail/"

echo "Fetching regions from CloudTrail logs..."
# Using tr to normalize spaces/newlines
CLOUDTRAIL_REGIONS=$(aws s3 ls "s3://$BUCKET/$PREFIX" | awk '/PRE/ {print $2}' | sed 's/\///' | tr '\n' ' ')

echo "Potential active regions from CloudTrail: $CLOUDTRAIL_REGIONS"

# Get enabled regions and normalize to space-separated string
ENABLED_REGIONS=$(aws ec2 describe-regions --region us-east-1 --query 'Regions[?OptInStatus!='"'"'not-opted-in'"'"'].RegionName' --output text | tr '\t' ' ')

echo "Enabled regions for this account: $ENABLED_REGIONS"

ACTIVE_REGIONS=""
for REGION in $CLOUDTRAIL_REGIONS; do
    # Check if the region is in the enabled list using a more robust check
    if echo "$ENABLED_REGIONS" | grep -qw "$REGION"; then
        ACTIVE_REGIONS="$ACTIVE_REGIONS $REGION"
    fi
done

if [ -z "$ACTIVE_REGIONS" ]; then
    echo "No overlapping enabled regions found with CloudTrail logs. Defaulting to us-east-1."
    ACTIVE_REGIONS="us-east-1"
fi

# Store as space separated in a single line
echo "$ACTIVE_REGIONS" | xargs > scripts/discovery/active_regions.txt
echo "Active regions saved to scripts/discovery/active_regions.txt: $(cat scripts/discovery/active_regions.txt)"
