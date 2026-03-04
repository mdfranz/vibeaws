#!/bin/bash
# Discover Route 53 Hosted Zones
OUTPUT_DIR="scripts/discovery/results/global"
mkdir -p "$OUTPUT_DIR"

echo "--- Route 53 Hosted Zones ---"
aws route53 list-hosted-zones --query 'HostedZones[*].[Id, Name, Config.PrivateZone, ResourceRecordSetCount]' --output table | tee "$OUTPUT_DIR/route53_hosted_zones.txt"
aws route53 list-hosted-zones --output json > "$OUTPUT_DIR/route53_hosted_zones.json"

# For each hosted zone, list its record sets (top 10 to keep it manageable)
echo "--- Route 53 Record Sets (Sample) ---"
for ZONE_ID in $(aws route53 list-hosted-zones --query 'HostedZones[*].Id' --output text | sed 's/\/hostedzone\///g'); do
    echo "Zone: $ZONE_ID"
    aws route53 list-resource-record-sets --hosted-zone-id "$ZONE_ID" --max-items 10 --query 'ResourceRecordSets[*].[Name, Type, TTL]' --output table
done

echo "Results saved to $OUTPUT_DIR/route53_*"
