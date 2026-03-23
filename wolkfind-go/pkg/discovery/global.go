package discovery

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/pterm/pterm"
)

func DiscoverGlobal(ctx context.Context, cfg aws.Config, accountDir string, verbose bool) error {
	if verbose {
		pterm.Info.Println("Scanning Global Services...")
	}

	// S3
	if verbose {
		pterm.Info.Println("  Scanning S3...")
	}
	s3Client := s3.NewFromConfig(cfg)
	buckets, err := SafeCall(func() (*s3.ListBucketsOutput, error) {
		return s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	})
	if err == nil && buckets != nil {
		WriteJSON(accountDir, "global", "s3", "buckets.json", buckets)
	}

	// IAM
	if verbose {
		pterm.Info.Println("  Scanning IAM...")
	}
	iamClient := iam.NewFromConfig(cfg)
	
	// List Users
	users, err := SafeCall(func() ([]interface{}, error) {
		paginator := iam.NewListUsersPaginator(iamClient, &iam.ListUsersInput{})
		var items []interface{}
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil { return nil, err }
			for _, u := range page.Users { items = append(items, u) }
		}
		return items, nil
	})
	if len(users) > 0 {
		WriteJSON(accountDir, "global", "iam", "users.json", map[string]interface{}{"Users": users})
	}

	// List Roles
	roles, err := SafeCall(func() ([]interface{}, error) {
		paginator := iam.NewListRolesPaginator(iamClient, &iam.ListRolesInput{})
		var items []interface{}
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil { return nil, err }
			for _, r := range page.Roles { items = append(items, r) }
		}
		return items, nil
	})
	if len(roles) > 0 {
		WriteJSON(accountDir, "global", "iam", "roles.json", map[string]interface{}{"Roles": roles})
	}

	// List Policies (Local)
	policies, err := SafeCall(func() ([]interface{}, error) {
		policyPaginator := iam.NewListPoliciesPaginator(iamClient, &iam.ListPoliciesInput{Scope: "Local"})
		var items []interface{}
		for policyPaginator.HasMorePages() {
			page, err := policyPaginator.NextPage(ctx)
			if err != nil { return nil, err }
			for _, p := range page.Policies { items = append(items, p) }
		}
		return items, nil
	})
	if len(policies) > 0 {
		WriteJSON(accountDir, "global", "iam", "policies.json", map[string]interface{}{"Policies": policies})
	}

	// Route53
	if verbose {
		pterm.Info.Println("  Scanning Route53...")
	}
	r53Client := route53.NewFromConfig(cfg)
	
	zones, err := SafeCall(func() ([]interface{}, error) {
		zonePaginator := route53.NewListHostedZonesPaginator(r53Client, &route53.ListHostedZonesInput{})
		var items []interface{}
		for zonePaginator.HasMorePages() {
			page, err := zonePaginator.NextPage(ctx)
			if err != nil { return nil, err }
			for _, z := range page.HostedZones {
				items = append(items, z)
				
				// Scan records for each zone
				zid := strings.Split(*z.Id, "/")[len(strings.Split(*z.Id, "/"))-1]
				records, err := SafeCall(func() ([]interface{}, error) {
					recPaginator := route53.NewListResourceRecordSetsPaginator(r53Client, &route53.ListResourceRecordSetsInput{HostedZoneId: z.Id})
					var ritems []interface{}
					for recPaginator.HasMorePages() {
						rpage, err := recPaginator.NextPage(ctx)
						if err != nil { return nil, err }
						for _, r := range rpage.ResourceRecordSets { ritems = append(ritems, r) }
					}
					return ritems, nil
				})
				if err == nil && len(records) > 0 {
					WriteJSON(accountDir, "global", "route53", fmt.Sprintf("records_%s.json", zid), map[string]interface{}{"ResourceRecordSets": records})
				}
			}
		}
		return items, nil
	})
	if len(zones) > 0 {
		WriteJSON(accountDir, "global", "route53", "hosted_zones.json", map[string]interface{}{"HostedZones": zones})
	}

	return nil
}
