package config

import (
	"github.com/aws/aws-sdk-go-v2/aws"
)

const (
	DefaultOutputDir  = "results"
	DefaultMaxWorkers = 10
	LookupDays        = 90
	TrailDiscoveryDays = 30
)

// BotoConfig equivalent in Go is usually handled at the client level with retry.NewStandard()
// But we'll define a base config helper later.

var ScannedServices = map[string]bool{
	"ec2.amazonaws.com":                       true,
	"rds.amazonaws.com":                       true,
	"lambda.amazonaws.com":                    true,
	"s3.amazonaws.com":                        true,
	"iam.amazonaws.com":                       true,
	"route53.amazonaws.com":                   true,
	"sqs.amazonaws.com":                       true,
	"dynamodb.amazonaws.com":                  true,
	"logs.amazonaws.com":                      true,
	"autoscaling.amazonaws.com":               true,
	"elasticloadbalancing.amazonaws.com":      true,
	"eks.amazonaws.com":                       true,
	"sns.amazonaws.com":                       true,
	"elasticfilesystem.amazonaws.com":         true,
	"cloudtrail.amazonaws.com":                true,
	"sts.amazonaws.com":                       true,
	"cloudformation.amazonaws.com":            true,
	"wafv2.amazonaws.com":                     true,
	"kms.amazonaws.com":                       true,
	"ssm.amazonaws.com":                       true,
	"apigateway.amazonaws.com":                true,
	"workspaces.amazonaws.com":                true,
	"ecr.amazonaws.com":                       true,
	"guardduty.amazonaws.com":                  true,
	"securityhub.amazonaws.com":               true,
	"amplify.amazonaws.com":                   true,
	"ecs.amazonaws.com":                       true,
	"elb.amazonaws.com":                       true,
	"elbv2.amazonaws.com":                     true,
	"waf-regional.amazonaws.com":              true,
	"internetmonitor.amazonaws.com":           true,
	"ssm-quicksetup.amazonaws.com":            true,
	"notifications.amazonaws.com":              true,
	"bedrock.amazonaws.com":                   true,
	"ds.amazonaws.com":                        true,
	"sso.amazonaws.com":                       true,
	"resource-explorer-2.amazonaws.com":       true,
	"monitoring.amazonaws.com":                true,
	"resource-groups.amazonaws.com":           true,
	"servicecatalog-appregistry.amazonaws.com": true,
	"tagging.amazonaws.com":                   true,
	"oam.amazonaws.com":                       true,
	"application-insights.amazonaws.com":     true,
	"athena.amazonaws.com":                    true,
	"events.amazonaws.com":                    true,
	"backup.amazonaws.com":                    true,
	"codebuild.amazonaws.com":                 true,
	"config.amazonaws.com":                    true,
	"redshift.amazonaws.com":                  true,
	"sagemaker.amazonaws.com":                 true,
	"access-analyzer.amazonaws.com":           true,
	"cognito-idp.amazonaws.com":               true,
	"es.amazonaws.com":                        true,
	"servicediscovery.amazonaws.com":          true,
	"opensearch.amazonaws.com":                true,
	"appconfig.amazonaws.com":                 true,
	"apprunner.amazonaws.com":                 true,
	"appstream.amazonaws.com":                 true,
	"firehose.amazonaws.com":                  true,
	"imagebuilder.amazonaws.com":              true,
	"codepipeline.amazonaws.com":              true,
	"detective.amazonaws.com":                 true,
	"macie2.amazonaws.com":                    true,
	"signin.amazonaws.com":                    true,
	"q.amazonaws.com":                         true,
	"dms.amazonaws.com":                       true,
	"datasync.amazonaws.com":                  true,
	"rolesanywhere.amazonaws.com":             true,
	"databrew.amazonaws.com":                  true,
	"deadline.amazonaws.com":                  true,
	"cloudcontrolapi.amazonaws.com":           true,
	"iotwireless.amazonaws.com":               true,
	"quicksight.amazonaws.com":                true,
}

// In Go, since we want strongly-typed handlers, the DISCOVERY_MAP will be 
// a list of tasks that we iterate through. Each task has a specific Go function to call.
// This will be populated in Phase 4.
type DiscoveryTask struct {
	Service  string
	Filename string
	Fetch    func(ctx interface{}, cfg aws.Config, region string) (interface{}, error)
}
