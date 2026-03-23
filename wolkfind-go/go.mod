module wolkfind

go 1.25.0

require (
	github.com/aws/aws-sdk-go-v2 v1.41.3
	github.com/aws/aws-sdk-go-v2/config v1.32.11
	github.com/aws/aws-sdk-go-v2/credentials v1.19.11
	github.com/aws/aws-sdk-go-v2/service/accessanalyzer v1.45.10
	github.com/aws/aws-sdk-go-v2/service/appconfig v1.43.11
	github.com/aws/aws-sdk-go-v2/service/apprunner v1.39.12
	github.com/aws/aws-sdk-go-v2/service/athena v1.57.2
	github.com/aws/aws-sdk-go-v2/service/autoscaling v1.64.2
	github.com/aws/aws-sdk-go-v2/service/backup v1.54.8
	github.com/aws/aws-sdk-go-v2/service/cloudformation v1.71.7
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.55.7
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.64.0
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.68.11
	github.com/aws/aws-sdk-go-v2/service/codepipeline v1.46.19
	github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider v1.59.1
	github.com/aws/aws-sdk-go-v2/service/databasemigrationservice v1.61.7
	github.com/aws/aws-sdk-go-v2/service/databrew v1.39.12
	github.com/aws/aws-sdk-go-v2/service/datasync v1.57.3
	github.com/aws/aws-sdk-go-v2/service/deadline v1.25.2
	github.com/aws/aws-sdk-go-v2/service/detective v1.38.11
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.56.1
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.293.1
	github.com/aws/aws-sdk-go-v2/service/ecr v1.55.4
	github.com/aws/aws-sdk-go-v2/service/ecs v1.73.1
	github.com/aws/aws-sdk-go-v2/service/eks v1.80.2
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing v1.33.21
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.54.8
	github.com/aws/aws-sdk-go-v2/service/firehose v1.42.11
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.74.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.53.4
	github.com/aws/aws-sdk-go-v2/service/imagebuilder v1.51.2
	github.com/aws/aws-sdk-go-v2/service/kms v1.50.2
	github.com/aws/aws-sdk-go-v2/service/lambda v1.88.2
	github.com/aws/aws-sdk-go-v2/service/macie2 v1.50.11
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.59.0
	github.com/aws/aws-sdk-go-v2/service/rds v1.116.2
	github.com/aws/aws-sdk-go-v2/service/redshift v1.62.3
	github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi v1.31.8
	github.com/aws/aws-sdk-go-v2/service/rolesanywhere v1.22.5
	github.com/aws/aws-sdk-go-v2/service/route53 v1.62.3
	github.com/aws/aws-sdk-go-v2/service/s3 v1.96.3
	github.com/aws/aws-sdk-go-v2/service/sagemaker v1.235.0
	github.com/aws/aws-sdk-go-v2/service/securityhub v1.68.1
	github.com/aws/aws-sdk-go-v2/service/servicediscovery v1.39.24
	github.com/aws/aws-sdk-go-v2/service/sns v1.39.13
	github.com/aws/aws-sdk-go-v2/service/sqs v1.42.23
	github.com/aws/aws-sdk-go-v2/service/ssm v1.68.2
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.8
	github.com/aws/aws-sdk-go-v2/service/wafregional v1.30.19
	github.com/aws/aws-sdk-go-v2/service/wafv2 v1.71.1
	github.com/aws/smithy-go v1.24.2
	github.com/pterm/pterm v0.12.83
	github.com/urfave/cli/v2 v2.27.7
)

require (
	atomicgo.dev/cursor v0.2.0 // indirect
	atomicgo.dev/keyboard v0.2.9 // indirect
	atomicgo.dev/schedule v0.1.0 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.6 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.19 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.19 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.19 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.38.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.33.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/configservice v1.61.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.11.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.16 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/containerd/console v1.0.5 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/gookit/color v1.6.0 // indirect
	github.com/lithammer/fuzzysearch v1.1.8 // indirect
	github.com/mattn/go-runewidth v0.0.20 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	github.com/xrash/smetrics v0.0.0-20240521201337-686a1a2994c1 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/term v0.40.0 // indirect
	golang.org/x/text v0.34.0 // indirect
)
