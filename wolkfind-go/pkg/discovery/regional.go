package discovery

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/appconfig"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	"github.com/aws/aws-sdk-go-v2/service/databrew"
	"github.com/aws/aws-sdk-go-v2/service/datasync"
	"github.com/aws/aws-sdk-go-v2/service/deadline"
	"github.com/aws/aws-sdk-go-v2/service/detective"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/imagebuilder"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	"github.com/aws/aws-sdk-go-v2/service/rolesanywhere"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/servicediscovery"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/wafregional"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/pterm/pterm"
)

type RegionalFetcher func(ctx context.Context, cfg aws.Config) (interface{}, string, error)

var RegionalTasks = map[string]map[string]RegionalFetcher{
	"ec2": {
		"vpcs.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := ec2.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := ec2.NewDescribeVpcsPaginator(client, &ec2.DescribeVpcsInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Vpcs { items = append(items, v) }
				}
				return items, nil
			})
			return items, "Vpcs", err
		},
		"subnets.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := ec2.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := ec2.NewDescribeSubnetsPaginator(client, &ec2.DescribeSubnetsInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Subnets { items = append(items, v) }
				}
				return items, nil
			})
			return items, "Subnets", err
		},
		"instances.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := ec2.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Reservations { items = append(items, v) }
				}
				return items, nil
			})
			return items, "Reservations", err
		},
		"volumes.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := ec2.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := ec2.NewDescribeVolumesPaginator(client, &ec2.DescribeVolumesInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Volumes { items = append(items, v) }
				}
				return items, nil
			})
			return items, "Volumes", err
		},
		"snapshots.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := ec2.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := ec2.NewDescribeSnapshotsPaginator(client, &ec2.DescribeSnapshotsInput{OwnerIds: []string{"self"}})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Snapshots { items = append(items, v) }
				}
				return items, nil
			})
			return items, "Snapshots", err
		},
		"security_groups.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := ec2.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.SecurityGroups { items = append(items, v) }
				}
				return items, nil
			})
			return items, "SecurityGroups", err
		},
	},
	"rds": {
		"instances.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := rds.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.DBInstances { items = append(items, v) }
				}
				return items, nil
			})
			return items, "DBInstances", err
		},
	},
	"lambda": {
		"functions.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := lambda.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := lambda.NewListFunctionsPaginator(client, &lambda.ListFunctionsInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Functions { items = append(items, v) }
				}
				return items, nil
			})
			return items, "Functions", err
		},
	},
	"dynamodb": {
		"tables.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := dynamodb.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := dynamodb.NewListTablesPaginator(client, &dynamodb.ListTablesInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.TableNames { items = append(items, v) }
				}
				return items, nil
			})
			return items, "TableNames", err
		},
	},
	"sqs": {
		"queues.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := sqs.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := sqs.NewListQueuesPaginator(client, &sqs.ListQueuesInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.QueueUrls { items = append(items, v) }
				}
				return items, nil
			})
			return items, "QueueUrls", err
		},
	},
	"sns": {
		"topics.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := sns.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := sns.NewListTopicsPaginator(client, &sns.ListTopicsInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Topics { items = append(items, v) }
				}
				return items, nil
			})
			return items, "Topics", err
		},
	},
	"logs": {
		"log_groups.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := cloudwatchlogs.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(client, &cloudwatchlogs.DescribeLogGroupsInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.LogGroups { items = append(items, v) }
				}
				return items, nil
			})
			return items, "logGroups", err
		},
	},
	"cloudformation": {
		"stacks.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := cloudformation.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := cloudformation.NewDescribeStacksPaginator(client, &cloudformation.DescribeStacksInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Stacks { items = append(items, v) }
				}
				return items, nil
			})
			return items, "Stacks", err
		},
	},
	"kms": {
		"keys.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := kms.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := kms.NewListAliasesPaginator(client, &kms.ListAliasesInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Aliases { items = append(items, v) }
				}
				return items, nil
			})
			return items, "Aliases", err
		},
	},
	"ssm": {
		"parameters.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := ssm.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := ssm.NewDescribeParametersPaginator(client, &ssm.DescribeParametersInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Parameters { items = append(items, v) }
				}
				return items, nil
			})
			return items, "Parameters", err
		},
	},
	"apigateway": {
		"rest_apis.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := apigateway.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := apigateway.NewGetRestApisPaginator(client, &apigateway.GetRestApisInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Items { items = append(items, v) }
				}
				return items, nil
			})
			return items, "items", err
		},
	},
	"apigatewayv2": {
		"apis.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := apigatewayv2.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				var items []interface{}
				var nextToken *string
				for {
					resp, err := client.GetApis(ctx, &apigatewayv2.GetApisInput{NextToken: nextToken})
					if err != nil { return nil, err }
					for _, v := range resp.Items { items = append(items, v) }
					if resp.NextToken == nil { break }
					nextToken = resp.NextToken
				}
				return items, nil
			})
			return items, "Items", err
		},
	},
	"eks": {
		"clusters.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := eks.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := eks.NewListClustersPaginator(client, &eks.ListClustersInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Clusters { items = append(items, v) }
				}
				return items, nil
			})
			return items, "clusters", err
		},
	},
	"ecs": {
		"clusters.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := ecs.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := ecs.NewListClustersPaginator(client, &ecs.ListClustersInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.ClusterArns { items = append(items, v) }
				}
				return items, nil
			})
			return items, "clusterArns", err
		},
	},
	"elb": {
		"load_balancers.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := elasticloadbalancing.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				resp, err := client.DescribeLoadBalancers(ctx, &elasticloadbalancing.DescribeLoadBalancersInput{})
				if err != nil { return nil, err }
				var items []interface{}
				for _, v := range resp.LoadBalancerDescriptions { items = append(items, v) }
				return items, nil
			})
			return items, "LoadBalancerDescriptions", err
		},
	},
	"elbv2": {
		"load_balancers.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := elasticloadbalancingv2.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(client, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.LoadBalancers { items = append(items, v) }
				}
				return items, nil
			})
			return items, "LoadBalancers", err
		},
	},
	"autoscaling": {
		"groups.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := autoscaling.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := autoscaling.NewDescribeAutoScalingGroupsPaginator(client, &autoscaling.DescribeAutoScalingGroupsInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.AutoScalingGroups { items = append(items, v) }
				}
				return items, nil
			})
			return items, "AutoScalingGroups", err
		},
	},
	"wafv2": {
		"web_acls.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := wafv2.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				resp, err := client.ListWebACLs(ctx, &wafv2.ListWebACLsInput{Scope: "REGIONAL"})
				if err != nil { return nil, err }
				var items []interface{}
				for _, v := range resp.WebACLs { items = append(items, v) }
				return items, nil
			})
			return items, "WebACLs", err
		},
	},
	"waf-regional": {
		"web_acls.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := wafregional.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				resp, err := client.ListWebACLs(ctx, &wafregional.ListWebACLsInput{})
				if err != nil { return nil, err }
				var items []interface{}
				for _, v := range resp.WebACLs { items = append(items, v) }
				return items, nil
			})
			return items, "WebACLs", err
		},
	},
	"guardduty": {
		"detectors.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := guardduty.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := guardduty.NewListDetectorsPaginator(client, &guardduty.ListDetectorsInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.DetectorIds { items = append(items, v) }
				}
				return items, nil
			})
			return items, "DetectorIds", err
		},
	},
	"securityhub": {
		"hub.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := securityhub.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				resp, err := client.DescribeHub(ctx, &securityhub.DescribeHubInput{})
				if err != nil { return nil, err }
				return resp.HubArn, nil
			})
			return items, "HubArn", err
		},
	},
	"accessanalyzer": {
		"analyzers.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := accessanalyzer.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := accessanalyzer.NewListAnalyzersPaginator(client, &accessanalyzer.ListAnalyzersInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Analyzers { items = append(items, v) }
				}
				return items, nil
			})
			return items, "analyzers", err
		},
	},
	"backup": {
		"vaults.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := backup.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := backup.NewListBackupVaultsPaginator(client, &backup.ListBackupVaultsInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.BackupVaultList { items = append(items, v) }
				}
				return items, nil
			})
			return items, "BackupVaultList", err
		},
	},
	"config": {
		"rules.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := configservice.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := configservice.NewDescribeConfigRulesPaginator(client, &configservice.DescribeConfigRulesInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.ConfigRules { items = append(items, v) }
				}
				return items, nil
			})
			return items, "ConfigRules", err
		},
	},
	"ecr": {
		"repositories.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := ecr.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := ecr.NewDescribeRepositoriesPaginator(client, &ecr.DescribeRepositoriesInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Repositories { items = append(items, v) }
				}
				return items, nil
			})
			return items, "repositories", err
		},
	},
	"redshift": {
		"clusters.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := redshift.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := redshift.NewDescribeClustersPaginator(client, &redshift.DescribeClustersInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Clusters { items = append(items, v) }
				}
				return items, nil
			})
			return items, "Clusters", err
		},
	},
	"sagemaker": {
		"notebooks.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := sagemaker.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := sagemaker.NewListNotebookInstancesPaginator(client, &sagemaker.ListNotebookInstancesInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.NotebookInstances { items = append(items, v) }
				}
				return items, nil
			})
			return items, "NotebookInstances", err
		},
	},
	"cognito-idp": {
		"user_pools.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := cognitoidentityprovider.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := cognitoidentityprovider.NewListUserPoolsPaginator(client, &cognitoidentityprovider.ListUserPoolsInput{MaxResults: aws.Int32(60)})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.UserPools { items = append(items, v) }
				}
				return items, nil
			})
			return items, "UserPools", err
		},
	},
	"opensearch": {
		"domains.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := opensearch.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				resp, err := client.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
				if err != nil { return nil, err }
				var items []interface{}
				for _, v := range resp.DomainNames { items = append(items, v) }
				return items, nil
			})
			return items, "DomainNames", err
		},
	},
	"athena": {
		"workgroups.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := athena.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := athena.NewListWorkGroupsPaginator(client, &athena.ListWorkGroupsInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.WorkGroups { items = append(items, v) }
				}
				return items, nil
			})
			return items, "WorkGroups", err
		},
	},
	"apprunner": {
		"vpc_connectors.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := apprunner.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				resp, err := client.ListVpcConnectors(ctx, &apprunner.ListVpcConnectorsInput{})
				if err != nil { return nil, err }
				var items []interface{}
				for _, v := range resp.VpcConnectors { items = append(items, v) }
				return items, nil
			})
			return items, "VpcConnectors", err
		},
	},
	"firehose": {
		"delivery_streams.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := firehose.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				resp, err := client.ListDeliveryStreams(ctx, &firehose.ListDeliveryStreamsInput{})
				if err != nil { return nil, err }
				var items []interface{}
				for _, v := range resp.DeliveryStreamNames { items = append(items, v) }
				return items, nil
			})
			return items, "DeliveryStreamNames", err
		},
	},
	"imagebuilder": {
		"recipes.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := imagebuilder.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				resp, err := client.ListContainerRecipes(ctx, &imagebuilder.ListContainerRecipesInput{})
				if err != nil { return nil, err }
				var items []interface{}
				for _, v := range resp.ContainerRecipeSummaryList { items = append(items, v) }
				return items, nil
			})
			return items, "containerRecipeSummaryList", err
		},
	},
	"codepipeline": {
		"pipelines.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := codepipeline.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := codepipeline.NewListPipelinesPaginator(client, &codepipeline.ListPipelinesInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Pipelines { items = append(items, v) }
				}
				return items, nil
			})
			return items, "pipelines", err
		},
	},
	"detective": {
		"graphs.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := detective.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				resp, err := client.ListGraphs(ctx, &detective.ListGraphsInput{})
				if err != nil { return nil, err }
				var items []interface{}
				for _, v := range resp.GraphList { items = append(items, v) }
				return items, nil
			})
			return items, "GraphList", err
		},
	},
	"macie2": {
		"session.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := macie2.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				resp, err := client.GetMacieSession(ctx, &macie2.GetMacieSessionInput{})
				if err != nil { return nil, err }
				return resp.Status, nil
			})
			return items, "status", err
		},
	},
	"dms": {
		"certificates.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := databasemigrationservice.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := databasemigrationservice.NewDescribeCertificatesPaginator(client, &databasemigrationservice.DescribeCertificatesInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Certificates { items = append(items, v) }
				}
				return items, nil
			})
			return items, "Certificates", err
		},
	},
	"datasync": {
		"locations.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := datasync.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := datasync.NewListLocationsPaginator(client, &datasync.ListLocationsInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Locations { items = append(items, v) }
				}
				return items, nil
			})
			return items, "Locations", err
		},
	},
	"rolesanywhere": {
		"profiles.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := rolesanywhere.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				resp, err := client.ListProfiles(ctx, &rolesanywhere.ListProfilesInput{})
				if err != nil { return nil, err }
				var items []interface{}
				for _, v := range resp.Profiles { items = append(items, v) }
				return items, nil
			})
			return items, "profiles", err
		},
	},
	"databrew": {
		"recipes.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := databrew.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := databrew.NewListRecipesPaginator(client, &databrew.ListRecipesInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Recipes { items = append(items, v) }
				}
				return items, nil
			})
			return items, "Recipes", err
		},
	},
	"deadline": {
		"farms.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := deadline.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := deadline.NewListFarmsPaginator(client, &deadline.ListFarmsInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Farms { items = append(items, v) }
				}
				return items, nil
			})
			return items, "farms", err
		},
	},
	"codebuild": {
		"projects.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := codebuild.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				resp, err := client.ListProjects(ctx, &codebuild.ListProjectsInput{})
				if err != nil { return nil, err }
				var items []interface{}
				for _, v := range resp.Projects { items = append(items, v) }
				return items, nil
			})
			return items, "projects", err
		},
	},
	"servicediscovery": {
		"namespaces.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := servicediscovery.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := servicediscovery.NewListNamespacesPaginator(client, &servicediscovery.ListNamespacesInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Namespaces { items = append(items, v) }
				}
				return items, nil
			})
			return items, "Namespaces", err
		},
	},
	"appconfig": {
		"applications.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := appconfig.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := appconfig.NewListApplicationsPaginator(client, &appconfig.ListApplicationsInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.Items { items = append(items, v) }
				}
				return items, nil
			})
			return items, "Items", err
		},
	},
	"resourcegroupstaggingapi": {
		"resources.json": func(ctx context.Context, cfg aws.Config) (interface{}, string, error) {
			client := resourcegroupstaggingapi.NewFromConfig(cfg)
			items, err := SafeCall(func() (interface{}, error) {
				paginator := resourcegroupstaggingapi.NewGetResourcesPaginator(client, &resourcegroupstaggingapi.GetResourcesInput{})
				var items []interface{}
				for paginator.HasMorePages() {
					page, err := paginator.NextPage(ctx)
					if err != nil { return nil, err }
					for _, v := range page.ResourceTagMappingList { items = append(items, v) }
				}
				return items, nil
			})
			return items, "ResourceTagMappingList", err
		},
	},
}

func DiscoverRegion(
	ctx context.Context, 
	cfg aws.Config, 
	accountID, accountDir, region string, 
	verbose bool, 
	deeptrail bool, 
	trailDays int,
) error {
	// 1. Regional API Scans
	for svc, files := range RegionalTasks {
		if verbose {
			pterm.Info.Printf("    (%s) Scanning %s...\n", region, svc)
		}
		for filename, fetcher := range files {
			data, key, err := fetcher(ctx, cfg)
			if err != nil {
				// Silently skip common errors like AccessDenied in verbose mode if preferred, 
				// but here we just log and continue.
				continue
			}
			if data != nil {
				// Only write if we have items (most tasks return []interface{})
				if items, ok := data.([]interface{}); ok {
					if len(items) > 0 {
						WriteJSON(accountDir, region, svc, filename, map[string]interface{}{key: data})
					}
				} else {
					// Not a slice, write as is (for single object responses)
					WriteJSON(accountDir, region, svc, filename, map[string]interface{}{key: data})
				}
			}
		}
	}

	// 2. DeepTrail Analysis
	if deeptrail {
		trailCfg, err := GetTrailConfig(ctx, cfg, verbose)
		if err == nil {
			paths, err := DownloadTrailSamples(ctx, cfg, accountID, accountDir, region, trailCfg.Bucket, trailCfg.Prefix, trailDays, verbose)
			if err == nil && len(paths) > 0 {
				events, err := ParseTrailEvents(paths)
				if err == nil && len(events) > 0 {
					WriteJSON(accountDir, region, "cloudtrail", "discovery_events.json", map[string]interface{}{"Records": events})
					if verbose {
						pterm.Info.Printf("    Parsed %d events for discovery in %s\n", len(events), region)
					}
				}
			}
		}
	}

	return nil
}

func RunDiscovery(
	ctx context.Context, 
	cfg aws.Config, 
	accountID, accountDir string, 
	regions []string, 
	maxWorkers int, 
	verbose bool, 
	deeptrail bool, 
	trailDays int,
) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxWorkers)

	for _, region := range regions {
		wg.Add(1)
		go func(r string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Create a copy of the config with the region set
			regionalCfg := cfg.Copy()
			regionalCfg.Region = r

			err := DiscoverRegion(ctx, regionalCfg, accountID, accountDir, r, verbose, deeptrail, trailDays)
			if err != nil {
				pterm.Error.Printf("Discovery failed for region %s: %v\n", r, err)
			} else {
				pterm.Success.Printf("  Region: %s\n", r)
			}
		}(region)
	}

	wg.Wait()
}
