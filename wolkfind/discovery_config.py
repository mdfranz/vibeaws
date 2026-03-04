# /// script
# dependencies = []
# ///
from __future__ import annotations

from typing import Dict, Tuple

from botocore.config import Config

DEFAULT_OUTPUT_DIR = "wolkfind/results"
DEFAULT_MAX_WORKERS = 10
LOOKUP_DAYS = 90
TRAIL_DISCOVERY_DAYS = 30

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})

SCANNED_SERVICES = {
    "ec2.amazonaws.com",
    "rds.amazonaws.com",
    "lambda.amazonaws.com",
    "s3.amazonaws.com",
    "iam.amazonaws.com",
    "route53.amazonaws.com",
    "sqs.amazonaws.com",
    "dynamodb.amazonaws.com",
    "logs.amazonaws.com",
    "autoscaling.amazonaws.com",
    "elasticloadbalancing.amazonaws.com",
    "eks.amazonaws.com",
    "sns.amazonaws.com",
    "elasticfilesystem.amazonaws.com",
    "cloudtrail.amazonaws.com",
    "sts.amazonaws.com",
    "cloudformation.amazonaws.com",
    "wafv2.amazonaws.com",
    "kms.amazonaws.com",
    "ssm.amazonaws.com",
    "apigateway.amazonaws.com",
    "workspaces.amazonaws.com",
    "ecr.amazonaws.com",
    "guardduty.amazonaws.com",
    "securityhub.amazonaws.com",
    "amplify.amazonaws.com",
    "ecs.amazonaws.com",
    "elb.amazonaws.com",
    "elbv2.amazonaws.com",
    "waf-regional.amazonaws.com",
    "internetmonitor.amazonaws.com",
    "ssm-quicksetup.amazonaws.com",
    "notifications.amazonaws.com",
    "bedrock.amazonaws.com",
    "ds.amazonaws.com",
    "sso.amazonaws.com",
    "resource-explorer-2.amazonaws.com",
    "monitoring.amazonaws.com",
    "resource-groups.amazonaws.com",
    "servicecatalog-appregistry.amazonaws.com",
    "tagging.amazonaws.com",
    "oam.amazonaws.com",
    "application-insights.amazonaws.com",
    "athena.amazonaws.com",
    "events.amazonaws.com",
    "backup.amazonaws.com",
    "codebuild.amazonaws.com",
    "config.amazonaws.com",
    "redshift.amazonaws.com",
    "sagemaker.amazonaws.com",
    "access-analyzer.amazonaws.com",
    "cognito-idp.amazonaws.com",
    "es.amazonaws.com",
    "servicediscovery.amazonaws.com",
    "opensearch.amazonaws.com",
    "appconfig.amazonaws.com",
    "apprunner.amazonaws.com",
    "appstream.amazonaws.com",
    "firehose.amazonaws.com",
    "imagebuilder.amazonaws.com",
    "codepipeline.amazonaws.com",
    "detective.amazonaws.com",
    "macie2.amazonaws.com",
    "signin.amazonaws.com",
    "q.amazonaws.com",
}

# service -> filename -> (op, result_key, optional kwargs)
DISCOVERY_MAP: Dict[str, Dict[str, Tuple[str, str, dict]]] = {
    "ec2": {
        "vpcs.json": ("describe_vpcs", "Vpcs", {}),
        "subnets.json": ("describe_subnets", "Subnets", {}),
        "instances.json": ("describe_instances", "Reservations", {}),
        "volumes.json": ("describe_volumes", "Volumes", {}),
        "security_groups.json": ("describe_security_groups", "SecurityGroups", {}),
    },
    "rds": {"instances.json": ("describe_db_instances", "DBInstances", {})},
    "lambda": {"functions.json": ("list_functions", "Functions", {})},
    "dynamodb": {"tables.json": ("list_tables", "TableNames", {})},
    "sqs": {"queues.json": ("list_queues", "QueueUrls", {})},
    "sns": {"topics.json": ("list_topics", "Topics", {})},
    "logs": {"log_groups.json": ("describe_log_groups", "logGroups", {})},
    "cloudformation": {"stacks.json": ("describe_stacks", "Stacks", {})},
    "kms": {"keys.json": ("list_aliases", "Aliases", {})},

    "ssm": {"parameters.json": ("describe_parameters", "Parameters", {})},
    "apigateway": {"rest_apis.json": ("get_rest_apis", "items", {})},
    "apigatewayv2": {"apis.json": ("get_apis", "Items", {})},
    "workspaces": {"workspaces.json": ("describe_workspaces", "Workspaces", {})},
    "ecr": {"repositories.json": ("describe_repositories", "repositories", {})},
    "guardduty": {"detectors.json": ("list_detectors", "DetectorIds", {})},
    "securityhub": {"hub.json": ("describe_hub", "HubArn", {})},
    "amplify": {"apps.json": ("list_apps", "apps", {})},
    "eks": {"clusters.json": ("list_clusters", "clusters", {})},
    "ecs": {"clusters.json": ("list_clusters", "clusterArns", {})},
    "elb": {"load_balancers.json": ("describe_load_balancers", "LoadBalancerDescriptions", {})},
    "elbv2": {"load_balancers.json": ("describe_load_balancers", "LoadBalancers", {})},
    "autoscaling": {"groups.json": ("describe_auto_scaling_groups", "AutoScalingGroups", {})},
    "waf-regional": {"web_acls.json": ("list_web_acls", "WebACLs", {})},
    "internetmonitor": {"monitors.json": ("list_monitors", "Monitors", {})},
    "resourcegroupstaggingapi": {
        "resources.json": ("get_resources", "ResourceTagMappingList", {})
    },
    "athena": {"workgroups.json": ("list_work_groups", "WorkGroups", {})},
    "events": {"rules.json": ("list_rules", "Rules", {})},
    "backup": {"vaults.json": ("list_backup_vaults", "BackupVaultList", {})},
    "codebuild": {"projects.json": ("list_projects", "projects", {})},
    "config": {"rules.json": ("describe_config_rules", "ConfigRules", {})},
    "redshift": {"clusters.json": ("describe_clusters", "Clusters", {})},
    "sagemaker": {"notebooks.json": ("list_notebook_instances", "NotebookInstances", {})},
    "accessanalyzer": {"analyzers.json": ("list_analyzers", "analyzers", {})},
    "cognito-idp": {
        "user_pools.json": ("list_user_pools", "UserPools", {"MaxResults": 60})
    },
    "opensearch": {"domains.json": ("list_domain_names", "DomainNames", {})},
    "servicediscovery": {"namespaces.json": ("list_namespaces", "Namespaces", {})},
    "appconfig": {"applications.json": ("list_applications", "Items", {})},
    "apprunner": {"vpc_connectors.json": ("list_vpc_connectors", "VpcConnectors", {})},
    "firehose": {"delivery_streams.json": ("list_delivery_streams", "DeliveryStreamNames", {})},
    "imagebuilder": {
        "recipes.json": ("list_container_recipes", "containerRecipeSummaryList", {})
    },
    "codepipeline": {"pipelines.json": ("list_pipelines", "pipelines", {})},
    "detective": {"graphs.json": ("list_graphs", "GraphList", {})},
    "macie2": {"session.json": ("get_macie_session", "status", {})},
}
