package awsutil

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type SessionManager struct {
	Config    aws.Config
	AccountID string
}

func NewSessionManager(ctx context.Context, roleARN string) (*SessionManager, error) {
	// Load default config (handles env vars, shared config files, etc.)
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		return nil, fmt.Errorf("failed to load SDK configuration: %w", err)
	}

	// If roleARN is provided, assume that role
	if roleARN != "" {
		stsClient := sts.NewFromConfig(cfg)
		provider := stscreds.NewAssumeRoleProvider(stsClient, roleARN)
		cfg.Credentials = aws.NewCredentialsCache(provider)
	}

	// Retrieve Account ID
	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get caller identity: %w", err)
	}

	return &SessionManager{
		Config:    cfg,
		AccountID: *identity.Account,
	}, nil
}

func (s *SessionManager) GetActiveRegions(ctx context.Context) ([]string, error) {
	ec2Client := ec2.NewFromConfig(s.Config, func(o *ec2.Options) {
		o.Region = "us-east-1"
	})
	resp, err := ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return []string{"us-east-1"}, nil // Fallback
	}

	var regions []string
	for _, r := range resp.Regions {
		regions = append(regions, *r.RegionName)
	}
	return regions, nil
}
