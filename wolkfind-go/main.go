package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"

	"wolkfind/pkg/awsutil"
	"wolkfind/pkg/config"
	"wolkfind/pkg/discovery"
	"wolkfind/pkg/report"

	"github.com/pterm/pterm"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "wolkfind",
		Usage: "AWS resource discovery and reporting tool",
		Commands: []*cli.Command{
			{
				Name:  "discover",
				Usage: "Scan AWS accounts for resources",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "region",
						Usage: "Comma-separated regions to scan",
					},
					&cli.StringFlag{
						Name:  "role-arn",
						Usage: "Comma-separated AWS Role ARNs to assume",
					},
					&cli.BoolFlag{
						Name:  "deeptrail",
						Usage: "Enable DeepTrail analysis (S3 log sampling)",
					},
					&cli.IntFlag{
						Name:  "trail-months",
						Value: 1,
						Usage: "Number of months of CloudTrail logs to sample",
					},
					&cli.BoolFlag{
						Name:  "detailed",
						Usage: "Show detailed progress",
					},
					&cli.BoolFlag{
						Name:  "verbose",
						Usage: "Enable verbose output",
					},
					&cli.StringFlag{
						Name:  "output-dir",
						Value: config.DefaultOutputDir,
						Usage: "Root directory to save results",
					},
					&cli.IntFlag{
						Name:  "max-workers",
						Value: config.DefaultMaxWorkers,
						Usage: "Maximum parallel regional scans",
					},
				},
				Action: func(c *cli.Context) error {
					ctx := context.Background()
					verbose := c.Bool("verbose")
					outputDir := c.String("output-dir")
					maxWorkers := c.Int("max-workers")
					trailMonths := c.Int("trail-months")
					deeptrail := c.Bool("deeptrail")
					trailDays := trailMonths * 30

					roleARNs := strings.Split(c.String("role-arn"), ",")
					if c.String("role-arn") == "" {
						roleARNs = []string{""}
					}

					for _, roleARN := range roleARNs {
						roleARN = strings.TrimSpace(roleARN)
						sm, err := awsutil.NewSessionManager(ctx, roleARN)
						if err != nil {
							pterm.Error.Printf("Failed to initialize session for role %s: %v\n", roleARN, err)
							continue
						}

						accountID := sm.AccountID
						accountDir := filepath.Join(outputDir, accountID)
						
						pterm.DefaultHeader.WithFullWidth().Printf("AWS Discovery: %s\n", accountID)

						// 1. Global Discovery
						if err := discovery.DiscoverGlobal(ctx, sm.Config, accountDir, verbose); err != nil {
							pterm.Error.Printf("Global discovery failed: %v\n", err)
						}

						// 2. Regional Discovery
						regionsStr := c.String("region")
						var regions []string
						if regionsStr != "" {
							regions = strings.Split(regionsStr, ",")
						} else {
							regions, err = sm.GetActiveRegions(ctx)
							if err != nil {
								pterm.Error.Printf("Failed to get active regions: %v\n", err)
								regions = []string{"us-east-1"}
							}
						}

						pterm.Info.Printf("Scanning %d regions...\n", len(regions))
						discovery.RunDiscovery(ctx, sm.Config, accountID, accountDir, regions, maxWorkers, verbose, deeptrail, trailDays)
					}

					return nil
				},
			},
			{
				Name:  "report",
				Usage: "Generate report from discovered data",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "output-dir",
						Value: config.DefaultOutputDir,
						Usage: "Directory containing discovery results",
					},
					&cli.BoolFlag{
						Name:  "detailed",
						Usage: "Generate detailed resource map",
					},
					&cli.BoolFlag{
						Name:  "stale",
						Usage: "Generate a CSV of stale resources",
					},
					&cli.BoolFlag{
						Name:  "verbose",
						Usage: "Enable verbose output",
					},
				},
				Action: func(c *cli.Context) error {
					outputDir := c.String("output-dir")
					detailed := c.Bool("detailed")
					stale := c.Bool("stale")

					return report.GenerateDiscoveryReport(outputDir, detailed, stale)
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
