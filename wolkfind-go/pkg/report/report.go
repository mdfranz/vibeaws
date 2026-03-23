package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pterm/pterm"
)

var ServiceNames = map[string]string{
	"ec2":                      "Compute (EC2)",
	"lambda":                   "Lambda",
	"eks":                      "EKS Clusters",
	"ecs":                      "ECS Clusters",
	"autoscaling":              "Auto Scaling",
	"vpc":                      "VPCs", // Note: EC2 fetcher puts VPCs under ec2/vpcs.json, but Python might map differently. I'll use svc names from dirs.
	"subnets":                  "Subnets",
	"elb":                      "Load Balancers (Classic)",
	"elbv2":                    "Load Balancers",
	"efs":                      "EFS",
	"ecr":                      "ECR Repos",
	"backup":                   "Backup Vaults",
	"wafv2":                    "WAFv2 ACLs",
	"waf-regional":             "WAF Regional ACLs",
	"kms":                      "KMS Keys",
	"guardduty":                "GuardDuty",
	"securityhub":              "Security Hub",
	"dynamodb":                 "DynamoDB",
	"sqs":                      "SQS Queues",
	"sns":                      "SNS Topics",
	"rds":                      "RDS Instances",
	"redshift":                 "Redshift",
	"cloudformation":           "CloudFormation",
	"ssm":                      "SSM Params",
	"apigateway":               "API Gateways",
	"apigatewayv2":             "API Gateways v2",
	"databasemigrationservice": "DMS",
	"datasync":                 "DataSync",
	"rolesanywhere":            "RolesAnywhere",
	"databrew":                 "DataBrew",
	"deadline":                 "Deadline",
	"athena":                   "Athena",
	"codebuild":                "CodeBuild",
	"codepipeline":             "CodePipeline",
}

var CategoryMap = map[string][]string{
	"Compute":  {"ec2", "lambda", "eks", "ecs", "autoscaling"},
	"Network":  {"vpc", "subnets", "elb", "elbv2"},
	"Storage":  {"ecr", "backup", "efs", "s3"},
	"Security": {"kms", "guardduty", "securityhub", "accessanalyzer", "wafv2", "waf-regional", "macie2", "detective"},
	"Data":     {"dynamodb", "rds", "redshift", "athena", "databrew", "datasync"},
	"Apps":     {"cloudformation", "ssm", "apigateway", "apigatewayv2", "codebuild", "codepipeline", "servicediscovery", "appconfig", "apprunner", "deadline"},
}

var RegionShort = map[string]string{
	"us-east-1":      "use1",
	"us-east-2":      "use2",
	"us-west-1":      "usw1",
	"us-west-2":      "usw2",
	"af-south-1":     "afs1",
	"ap-east-1":      "ape1",
	"ap-south-1":     "aps1",
	"ap-northeast-3": "apn3",
	"ap-northeast-2": "apn2",
	"ap-northeast-1": "apn1",
	"ap-southeast-1": "apse1",
	"ap-southeast-2": "apse2",
	"ca-central-1":   "cac1",
	"eu-central-1":   "euc1",
	"eu-west-1":      "euw1",
	"eu-west-2":      "euw2",
	"eu-south-1":     "eus1",
	"eu-west-3":      "euw3",
	"eu-north-1":     "eun1",
	"me-south-1":     "mes1",
	"sa-east-1":      "sae1",
}

func ShortenRegion(r string) string {
	if short, ok := RegionShort[r]; ok {
		return short
	}
	return r
}

func LoadJSON(path string) (map[string]interface{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var data map[string]interface{}
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		return nil, err
	}
	return data, nil
}

func GenerateDiscoveryReport(outputDir string, detailed bool, stale bool) error {
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return err
	}

	var staleRows [][]string
	if stale {
		staleRows = append(staleRows, []string{"account", "asset", "last_date"})
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		accountID := entry.Name()
		if len(accountID) != 12 {
			continue
		}

		pterm.DefaultHeader.WithFullWidth().Printf("AWS ACCOUNT DISCOVERY: %s\n", accountID)
		accDir := filepath.Join(outputDir, accountID)

		// 1. Global Summary
		globals := make(map[string]int)
		
		// S3
		if data, err := LoadJSON(filepath.Join(accDir, "global", "s3", "buckets.json")); err == nil {
			if buckets, ok := data["Buckets"].([]interface{}); ok {
				globals["S3 Buckets"] = len(buckets)
				if stale {
					for _, b := range buckets {
						if bm, ok := b.(map[string]interface{}); ok {
							if cd, ok := bm["CreationDate"].(string); ok {
								if isStale(cd, 90) {
									staleRows = append(staleRows, []string{accountID, fmt.Sprintf("S3 Bucket: %v", bm["Name"]), cd[:10]})
								}
							}
						}
					}
				}
			}
		}
		// IAM
		if data, err := LoadJSON(filepath.Join(accDir, "global", "iam", "users.json")); err == nil {
			if users, ok := data["Users"].([]interface{}); ok {
				globals["IAM Users"] = len(users)
			}
		}
		if data, err := LoadJSON(filepath.Join(accDir, "global", "iam", "roles.json")); err == nil {
			if roles, ok := data["Roles"].([]interface{}); ok {
				globals["IAM Roles"] = len(roles)
				if stale {
					for _, r := range roles {
						if rm, ok := r.(map[string]interface{}); ok {
							if cd, ok := rm["CreateDate"].(string); ok {
								if isStale(cd, 90) {
									staleRows = append(staleRows, []string{accountID, fmt.Sprintf("IAM Role: %v", rm["RoleName"]), cd[:10]})
								}
							}
						}
					}
				}
			}
		}

		globalStr := ""
		for k, v := range globals {
			globalStr += fmt.Sprintf("%s: [bold]%d[/] | ", k, v)
		}
		if globalStr != "" {
			pterm.DefaultSection.Println("Global Services")
			pterm.Println(strings.TrimSuffix(globalStr, " | "))
			pterm.Println()
		}

		// 2. Regional Summary (Categorized)
		regionalEntries, _ := os.ReadDir(accDir)
		regionalData := make(map[string]map[string]int)
		var regions []string

		for _, re := range regionalEntries {
			if !re.IsDir() || re.Name() == "global" {
				continue
			}
			region := re.Name()
			regions = append(regions, region)
			regionalData[region] = make(map[string]int)

			rDir := filepath.Join(accDir, region)
			filepath.Walk(rDir, func(path string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() && strings.HasSuffix(info.Name(), ".json") && info.Name() != "discovery_events.json" {
					data, err := LoadJSON(path)
					if err == nil {
						for _, v := range data {
							if items, ok := v.([]interface{}); ok {
								svc := filepath.Base(filepath.Dir(path))
								regionalData[region][svc] += len(items)
								
								if stale {
									// Track stale resources per category if date field found
									// This is handled later or can be integrated here
								}
							}
						}
					}
				}
				return nil
			})
		}

		if len(regions) > 0 {
			sort.Strings(regions)
			
			categories := []string{"Compute", "Network", "Storage", "Security", "Data", "Apps"}
			for _, cat := range categories {
				catSvcs := CategoryMap[cat]
				tableData := pterm.TableData{{"Service"}}
				for _, r := range regions {
					tableData[0] = append(tableData[0], ShortenRegion(r))
				}

				hasCatData := false
				for _, svc := range catSvcs {
					row := []string{ServiceNames[svc]}
					if ServiceNames[svc] == "" { row[0] = svc }
					hasSvcData := false
					for _, r := range regions {
						cnt := regionalData[r][svc]
						if cnt > 0 {
							row = append(row, fmt.Sprintf("%d", cnt))
							hasSvcData = true
							hasCatData = true
						} else {
							row = append(row, "-")
						}
					}
					if hasSvcData {
						tableData = append(tableData, row)
					}
				}

				if hasCatData {
					pterm.DefaultSection.Printf("%s Resources\n", cat)
					pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
					pterm.Println()
				}
			}
		}

		if detailed {
			renderDetailedTree(accDir)
			renderDeepDiscovery(accDir, regions)
		}
		if stale {
			findStaleResources(accDir) // Keep existing console view, but we also collect for CSV
		}
	}

	if stale && len(staleRows) > 1 {
		writeStaleCSV(outputDir, staleRows)
	}

	return nil
}

func isStale(dateStr string, days int) bool {
	t, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		// Try other formats if needed
		return false
	}
	return time.Since(t).Hours() > float64(24*days)
}

func writeStaleCSV(outputDir string, rows [][]string) {
	csvPath := filepath.Join(outputDir, "stale_resources.csv")
	f, err := os.Create(csvPath)
	if err != nil {
		return
	}
	defer f.Close()

	for _, row := range rows {
		f.WriteString(strings.Join(row, ",") + "\n")
	}
	pterm.Success.Printf("Stale resources CSV written to: [blue]%s[/]\n", csvPath)
}

func extractIdentifiers(accDir, region string) map[string]bool {
	ids := make(map[string]bool)
	rPath := filepath.Join(accDir, region)
	
	filepath.Walk(rPath, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(info.Name(), ".json") && info.Name() != "discovery_events.json" {
			data, err := LoadJSON(path)
			if err == nil {
				for _, v := range data {
					if items, ok := v.([]interface{}); ok {
						for _, item := range items {
							if m, ok := item.(map[string]interface{}); ok {
								// Extract common ID/Name fields
								for _, f := range []string{"VpcId", "SubnetId", "InstanceId", "DBInstanceIdentifier", "FunctionName", "StackName", "TopicArn", "QueueUrl", "Arn", "Id", "Name"} {
									if val, ok := m[f].(string); ok && len(val) > 5 {
										ids[val] = true
									}
								}
							}
						}
					}
				}
			}
		}
		return nil
	})
	return ids
}

func renderDeepDiscovery(accDir string, regions []string) {
	// Import config to use ScannedServices
	// Since we are in the same module, we can access it if exported or use qualified name
	// But let's just use a local set for now or pass it.
	
	// We'll re-implement the logic from Python
	for _, region := range regions {
		rPath := filepath.Join(accDir, region)
		eventsPath := filepath.Join(rPath, "cloudtrail", "discovery_events.json")
		if _, err := os.Stat(eventsPath); err != nil {
			continue
		}

		data, err := LoadJSON(eventsPath)
		if err != nil {
			continue
		}

		records, ok := data["Records"].([]interface{})
		if !ok || len(records) == 0 {
			continue
		}

		ids := extractIdentifiers(accDir, region)
		// Also add Global IDs
		globalS3, _ := LoadJSON(filepath.Join(accDir, "global", "s3", "buckets.json"))
		if buckets, ok := globalS3["Buckets"].([]interface{}); ok {
			for _, b := range buckets {
				if bm, ok := b.(map[string]interface{}); ok {
					if name, ok := bm["Name"].(string); ok { ids[name] = true }
				}
			}
		}

		unmapped := make(map[string]map[string]bool)
		for _, rec := range records {
			rm, ok := rec.(map[string]interface{})
			if !ok { continue }
			
			src, _ := rm["eventSource"].(string)
			// Check if src is in ScannedServices (hardcoded here for simplicity or use config)
			// For now, let's just find anything touching our IDs
			
			recStr, _ := json.Marshal(rec)
			found := false
			for id := range ids {
				if strings.Contains(string(recStr), id) {
					found = true
					break
				}
			}

			if found {
				if unmapped[src] == nil { unmapped[src] = make(map[string]bool) }
				eventName, _ := rm["eventName"].(string)
				unmapped[src][eventName] = true
			}
		}

		if len(unmapped) > 0 {
			pterm.DefaultSection.Printf("Deep Discovery: %s\n", region)
			root := pterm.TreeNode{Text: "Unmapped Services Touching Existing Resources"}
			
			// Sort sources
			var srcs []string
			for s := range unmapped { srcs = append(srcs, s) }
			sort.Strings(srcs)

			for _, s := range srcs {
				svcNode := pterm.TreeNode{Text: s}
				var actions []string
				for a := range unmapped[s] { actions = append(actions, a) }
				sort.Strings(actions)
				for i, a := range actions {
					if i >= 5 { break }
					svcNode.Children = append(svcNode.Children, pterm.TreeNode{Text: a})
				}
				root.Children = append(root.Children, svcNode)
			}
			pterm.DefaultTree.WithRoot(root).Render()
		}
	}
}

func renderDetailedTree(accDir string) {
	pterm.DefaultSection.Println("Resource Inventory")
	root := pterm.TreeNode{Text: "AWS Account"}

	// Global
	globalNode := pterm.TreeNode{Text: "Global"}
	globalDir := filepath.Join(accDir, "global")
	if _, err := os.Stat(globalDir); err == nil {
		svcs, _ := os.ReadDir(globalDir)
		for _, svcDir := range svcs {
			if !svcDir.IsDir() {
				continue
			}
			svcNode := pterm.TreeNode{Text: svcDir.Name()}
			files, _ := os.ReadDir(filepath.Join(globalDir, svcDir.Name()))
			for _, f := range files {
				if !strings.HasSuffix(f.Name(), ".json") {
					continue
				}
				data, err := LoadJSON(filepath.Join(globalDir, svcDir.Name(), f.Name()))
				if err == nil {
					for _, v := range data {
						if items, ok := v.([]interface{}); ok {
							for _, item := range items {
								name := extractResourceName(svcDir.Name(), f.Name(), item)
								svcNode.Children = append(svcNode.Children, pterm.TreeNode{Text: name})
							}
						}
					}
				}
			}
			if len(svcNode.Children) > 0 {
				globalNode.Children = append(globalNode.Children, svcNode)
			}
		}
	}
	if len(globalNode.Children) > 0 {
		root.Children = append(root.Children, globalNode)
	}

	// Regional
	regionalEntries, _ := os.ReadDir(accDir)
	var regions []string
	for _, re := range regionalEntries {
		if re.IsDir() && re.Name() != "global" {
			regions = append(regions, re.Name())
		}
	}
	sort.Strings(regions)

	for _, region := range regions {
		regionNode := pterm.TreeNode{Text: region}
		rDir := filepath.Join(accDir, region)
		svcs, _ := os.ReadDir(rDir)
		for _, svcDir := range svcs {
			if !svcDir.IsDir() || svcDir.Name() == "cloudtrail" {
				continue
			}
			svcNode := pterm.TreeNode{Text: svcDir.Name()}
			files, _ := os.ReadDir(filepath.Join(rDir, svcDir.Name()))
			for _, f := range files {
				if !strings.HasSuffix(f.Name(), ".json") {
					continue
				}
				data, err := LoadJSON(filepath.Join(rDir, svcDir.Name(), f.Name()))
				if err == nil {
					for _, v := range data {
						if items, ok := v.([]interface{}); ok {
							for _, item := range items {
								name := extractResourceName(svcDir.Name(), f.Name(), item)
								svcNode.Children = append(svcNode.Children, pterm.TreeNode{Text: name})
							}
						} else if item, ok := v.(map[string]interface{}); ok {
							// Handle cases where it's a single object instead of a list
							name := extractResourceName(svcDir.Name(), f.Name(), item)
							svcNode.Children = append(svcNode.Children, pterm.TreeNode{Text: name})
						}
					}
				}
			}
			if len(svcNode.Children) > 0 {
				regionNode.Children = append(regionNode.Children, svcNode)
			}
		}
		if len(regionNode.Children) > 0 {
			root.Children = append(root.Children, regionNode)
		}
	}

	pterm.DefaultTree.WithRoot(root).Render()
}

func extractResourceName(svc, filename string, item interface{}) string {
	m, ok := item.(map[string]interface{})
	if !ok {
		if s, ok := item.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", item)
	}

	// EC2 Instances are special (Reservations -> Instances)
	if svc == "ec2" && filename == "instances.json" {
		if instances, ok := m["Instances"].([]interface{}); ok && len(instances) > 0 {
			if first, ok := instances[0].(map[string]interface{}); ok {
				if id, ok := first["InstanceId"].(string); ok {
					// Try to find Name tag
					if tags, ok := first["Tags"].([]interface{}); ok {
						for _, t := range tags {
							if tm, ok := t.(map[string]interface{}); ok {
								if tm["Key"] == "Name" {
									return fmt.Sprintf("%s (%s)", tm["Value"], id)
								}
							}
						}
					}
					return id
				}
			}
		}
	}

	// Specific fields per service/file
	switch filename {
	case "buckets.json":
		if v, ok := m["Name"].(string); ok { return v }
	case "users.json":
		if v, ok := m["UserName"].(string); ok { return v }
	case "roles.json":
		if v, ok := m["RoleName"].(string); ok { return v }
	case "policies.json":
		if v, ok := m["PolicyName"].(string); ok { return v }
	case "hosted_zones.json":
		if v, ok := m["Name"].(string); ok { return v }
	case "vpcs.json":
		if v, ok := m["VpcId"].(string); ok { return v }
	case "subnets.json":
		if v, ok := m["SubnetId"].(string); ok { return v }
	case "volumes.json":
		if v, ok := m["VolumeId"].(string); ok { return v }
	case "snapshots.json":
		if v, ok := m["SnapshotId"].(string); ok { return v }
	case "security_groups.json":
		return fmt.Sprintf("%s (%s)", m["GroupName"], m["GroupId"])
	case "instances.json":
		if svc == "rds" {
			if v, ok := m["DBInstanceIdentifier"].(string); ok { return v }
		}
	case "functions.json":
		if v, ok := m["FunctionName"].(string); ok { return v }
	case "tables.json":
		if v, ok := m["TableName"].(string); ok { return v }
	case "stacks.json":
		if v, ok := m["StackName"].(string); ok { return v }
	case "topics.json":
		if v, ok := m["TopicArn"].(string); ok { return v }
	case "queues.json":
		if v, ok := m["QueueUrl"].(string); ok { return v }
	case "parameters.json":
		if v, ok := m["Name"].(string); ok { return v }
	case "repositories.json":
		if v, ok := m["RepositoryName"].(string); ok { return v }
	case "clusters.json":
		if svc == "eks" {
			if v, ok := m["name"].(string); ok { return v }
		}
		if svc == "ecs" {
			if v, ok := m["clusterName"].(string); ok { return v }
		}
	case "projects.json":
		if svc == "codebuild" {
			if v, ok := m["name"].(string); ok { return v }
		}
	case "rules.json":
		if svc == "config" {
			if v, ok := m["ConfigRuleName"].(string); ok { return v }
		}
	case "resources.json":
		if v, ok := m["ResourceARN"].(string); ok { return v }
	}

	// Priority fields fallback
	fields := []string{"Name", "UserName", "RoleName", "VpcId", "SubnetId", "InstanceId", "DBInstanceIdentifier", "FunctionName", "StackName", "TopicArn", "QueueUrl", "AliasName", "ParameterName", "RepositoryName", "Id", "Arn", "ResourceARN"}
	for _, f := range fields {
		if v, ok := m[f].(string); ok {
			return v
		}
	}

	return fmt.Sprintf("%v", item)
}

func findStaleResources(accDir string) {
	pterm.DefaultSection.Println("Potential Stale Resources")
	tableData := pterm.TableData{{"Region", "Service", "Resource", "Reason"}}
	now := time.Now()

	// 1. Global (IAM)
	iamUserPath := filepath.Join(accDir, "global", "iam", "users.json")
	if data, err := LoadJSON(iamUserPath); err == nil {
		if users, ok := data["Users"].([]interface{}); ok {
			for _, u := range users {
				if m, ok := u.(map[string]interface{}); ok {
					name, _ := m["UserName"].(string)
					stale := false
					reason := ""

					// Password Last Used
					if plu, ok := m["PasswordLastUsed"].(string); ok {
						t, err := time.Parse(time.RFC3339, plu)
						if err == nil && now.Sub(t).Hours() > 24*90 {
							stale = true
							reason = fmt.Sprintf("Password not used in %d days", int(now.Sub(t).Hours()/24))
						}
					} else {
						// Check CreateDate
						if cd, ok := m["CreateDate"].(string); ok {
							t, err := time.Parse(time.RFC3339, cd)
							if err == nil && now.Sub(t).Hours() > 24*90 {
								stale = true
								reason = "Password never used, account older than 90 days"
							}
						}
					}

					if stale {
						tableData = append(tableData, []string{"global", "iam", name, reason})
					}
				}
			}
		}
	}

	// 2. Regional
	entries, _ := os.ReadDir(accDir)
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "global" {
			continue
		}
		region := entry.Name()
		rDir := filepath.Join(accDir, region)

		// EC2 Instances (Stopped)
		if data, err := LoadJSON(filepath.Join(rDir, "ec2", "instances.json")); err == nil {
			if reservations, ok := data["Reservations"].([]interface{}); ok {
				for _, res := range reservations {
					if resM, ok := res.(map[string]interface{}); ok {
						if instances, ok := resM["Instances"].([]interface{}); ok {
							for _, ins := range instances {
								if im, ok := ins.(map[string]interface{}); ok {
									if stateInfo, ok := im["State"].(map[string]interface{}); ok {
										state := stateInfo["Name"].(string)
										if state == "stopped" {
											id := im["InstanceId"].(string)
											tableData = append(tableData, []string{region, "ec2", id, "Instance is stopped"})
										}
									}
								}
							}
						}
					}
				}
			}
		}

		// EBS Volumes (Available)
		if data, err := LoadJSON(filepath.Join(rDir, "ec2", "volumes.json")); err == nil {
			if volumes, ok := data["Volumes"].([]interface{}); ok {
				for _, v := range volumes {
					if vm, ok := v.(map[string]interface{}); ok {
						state := vm["State"].(string)
						if state == "available" {
							id := vm["VolumeId"].(string)
							tableData = append(tableData, []string{region, "ec2", id, "Volume is unattached (available)"})
						}
					}
				}
			}
		}

		// Snapshots (Old)
		if data, err := LoadJSON(filepath.Join(rDir, "ec2", "snapshots.json")); err == nil {
			if snapshots, ok := data["Snapshots"].([]interface{}); ok {
				for _, s := range snapshots {
					if sm, ok := s.(map[string]interface{}); ok {
						startTime := sm["StartTime"].(string)
						t, err := time.Parse(time.RFC3339, startTime)
						if err == nil && now.Sub(t).Hours() > 24*180 {
							id := sm["SnapshotId"].(string)
							tableData = append(tableData, []string{region, "ec2", id, fmt.Sprintf("Snapshot older than 180 days (%d days)", int(now.Sub(t).Hours()/24))})
						}
					}
				}
			}
		}
	}

	if len(tableData) > 1 {
		pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
	} else {
		pterm.Success.Println("No stale resources identified.")
	}
}
