package discovery

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/pterm/pterm"
)

type TrailConfig struct {
	Bucket string
	Prefix string
}

func GetTrailConfig(ctx context.Context, cfg aws.Config, verbose bool) (*TrailConfig, error) {
	// Need to query cloudtrail in us-east-1 (or current region)
	ctClient := cloudtrail.NewFromConfig(cfg)
	resp, err := ctClient.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil || len(resp.TrailList) == 0 {
		return nil, fmt.Errorf("no trails found or failed to describe: %v", err)
	}

	trail := resp.TrailList[0]
	if verbose {
		pterm.Info.Printf("Using Trail: %s (S3: %s)\n", *trail.Name, *trail.S3BucketName)
	}

	prefix := ""
	if trail.S3KeyPrefix != nil {
		prefix = *trail.S3KeyPrefix
	}

	return &TrailConfig{
		Bucket: *trail.S3BucketName,
		Prefix: prefix,
	}, nil
}

func DownloadTrailSamples(ctx context.Context, cfg aws.Config, accountID, accountDir, region, bucket, prefix string, days int, verbose bool) ([]string, error) {
	s3Client := s3.NewFromConfig(cfg)
	var downloadedPaths []string
	now := time.Now().UTC()

	cacheDir := filepath.Join(accountDir, region, "cache", "cloudtrail")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, err
	}

	for i := 0; i < days; i++ {
		dt := now.AddDate(0, 0, -i)
		dayPrefix := fmt.Sprintf("%s/AWSLogs/%s/CloudTrail/%s/%d/%02d/%02d/",
			prefix, accountID, region, dt.Year(), dt.Month(), dt.Day())
		
		// If prefix is empty, we might have double slashes
		dayPrefix = filepath.Clean(dayPrefix)
		if strings.HasPrefix(dayPrefix, "/") {
			dayPrefix = dayPrefix[1:]
		}

		resp, err := s3Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(bucket),
			Prefix: aws.String(dayPrefix),
			MaxKeys: aws.Int32(5),
		})

		if err != nil || len(resp.Contents) == 0 {
			continue
		}

		obj := resp.Contents[0]
		key := *obj.Key
		fname := filepath.Base(key)
		localPath := filepath.Join(cacheDir, fname)

		if _, err := os.Stat(localPath); os.IsNotExist(err) {
			if verbose {
				pterm.Info.Printf("  Downloading sample for %s...\n", dt.Format("2006-01-02"))
			}
			
			getObjResp, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
				Bucket: aws.String(bucket),
				Key:    aws.String(key),
			})
			if err != nil {
				continue
			}

			f, err := os.Create(localPath)
			if err != nil {
				getObjResp.Body.Close()
				continue
			}
			_, err = io.Copy(f, getObjResp.Body)
			f.Close()
			getObjResp.Body.Close()
			if err != nil {
				continue
			}
		}

		downloadedPaths = append(downloadedPaths, localPath)
	}

	return downloadedPaths, nil
}

func ParseTrailEvents(paths []string) ([]map[string]interface{}, error) {
	var events []map[string]interface{}
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			continue
		}

		var data struct {
			Records []map[string]interface{} `json:"Records"`
		}
		if err := json.NewDecoder(gz).Decode(&data); err == nil {
			events = append(events, data.Records...)
		}
		
		gz.Close()
		f.Close()
	}
	return events, nil
}
