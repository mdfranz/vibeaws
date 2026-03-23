package discovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aws/smithy-go"
)

func EnsureDir(path string) error {
	dir := filepath.Dir(path)
	return os.MkdirAll(dir, 0755)
}

func SafeCall[T any](fn func() (T, error)) (T, error) {
	resp, err := fn()
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) {
			code := ae.ErrorCode()
			// Benign errors we want to ignore and just return empty/nil
			switch code {
			case "AccessDenied", "UnauthorizedOperation", "AccessDeniedException", "404", "NoSuchKey", "UnrecognizedClientException", "InvalidAccessException", "NotSignedUp":
				var zero T
				return zero, nil
			}
		}
		var zero T
		return zero, err
	}
	return resp, nil
}

func WriteJSON(accountDir, region, service, filename string, data interface{}) error {
	path := filepath.Join(accountDir, region, service, filename)
	if err := EnsureDir(path); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	// Go's default JSON marshaller handles time.Time by RFC3339, which is a string.
	// This should be compatible enough with Python's default=str.
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	return nil
}
