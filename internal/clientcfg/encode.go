package clientcfg

import (
	"encoding/base64"
	"strings"
)

const uriScheme = "slipnet://"

// Encode takes fields and produces a slipnet:// URI.
// Uses standard base64 (not URL-safe) with no padding wrapping, matching the app.
func Encode(fields []string) string {
	payload := strings.Join(fields, "|")
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))
	return uriScheme + encoded
}

// Decode parses a slipnet:// URI back into fields.
func Decode(uri string) ([TotalFields]string, error) {
	var fields [TotalFields]string

	encoded := strings.TrimPrefix(uri, uriScheme)
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Try URL-safe encoding as fallback
		data, err = base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			return fields, err
		}
	}

	parts := strings.Split(string(data), "|")
	for i := 0; i < len(parts) && i < TotalFields; i++ {
		fields[i] = parts[i]
	}

	return fields, nil
}
