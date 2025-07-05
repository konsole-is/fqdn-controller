package utils

import (
	"encoding/json"
	"fmt"
)

// PrettyForPrint returns an indented string version of any Go struct or value.
func PrettyForPrint(v interface{}) string {
	bytes, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("PrettyPrint error: %v", err)
	}
	return string(bytes)
}
