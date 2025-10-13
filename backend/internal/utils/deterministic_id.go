package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// GenerateDeterministicNodeID generates a deterministic UUID-like string
// based on cluster ID and node name
func GenerateDeterministicNodeID(clusterID, nodeName string) string {
	// Create a deterministic hash from cluster ID and node name
	data := fmt.Sprintf("cluster:%s:node:%s", clusterID, strings.ToLower(nodeName))
	hash := sha256.Sum256([]byte(data))
	
	// Format as UUID v5-like string (deterministic namespace-based)
	// xxxxxxxx-xxxx-5xxx-xxxx-xxxxxxxxxxxx where 5 indicates v5 (SHA-1 namespace)
	// We use SHA-256 but format similarly for compatibility
	hashStr := hex.EncodeToString(hash[:])
	
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hashStr[0:8],   // time_low
		hashStr[8:12],   // time_mid
		"5" + hashStr[13:16], // time_hi_and_version (5 for deterministic)
		hashStr[16:20],  // clock_seq_hi_and_reserved + clock_seq_low
		hashStr[20:32],  // node
	)
}
