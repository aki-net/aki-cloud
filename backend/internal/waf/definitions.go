package waf

import "aki-cloud/backend/internal/models"

// Definition describes a built-in WAF preset or rule.
type Definition struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

var builtinDefinitions = []Definition{
	{
		Key:         string(models.WAFPresetAllowGooglebotOnly),
		Name:        "Allow Only Verified Googlebot",
		Category:    "Traffic Allow Lists",
		Type:        "preset",
		Description: "Blocks all requests except those originating from verified Googlebot addresses using reverse DNS validation with forward confirmation.",
	},
}

// Definitions returns a copy of the built-in WAF definitions.
func Definitions() []Definition {
	out := make([]Definition, len(builtinDefinitions))
	copy(out, builtinDefinitions)
	return out
}
