package models

// ExtensionsState wraps extension configuration with version metadata for synchronization.
type ExtensionsState struct {
	Config  ExtensionsConfig `json:"config"`
	Version ClockVersion     `json:"version"`
}
