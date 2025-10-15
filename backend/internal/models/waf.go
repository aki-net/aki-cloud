package models

import (
	"sort"
	"strings"
)

// DomainWAFPreset describes a built-in WAF preset key.
type DomainWAFPreset string

const (
	// WAFPresetAllowGooglebotOnly allows only verified Googlebot traffic.
	WAFPresetAllowGooglebotOnly DomainWAFPreset = "allow_googlebot_only"
)

var validDomainWAFPresets = map[DomainWAFPreset]struct{}{
	WAFPresetAllowGooglebotOnly: {},
}

// DomainWAF captures per-domain WAF configuration.
type DomainWAF struct {
	Enabled bool              `json:"enabled"`
	Presets []DomainWAFPreset `json:"presets,omitempty"`
}

// Normalize trims and deduplicates preset keys and ensures deterministic ordering.
func (w *DomainWAF) Normalize() {
	if w == nil {
		return
	}
	if w.Presets == nil {
		w.Presets = make([]DomainWAFPreset, 0)
	}
	if len(w.Presets) == 0 {
		w.Enabled = false
		return
	}
	seen := make(map[DomainWAFPreset]struct{}, len(w.Presets))
	out := make([]DomainWAFPreset, 0, len(w.Presets))
	for _, preset := range w.Presets {
		key := DomainWAFPreset(strings.TrimSpace(strings.ToLower(string(preset))))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	if len(out) == 0 {
		w.Enabled = false
		w.Presets = make([]DomainWAFPreset, 0)
		return
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i] < out[j]
	})
	w.Presets = out
}

// Validate ensures the WAF configuration uses supported presets.
func (w *DomainWAF) Validate() error {
	if w == nil {
		return nil
	}
	for _, preset := range w.Presets {
		if _, ok := validDomainWAFPresets[preset]; !ok {
			return ErrValidation("invalid waf preset: " + string(preset))
		}
	}
	if w.Enabled && len(w.Presets) == 0 {
		return ErrValidation("waf enabled without presets")
	}
	return nil
}

// HasPreset reports whether the preset is active on this domain.
func (w DomainWAF) HasPreset(target DomainWAFPreset) bool {
	for _, preset := range w.Presets {
		if preset == target {
			return true
		}
	}
	return false
}

// IsActive reports whether the WAF should be enforced.
func (w DomainWAF) IsActive() bool {
	return w.Enabled && len(w.Presets) > 0
}
