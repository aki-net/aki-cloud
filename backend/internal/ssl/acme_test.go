package ssl

import (
	"reflect"
	"testing"
)

func TestUniqueDomains(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "apex",
			input: "Example.com",
			want:  []string{"example.com", "*.example.com"},
		},
		{
			name:  "trimmed",
			input: " foo.bar ",
			want:  []string{"foo.bar", "*.foo.bar"},
		},
		{
			name:  "wildcard input",
			input: "*.foo.com",
			want:  []string{"*.foo.com"},
		},
		{
			name:  "empty",
			input: "",
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uniqueDomains(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("uniqueDomains(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
