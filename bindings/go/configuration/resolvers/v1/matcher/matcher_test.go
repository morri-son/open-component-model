package matcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolverMatcher(t *testing.T) {
	tests := []struct {
		name          string
		pattern       string
		componentName string
		shouldMatch   bool
		expectError   bool
	}{
		{
			name:          "glob pattern with wildcard",
			pattern:       "ocm.software/core/*",
			componentName: "ocm.software/core/test",
			shouldMatch:   true,
		},
		{
			name:          "glob pattern no match",
			pattern:       "ocm.software/core/*",
			componentName: "ocm.software/other/test",
			shouldMatch:   false,
		},
		{
			name:          "glob pattern with question mark",
			pattern:       "ocm.software/core/?est",
			componentName: "ocm.software/core/test",
			shouldMatch:   true,
		},
		{
			name:          "glob pattern with character class",
			pattern:       "ocm.software/core/[tc]est",
			componentName: "ocm.software/core/test",
			shouldMatch:   true,
		},
		{
			name:          "exact match",
			pattern:       "ocm.software/core/test",
			componentName: "ocm.software/core/test",
			shouldMatch:   true,
		},
		{
			name:          "exact no match",
			pattern:       "ocm.software/core/test",
			componentName: "ocm.software/core/other",
			shouldMatch:   false,
		},
		{
			name:          "glob pattern with multiple wildcards",
			pattern:       "*.software/*/test",
			componentName: "ocm.software/core/test",
			shouldMatch:   true,
		},
		{
			name:          "path pattern with wildcard",
			pattern:       "ocm.software/core/*",
			componentName: "ocm.software/core/test",
			shouldMatch:   true,
		},
		{
			name:          "path pattern no match",
			pattern:       "ocm.software/core/*",
			componentName: "ocm.software/other/test",
			shouldMatch:   false,
		},
		{
			name:          "path pattern with question mark",
			pattern:       "ocm.software/core/?est",
			componentName: "ocm.software/core/test",
			shouldMatch:   true,
		},
		{
			name:          "path pattern with character class",
			pattern:       "ocm.software/core/[tc]est",
			componentName: "ocm.software/core/test",
			shouldMatch:   true,
		},
		{
			name:          "path exact match",
			pattern:       "ocm.software/core/test",
			componentName: "ocm.software/core/test",
			shouldMatch:   true,
		},
		{
			name:          "path exact no match",
			pattern:       "ocm.software/core/test",
			componentName: "ocm.software/core/other",
			shouldMatch:   false,
		},
		{
			name:          "path pattern with multiple wildcards",
			pattern:       "*/software/*/test",
			componentName: "ocm/software/core/test",
			shouldMatch:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolverMatcher, err := NewResolverMatcher(tt.pattern)
			if tt.expectError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.shouldMatch, resolverMatcher.Match(tt.componentName, ""))
			assert.Equal(t, tt.shouldMatch, resolverMatcher.MatchComponent(tt.componentName))
		})
	}
}
