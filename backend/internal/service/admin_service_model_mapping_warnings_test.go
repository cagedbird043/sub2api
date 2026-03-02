//go:build unit

package service

import (
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestBuildDeprecatedWarnings_TargetBasedDetection(t *testing.T) {
	t.Run("source old but target latest should not warn", func(t *testing.T) {
		warnings := buildDeprecatedWarnings(PlatformAntigravity, map[string]string{
			"claude-sonnet-4-5": "claude-sonnet-4-6",
		})

		require.Empty(t, warnings)
	})

	t.Run("deprecated target should warn with replacement", func(t *testing.T) {
		warnings := buildDeprecatedWarnings(PlatformAntigravity, map[string]string{
			"custom-model": "claude-sonnet-4-5",
		})

		require.Len(t, warnings, 1)
		require.Equal(t, "custom-model", warnings[0].From)
		require.Equal(t, "claude-sonnet-4-5", warnings[0].To)
		require.Equal(t, "claude-sonnet-4-5", warnings[0].DeprecatedModel)
		require.Equal(t, "claude-sonnet-4-6", warnings[0].SuggestedModel)
		require.NotEmpty(t, warnings[0].Reason)
	})

	t.Run("non-antigravity platform should not warn", func(t *testing.T) {
		warnings := buildDeprecatedWarnings(PlatformAnthropic, map[string]string{
			"custom-model": "claude-sonnet-4-5",
		})

		require.Empty(t, warnings)
	})

	t.Run("platform default mapping should not warn", func(t *testing.T) {
		warnings := buildDeprecatedWarnings(PlatformAntigravity, domain.DefaultAntigravityModelMapping)

		require.Empty(t, warnings)
	})
}
