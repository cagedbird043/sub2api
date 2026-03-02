-- Upgrade Antigravity accounts: Sonnet 4.5 → 4.6, remove preview Gemini mappings
--
-- Background:
-- 1. Antigravity no longer supports Claude Sonnet 4.5 (all variants).
--    All Sonnet 4.5 requests should be routed to claude-sonnet-4-6.
-- 2. Antigravity does not expose preview Gemini models (gemini-3-*-preview).
--    These entries are removed to prevent routing to non-existent targets.
--
-- Strategy:
-- Overwrite the entire model_mapping with the current DefaultAntigravityModelMapping
-- to ensure full consistency with constants.go.

-- +goose Up
-- +goose StatementBegin
UPDATE accounts
SET credentials = jsonb_set(
    credentials,
    '{model_mapping}',
    '{
        "claude-opus-4-6-thinking":   "claude-opus-4-6-thinking",
        "claude-opus-4-6":            "claude-opus-4-6-thinking",
        "claude-opus-4-5-thinking":   "claude-opus-4-6-thinking",
        "claude-opus-4-5-20251101":   "claude-opus-4-6-thinking",
        "claude-sonnet-4-6":          "claude-sonnet-4-6",
        "claude-sonnet-4-5":          "claude-sonnet-4-6",
        "claude-sonnet-4-5-thinking": "claude-sonnet-4-6",
        "claude-sonnet-4-5-20250929": "claude-sonnet-4-6",
        "claude-haiku-4-5":           "claude-sonnet-4-6",
        "claude-haiku-4-5-20251001":  "claude-sonnet-4-6",
        "gemini-2.5-flash":           "gemini-2.5-flash",
        "gemini-2.5-flash-lite":      "gemini-2.5-flash-lite",
        "gemini-2.5-flash-thinking":  "gemini-2.5-flash-thinking",
        "gemini-2.5-pro":             "gemini-2.5-pro",
        "gemini-3-flash":             "gemini-3-flash",
        "gemini-3-pro-high":          "gemini-3.1-pro-high",
        "gemini-3-pro-low":           "gemini-3.1-pro-low",
        "gemini-3-pro-image":         "gemini-3-pro-image",
        "gemini-3.1-pro-high":        "gemini-3.1-pro-high",
        "gemini-3.1-pro-low":         "gemini-3.1-pro-low",
        "gpt-oss-120b-medium":        "gpt-oss-120b-medium",
        "tab_flash_lite_preview":     "tab_flash_lite_preview"
    }'::jsonb
)
WHERE platform = 'antigravity'
  AND deleted_at IS NULL
  AND credentials->'model_mapping' IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Restore previous mapping (Sonnet 4.5 targets, with preview Gemini entries)
UPDATE accounts
SET credentials = jsonb_set(
    credentials,
    '{model_mapping}',
    '{
        "claude-opus-4-6-thinking":   "claude-opus-4-6-thinking",
        "claude-opus-4-6":            "claude-opus-4-6-thinking",
        "claude-opus-4-5-thinking":   "claude-opus-4-6-thinking",
        "claude-opus-4-5-20251101":   "claude-opus-4-6-thinking",
        "claude-sonnet-4-5":          "claude-sonnet-4-5",
        "claude-sonnet-4-5-thinking": "claude-sonnet-4-5-thinking",
        "claude-sonnet-4-5-20250929": "claude-sonnet-4-5",
        "claude-haiku-4-5":           "claude-sonnet-4-5",
        "claude-haiku-4-5-20251001":  "claude-sonnet-4-5",
        "gemini-2.5-flash":           "gemini-2.5-flash",
        "gemini-2.5-flash-lite":      "gemini-2.5-flash-lite",
        "gemini-2.5-flash-thinking":  "gemini-2.5-flash-thinking",
        "gemini-2.5-pro":             "gemini-2.5-pro",
        "gemini-3-flash":             "gemini-3-flash",
        "gemini-3-pro-high":          "gemini-3-pro-high",
        "gemini-3-pro-low":           "gemini-3-pro-low",
        "gemini-3-pro-image":         "gemini-3-pro-image",
        "gemini-3-flash-preview":     "gemini-3-flash",
        "gemini-3-pro-preview":       "gemini-3-pro-high",
        "gemini-3-pro-image-preview": "gemini-3-pro-image",
        "gpt-oss-120b-medium":        "gpt-oss-120b-medium",
        "tab_flash_lite_preview":     "tab_flash_lite_preview"
    }'::jsonb
)
WHERE platform = 'antigravity'
  AND deleted_at IS NULL
  AND credentials->'model_mapping' IS NOT NULL;
-- +goose StatementEnd
