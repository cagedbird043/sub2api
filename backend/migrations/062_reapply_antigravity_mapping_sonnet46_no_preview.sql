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
