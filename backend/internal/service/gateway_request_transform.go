package service

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/gin-gonic/gin"
)

func (s *GatewayService) replaceModelInBody(body []byte, newModel string) []byte {
	var req map[string]json.RawMessage
	if err := json.Unmarshal(body, &req); err != nil {
		return body
	}
	// 只序列化 model 字段
	modelBytes, err := json.Marshal(newModel)
	if err != nil {
		return body
	}
	req["model"] = modelBytes
	newBody, err := json.Marshal(req)
	if err != nil {
		return body
	}
	return newBody
}

type claudeOAuthNormalizeOptions struct {
	injectMetadata          bool
	metadataUserID          string
	stripSystemCacheControl bool
}

// sanitizeSystemText rewrites only the fixed OpenCode identity sentence (if present).
// We intentionally avoid broad keyword replacement in system prompts to prevent
// accidentally changing user-provided instructions.
func sanitizeSystemText(text string) string {
	if text == "" {
		return text
	}
	// Some clients include a fixed OpenCode identity sentence. Anthropic may treat
	// this as a non-Claude-Code fingerprint, so rewrite it to the canonical
	// Claude Code banner before generic "OpenCode"/"opencode" replacements.
	text = strings.ReplaceAll(
		text,
		"You are OpenCode, the best coding agent on the planet.",
		strings.TrimSpace(claudeCodeSystemPrompt),
	)
	return text
}

func stripCacheControlFromSystemBlocks(system any) bool {
	blocks, ok := system.([]any)
	if !ok {
		return false
	}
	changed := false
	for _, item := range blocks {
		block, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if _, exists := block["cache_control"]; !exists {
			continue
		}
		delete(block, "cache_control")
		changed = true
	}
	return changed
}

func normalizeClaudeOAuthRequestBody(body []byte, modelID string, opts claudeOAuthNormalizeOptions) ([]byte, string) {
	if len(body) == 0 {
		return body, modelID
	}

	// 解析为 map[string]any 用于修改字段
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return body, modelID
	}

	modified := false

	if system, ok := req["system"]; ok {
		switch v := system.(type) {
		case string:
			sanitized := sanitizeSystemText(v)
			if sanitized != v {
				req["system"] = sanitized
				modified = true
			}
		case []any:
			for _, item := range v {
				block, ok := item.(map[string]any)
				if !ok {
					continue
				}
				if blockType, _ := block["type"].(string); blockType != "text" {
					continue
				}
				text, ok := block["text"].(string)
				if !ok || text == "" {
					continue
				}
				sanitized := sanitizeSystemText(text)
				if sanitized != text {
					block["text"] = sanitized
					modified = true
				}
			}
		}
	}

	if rawModel, ok := req["model"].(string); ok {
		normalized := claude.NormalizeModelID(rawModel)
		if normalized != rawModel {
			req["model"] = normalized
			modelID = normalized
			modified = true
		}
	}

	// 确保 tools 字段存在（即使为空数组）
	if _, exists := req["tools"]; !exists {
		req["tools"] = []any{}
		modified = true
	}

	if opts.stripSystemCacheControl {
		if system, ok := req["system"]; ok {
			_ = stripCacheControlFromSystemBlocks(system)
			modified = true
		}
	}

	if opts.injectMetadata && opts.metadataUserID != "" {
		metadata, ok := req["metadata"].(map[string]any)
		if !ok {
			metadata = map[string]any{}
			req["metadata"] = metadata
		}
		if existing, ok := metadata["user_id"].(string); !ok || existing == "" {
			metadata["user_id"] = opts.metadataUserID
			modified = true
		}
	}

	if _, hasTemp := req["temperature"]; hasTemp {
		delete(req, "temperature")
		modified = true
	}
	if _, hasChoice := req["tool_choice"]; hasChoice {
		delete(req, "tool_choice")
		modified = true
	}

	if !modified {
		return body, modelID
	}

	newBody, err := json.Marshal(req)
	if err != nil {
		return body, modelID
	}
	return newBody, modelID
}

func (s *GatewayService) buildOAuthMetadataUserID(parsed *ParsedRequest, account *Account, fp *Fingerprint) string {
	if parsed == nil || account == nil {
		return ""
	}
	if parsed.MetadataUserID != "" {
		return ""
	}

	userID := strings.TrimSpace(account.GetClaudeUserID())
	if userID == "" && fp != nil {
		userID = fp.ClientID
	}
	if userID == "" {
		// Fall back to a random, well-formed client id so we can still satisfy
		// Claude Code OAuth requirements when account metadata is incomplete.
		userID = generateClientID()
	}

	sessionHash := s.GenerateSessionHash(parsed)
	sessionID := uuid.NewString()
	if sessionHash != "" {
		seed := fmt.Sprintf("%d::%s", account.ID, sessionHash)
		sessionID = generateSessionUUID(seed)
	}

	// Prefer the newer format that includes account_uuid (if present),
	// otherwise fall back to the legacy Claude Code format.
	accountUUID := strings.TrimSpace(account.GetExtraString("account_uuid"))
	if accountUUID != "" {
		return fmt.Sprintf("user_%s_account_%s_session_%s", userID, accountUUID, sessionID)
	}
	return fmt.Sprintf("user_%s_account__session_%s", userID, sessionID)
}

func generateSessionUUID(seed string) string {
	if seed == "" {
		return uuid.NewString()
	}
	hash := sha256.Sum256([]byte(seed))
	bytes := hash[:16]
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16])
}

// SelectAccount 选择账号（粘性会话+优先级）
func isClaudeCodeClient(userAgent string, metadataUserID string) bool {
	if metadataUserID == "" {
		return false
	}
	return claudeCliUserAgentRe.MatchString(userAgent)
}

func isClaudeCodeRequest(ctx context.Context, c *gin.Context, parsed *ParsedRequest) bool {
	if IsClaudeCodeClient(ctx) {
		return true
	}
	if parsed == nil || c == nil {
		return false
	}
	return isClaudeCodeClient(c.GetHeader("User-Agent"), parsed.MetadataUserID)
}

// systemIncludesClaudeCodePrompt 检查 system 中是否已包含 Claude Code 提示词
// 使用前缀匹配支持多种变体（标准版、Agent SDK 版等）
func systemIncludesClaudeCodePrompt(system any) bool {
	switch v := system.(type) {
	case string:
		return hasClaudeCodePrefix(v)
	case []any:
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				if text, ok := m["text"].(string); ok && hasClaudeCodePrefix(text) {
					return true
				}
			}
		}
	}
	return false
}

// hasClaudeCodePrefix 检查文本是否以 Claude Code 提示词的特征前缀开头
func hasClaudeCodePrefix(text string) bool {
	for _, prefix := range claudeCodePromptPrefixes {
		if strings.HasPrefix(text, prefix) {
			return true
		}
	}
	return false
}

// matchesFilterPrefix 检查文本是否匹配任一过滤前缀
func matchesFilterPrefix(text string) bool {
	for _, prefix := range systemBlockFilterPrefixes {
		if strings.HasPrefix(text, prefix) {
			return true
		}
	}
	return false
}

// filterSystemBlocksByPrefix 从 body 的 system 中移除文本匹配 systemBlockFilterPrefixes 前缀的元素
// 直接从 body 解析 system，不依赖外部传入的 parsed.System（因为前置步骤可能已修改 body 中的 system）
func filterSystemBlocksByPrefix(body []byte) []byte {
	sys := gjson.GetBytes(body, "system")
	if !sys.Exists() {
		return body
	}

	switch {
	case sys.Type == gjson.String:
		if matchesFilterPrefix(sys.Str) {
			result, err := sjson.DeleteBytes(body, "system")
			if err != nil {
				return body
			}
			return result
		}
	case sys.IsArray():
		var parsed []any
		if err := json.Unmarshal([]byte(sys.Raw), &parsed); err != nil {
			return body
		}
		filtered := make([]any, 0, len(parsed))
		changed := false
		for _, item := range parsed {
			if m, ok := item.(map[string]any); ok {
				if text, ok := m["text"].(string); ok && matchesFilterPrefix(text) {
					changed = true
					continue
				}
			}
			filtered = append(filtered, item)
		}
		if changed {
			result, err := sjson.SetBytes(body, "system", filtered)
			if err != nil {
				return body
			}
			return result
		}
	}
	return body
}

// injectClaudeCodePrompt 在 system 开头注入 Claude Code 提示词
// 处理 null、字符串、数组三种格式
func injectClaudeCodePrompt(body []byte, system any) []byte {
	claudeCodeBlock := map[string]any{
		"type":          "text",
		"text":          claudeCodeSystemPrompt,
		"cache_control": map[string]string{"type": "ephemeral"},
	}
	// Opencode plugin applies an extra safeguard: it not only prepends the Claude Code
	// banner, it also prefixes the next system instruction with the same banner plus
	// a blank line. This helps when upstream concatenates system instructions.
	claudeCodePrefix := strings.TrimSpace(claudeCodeSystemPrompt)

	var newSystem []any

	switch v := system.(type) {
	case nil:
		newSystem = []any{claudeCodeBlock}
	case string:
		// Be tolerant of older/newer clients that may differ only by trailing whitespace/newlines.
		if strings.TrimSpace(v) == "" || strings.TrimSpace(v) == strings.TrimSpace(claudeCodeSystemPrompt) {
			newSystem = []any{claudeCodeBlock}
		} else {
			// Mirror opencode behavior: keep the banner as a separate system entry,
			// but also prefix the next system text with the banner.
			merged := v
			if !strings.HasPrefix(v, claudeCodePrefix) {
				merged = claudeCodePrefix + "\n\n" + v
			}
			newSystem = []any{claudeCodeBlock, map[string]any{"type": "text", "text": merged}}
		}
	case []any:
		newSystem = make([]any, 0, len(v)+1)
		newSystem = append(newSystem, claudeCodeBlock)
		prefixedNext := false
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				if text, ok := m["text"].(string); ok && strings.TrimSpace(text) == strings.TrimSpace(claudeCodeSystemPrompt) {
					continue
				}
				// Prefix the first subsequent text system block once.
				if !prefixedNext {
					if blockType, _ := m["type"].(string); blockType == "text" {
						if text, ok := m["text"].(string); ok && strings.TrimSpace(text) != "" && !strings.HasPrefix(text, claudeCodePrefix) {
							m["text"] = claudeCodePrefix + "\n\n" + text
							prefixedNext = true
						}
					}
				}
			}
			newSystem = append(newSystem, item)
		}
	default:
		newSystem = []any{claudeCodeBlock}
	}

	result, err := sjson.SetBytes(body, "system", newSystem)
	if err != nil {
		log.Printf("Warning: failed to inject Claude Code prompt: %v", err)
		return body
	}
	return result
}

// enforceCacheControlLimit 强制执行 cache_control 块数量限制（最多 4 个）
// 超限时优先从 messages 中移除 cache_control，保护 system 中的缓存控制
func enforceCacheControlLimit(body []byte) []byte {
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return body
	}

	// 清理 thinking 块中的非法 cache_control（thinking 块不支持该字段）
	removeCacheControlFromThinkingBlocks(data)

	// 计算当前 cache_control 块数量
	count := countCacheControlBlocks(data)
	if count <= maxCacheControlBlocks {
		return body
	}

	// 超限：优先从 messages 中移除，再从 system 中移除
	for count > maxCacheControlBlocks {
		if removeCacheControlFromMessages(data) {
			count--
			continue
		}
		if removeCacheControlFromSystem(data) {
			count--
			continue
		}
		break
	}

	result, err := json.Marshal(data)
	if err != nil {
		return body
	}
	return result
}

// countCacheControlBlocks 统计 system 和 messages 中的 cache_control 块数量
// 注意：thinking 块不支持 cache_control，统计时跳过
func countCacheControlBlocks(data map[string]any) int {
	count := 0

	// 统计 system 中的块
	if system, ok := data["system"].([]any); ok {
		for _, item := range system {
			if m, ok := item.(map[string]any); ok {
				// thinking 块不支持 cache_control，跳过
				if blockType, _ := m["type"].(string); blockType == "thinking" {
					continue
				}
				if _, has := m["cache_control"]; has {
					count++
				}
			}
		}
	}

	// 统计 messages 中的块
	if messages, ok := data["messages"].([]any); ok {
		for _, msg := range messages {
			if msgMap, ok := msg.(map[string]any); ok {
				if content, ok := msgMap["content"].([]any); ok {
					for _, item := range content {
						if m, ok := item.(map[string]any); ok {
							// thinking 块不支持 cache_control，跳过
							if blockType, _ := m["type"].(string); blockType == "thinking" {
								continue
							}
							if _, has := m["cache_control"]; has {
								count++
							}
						}
					}
				}
			}
		}
	}

	return count
}

// removeCacheControlFromMessages 从 messages 中移除一个 cache_control（从头开始）
// 返回 true 表示成功移除，false 表示没有可移除的
// 注意：跳过 thinking 块（它不支持 cache_control）
func removeCacheControlFromMessages(data map[string]any) bool {
	messages, ok := data["messages"].([]any)
	if !ok {
		return false
	}

	for _, msg := range messages {
		msgMap, ok := msg.(map[string]any)
		if !ok {
			continue
		}
		content, ok := msgMap["content"].([]any)
		if !ok {
			continue
		}
		for _, item := range content {
			if m, ok := item.(map[string]any); ok {
				// thinking 块不支持 cache_control，跳过
				if blockType, _ := m["type"].(string); blockType == "thinking" {
					continue
				}
				if _, has := m["cache_control"]; has {
					delete(m, "cache_control")
					return true
				}
			}
		}
	}
	return false
}

// removeCacheControlFromSystem 从 system 中移除一个 cache_control（从尾部开始，保护注入的 prompt）
// 返回 true 表示成功移除，false 表示没有可移除的
// 注意：跳过 thinking 块（它不支持 cache_control）
func removeCacheControlFromSystem(data map[string]any) bool {
	system, ok := data["system"].([]any)
	if !ok {
		return false
	}

	// 从尾部开始移除，保护开头注入的 Claude Code prompt
	for i := len(system) - 1; i >= 0; i-- {
		if m, ok := system[i].(map[string]any); ok {
			// thinking 块不支持 cache_control，跳过
			if blockType, _ := m["type"].(string); blockType == "thinking" {
				continue
			}
			if _, has := m["cache_control"]; has {
				delete(m, "cache_control")
				return true
			}
		}
	}
	return false
}

// removeCacheControlFromThinkingBlocks 强制清理所有 thinking 块中的非法 cache_control
// thinking 块不支持 cache_control 字段，这个函数确保所有 thinking 块都不含该字段
func removeCacheControlFromThinkingBlocks(data map[string]any) {
	// 清理 system 中的 thinking 块
	if system, ok := data["system"].([]any); ok {
		for _, item := range system {
			if m, ok := item.(map[string]any); ok {
				if blockType, _ := m["type"].(string); blockType == "thinking" {
					if _, has := m["cache_control"]; has {
						delete(m, "cache_control")
						log.Printf("[Warning] Removed illegal cache_control from thinking block in system")
					}
				}
			}
		}
	}

	// 清理 messages 中的 thinking 块
	if messages, ok := data["messages"].([]any); ok {
		for msgIdx, msg := range messages {
			if msgMap, ok := msg.(map[string]any); ok {
				if content, ok := msgMap["content"].([]any); ok {
					for contentIdx, item := range content {
						if m, ok := item.(map[string]any); ok {
							if blockType, _ := m["type"].(string); blockType == "thinking" {
								if _, has := m["cache_control"]; has {
									delete(m, "cache_control")
									log.Printf("[Warning] Removed illegal cache_control from thinking block in messages[%d].content[%d]", msgIdx, contentIdx)
								}
							}
						}
					}
				}
			}
		}
	}
}

// Forward 转发请求到Claude API
