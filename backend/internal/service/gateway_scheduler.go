package service

// BaseGatewayScheduler 持有 OpenAI 与 Gemini 调度器共用的 priority+LRU 比较逻辑。
// 设计为零依赖值类型，直接嵌入到各 gateway service struct 中使用。
type BaseGatewayScheduler struct{}

// comparePriorityAndLRU 比较两个账号的优先级与最后使用时间。
// 返回 (better bool, tieNilNil bool)：
//   - better=true 表示 candidate 优于 current
//   - tieNilNil=true 表示优先级相同且两者都从未使用（由调用方处理 tie-breaker）
func (BaseGatewayScheduler) comparePriorityAndLRU(candidate, current *Account) (better, tieNilNil bool) {
	if candidate.Priority < current.Priority {
		return true, false
	}
	if candidate.Priority > current.Priority {
		return false, false
	}

	switch {
	case candidate.LastUsedAt == nil && current.LastUsedAt != nil:
		return true, false
	case candidate.LastUsedAt != nil && current.LastUsedAt == nil:
		return false, false
	case candidate.LastUsedAt == nil && current.LastUsedAt == nil:
		return false, true // 由调用方决定 tie-breaker
	default:
		return candidate.LastUsedAt.Before(*current.LastUsedAt), false
	}
}
