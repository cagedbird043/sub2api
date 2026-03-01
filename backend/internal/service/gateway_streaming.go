package service

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/util/responseheaders"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

func (s *GatewayService) handleStreamingResponse(ctx context.Context, resp *http.Response, c *gin.Context, account *Account, startTime time.Time, originalModel, mappedModel string, mimicClaudeCode bool) (*streamingResult, error) {
	// 更新5h窗口状态
	s.rateLimitService.UpdateSessionWindow(ctx, account, resp.Header)

	if s.cfg != nil {
		responseheaders.WriteFilteredHeaders(c.Writer.Header(), resp.Header, s.cfg.Security.ResponseHeaders)
	}

	// 设置SSE响应头
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	// 透传其他响应头
	if v := resp.Header.Get("x-request-id"); v != "" {
		c.Header("x-request-id", v)
	}

	w := c.Writer
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, errors.New("streaming not supported")
	}

	usage := &ClaudeUsage{}
	var firstTokenMs *int
	scanner := bufio.NewScanner(resp.Body)
	// 设置更大的buffer以处理长行
	maxLineSize := defaultMaxLineSize
	if s.cfg != nil && s.cfg.Gateway.MaxLineSize > 0 {
		maxLineSize = s.cfg.Gateway.MaxLineSize
	}
	scanner.Buffer(make([]byte, 64*1024), maxLineSize)

	type scanEvent struct {
		line string
		err  error
	}
	// 独立 goroutine 读取上游，避免读取阻塞导致超时/keepalive无法处理
	events := make(chan scanEvent, 16)
	done := make(chan struct{})
	sendEvent := func(ev scanEvent) bool {
		select {
		case events <- ev:
			return true
		case <-done:
			return false
		}
	}
	var lastReadAt int64
	atomic.StoreInt64(&lastReadAt, time.Now().UnixNano())
	go func() {
		defer close(events)
		for scanner.Scan() {
			atomic.StoreInt64(&lastReadAt, time.Now().UnixNano())
			if !sendEvent(scanEvent{line: scanner.Text()}) {
				return
			}
		}
		if err := scanner.Err(); err != nil {
			_ = sendEvent(scanEvent{err: err})
		}
	}()
	defer close(done)

	streamInterval := time.Duration(0)
	if s.cfg != nil && s.cfg.Gateway.StreamDataIntervalTimeout > 0 {
		streamInterval = time.Duration(s.cfg.Gateway.StreamDataIntervalTimeout) * time.Second
	}
	// 仅监控上游数据间隔超时，避免下游写入阻塞导致误判
	var intervalTicker *time.Ticker
	if streamInterval > 0 {
		intervalTicker = time.NewTicker(streamInterval)
		defer intervalTicker.Stop()
	}
	var intervalCh <-chan time.Time
	if intervalTicker != nil {
		intervalCh = intervalTicker.C
	}

	// 仅发送一次错误事件，避免多次写入导致协议混乱（写失败时尽力通知客户端）
	errorEventSent := false
	sendErrorEvent := func(reason string) {
		if errorEventSent {
			return
		}
		errorEventSent = true
		_, _ = fmt.Fprintf(w, "event: error\ndata: {\"error\":\"%s\"}\n\n", reason)
		flusher.Flush()
	}

	needModelReplace := originalModel != mappedModel
	clientDisconnected := false // 客户端断开标志，断开后继续读取上游以获取完整usage

	pendingEventLines := make([]string, 0, 4)

	processSSEEvent := func(lines []string) ([]string, string, error) {
		if len(lines) == 0 {
			return nil, "", nil
		}

		eventName := ""
		dataLine := ""
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "event:") {
				eventName = strings.TrimSpace(strings.TrimPrefix(trimmed, "event:"))
				continue
			}
			if dataLine == "" && sseDataRe.MatchString(trimmed) {
				dataLine = sseDataRe.ReplaceAllString(trimmed, "")
			}
		}

		if eventName == "error" {
			return nil, dataLine, errors.New("have error in stream")
		}

		if dataLine == "" {
			return []string{strings.Join(lines, "\n") + "\n\n"}, "", nil
		}

		if dataLine == "[DONE]" {
			block := ""
			if eventName != "" {
				block = "event: " + eventName + "\n"
			}
			block += "data: " + dataLine + "\n\n"
			return []string{block}, dataLine, nil
		}

		var event map[string]any
		if err := json.Unmarshal([]byte(dataLine), &event); err != nil {
			// JSON 解析失败，直接透传原始数据
			block := ""
			if eventName != "" {
				block = "event: " + eventName + "\n"
			}
			block += "data: " + dataLine + "\n\n"
			return []string{block}, dataLine, nil
		}

		eventType, _ := event["type"].(string)
		if eventName == "" {
			eventName = eventType
		}

		// 兼容 Kimi cached_tokens → cache_read_input_tokens
		if eventType == "message_start" {
			if msg, ok := event["message"].(map[string]any); ok {
				if u, ok := msg["usage"].(map[string]any); ok {
					reconcileCachedTokens(u)
				}
			}
		}
		if eventType == "message_delta" {
			if u, ok := event["usage"].(map[string]any); ok {
				reconcileCachedTokens(u)
			}
		}

		// Cache TTL Override: 重写 SSE 事件中的 cache_creation 分类
		if account.IsCacheTTLOverrideEnabled() {
			overrideTarget := account.GetCacheTTLOverrideTarget()
			if eventType == "message_start" {
				if msg, ok := event["message"].(map[string]any); ok {
					if u, ok := msg["usage"].(map[string]any); ok {
						rewriteCacheCreationJSON(u, overrideTarget)
					}
				}
			}
			if eventType == "message_delta" {
				if u, ok := event["usage"].(map[string]any); ok {
					rewriteCacheCreationJSON(u, overrideTarget)
				}
			}
		}

		if needModelReplace {
			if msg, ok := event["message"].(map[string]any); ok {
				if model, ok := msg["model"].(string); ok && model == mappedModel {
					msg["model"] = originalModel
				}
			}
		}

		newData, err := json.Marshal(event)
		if err != nil {
			// 序列化失败，直接透传原始数据
			block := ""
			if eventName != "" {
				block = "event: " + eventName + "\n"
			}
			block += "data: " + dataLine + "\n\n"
			return []string{block}, dataLine, nil
		}

		block := ""
		if eventName != "" {
			block = "event: " + eventName + "\n"
		}
		block += "data: " + string(newData) + "\n\n"
		return []string{block}, string(newData), nil
	}

	for {
		select {
		case ev, ok := <-events:
			if !ok {
				// 上游完成，返回结果
				return &streamingResult{usage: usage, firstTokenMs: firstTokenMs, clientDisconnect: clientDisconnected}, nil
			}
			if ev.err != nil {
				// 检测 context 取消（客户端断开会导致 context 取消，进而影响上游读取）
				if errors.Is(ev.err, context.Canceled) || errors.Is(ev.err, context.DeadlineExceeded) {
					log.Printf("Context canceled during streaming, returning collected usage")
					return &streamingResult{usage: usage, firstTokenMs: firstTokenMs, clientDisconnect: true}, nil
				}
				// 客户端已通过写入失败检测到断开，上游也出错了，返回已收集的 usage
				if clientDisconnected {
					log.Printf("Upstream read error after client disconnect: %v, returning collected usage", ev.err)
					return &streamingResult{usage: usage, firstTokenMs: firstTokenMs, clientDisconnect: true}, nil
				}
				// 客户端未断开，正常的错误处理
				if errors.Is(ev.err, bufio.ErrTooLong) {
					log.Printf("SSE line too long: account=%d max_size=%d error=%v", account.ID, maxLineSize, ev.err)
					sendErrorEvent("response_too_large")
					return &streamingResult{usage: usage, firstTokenMs: firstTokenMs}, ev.err
				}
				sendErrorEvent("stream_read_error")
				return &streamingResult{usage: usage, firstTokenMs: firstTokenMs}, fmt.Errorf("stream read error: %w", ev.err)
			}
			line := ev.line
			trimmed := strings.TrimSpace(line)

			if trimmed == "" {
				if len(pendingEventLines) == 0 {
					continue
				}

				outputBlocks, data, err := processSSEEvent(pendingEventLines)
				pendingEventLines = pendingEventLines[:0]
				if err != nil {
					if clientDisconnected {
						return &streamingResult{usage: usage, firstTokenMs: firstTokenMs, clientDisconnect: true}, nil
					}
					return nil, err
				}

				for _, block := range outputBlocks {
					if !clientDisconnected {
						if _, werr := fmt.Fprint(w, block); werr != nil {
							clientDisconnected = true
							log.Printf("Client disconnected during streaming, continuing to drain upstream for billing")
							break
						}
						flusher.Flush()
					}
					if data != "" {
						if firstTokenMs == nil && data != "[DONE]" {
							ms := int(time.Since(startTime).Milliseconds())
							firstTokenMs = &ms
						}
						s.parseSSEUsage(data, usage)
					}
				}
				continue
			}

			pendingEventLines = append(pendingEventLines, line)

		case <-intervalCh:
			lastRead := time.Unix(0, atomic.LoadInt64(&lastReadAt))
			if time.Since(lastRead) < streamInterval {
				continue
			}
			if clientDisconnected {
				// 客户端已断开，上游也超时了，返回已收集的 usage
				log.Printf("Upstream timeout after client disconnect, returning collected usage")
				return &streamingResult{usage: usage, firstTokenMs: firstTokenMs, clientDisconnect: true}, nil
			}
			log.Printf("Stream data interval timeout: account=%d model=%s interval=%s", account.ID, originalModel, streamInterval)
			// 处理流超时，可能标记账户为临时不可调度或错误状态
			if s.rateLimitService != nil {
				s.rateLimitService.HandleStreamTimeout(ctx, account, originalModel)
			}
			sendErrorEvent("stream_timeout")
			return &streamingResult{usage: usage, firstTokenMs: firstTokenMs}, fmt.Errorf("stream data interval timeout")
		}
	}

}

func (s *GatewayService) parseSSEUsage(data string, usage *ClaudeUsage) {
	// 解析message_start获取input tokens（标准Claude API格式）
	var msgStart struct {
		Type    string `json:"type"`
		Message struct {
			Usage ClaudeUsage `json:"usage"`
		} `json:"message"`
	}
	if json.Unmarshal([]byte(data), &msgStart) == nil && msgStart.Type == "message_start" {
		usage.InputTokens = msgStart.Message.Usage.InputTokens
		usage.CacheCreationInputTokens = msgStart.Message.Usage.CacheCreationInputTokens
		usage.CacheReadInputTokens = msgStart.Message.Usage.CacheReadInputTokens

		// 解析嵌套的 cache_creation 对象中的 5m/1h 明细
		cc5m := gjson.Get(data, "message.usage.cache_creation.ephemeral_5m_input_tokens")
		cc1h := gjson.Get(data, "message.usage.cache_creation.ephemeral_1h_input_tokens")
		if cc5m.Exists() || cc1h.Exists() {
			usage.CacheCreation5mTokens = int(cc5m.Int())
			usage.CacheCreation1hTokens = int(cc1h.Int())
		}
	}

	// 解析message_delta获取tokens（兼容GLM等把所有usage放在delta中的API）
	var msgDelta struct {
		Type  string `json:"type"`
		Usage struct {
			InputTokens              int `json:"input_tokens"`
			OutputTokens             int `json:"output_tokens"`
			CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
			CacheReadInputTokens     int `json:"cache_read_input_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal([]byte(data), &msgDelta) == nil && msgDelta.Type == "message_delta" {
		// message_delta 仅覆盖存在且非0的字段
		// 避免覆盖 message_start 中已有的值（如 input_tokens）
		// Claude API 的 message_delta 通常只包含 output_tokens
		if msgDelta.Usage.InputTokens > 0 {
			usage.InputTokens = msgDelta.Usage.InputTokens
		}
		if msgDelta.Usage.OutputTokens > 0 {
			usage.OutputTokens = msgDelta.Usage.OutputTokens
		}
		if msgDelta.Usage.CacheCreationInputTokens > 0 {
			usage.CacheCreationInputTokens = msgDelta.Usage.CacheCreationInputTokens
		}
		if msgDelta.Usage.CacheReadInputTokens > 0 {
			usage.CacheReadInputTokens = msgDelta.Usage.CacheReadInputTokens
		}

		// 解析嵌套的 cache_creation 对象中的 5m/1h 明细
		cc5m := gjson.Get(data, "usage.cache_creation.ephemeral_5m_input_tokens")
		cc1h := gjson.Get(data, "usage.cache_creation.ephemeral_1h_input_tokens")
		if cc5m.Exists() || cc1h.Exists() {
			usage.CacheCreation5mTokens = int(cc5m.Int())
			usage.CacheCreation1hTokens = int(cc1h.Int())
		}
	}
}

// applyCacheTTLOverride 将所有 cache creation tokens 归入指定的 TTL 类型。
// target 为 "5m" 或 "1h"。返回 true 表示发生了变更。
func applyCacheTTLOverride(usage *ClaudeUsage, target string) bool {
	// Fallback: 如果只有聚合字段但无 5m/1h 明细，将聚合字段归入 5m 默认类别
	if usage.CacheCreation5mTokens == 0 && usage.CacheCreation1hTokens == 0 && usage.CacheCreationInputTokens > 0 {
		usage.CacheCreation5mTokens = usage.CacheCreationInputTokens
	}

	total := usage.CacheCreation5mTokens + usage.CacheCreation1hTokens
	if total == 0 {
		return false
	}
	switch target {
	case "1h":
		if usage.CacheCreation1hTokens == total {
			return false // 已经全是 1h
		}
		usage.CacheCreation1hTokens = total
		usage.CacheCreation5mTokens = 0
	default: // "5m"
		if usage.CacheCreation5mTokens == total {
			return false // 已经全是 5m
		}
		usage.CacheCreation5mTokens = total
		usage.CacheCreation1hTokens = 0
	}
	return true
}

// rewriteCacheCreationJSON 在 JSON usage 对象中重写 cache_creation 嵌套对象的 TTL 分类。
// usageObj 是 usage JSON 对象（map[string]any）。
func rewriteCacheCreationJSON(usageObj map[string]any, target string) {
	ccObj, ok := usageObj["cache_creation"].(map[string]any)
	if !ok {
		return
	}
	v5m, _ := ccObj["ephemeral_5m_input_tokens"].(float64)
	v1h, _ := ccObj["ephemeral_1h_input_tokens"].(float64)
	total := v5m + v1h
	if total == 0 {
		return
	}
	switch target {
	case "1h":
		ccObj["ephemeral_1h_input_tokens"] = total
		ccObj["ephemeral_5m_input_tokens"] = float64(0)
	default: // "5m"
		ccObj["ephemeral_5m_input_tokens"] = total
		ccObj["ephemeral_1h_input_tokens"] = float64(0)
	}
}
