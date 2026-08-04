package customresourcebudgetguardrail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	pendingRequestBlockMetadataKey = "wso2.ai.pending-request-block"
	policyName                     = "custom-resource-budget-guardrail"
)

type ResourceBudgetGuardrailPolicy struct {
	maxRequestBodySize, maxMessages, maxPromptCharacters, maxOutputTokens, maxTools int
	allowStreaming, allowLogprobs, applyDefaultOutputLimit, showAssessment          bool
	quarantineModel, quarantineMessage                                              string
}

func (p *ResourceBudgetGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{RequestHeaderMode: policy.HeaderModeSkip, RequestBodyMode: policy.BodyModeBuffer, ResponseHeaderMode: policy.HeaderModeSkip, ResponseBodyMode: policy.BodyModeSkip}
}
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	vals := []struct {
		name     string
		fallback int
		target   *int
	}{{"maxRequestBodySize", 1048576, new(int)}, {"maxMessages", 32, new(int)}, {"maxPromptCharacters", 32000, new(int)}, {"maxOutputTokens", 2048, new(int)}, {"maxTools", 8, new(int)}}
	parsed := map[string]int{}
	for _, v := range vals {
		n, e := integerParameter(params, v.name, v.fallback)
		if e != nil {
			return nil, e
		}
		if n < 0 || (v.name != "maxTools" && n == 0) {
			return nil, fmt.Errorf("%s must be greater than zero", v.name)
		}
		parsed[v.name] = n
	}
	allowStreaming, e := booleanParameter(params, "allowStreaming", false)
	if e != nil {
		return nil, e
	}
	allowLogprobs, e := booleanParameter(params, "allowLogprobs", false)
	if e != nil {
		return nil, e
	}
	applyDefault, e := booleanParameter(params, "applyDefaultOutputTokenLimit", true)
	if e != nil {
		return nil, e
	}
	show, e := booleanParameter(params, "showAssessment", true)
	if e != nil {
		return nil, e
	}
	qm, e := stringParameter(params, "quarantineModel", "gpt-4o-mini")
	if e != nil {
		return nil, e
	}
	qmsg, e := stringParameter(params, "quarantineMessage", "Reply exactly with OK.")
	if e != nil {
		return nil, e
	}
	return &ResourceBudgetGuardrailPolicy{parsed["maxRequestBodySize"], parsed["maxMessages"], parsed["maxPromptCharacters"], parsed["maxOutputTokens"], parsed["maxTools"], allowStreaming, allowLogprobs, applyDefault, show, qm, qmsg}, nil
}
func (p *ResourceBudgetGuardrailPolicy) OnRequestBody(_ context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if reqCtx == nil || pending(reqCtx.Metadata) {
		return nil
	}
	if reqCtx.Body == nil || len(reqCtx.Body.Content) == 0 {
		return p.block(reqCtx, nil, "resource-budget", "Request body is empty.", nil)
	}
	if len(reqCtx.Body.Content) > p.maxRequestBodySize {
		return p.block(reqCtx, nil, "resource-budget", "Request body exceeds the configured byte budget.", map[string]interface{}{"limit": "requestBytes", "maximum": p.maxRequestBodySize, "actual": len(reqCtx.Body.Content)})
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(reqCtx.Body.Content, &payload); err != nil {
		return p.block(reqCtx, nil, "resource-budget", "Request body is not valid JSON.", safeError(err))
	}
	messages, ok := payload["messages"].([]interface{})
	if !ok || len(messages) == 0 {
		return p.block(reqCtx, payload, "resource-budget", "messages must be a non-empty array.", nil)
	}
	if len(messages) > p.maxMessages {
		return p.block(reqCtx, payload, "resource-budget", "Message count exceeds the configured budget.", map[string]interface{}{"limit": "messages", "maximum": p.maxMessages, "actual": len(messages)})
	}
	chars := 0
	for _, raw := range messages {
		if msg, ok := raw.(map[string]interface{}); ok {
			switch c := msg["content"].(type) {
			case string:
				chars += len([]rune(c))
			case []interface{}:
				for _, part := range c {
					if obj, ok := part.(map[string]interface{}); ok {
						if text, ok := obj["text"].(string); ok {
							chars += len([]rune(text))
						}
					}
				}
			}
		}
	}
	if chars > p.maxPromptCharacters {
		return p.block(reqCtx, payload, "resource-budget", "Prompt content exceeds the configured character budget.", map[string]interface{}{"limit": "promptCharacters", "maximum": p.maxPromptCharacters, "actual": chars})
	}
	requestedTokens := numeric(payload["max_completion_tokens"])
	if requestedTokens == 0 {
		requestedTokens = numeric(payload["max_tokens"])
	}
	if requestedTokens < 0 {
		return p.block(reqCtx, payload, "resource-budget", "Requested output tokens must be a positive integer.", map[string]interface{}{"limit": "outputTokens", "actual": requestedTokens})
	}
	if requestedTokens > p.maxOutputTokens {
		return p.block(reqCtx, payload, "resource-budget", "Requested output tokens exceed the configured budget.", map[string]interface{}{"limit": "outputTokens", "maximum": p.maxOutputTokens, "actual": requestedTokens})
	}
	changed := false
	if requestedTokens == 0 && p.applyDefaultOutputLimit {
		payload["max_completion_tokens"] = p.maxOutputTokens
		changed = true
	}
	tools := 0
	if raw, ok := payload["tools"].([]interface{}); ok {
		tools = len(raw)
	}
	if tools > p.maxTools {
		return p.block(reqCtx, payload, "resource-budget", "Tool count exceeds the configured budget.", map[string]interface{}{"limit": "tools", "maximum": p.maxTools, "actual": tools})
	}
	if stream, _ := payload["stream"].(bool); stream && !p.allowStreaming {
		return p.block(reqCtx, payload, "resource-budget", "Streaming is disabled because this endpoint applies buffered response guardrails.", map[string]interface{}{"limit": "streaming", "allowed": false})
	}
	if !p.allowLogprobs {
		if enabled, _ := payload["logprobs"].(bool); enabled {
			return p.block(reqCtx, payload, "resource-budget", "Log probability output is disabled for this endpoint.", map[string]interface{}{"limit": "logprobs", "allowed": false})
		}
		if numeric(payload["top_logprobs"]) > 0 {
			return p.block(reqCtx, payload, "resource-budget", "Top log probabilities are disabled for this endpoint.", map[string]interface{}{"limit": "topLogprobs", "allowed": false})
		}
	}
	if !changed {
		return nil
	}
	updatedBody, err := json.Marshal(payload)
	if err != nil {
		return p.block(reqCtx, payload, "resource-budget", "Unable to apply the default output-token budget.", safeError(err))
	}
	return policy.UpstreamRequestModifications{
		Body: updatedBody,
		AnalyticsMetadata: map[string]interface{}{
			"ai.security.output_token_limit_applied": true,
			"ai.security.output_token_limit":         p.maxOutputTokens,
		},
	}
}
func (p *ResourceBudgetGuardrailPolicy) block(reqCtx *policy.RequestContext, original map[string]interface{}, check, reason string, assessment interface{}) policy.RequestAction {
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = map[string]interface{}{}
	}
	if !p.showAssessment {
		assessment = nil
	}
	reqCtx.Metadata[pendingRequestBlockMetadataKey] = map[string]interface{}{"policy": policyName, "check": check, "reason": reason, "assessment": assessment}
	safe := map[string]interface{}{"model": p.quarantineModel, "temperature": 0, "stream": false, "messages": []interface{}{map[string]interface{}{"role": "user", "content": p.quarantineMessage}}}
	body, _ := json.Marshal(safe)
	return policy.UpstreamRequestModifications{Body: body, AnalyticsMetadata: map[string]interface{}{"ai.security.request_blocked": true, "ai.security.blocking_policy": policyName}}
}
func numeric(v interface{}) int {
	switch t := v.(type) {
	case int:
		return t
	case int32:
		return int(t)
	case int64:
		return int(t)
	case float64:
		return int(t)
	case json.Number:
		n, _ := t.Int64()
		return int(n)
	default:
		return 0
	}
}
func pending(m map[string]interface{}) bool {
	if m == nil {
		return false
	}
	_, ok := m[pendingRequestBlockMetadataKey]
	return ok
}
func stringParameter(p map[string]interface{}, n, f string) (string, error) {
	v, ok := p[n]
	if !ok || v == nil {
		return f, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("parameter %q must be a string, received %T", n, v)
	}
	return s, nil
}
func booleanParameter(p map[string]interface{}, n string, f bool) (bool, error) {
	v, ok := p[n]
	if !ok || v == nil {
		return f, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("parameter %q must be a boolean, received %T", n, v)
	}
	return b, nil
}
func integerParameter(p map[string]interface{}, n string, f int) (int, error) {
	v, ok := p[n]
	if !ok || v == nil {
		return f, nil
	}
	switch t := v.(type) {
	case int:
		return t, nil
	case int32:
		return int(t), nil
	case int64:
		return int(t), nil
	case float64:
		return int(t), nil
	case json.Number:
		x, e := t.Int64()
		return int(x), e
	default:
		return 0, fmt.Errorf("parameter %q must be an integer, received %T", n, v)
	}
}
func safeError(e error) string {
	if e == nil {
		return ""
	}
	s := e.Error()
	if len(s) > 1000 {
		return s[:1000] + "..."
	}
	return s
}

var _ = errors.New
