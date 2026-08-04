package customrequestregexguardrail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	pendingRequestBlockMetadataKey = "wso2.ai.pending-request-block"
	policyName                     = "custom-request-regex-guardrail"
)

type RequestRegexGuardrailPolicy struct {
	expression         *regexp.Regexp
	maxRequestBodySize int
	quarantineMessage  string
	showAssessment     bool
}

func (p *RequestRegexGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	expressionText, err := stringParameter(params, "regex", "")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(expressionText) == "" {
		return nil, errors.New("regex must not be empty")
	}
	expression, err := regexp.Compile(expressionText)
	if err != nil {
		return nil, fmt.Errorf("invalid regex: %w", err)
	}
	maxRequestBodySize, err := integerParameter(params, "maxRequestBodySize", 1048576)
	if err != nil {
		return nil, err
	}
	if maxRequestBodySize <= 0 {
		return nil, errors.New("maxRequestBodySize must be greater than zero")
	}
	quarantineMessage, err := stringParameter(params, "quarantineMessage", "Reply exactly with OK.")
	if err != nil {
		return nil, err
	}
	showAssessment, err := booleanParameter(params, "showAssessment", true)
	if err != nil {
		return nil, err
	}
	return &RequestRegexGuardrailPolicy{
		expression: expression, maxRequestBodySize: maxRequestBodySize,
		quarantineMessage: quarantineMessage, showAssessment: showAssessment,
	}, nil
}

func (p *RequestRegexGuardrailPolicy) OnRequestBody(
	_ context.Context,
	reqCtx *policy.RequestContext,
	_ map[string]interface{},
) policy.RequestAction {
	if reqCtx == nil || pendingRequestBlock(reqCtx.Metadata) {
		return nil
	}
	if reqCtx.Body == nil || len(reqCtx.Body.Content) == 0 {
		return p.quarantine(reqCtx, nil, "request-structure", "Request body is empty.", nil)
	}
	if len(reqCtx.Body.Content) > p.maxRequestBodySize {
		return p.quarantine(reqCtx, nil, "request-size", "Request body exceeds the configured maximum size.", map[string]interface{}{
			"maximumBytes": p.maxRequestBodySize,
			"actualBytes":  len(reqCtx.Body.Content),
		})
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(reqCtx.Body.Content, &payload); err != nil {
		return p.quarantine(reqCtx, nil, "request-structure", "Request body is not valid JSON.", safeError(err))
	}
	messages, err := extractMessages(payload)
	if err != nil {
		return p.quarantine(reqCtx, payload, "request-structure", "Unable to extract the messages array.", safeError(err))
	}
	content, err := extractLastMessageContent(messages)
	if err != nil {
		return p.quarantine(reqCtx, payload, "request-structure", "Unable to extract the latest message content.", safeError(err))
	}
	if !p.expression.MatchString(content) {
		return nil
	}
	assessment := interface{}(nil)
	if p.showAssessment {
		assessment = map[string]interface{}{"patternMatched": true}
	}
	return p.quarantine(reqCtx, payload, "request-regex", "Request content matched a blocked expression.", assessment)
}

func (p *RequestRegexGuardrailPolicy) quarantine(
	reqCtx *policy.RequestContext,
	originalPayload map[string]interface{},
	check string,
	reason string,
	assessment interface{},
) policy.RequestAction {
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = map[string]interface{}{}
	}
	reqCtx.Metadata[pendingRequestBlockMetadataKey] = map[string]interface{}{
		"policy": policyName, "check": check, "reason": reason, "assessment": assessment,
	}
	safePayload := map[string]interface{}{
		"model": "gpt-4o-mini", "temperature": 0, "stream": false,
		"messages": []interface{}{map[string]interface{}{"role": "user", "content": p.quarantineMessage}},
	}
	if originalPayload != nil {
		if model, exists := originalPayload["model"]; exists {
			safePayload["model"] = model
		}
	}
	safeBody, err := json.Marshal(safePayload)
	if err != nil {
		safeBody = []byte(`{"model":"gpt-4o-mini","temperature":0,"stream":false,"messages":[{"role":"user","content":"Reply exactly with OK."}]}`)
	}
	return policy.UpstreamRequestModifications{
		Body: safeBody,
		AnalyticsMetadata: map[string]interface{}{
			"ai.security.request_blocked": true,
			"ai.security.blocking_policy": policyName,
		},
	}
}

func pendingRequestBlock(metadata map[string]interface{}) bool {
	if metadata == nil {
		return false
	}
	_, exists := metadata[pendingRequestBlockMetadataKey]
	return exists
}

func extractMessages(payload map[string]interface{}) ([]interface{}, error) {
	raw, exists := payload["messages"]
	if !exists {
		return nil, errors.New("key not found: messages")
	}
	messages, ok := raw.([]interface{})
	if !ok || len(messages) == 0 {
		return nil, errors.New("messages is not a non-empty array")
	}
	return messages, nil
}

func extractLastMessageContent(messages []interface{}) (string, error) {
	message, ok := messages[len(messages)-1].(map[string]interface{})
	if !ok {
		return "", errors.New("latest message is not an object")
	}
	content, ok := message["content"].(string)
	if !ok {
		return "", errors.New("latest message content is not a string")
	}
	return content, nil
}

func stringParameter(params map[string]interface{}, name, fallback string) (string, error) {
	value, exists := params[name]
	if !exists || value == nil {
		return fallback, nil
	}
	typed, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("parameter %q must be a string, received %T", name, value)
	}
	return typed, nil
}

func booleanParameter(params map[string]interface{}, name string, fallback bool) (bool, error) {
	value, exists := params[name]
	if !exists || value == nil {
		return fallback, nil
	}
	typed, ok := value.(bool)
	if !ok {
		return false, fmt.Errorf("parameter %q must be a boolean, received %T", name, value)
	}
	return typed, nil
}

func integerParameter(params map[string]interface{}, name string, fallback int) (int, error) {
	value, exists := params[name]
	if !exists || value == nil {
		return fallback, nil
	}
	switch typed := value.(type) {
	case int:
		return typed, nil
	case int32:
		return int(typed), nil
	case int64:
		return int(typed), nil
	case float64:
		return int(typed), nil
	case json.Number:
		parsed, err := typed.Int64()
		return int(parsed), err
	default:
		return 0, fmt.Errorf("parameter %q must be an integer, received %T", name, value)
	}
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	value := err.Error()
	if len(value) > 1000 {
		return value[:1000] + "..."
	}
	return value
}
