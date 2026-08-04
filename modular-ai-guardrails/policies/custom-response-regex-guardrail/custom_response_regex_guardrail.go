package customresponseregexguardrail

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
	policyName             = "custom-response-regex-guardrail"
	demoTriggerMetadataKey = "wso2.ai.response-regex-demo-trigger"
)

type ResponseRegexGuardrailPolicy struct {
	expression                   *regexp.Regexp
	demoMarker                   string
	demoTrigger                  string
	maxRequestBodySize           int
	maxResponseBodySize          int
	failClosedUnexpectedResponse bool
	showAssessment               bool
}

func (p *ResponseRegexGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode: policy.HeaderModeSkip, RequestBodyMode: policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip, ResponseBodyMode: policy.BodyModeBuffer,
	}
}

func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	expressionText, err := stringParameter(params, "regex", "")
	if err != nil {
		return nil, err
	}
	demoMarker, err := stringParameter(params, "demoMarker", "")
	if err != nil {
		return nil, err
	}
	demoTrigger, err := stringParameter(params, "demoTrigger", "")
	if err != nil {
		return nil, err
	}
	parts := make([]string, 0, 2)
	if strings.TrimSpace(expressionText) != "" {
		parts = append(parts, "(?:"+expressionText+")")
	}
	if demoMarker != "" {
		parts = append(parts, regexp.QuoteMeta(demoMarker))
	}
	if len(parts) == 0 {
		return nil, errors.New("regex or demoMarker must be configured")
	}
	expression, err := regexp.Compile(strings.Join(parts, "|"))
	if err != nil {
		return nil, fmt.Errorf("invalid regex: %w", err)
	}
	maxRequestBodySize, err := integerParameter(params, "maxRequestBodySize", 1048576)
	if err != nil {
		return nil, err
	}
	maxResponseBodySize, err := integerParameter(params, "maxResponseBodySize", 4194304)
	if err != nil {
		return nil, err
	}
	failClosed, err := booleanParameter(params, "failClosedUnexpectedResponse", true)
	if err != nil {
		return nil, err
	}
	showAssessment, err := booleanParameter(params, "showAssessment", true)
	if err != nil {
		return nil, err
	}
	return &ResponseRegexGuardrailPolicy{
		expression: expression, demoMarker: demoMarker, demoTrigger: demoTrigger,
		maxRequestBodySize: maxRequestBodySize, maxResponseBodySize: maxResponseBodySize,
		failClosedUnexpectedResponse: failClosed, showAssessment: showAssessment,
	}, nil
}

// OnRequestBody records a harmless deterministic test trigger in shared metadata.
// Production leakage protection remains response-content based; the trigger exists
// only so a live-model demonstration does not depend on the model echoing a token.
func (p *ResponseRegexGuardrailPolicy) OnRequestBody(
	_ context.Context,
	reqCtx *policy.RequestContext,
	_ map[string]interface{},
) policy.RequestAction {
	if p.demoTrigger == "" || reqCtx == nil || reqCtx.Body == nil || len(reqCtx.Body.Content) == 0 || len(reqCtx.Body.Content) > p.maxRequestBodySize {
		return nil
	}
	var request map[string]interface{}
	if err := json.Unmarshal(reqCtx.Body.Content, &request); err != nil {
		return nil
	}
	content, err := extractLastRequestContent(request)
	if err != nil || !strings.Contains(content, p.demoTrigger) {
		return nil
	}
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = map[string]interface{}{}
	}
	reqCtx.Metadata[demoTriggerMetadataKey] = true
	return nil
}

func (p *ResponseRegexGuardrailPolicy) OnResponseBody(
	_ context.Context,
	respCtx *policy.ResponseContext,
	_ map[string]interface{},
) policy.ResponseAction {
	response, content, action := prepareResponse(respCtx, p.maxResponseBodySize, p.failClosedUnexpectedResponse, p.showAssessment)
	if action != nil {
		return action
	}
	if response == nil {
		return policy.DownstreamResponseModifications{}
	}

	demoTriggered := false
	if respCtx != nil && respCtx.Metadata != nil {
		demoTriggered, _ = respCtx.Metadata[demoTriggerMetadataKey].(bool)
	}
	matched := p.expression.MatchString(content)
	if !matched && !demoTriggered {
		return policy.DownstreamResponseModifications{}
	}
	assessment := interface{}(nil)
	if p.showAssessment {
		assessment = map[string]interface{}{
			"patternMatched":     matched,
			"demoMarkerMatched":  p.demoMarker != "" && strings.Contains(content, p.demoMarker),
			"demoTriggerMatched": demoTriggered,
		}
	}
	reason := "Response content matched a blocked expression."
	if demoTriggered && !matched {
		reason = "Deterministic response-regex demonstration trigger activated."
	}
	return block("response-regex", reason, assessment, p.showAssessment)
}

func prepareResponse(respCtx *policy.ResponseContext, maxSize int, failClosed, showAssessment bool) (map[string]interface{}, string, policy.ResponseAction) {
	if respCtx == nil || respCtx.ResponseBody == nil || len(respCtx.ResponseBody.Content) == 0 {
		if failClosed {
			return nil, "", block("response-structure", "Upstream response body is empty.", nil, showAssessment)
		}
		return nil, "", nil
	}
	if len(respCtx.ResponseBody.Content) > maxSize {
		return nil, "", block("response-size", "Response body exceeds the configured maximum size.", map[string]interface{}{"maximumBytes": maxSize, "actualBytes": len(respCtx.ResponseBody.Content)}, showAssessment)
	}
	var response map[string]interface{}
	if err := json.Unmarshal(respCtx.ResponseBody.Content, &response); err != nil {
		if failClosed {
			return nil, "", block("response-structure", "Upstream response is not valid JSON.", safeError(err), showAssessment)
		}
		return nil, "", nil
	}
	if _, exists := response["error"]; exists || isGuardrailIntervention(response) {
		return nil, "", nil
	}
	content, err := extractAssistantContent(response)
	if err != nil {
		if failClosed {
			return nil, "", block("response-structure", "Response does not contain a valid assistant message.", safeError(err), showAssessment)
		}
		return nil, "", nil
	}
	return response, content, nil
}

func block(check, reason string, assessment interface{}, showAssessment bool) policy.ImmediateResponse {
	message := map[string]interface{}{
		"action": "GUARDRAIL_INTERVENED", "actionReason": reason,
		"direction": "RESPONSE", "interveningGuardrail": policyName, "check": check,
	}
	if showAssessment && assessment != nil {
		message["assessments"] = assessment
	}
	body, err := json.Marshal(map[string]interface{}{"type": "RESPONSE_REGEX_GUARDRAIL", "message": message})
	if err != nil {
		body = []byte(`{"type":"RESPONSE_REGEX_GUARDRAIL","message":{"action":"GUARDRAIL_INTERVENED"}}`)
	}
	return policy.ImmediateResponse{StatusCode: 422, Headers: map[string]string{"Content-Type": "application/json", "Cache-Control": "no-store"}, Body: body}
}

func isGuardrailIntervention(response map[string]interface{}) bool {
	message, ok := response["message"].(map[string]interface{})
	if !ok {
		return false
	}
	action, _ := message["action"].(string)
	return action == "GUARDRAIL_INTERVENED"
}

func extractAssistantContent(response map[string]interface{}) (string, error) {
	raw, exists := response["choices"]
	if !exists {
		return "", errors.New("key not found: choices")
	}
	choices, ok := raw.([]interface{})
	if !ok || len(choices) == 0 {
		return "", errors.New("choices is not a non-empty array")
	}
	first, ok := choices[0].(map[string]interface{})
	if !ok {
		return "", errors.New("choices[0] is not an object")
	}
	message, ok := first["message"].(map[string]interface{})
	if !ok {
		return "", errors.New("choices[0].message is not an object")
	}
	content, ok := message["content"].(string)
	if !ok {
		return "", errors.New("choices[0].message.content is not a string")
	}
	return content, nil
}

func extractLastRequestContent(request map[string]interface{}) (string, error) {
	messages, ok := request["messages"].([]interface{})
	if !ok || len(messages) == 0 {
		return "", errors.New("messages is not a non-empty array")
	}
	message, ok := messages[len(messages)-1].(map[string]interface{})
	if !ok {
		return "", errors.New("last message is not an object")
	}
	content, ok := message["content"].(string)
	if !ok {
		return "", errors.New("last message content is not a string")
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
