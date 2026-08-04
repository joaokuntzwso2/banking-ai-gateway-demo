package customresponsejsonschemaguardrail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const policyName = "custom-response-json-schema-guardrail"

type ResponseJSONSchemaGuardrailPolicy struct {
	schema                       *jsonschema.Schema
	target                       string
	enforcementMode              string
	maxResponseBodySize          int
	failClosedUnexpectedResponse bool
	showAssessment               bool
}

func (p *ResponseJSONSchemaGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode: policy.HeaderModeSkip, RequestBodyMode: policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip, ResponseBodyMode: policy.BodyModeBuffer,
	}
}

func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	schemaText, err := stringParameter(params, "responseSchema", "")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(schemaText) == "" {
		return nil, errors.New("responseSchema must not be empty")
	}
	compiled, err := jsonschema.CompileString("custom-response-schema.json", schemaText)
	if err != nil {
		return nil, fmt.Errorf("invalid responseSchema: %w", err)
	}
	target, err := stringParameter(params, "responseSchemaTarget", "content-json")
	if err != nil {
		return nil, err
	}
	if target != "content-json" && target != "message" && target != "response" {
		return nil, errors.New("responseSchemaTarget must be content-json, message, or response")
	}
	mode, err := stringParameter(params, "schemaEnforcementMode", "when-requested")
	if err != nil {
		return nil, err
	}
	if mode != "always" && mode != "when-requested" && mode != "when-json" && mode != "disabled" {
		return nil, errors.New("schemaEnforcementMode must be always, when-requested, when-json, or disabled")
	}
	maxSize, err := integerParameter(params, "maxResponseBodySize", 4194304)
	if err != nil {
		return nil, err
	}
	failClosed, err := booleanParameter(params, "failClosedUnexpectedResponse", true)
	if err != nil {
		return nil, err
	}
	show, err := booleanParameter(params, "showAssessment", true)
	if err != nil {
		return nil, err
	}
	return &ResponseJSONSchemaGuardrailPolicy{schema: compiled, target: target, enforcementMode: mode, maxResponseBodySize: maxSize, failClosedUnexpectedResponse: failClosed, showAssessment: show}, nil
}

func (p *ResponseJSONSchemaGuardrailPolicy) OnResponseBody(_ context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	response, message, content, action := p.prepareResponse(respCtx)
	if action != nil {
		return action
	}
	if response == nil {
		return policy.DownstreamResponseModifications{}
	}
	if !p.shouldValidate(respCtx, content) {
		return policy.DownstreamResponseModifications{}
	}
	var target interface{}
	switch p.target {
	case "response":
		target = response
	case "message":
		target = message
	case "content-json":
		var decoded interface{}
		if err := decodeJSON([]byte(content), &decoded); err != nil {
			return p.block("json-schema", "Assistant content is not valid JSON.", safeError(err))
		}
		target = decoded
	}
	if err := p.schema.Validate(target); err != nil {
		return p.block("json-schema", "Response violated the configured JSON Schema.", safeError(err))
	}
	return policy.DownstreamResponseModifications{}
}

func (p *ResponseJSONSchemaGuardrailPolicy) shouldValidate(respCtx *policy.ResponseContext, content string) bool {
	switch p.enforcementMode {
	case "disabled":
		return false
	case "always":
		return true
	case "when-json":
		var value interface{}
		return decodeJSON([]byte(content), &value) == nil
	case "when-requested":
		return requestAsksForStructuredJSON(respCtx)
	default:
		return false
	}
}

func requestAsksForStructuredJSON(respCtx *policy.ResponseContext) bool {
	if respCtx == nil || respCtx.RequestBody == nil || len(respCtx.RequestBody.Content) == 0 {
		return false
	}
	var request map[string]interface{}
	if err := decodeJSON(respCtx.RequestBody.Content, &request); err != nil {
		return false
	}
	raw, exists := request["response_format"]
	if !exists {
		return false
	}
	format, ok := raw.(map[string]interface{})
	if !ok {
		return false
	}
	kind, _ := format["type"].(string)
	return kind == "json_schema" || kind == "json_object"
}

func (p *ResponseJSONSchemaGuardrailPolicy) prepareResponse(respCtx *policy.ResponseContext) (map[string]interface{}, map[string]interface{}, string, policy.ResponseAction) {
	if respCtx == nil || respCtx.ResponseBody == nil || len(respCtx.ResponseBody.Content) == 0 {
		if p.failClosedUnexpectedResponse {
			return nil, nil, "", p.block("response-structure", "Upstream response body is empty.", nil)
		}
		return nil, nil, "", nil
	}
	if len(respCtx.ResponseBody.Content) > p.maxResponseBodySize {
		return nil, nil, "", p.block("response-size", "Response body exceeds the configured maximum size.", map[string]interface{}{"maximumBytes": p.maxResponseBodySize, "actualBytes": len(respCtx.ResponseBody.Content)})
	}
	var response map[string]interface{}
	if err := decodeJSON(respCtx.ResponseBody.Content, &response); err != nil {
		if p.failClosedUnexpectedResponse {
			return nil, nil, "", p.block("response-structure", "Upstream response is not valid JSON.", safeError(err))
		}
		return nil, nil, "", nil
	}
	if _, exists := response["error"]; exists || isGuardrailIntervention(response) {
		return nil, nil, "", nil
	}
	message, content, err := extractAssistantMessage(response)
	if err != nil {
		if p.failClosedUnexpectedResponse {
			return nil, nil, "", p.block("response-structure", "Response does not contain a valid assistant message.", safeError(err))
		}
		return nil, nil, "", nil
	}
	return response, message, content, nil
}

func (p *ResponseJSONSchemaGuardrailPolicy) block(check, reason string, assessment interface{}) policy.ImmediateResponse {
	message := map[string]interface{}{"action": "GUARDRAIL_INTERVENED", "actionReason": reason, "direction": "RESPONSE", "interveningGuardrail": policyName, "check": check}
	if p.showAssessment && assessment != nil {
		message["assessments"] = assessment
	}
	body, err := json.Marshal(map[string]interface{}{"type": "RESPONSE_JSON_SCHEMA_GUARDRAIL", "message": message})
	if err != nil {
		body = []byte(`{"type":"RESPONSE_JSON_SCHEMA_GUARDRAIL","message":{"action":"GUARDRAIL_INTERVENED"}}`)
	}
	return policy.ImmediateResponse{StatusCode: 422, Headers: map[string]string{"Content-Type": "application/json", "Cache-Control": "no-store"}, Body: body}
}
func decodeJSON(data []byte, target interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing interface{}
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON documents are not allowed")
	}
	return err
}
func isGuardrailIntervention(response map[string]interface{}) bool {
	message, ok := response["message"].(map[string]interface{})
	if !ok {
		return false
	}
	action, _ := message["action"].(string)
	return action == "GUARDRAIL_INTERVENED"
}
func extractAssistantMessage(response map[string]interface{}) (map[string]interface{}, string, error) {
	raw, exists := response["choices"]
	if !exists {
		return nil, "", errors.New("key not found: choices")
	}
	choices, ok := raw.([]interface{})
	if !ok || len(choices) == 0 {
		return nil, "", errors.New("choices is not a non-empty array")
	}
	first, ok := choices[0].(map[string]interface{})
	if !ok {
		return nil, "", errors.New("choices[0] is not an object")
	}
	message, ok := first["message"].(map[string]interface{})
	if !ok {
		return nil, "", errors.New("choices[0].message is not an object")
	}
	content, ok := message["content"].(string)
	if !ok {
		return nil, "", errors.New("choices[0].message.content is not a string")
	}
	return message, content, nil
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
