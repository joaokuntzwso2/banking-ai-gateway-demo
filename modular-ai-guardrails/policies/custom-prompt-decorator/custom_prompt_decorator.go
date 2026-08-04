package custompromptdecorator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const pendingRequestBlockMetadataKey = "wso2.ai.pending-request-block"

type PromptDecoratorPolicy struct {
	systemMessage      string
	placement          string
	maxRequestBodySize int
}

func (p *PromptDecoratorPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode: policy.HeaderModeSkip, RequestBodyMode: policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip, ResponseBodyMode: policy.BodyModeSkip,
	}
}

func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	systemMessage, err := stringParameter(params, "systemMessage", "")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(systemMessage) == "" {
		return nil, errors.New("systemMessage must not be empty")
	}
	placement, err := stringParameter(params, "promptPlacement", "prepend")
	if err != nil {
		return nil, err
	}
	if placement != "prepend" && placement != "append" {
		return nil, errors.New("promptPlacement must be prepend or append")
	}
	maxRequestBodySize, err := integerParameter(params, "maxRequestBodySize", 1048576)
	if err != nil {
		return nil, err
	}
	if maxRequestBodySize <= 0 {
		return nil, errors.New("maxRequestBodySize must be greater than zero")
	}
	return &PromptDecoratorPolicy{systemMessage: systemMessage, placement: placement, maxRequestBodySize: maxRequestBodySize}, nil
}

func (p *PromptDecoratorPolicy) OnRequestBody(
	_ context.Context,
	reqCtx *policy.RequestContext,
	_ map[string]interface{},
) policy.RequestAction {
	if reqCtx == nil || pendingRequestBlock(reqCtx.Metadata) {
		return nil
	}
	if reqCtx.Body == nil || len(reqCtx.Body.Content) == 0 || len(reqCtx.Body.Content) > p.maxRequestBodySize {
		return nil
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(reqCtx.Body.Content, &payload); err != nil {
		return nil
	}
	rawMessages, exists := payload["messages"]
	if !exists {
		return nil
	}
	messages, ok := rawMessages.([]interface{})
	if !ok || len(messages) == 0 {
		return nil
	}
	payload["messages"] = decorateMessages(messages, p.systemMessage, p.placement)
	updatedBody, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return policy.UpstreamRequestModifications{
		Body:              updatedBody,
		AnalyticsMetadata: map[string]interface{}{"ai.security.prompt_decorated": true},
	}
}

func pendingRequestBlock(metadata map[string]interface{}) bool {
	if metadata == nil {
		return false
	}
	_, exists := metadata[pendingRequestBlockMetadataKey]
	return exists
}

func decorateMessages(messages []interface{}, systemMessage, placement string) []interface{} {
	decoration := map[string]interface{}{"role": "system", "content": systemMessage}
	for _, raw := range messages {
		message, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		role, _ := message["role"].(string)
		content, _ := message["content"].(string)
		if role == "system" && content == systemMessage {
			return messages
		}
	}
	result := make([]interface{}, 0, len(messages)+1)
	if placement == "append" {
		result = append(result, messages...)
		return append(result, decoration)
	}
	result = append(result, decoration)
	return append(result, messages...)
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
