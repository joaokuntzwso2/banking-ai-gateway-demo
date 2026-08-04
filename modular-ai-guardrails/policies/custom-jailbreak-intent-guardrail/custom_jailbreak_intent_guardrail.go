package customjailbreakintentguardrail

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
	policyName                     = "custom-jailbreak-intent-guardrail"
)

type compiledIntent struct {
	category   string
	expression *regexp.Regexp
}
type JailbreakIntentGuardrailPolicy struct {
	intents            []compiledIntent
	maxRequestBodySize int
	quarantineMessage  string
	showAssessment     bool
}

func (p *JailbreakIntentGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{RequestHeaderMode: policy.HeaderModeSkip, RequestBodyMode: policy.BodyModeBuffer, ResponseHeaderMode: policy.HeaderModeSkip, ResponseBodyMode: policy.BodyModeSkip}
}

func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	definitions := []struct{ name, category, fallback string }{
		{"systemPromptExtractionRegex", "SYSTEM_PROMPT_EXTRACTION", `(?i)(imprime|muestra|repite|expone|revela).*(texto privado|reglas internas|instrucciones ocultas|prompt de sistema|system prompt)`},
		{"professionalAuthorityRegex", "PROFESSIONAL_AUTHORITY_BYPASS", `(?i)(auditor|director|administrador|regulador|cumplimiento).*(autorizad[oa]|senior|directorio).*(omitir|ignorar|eludir|bypass).*(pol[ií]ticas|reglas|controles|instrucciones)`},
		{"personaSwitchRegex", "PERSONA_SWITCH_JAILBREAK", `(?i)(a partir de ahora|from now on).*(DAN|administrador sin restricciones|unrestricted administrator|sin restricciones)`},
	}
	intents := make([]compiledIntent, 0, len(definitions))
	for _, definition := range definitions {
		value, err := stringParameter(params, definition.name, definition.fallback)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(value) == "" {
			continue
		}
		expression, err := regexp.Compile(value)
		if err != nil {
			return nil, fmt.Errorf("invalid %s: %w", definition.name, err)
		}
		intents = append(intents, compiledIntent{category: definition.category, expression: expression})
	}
	if len(intents) == 0 {
		return nil, errors.New("at least one jailbreak intent regex must be configured")
	}
	maxSize, err := integerParameter(params, "maxRequestBodySize", 1048576)
	if err != nil {
		return nil, err
	}
	quarantineMessage, err := stringParameter(params, "quarantineMessage", "Reply exactly with OK.")
	if err != nil {
		return nil, err
	}
	show, err := booleanParameter(params, "showAssessment", true)
	if err != nil {
		return nil, err
	}
	return &JailbreakIntentGuardrailPolicy{intents: intents, maxRequestBodySize: maxSize, quarantineMessage: quarantineMessage, showAssessment: show}, nil
}

func (p *JailbreakIntentGuardrailPolicy) OnRequestBody(_ context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
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
	content, ok := latestContent(payload)
	if !ok {
		return nil
	}
	for _, intent := range p.intents {
		if intent.expression.MatchString(content) {
			assessment := interface{}(nil)
			if p.showAssessment {
				assessment = map[string]interface{}{"classification": intent.category, "confidence": 1.0, "classifier": "deterministic-intent-v1"}
			}
			return p.quarantine(reqCtx, payload, "jailbreak-intent", "Request matched a blocked jailbreak intent.", assessment)
		}
	}
	return nil
}

func (p *JailbreakIntentGuardrailPolicy) quarantine(reqCtx *policy.RequestContext, original map[string]interface{}, check, reason string, assessment interface{}) policy.RequestAction {
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = map[string]interface{}{}
	}
	reqCtx.Metadata[pendingRequestBlockMetadataKey] = map[string]interface{}{"policy": policyName, "check": check, "reason": reason, "assessment": assessment}
	safe := map[string]interface{}{"model": "gpt-4o-mini", "temperature": 0, "stream": false, "messages": []interface{}{map[string]interface{}{"role": "user", "content": p.quarantineMessage}}}
	if model, exists := original["model"]; exists {
		safe["model"] = model
	}
	body, _ := json.Marshal(safe)
	return policy.UpstreamRequestModifications{Body: body, AnalyticsMetadata: map[string]interface{}{"ai.security.request_blocked": true, "ai.security.blocking_policy": policyName}}
}

func latestContent(payload map[string]interface{}) (string, bool) {
	messages, ok := payload["messages"].([]interface{})
	if !ok || len(messages) == 0 {
		return "", false
	}
	message, ok := messages[len(messages)-1].(map[string]interface{})
	if !ok {
		return "", false
	}
	value, ok := message["content"].(string)
	return value, ok
}
func pendingRequestBlock(metadata map[string]interface{}) bool {
	if metadata == nil {
		return false
	}
	_, ok := metadata[pendingRequestBlockMetadataKey]
	return ok
}
func stringParameter(params map[string]interface{}, name, fallback string) (string, error) {
	v, ok := params[name]
	if !ok || v == nil {
		return fallback, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("parameter %q must be a string", name)
	}
	return s, nil
}
func booleanParameter(params map[string]interface{}, name string, fallback bool) (bool, error) {
	v, ok := params[name]
	if !ok || v == nil {
		return fallback, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("parameter %q must be a boolean", name)
	}
	return b, nil
}
func integerParameter(params map[string]interface{}, name string, fallback int) (int, error) {
	v, ok := params[name]
	if !ok || v == nil {
		return fallback, nil
	}
	switch n := v.(type) {
	case int:
		return n, nil
	case int32:
		return int(n), nil
	case int64:
		return int(n), nil
	case float64:
		return int(n), nil
	case json.Number:
		i, e := n.Int64()
		return int(i), e
	default:
		return 0, fmt.Errorf("parameter %q must be an integer", name)
	}
}
