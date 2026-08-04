package customrequestblockfinalizer

import (
	"context"
	"encoding/json"
	"fmt"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const pendingRequestBlockMetadataKey = "wso2.ai.pending-request-block"

type RequestBlockFinalizerPolicy struct{ showAssessment bool }

func (p *RequestBlockFinalizerPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode: policy.HeaderModeSkip, RequestBodyMode: policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip, ResponseBodyMode: policy.BodyModeBuffer,
	}
}

func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	showAssessment, err := booleanParameter(params, "showAssessment", true)
	if err != nil {
		return nil, err
	}
	return &RequestBlockFinalizerPolicy{showAssessment: showAssessment}, nil
}

func (p *RequestBlockFinalizerPolicy) OnResponseBody(
	_ context.Context,
	respCtx *policy.ResponseContext,
	_ map[string]interface{},
) policy.ResponseAction {
	if respCtx == nil || respCtx.Metadata == nil {
		return policy.DownstreamResponseModifications{}
	}
	raw, exists := respCtx.Metadata[pendingRequestBlockMetadataKey]
	if !exists {
		return policy.DownstreamResponseModifications{}
	}
	pending, ok := raw.(map[string]interface{})
	if !ok {
		return policy.DownstreamResponseModifications{}
	}
	policyID, _ := pending["policy"].(string)
	check, _ := pending["check"].(string)
	reason, _ := pending["reason"].(string)
	assessment := pending["assessment"]
	if policyID == "" {
		policyID = check
	}
	if policyID == "" {
		policyID = "custom-request-block-finalizer"
	}
	if check == "" {
		check = "request-validation"
	}
	if reason == "" {
		reason = "Request validation failed."
	}
	message := map[string]interface{}{
		"action": "GUARDRAIL_INTERVENED", "actionReason": reason,
		"direction": "REQUEST", "interveningGuardrail": policyID, "check": check,
	}
	if p.showAssessment && assessment != nil {
		message["assessments"] = assessment
	}
	body, err := json.Marshal(map[string]interface{}{"type": "REQUEST_GUARDRAIL", "message": message})
	if err != nil {
		body = []byte(`{"type":"REQUEST_GUARDRAIL","message":{"action":"GUARDRAIL_INTERVENED","direction":"REQUEST"}}`)
	}
	return policy.ImmediateResponse{
		StatusCode: 422,
		Headers:    map[string]string{"Content-Type": "application/json", "Cache-Control": "no-store"},
		Body:       body,
		AnalyticsMetadata: map[string]interface{}{
			"ai.security.action": "BLOCK", "ai.security.direction": "REQUEST", "ai.security.blocking_policy": policyID,
		},
	}
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
