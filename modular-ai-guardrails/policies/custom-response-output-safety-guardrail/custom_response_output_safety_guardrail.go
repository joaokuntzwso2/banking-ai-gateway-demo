package customresponseoutputsafetyguardrail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"regexp"
	"strings"
)

const (
	policyName      = "custom-response-output-safety-guardrail"
	demoMetadataKey = "wso2.ai.output-safety-demo"
)

var (
	activeHTML     = regexp.MustCompile(`(?is)<\s*script\b|\bon(?:error|load|click|mouseover)\s*=|javascript\s*:|data\s*:\s*text/html`)
	destructiveSQL = regexp.MustCompile(`(?im)(^|[;\n])\s*(drop\s+table|truncate\s+table|alter\s+table|delete\s+from\s+[a-zA-Z0-9_.]+\s*(;|$))`)
	shellExec      = regexp.MustCompile(`(?im)^\s*(sudo\s+)?(rm\s+-rf\b|curl\s+\S+\s*\|\s*(sh|bash)\b|wget\s+\S+\s+-O-\s*\|\s*(sh|bash)\b|powershell(?:\.exe)?\s+-(enc|encodedcommand)\b)`)
	pathTraversal  = regexp.MustCompile(`(^|[\s"'=(])\.\.[/\\]`)
	markdownImage  = regexp.MustCompile(`!\[[^\]]*\]\(\s*https?://[^)]+\)`)
)

type ResponseOutputSafetyGuardrailPolicy struct {
	blockHTML, blockSQL, blockShell, blockPath, blockMarkdown bool
	maxRequestBodySize, maxResponseBodySize                   int
	failClosed, showAssessment                                bool
	triggers                                                  map[string]string
}

func (p *ResponseOutputSafetyGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{RequestHeaderMode: policy.HeaderModeSkip, RequestBodyMode: policy.BodyModeBuffer, ResponseHeaderMode: policy.HeaderModeSkip, ResponseBodyMode: policy.BodyModeBuffer}
}
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	bh, e := booleanParameter(params, "blockActiveHtml", true)
	if e != nil {
		return nil, e
	}
	bs, e := booleanParameter(params, "blockDestructiveSql", true)
	if e != nil {
		return nil, e
	}
	bsh, e := booleanParameter(params, "blockShellExecution", true)
	if e != nil {
		return nil, e
	}
	bp, e := booleanParameter(params, "blockPathTraversal", true)
	if e != nil {
		return nil, e
	}
	bm, e := booleanParameter(params, "blockExternalMarkdownImages", true)
	if e != nil {
		return nil, e
	}
	mr, e := integerParameter(params, "maxRequestBodySize", 1048576)
	if e != nil {
		return nil, e
	}
	mx, e := integerParameter(params, "maxResponseBodySize", 4194304)
	if e != nil {
		return nil, e
	}
	fc, e := booleanParameter(params, "failClosedUnexpectedResponse", true)
	if e != nil {
		return nil, e
	}
	sa, e := booleanParameter(params, "showAssessment", true)
	if e != nil {
		return nil, e
	}
	x, e := stringParameter(params, "demoXssTrigger", "WSO2-OUTPUT-XSS-DEMO-TRIGGER-7E3A9F")
	if e != nil {
		return nil, e
	}
	s, e := stringParameter(params, "demoSqlTrigger", "WSO2-OUTPUT-SQL-DEMO-TRIGGER-7E3A9F")
	if e != nil {
		return nil, e
	}
	sh, e := stringParameter(params, "demoShellTrigger", "WSO2-OUTPUT-SHELL-DEMO-TRIGGER-7E3A9F")
	if e != nil {
		return nil, e
	}
	pt, e := stringParameter(params, "demoPathTraversalTrigger", "WSO2-OUTPUT-PATH-DEMO-TRIGGER-7E3A9F")
	if e != nil {
		return nil, e
	}
	md, e := stringParameter(params, "demoMarkdownExfiltrationTrigger", "WSO2-OUTPUT-MARKDOWN-DEMO-TRIGGER-7E3A9F")
	if e != nil {
		return nil, e
	}
	return &ResponseOutputSafetyGuardrailPolicy{bh, bs, bsh, bp, bm, mr, mx, fc, sa, map[string]string{x: "active-html", s: "destructive-sql", sh: "shell-execution", pt: "path-traversal", md: "external-markdown-image"}}, nil
}
func (p *ResponseOutputSafetyGuardrailPolicy) OnRequestBody(_ context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if reqCtx == nil || reqCtx.Body == nil || len(reqCtx.Body.Content) == 0 || len(reqCtx.Body.Content) > p.maxRequestBodySize {
		return nil
	}
	var request map[string]interface{}
	if json.Unmarshal(reqCtx.Body.Content, &request) != nil {
		return nil
	}
	content, e := lastContent(request)
	if e != nil {
		return nil
	}
	for trigger, kind := range p.triggers {
		if trigger != "" && strings.Contains(content, trigger) {
			if reqCtx.Metadata == nil {
				reqCtx.Metadata = map[string]interface{}{}
			}
			reqCtx.Metadata[demoMetadataKey] = kind
			break
		}
	}
	return nil
}
func (p *ResponseOutputSafetyGuardrailPolicy) OnResponseBody(_ context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	response, content, action := prepare(respCtx, p.maxResponseBodySize, p.failClosed, p.showAssessment)
	if action != nil {
		return action
	}
	if response == nil {
		return policy.DownstreamResponseModifications{}
	}
	kind := ""
	matched := ""
	if respCtx != nil && respCtx.Metadata != nil {
		kind, _ = respCtx.Metadata[demoMetadataKey].(string)
	}
	if kind == "" {
		switch {
		case p.blockHTML && activeHTML.MatchString(content):
			kind = "active-html"
			matched = activeHTML.FindString(content)
		case p.blockSQL && destructiveSQL.MatchString(content):
			kind = "destructive-sql"
			matched = destructiveSQL.FindString(content)
		case p.blockShell && shellExec.MatchString(content):
			kind = "shell-execution"
			matched = shellExec.FindString(content)
		case p.blockPath && pathTraversal.MatchString(content):
			kind = "path-traversal"
			matched = pathTraversal.FindString(content)
		case p.blockMarkdown && markdownImage.MatchString(content):
			kind = "external-markdown-image"
			matched = markdownImage.FindString(content)
		}
	}
	if kind == "" {
		return policy.DownstreamResponseModifications{}
	}
	assessment := interface{}(nil)
	if p.showAssessment {
		assessment = map[string]interface{}{"riskType": kind, "patternMatched": matched != "", "matchedSample": truncate(matched, 160), "deterministicDemo": matched == ""}
	}
	return block("improper-output-handling", "Model output contained content that must not be rendered or executed without context-specific validation.", assessment, p.showAssessment)
}
func prepare(ctx *policy.ResponseContext, max int, fail, show bool) (map[string]interface{}, string, policy.ResponseAction) {
	if ctx == nil || ctx.ResponseBody == nil || len(ctx.ResponseBody.Content) == 0 {
		if fail {
			return nil, "", block("response-structure", "Upstream response body is empty.", nil, show)
		}
		return nil, "", nil
	}
	if len(ctx.ResponseBody.Content) > max {
		return nil, "", block("response-size", "Response body exceeds the configured maximum size.", map[string]interface{}{"maximumBytes": max, "actualBytes": len(ctx.ResponseBody.Content)}, show)
	}
	var response map[string]interface{}
	if e := json.Unmarshal(ctx.ResponseBody.Content, &response); e != nil {
		if fail {
			return nil, "", block("response-structure", "Upstream response is not valid JSON.", safeError(e), show)
		}
		return nil, "", nil
	}
	if _, ok := response["error"]; ok || intervention(response) {
		return nil, "", nil
	}
	c, e := assistantContent(response)
	if e != nil {
		if fail {
			return nil, "", block("response-structure", "Response does not contain a valid assistant message.", safeError(e), show)
		}
		return nil, "", nil
	}
	return response, c, nil
}
func block(check, reason string, assessment interface{}, show bool) policy.ImmediateResponse {
	m := map[string]interface{}{"action": "GUARDRAIL_INTERVENED", "actionReason": reason, "direction": "RESPONSE", "interveningGuardrail": policyName, "check": check}
	if show && assessment != nil {
		m["assessments"] = assessment
	}
	b, _ := json.Marshal(map[string]interface{}{"type": "OUTPUT_SAFETY_GUARDRAIL", "message": m})
	return policy.ImmediateResponse{StatusCode: 422, Headers: map[string]string{"Content-Type": "application/json", "Cache-Control": "no-store"}, Body: b}
}
func intervention(r map[string]interface{}) bool {
	m, ok := r["message"].(map[string]interface{})
	if !ok {
		return false
	}
	a, _ := m["action"].(string)
	return a == "GUARDRAIL_INTERVENED"
}
func assistantContent(r map[string]interface{}) (string, error) {
	a, ok := r["choices"].([]interface{})
	if !ok || len(a) == 0 {
		return "", errors.New("choices is not a non-empty array")
	}
	f, _ := a[0].(map[string]interface{})
	m, _ := f["message"].(map[string]interface{})
	c, ok := m["content"].(string)
	if !ok {
		return "", errors.New("message content is not a string")
	}
	return c, nil
}
func lastContent(r map[string]interface{}) (string, error) {
	a, ok := r["messages"].([]interface{})
	if !ok || len(a) == 0 {
		return "", errors.New("messages is not a non-empty array")
	}
	m, _ := a[len(a)-1].(map[string]interface{})
	c, ok := m["content"].(string)
	if !ok {
		return "", errors.New("content is not a string")
	}
	return c, nil
}
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
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
