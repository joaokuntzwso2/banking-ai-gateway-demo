package canonicalizeandclassify

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const supportedJSONPath = "$.messages[-1].content"

var forbiddenPattern = regexp.MustCompile(
	`(?i)(` +
		`ignore\s+(all\s+)?(previous|prior)\s+instructions|` +
		`ignora\s+(todas\s+)?las\s+instrucciones\s+anteriores|` +
		`reveal\s+(the\s+)?(system|developer)\s+prompt|` +
		`revela(r)?\s+(el\s+)?prompt\s+(de\s+)?sistema|` +
		`system\s+prompt|` +
		`developer\s+message|` +
		`mensaje\s+(de\s+)?sistema|` +
		`do\s+anything\s+now|` +
		`\bDAN\b|` +
		`jailbreak|` +
		`sin\s+restricciones|` +
		`session\s+token|` +
		`token\s+de\s+sesión|` +
		`other\s+user|` +
		`otro\s+usuario|` +
		`cross[-\s]?tenant|` +
		`export\s+customer\s+data|` +
		`exporta(r)?\s+datos\s+de\s+clientes` +
		`)`,
)

const pendingRequestBlockMetadataKey = "wso2.ai.pending-request-block"

// CanonicalizeAndClassifyPolicy canonicalizes the latest OpenAI-compatible
// chat message and blocks deterministic prompt-injection patterns.
type CanonicalizeAndClassifyPolicy struct {
	jsonPath           string
	maxBodySize        int
	maxDecodedSize     int
	maximumDecodeDepth int
	blockOnDetection   bool
}

// Mode tells the gateway to buffer the complete request body.
// WSO2 invokes OnRequestBody after the body is available.
func (p *CanonicalizeAndClassifyPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestBody processes OpenAI-compatible chat-completions payloads.
func (p *CanonicalizeAndClassifyPolicy) OnRequestBody(
	_ context.Context,
	reqCtx *policy.RequestContext,
	_ map[string]interface{},
) policy.RequestAction {
	if reqCtx == nil || reqCtx.Body == nil || !reqCtx.Body.Present {
		return nil
	}

	originalBody := reqCtx.Body.Content
	if len(originalBody) == 0 {
		return nil
	}

	if len(originalBody) > p.maxBodySize {
		return quarantineDetectedRequest(
			reqCtx,
			nil,
			"request-size",
			"Request body exceeds the configured canonicalization limit.",
			map[string]any{
				"bodySize":    len(originalBody),
				"maximumSize": p.maxBodySize,
			},
		)
	}

	var payload map[string]any
	if err := json.Unmarshal(originalBody, &payload); err != nil {
		// This policy targets JSON chat-completions requests.
		// Non-JSON payloads continue unchanged.
		return nil
	}

	messages, ok := payload["messages"].([]any)
	if !ok || len(messages) == 0 {
		return nil
	}

	lastMessage, ok := messages[len(messages)-1].(map[string]any)
	if !ok {
		return nil
	}

	content, ok := lastMessage["content"].(string)
	if !ok || content == "" {
		return nil
	}

	canonicalContent, decodeDepth, transformations, err :=
		p.canonicalize(content)

	if err != nil {
		return quarantineDetectedRequest(
			reqCtx,
			payload,
			"canonicalization-rejected",
			err.Error(),
			map[string]any{
				"decodeDepth":     decodeDepth,
				"transformations": transformations,
			},
		)
	}

	if forbiddenPattern.MatchString(canonicalContent) && p.blockOnDetection {
		return quarantineDetectedRequest(
			reqCtx,
			payload,
			"canonicalize-and-classify",
			"Encoded, obfuscated, or direct prompt-injection content was detected.",
			map[string]any{
				"owaspCategory":   "LLM01",
				"direction":       "REQUEST",
				"action":          "BLOCK",
				"decodeDepth":     decodeDepth,
				"transformations": transformations,
			},
		)
	}

	if canonicalContent == content {
		return nil
	}

	lastMessage["content"] = canonicalContent

	modifiedBody, err := json.Marshal(payload)
	if err != nil {
		return quarantineDetectedRequest(
			reqCtx,
			payload,
			"canonicalization-error",
			"Unable to serialize the canonicalized request.",
			nil,
		)
	}

	return policy.UpstreamRequestModifications{
		Body: modifiedBody,
		AnalyticsMetadata: map[string]any{
			"ai.security.canonicalized":   true,
			"ai.security.decode_depth":    decodeDepth,
			"ai.security.transformations": transformations,
		},
	}
}

func quarantineDetectedRequest(
	reqCtx *policy.RequestContext,
	originalPayload map[string]any,
	check string,
	reason string,
	assessment map[string]any,
) policy.RequestAction {
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = map[string]interface{}{}
	}

	reqCtx.Metadata[pendingRequestBlockMetadataKey] =
		map[string]interface{}{
			"policy":     "canonicalize-and-classify",
			"check":      check,
			"reason":     reason,
			"assessment": assessment,
		}

	// Do not forward the rejected user-controlled content upstream.
	safePayload := map[string]any{
		"temperature": 0,
		"stream":      false,
		"messages": []any{
			map[string]any{
				"role":    "user",
				"content": "Reply exactly with OK.",
			},
		},
	}

	if model, exists := originalPayload["model"]; exists {
		safePayload["model"] = model
	}

	safeBody, err := json.Marshal(safePayload)
	if err != nil {
		safeBody = []byte(
			`{"model":"gpt-4o-mini","temperature":0,"stream":false,"messages":[{"role":"user","content":"Reply exactly with OK."}]}`,
		)
	}

	return policy.UpstreamRequestModifications{
		Body: safeBody,
		AnalyticsMetadata: map[string]any{
			"ai.security.request_blocked": true,
			"ai.security.blocking_policy": check,
		},
	}
}

// canonicalize removes invisible controls and decodes complete values
// encoded using URL encoding, hexadecimal, or Base64.
//
// Decoding is intentionally bounded to prevent excessive expansion and
// recursively encoded payload attacks.
func (p *CanonicalizeAndClassifyPolicy) canonicalize(
	input string,
) (string, int, []string, error) {
	current := stripInvisibleCharacters(strings.TrimSpace(input))
	transformations := make([]string, 0)
	decodeDepth := 0

	if current != input {
		transformations = append(transformations, "INVISIBLE_OR_WHITESPACE_NORMALIZATION")
	}

	for decodeDepth < p.maximumDecodeDepth {
		decoded, transformation, changed := decodeOneLayer(current)
		if !changed {
			break
		}

		if len(decoded) > p.maxDecodedSize {
			return current,
				decodeDepth,
				transformations,
				fmt.Errorf(
					"decoded content exceeds the configured maximum of %d bytes",
					p.maxDecodedSize,
				)
		}

		current = stripInvisibleCharacters(strings.TrimSpace(decoded))
		decodeDepth++
		transformations = append(transformations, transformation)
	}

	return current, decodeDepth, transformations, nil
}

func decodeOneLayer(value string) (string, string, bool) {
	candidate := strings.TrimSpace(value)

	if strings.Contains(candidate, "%") {
		if decoded, err := url.PathUnescape(candidate); err == nil &&
			decoded != candidate &&
			isAcceptableText(decoded) {
			return decoded, "URL_DECODE", true
		}
	}

	if isHexCandidate(candidate) {
		if bytes, err := hex.DecodeString(candidate); err == nil {
			decoded := string(bytes)
			if isAcceptableText(decoded) {
				return decoded, "HEX_DECODE", true
			}
		}
	}

	if isBase64Candidate(candidate) {
		encodings := []*base64.Encoding{
			base64.StdEncoding,
			base64.RawStdEncoding,
			base64.URLEncoding,
			base64.RawURLEncoding,
		}

		for _, encoding := range encodings {
			bytes, err := encoding.DecodeString(candidate)
			if err != nil {
				continue
			}

			decoded := string(bytes)
			if isAcceptableText(decoded) {
				return decoded, "BASE64_DECODE", true
			}
		}
	}

	return value, "", false
}

func stripInvisibleCharacters(value string) string {
	return strings.Map(
		func(r rune) rune {
			switch r {
			case '\u200B', // zero-width space
				'\u200C', // zero-width non-joiner
				'\u200D', // zero-width joiner
				'\u2060', // word joiner
				'\uFEFF', // zero-width no-break space
				'\u202A', '\u202B', '\u202C', '\u202D', '\u202E',
				'\u2066', '\u2067', '\u2068', '\u2069':
				return -1
			default:
				return r
			}
		},
		value,
	)
}

func isHexCandidate(value string) bool {
	if len(value) < 8 || len(value)%2 != 0 {
		return false
	}

	for _, r := range value {
		isDigit := r >= '0' && r <= '9'
		isLowerHex := r >= 'a' && r <= 'f'
		isUpperHex := r >= 'A' && r <= 'F'

		if !isDigit && !isLowerHex && !isUpperHex {
			return false
		}
	}

	return true
}

func isBase64Candidate(value string) bool {
	if len(value) < 8 {
		return false
	}

	for _, r := range value {
		isAlphaNumeric :=
			(r >= 'a' && r <= 'z') ||
				(r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9')

		if !isAlphaNumeric &&
			r != '+' &&
			r != '/' &&
			r != '-' &&
			r != '_' &&
			r != '=' {
			return false
		}
	}

	return true
}

func isAcceptableText(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}

	printable := 0
	total := 0

	for _, r := range value {
		total++

		if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			printable++
		}
	}

	if total == 0 {
		return false
	}

	return float64(printable)/float64(total) >= 0.85
}

func immediateJSONResponse(
	statusCode int,
	eventType string,
	message string,
	assessment map[string]any,
) policy.RequestAction {
	body := map[string]any{
		"eventType": eventType,
		"message":   message,
	}

	if assessment != nil {
		body["assessment"] = assessment
	}

	encodedBody, err := json.Marshal(body)
	if err != nil {
		encodedBody = []byte(
			`{"eventType":"POLICY_ERROR","message":"Request blocked by policy."}`,
		)
	}

	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: encodedBody,
		AnalyticsMetadata: map[string]any{
			"ai.security.event_type": eventType,
			"ai.security.action":     "BLOCK",
		},
	}
}

func integerParameter(
	params map[string]interface{},
	name string,
	defaultValue int,
) (int, error) {
	value, exists := params[name]
	if !exists || value == nil {
		return defaultValue, nil
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
		return 0, fmt.Errorf(
			"parameter %q must be an integer, received %T",
			name,
			value,
		)
	}
}

func booleanParameter(
	params map[string]interface{},
	name string,
	defaultValue bool,
) (bool, error) {
	value, exists := params[name]
	if !exists || value == nil {
		return defaultValue, nil
	}

	typed, ok := value.(bool)
	if !ok {
		return false, fmt.Errorf(
			"parameter %q must be a boolean, received %T",
			name,
			value,
		)
	}

	return typed, nil
}

func stringParameter(
	params map[string]interface{},
	name string,
	defaultValue string,
) (string, error) {
	value, exists := params[name]
	if !exists || value == nil {
		return defaultValue, nil
	}

	typed, ok := value.(string)
	if !ok {
		return "", fmt.Errorf(
			"parameter %q must be a string, received %T",
			name,
			value,
		)
	}

	return typed, nil
}

// GetPolicy is the WSO2 policy factory discovered by the Gateway Builder.
func GetPolicy(
	_ policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	jsonPath, err := stringParameter(
		params,
		"jsonPath",
		supportedJSONPath,
	)
	if err != nil {
		return nil, err
	}

	if jsonPath != supportedJSONPath {
		return nil, fmt.Errorf(
			"unsupported jsonPath %q; this version supports only %q",
			jsonPath,
			supportedJSONPath,
		)
	}

	maxBodySize, err := integerParameter(
		params,
		"maxBodySize",
		1048576,
	)
	if err != nil {
		return nil, err
	}

	maxDecodedSize, err := integerParameter(
		params,
		"maxDecodedSize",
		2097152,
	)
	if err != nil {
		return nil, err
	}

	maximumDecodeDepth, err := integerParameter(
		params,
		"maximumDecodeDepth",
		2,
	)
	if err != nil {
		return nil, err
	}

	blockOnDetection, err := booleanParameter(
		params,
		"blockOnDetection",
		true,
	)
	if err != nil {
		return nil, err
	}

	if maxBodySize <= 0 {
		return nil, fmt.Errorf("maxBodySize must be greater than zero")
	}

	if maxDecodedSize <= 0 {
		return nil, fmt.Errorf("maxDecodedSize must be greater than zero")
	}

	if maximumDecodeDepth < 0 || maximumDecodeDepth > 5 {
		return nil, fmt.Errorf(
			"maximumDecodeDepth must be between zero and five",
		)
	}

	return &CanonicalizeAndClassifyPolicy{
		jsonPath:           jsonPath,
		maxBodySize:        maxBodySize,
		maxDecodedSize:     maxDecodedSize,
		maximumDecodeDepth: maximumDecodeDepth,
		blockOnDetection:   blockOnDetection,
	}, nil
}
