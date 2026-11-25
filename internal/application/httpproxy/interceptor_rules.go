package httpproxy

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
	"golang.org/x/net/http/httpguts"
)

var _ outbound.HeaderInterceptor = (*RuleEngineInterceptor)(nil)

// RuleEngineInterceptor evaluates pre-compiled declarative HeaderRules on request and response headers.
type RuleEngineInterceptor struct {
	requestRules  []compiledRule
	responseRules []compiledRule
}

type ruleAction uint8

const (
	actionSet ruleAction = iota
	actionAdd
	actionSetIfAbsent
	actionAppend
	actionRemove
)

type compiledRule struct {
	name      string
	direction model.TrafficDirection // empty means both
	action    ruleAction
	headerKey string // canonical header key
	segments  []templateSegment
	match     compiledMatch
}

type compiledMatch struct {
	namespaces   map[string]struct{}
	services     map[string]struct{}
	methods      map[string]struct{}
	pathPrefix   string
	headerExists string
	headerEquals map[string]string
}

type varKind uint8

const (
	varLiteral varKind = iota
	varTraceID
	varSpanID
	varTraceparent
	varRequestID
	varCallerIdentity
	varSourceNode
	varDestNode
	varNamespace
	varServiceName
	varNodeServiceID
	varDirection
	varProtocol
	varStatusCode
	varReqHeader
	varServiceLabel
	varUnknown
)

type templateSegment struct {
	kind varKind
	text string // literal text, canonical header name, or label key
}

// NewRuleEngineInterceptor validates and pre-compiles declarative rules into a zero-regex runtime engine.
func NewRuleEngineInterceptor(rules []model.HeaderRule) (*RuleEngineInterceptor, error) {
	engine := &RuleEngineInterceptor{}
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			return nil, err
		}
		cr := compileRule(r)
		if strings.EqualFold(strings.TrimSpace(r.Phase), "response") {
			engine.responseRules = append(engine.responseRules, cr)
		} else {
			engine.requestRules = append(engine.requestRules, cr)
		}
	}
	return engine, nil
}

// Name returns the interceptor identifier.
func (e *RuleEngineInterceptor) Name() string {
	return "rule-engine"
}

// OnRequest applies all matching request-phase rules.
func (e *RuleEngineInterceptor) OnRequest(_ context.Context, conn *model.ConnectionMeta, req *model.HTTPRequestContext) error {
	if len(e.requestRules) == 0 || conn == nil || req == nil {
		return nil
	}
	if req.Headers == nil {
		req.Headers = make(http.Header)
	}
	for i := range e.requestRules {
		e.requestRules[i].apply(conn, req, nil, req.Headers)
	}
	return nil
}

// OnResponse applies all matching response-phase rules.
func (e *RuleEngineInterceptor) OnResponse(_ context.Context, conn *model.ConnectionMeta, req *model.HTTPRequestContext, resp *model.HTTPResponseContext) error {
	if len(e.responseRules) == 0 || conn == nil || resp == nil {
		return nil
	}
	if resp.Headers == nil {
		resp.Headers = make(http.Header)
	}
	for i := range e.responseRules {
		e.responseRules[i].apply(conn, req, resp, resp.Headers)
	}
	return nil
}

func compileRule(r model.HeaderRule) compiledRule {
	var dir model.TrafficDirection
	switch strings.ToLower(strings.TrimSpace(r.Direction)) {
	case "outbound":
		dir = model.DirectionOutbound
	case "inbound":
		dir = model.DirectionInbound
	}

	var act ruleAction
	switch strings.ToLower(strings.TrimSpace(r.Action)) {
	case "add":
		act = actionAdd
	case "set_if_absent":
		act = actionSetIfAbsent
	case "append":
		act = actionAppend
	case "remove":
		act = actionRemove
	default:
		act = actionSet
	}

	var segments []templateSegment
	if act != actionRemove {
		segments = compileTemplate(r.Name, r.Value)
	}

	return compiledRule{
		name:      r.Name,
		direction: dir,
		action:    act,
		headerKey: http.CanonicalHeaderKey(r.Header),
		segments:  segments,
		match:     compileMatch(r.Match),
	}
}

func compileMatch(m model.RuleMatch) compiledMatch {
	cm := compiledMatch{
		pathPrefix: m.PathPrefix,
	}
	if len(m.Namespaces) > 0 {
		cm.namespaces = make(map[string]struct{}, len(m.Namespaces))
		for _, ns := range m.Namespaces {
			cm.namespaces[ns] = struct{}{}
		}
	}
	if len(m.Services) > 0 {
		cm.services = make(map[string]struct{}, len(m.Services))
		for _, svc := range m.Services {
			cm.services[svc] = struct{}{}
		}
	}
	if len(m.Methods) > 0 {
		cm.methods = make(map[string]struct{}, len(m.Methods))
		for _, method := range m.Methods {
			cm.methods[strings.ToUpper(strings.TrimSpace(method))] = struct{}{}
		}
	}
	if m.HeaderExists != "" {
		cm.headerExists = http.CanonicalHeaderKey(m.HeaderExists)
	}
	if len(m.HeaderEquals) > 0 {
		cm.headerEquals = make(map[string]string, len(m.HeaderEquals))
		for k, v := range m.HeaderEquals {
			cm.headerEquals[http.CanonicalHeaderKey(k)] = v
		}
	}
	return cm
}

func compileTemplate(ruleName, tmpl string) []templateSegment {
	if !strings.Contains(tmpl, "${") {
		if tmpl == "" {
			return nil
		}
		return []templateSegment{{kind: varLiteral, text: tmpl}}
	}

	var segments []templateSegment
	rest := tmpl
	for len(rest) > 0 {
		start := strings.Index(rest, "${")
		if start == -1 {
			segments = append(segments, templateSegment{kind: varLiteral, text: rest})
			break
		}
		if start > 0 {
			segments = append(segments, templateSegment{kind: varLiteral, text: rest[:start]})
		}
		end := strings.IndexByte(rest[start+2:], '}')
		if end == -1 {
			segments = append(segments, templateSegment{kind: varLiteral, text: rest[start:]})
			break
		}

		expr := rest[start+2 : start+2+end]
		segments = append(segments, parseTemplateVar(ruleName, expr))
		rest = rest[start+2+end+1:]
	}
	return segments
}

func parseTemplateVar(ruleName, expr string) templateSegment {
	switch expr {
	case "trace_id":
		return templateSegment{kind: varTraceID}
	case "span_id":
		return templateSegment{kind: varSpanID}
	case "traceparent":
		return templateSegment{kind: varTraceparent}
	case "request_id":
		return templateSegment{kind: varRequestID}
	case "caller_identity":
		return templateSegment{kind: varCallerIdentity}
	case "source_node":
		return templateSegment{kind: varSourceNode}
	case "dest_node":
		return templateSegment{kind: varDestNode}
	case "namespace":
		return templateSegment{kind: varNamespace}
	case "service_name":
		return templateSegment{kind: varServiceName}
	case "node_service_id":
		return templateSegment{kind: varNodeServiceID}
	case "direction":
		return templateSegment{kind: varDirection}
	case "protocol":
		return templateSegment{kind: varProtocol}
	case "status_code":
		return templateSegment{kind: varStatusCode}
	default:
		if hdr, ok := strings.CutPrefix(expr, "req.header."); ok && hdr != "" {
			return templateSegment{kind: varReqHeader, text: http.CanonicalHeaderKey(hdr)}
		}
		if lbl, ok := strings.CutPrefix(expr, "service.label."); ok && lbl != "" {
			return templateSegment{kind: varServiceLabel, text: lbl}
		}
		log.Printf("[HTTP L7] warning: header rule %q references unknown template variable ${%s}; resolving to empty string\n", ruleName, expr)
		return templateSegment{kind: varUnknown}
	}
}

func (r *compiledRule) apply(conn *model.ConnectionMeta, req *model.HTTPRequestContext, resp *model.HTTPResponseContext, target http.Header) {
	if r.direction != "" && conn.Direction != r.direction {
		return
	}
	if !r.match.matches(conn, req, target) {
		return
	}

	if r.action == actionRemove {
		target.Del(r.headerKey)
		return
	}

	rawVal := expandTemplate(r.segments, conn, req, resp)
	val := model.SanitizeHeaderValue(rawVal)
	if !httpguts.ValidHeaderFieldValue(val) {
		log.Printf("[HTTP L7] warning: rule %q skipped because expanded value for %q contains invalid control characters\n", r.name, r.headerKey)
		return
	}

	switch r.action {
	case actionSet:
		target.Set(r.headerKey, val)
	case actionAdd:
		target.Add(r.headerKey, val)
	case actionSetIfAbsent:
		if target.Get(r.headerKey) == "" {
			target.Set(r.headerKey, val)
		}
	case actionAppend:
		if existing := target.Get(r.headerKey); existing != "" {
			if val != "" {
				target.Set(r.headerKey, existing+", "+val)
			}
		} else {
			target.Set(r.headerKey, val)
		}
	}
}

func (m *compiledMatch) matches(conn *model.ConnectionMeta, req *model.HTTPRequestContext, phaseHeaders http.Header) bool {
	if len(m.namespaces) > 0 {
		if _, ok := m.namespaces[conn.Namespace]; !ok {
			return false
		}
	}
	if len(m.services) > 0 {
		_, matchName := m.services[conn.ServiceName]
		_, matchFull := m.services[formatDestService(conn.Namespace, conn.ServiceName)]
		if !matchName && !matchFull {
			return false
		}
	}
	if len(m.methods) > 0 {
		if req == nil {
			return false
		}
		if _, ok := m.methods[strings.ToUpper(req.Method)]; !ok {
			return false
		}
	}
	if m.pathPrefix != "" {
		if req == nil || req.URL == nil || !strings.HasPrefix(req.URL.Path, m.pathPrefix) {
			return false
		}
	}
	if m.headerExists != "" {
		if phaseHeaders == nil || phaseHeaders.Get(m.headerExists) == "" {
			return false
		}
	}
	for k, expected := range m.headerEquals {
		if req == nil || req.Headers == nil || req.Headers.Get(k) != expected {
			return false
		}
	}
	return true
}

func expandTemplate(segments []templateSegment, conn *model.ConnectionMeta, req *model.HTTPRequestContext, resp *model.HTTPResponseContext) string {
	if len(segments) == 0 {
		return ""
	}
	if len(segments) == 1 {
		return resolveSegment(segments[0], conn, req, resp)
	}

	var b strings.Builder
	for _, seg := range segments {
		b.WriteString(resolveSegment(seg, conn, req, resp))
	}
	return b.String()
}

func resolveSegment(seg templateSegment, conn *model.ConnectionMeta, req *model.HTTPRequestContext, resp *model.HTTPResponseContext) string {
	switch seg.kind {
	case varLiteral:
		return seg.text
	case varTraceID:
		if req != nil {
			return req.TraceContext.TraceIDHex()
		}
	case varSpanID:
		if req != nil {
			return req.TraceContext.ParentIDHex()
		}
	case varTraceparent:
		if req != nil {
			return req.TraceContext.FormatTraceparent()
		}
	case varRequestID:
		if req != nil {
			return req.RequestID
		}
	case varCallerIdentity:
		if conn != nil {
			return conn.CallerIdentity
		}
	case varSourceNode:
		if conn != nil {
			return conn.SourceNodeID
		}
	case varDestNode:
		if conn != nil {
			return conn.DestNodeID
		}
	case varNamespace:
		if conn != nil {
			return conn.Namespace
		}
	case varServiceName:
		if conn != nil {
			return conn.ServiceName
		}
	case varNodeServiceID:
		if conn != nil {
			return conn.NodeServiceID
		}
	case varDirection:
		if conn != nil {
			return string(conn.Direction)
		}
	case varProtocol:
		if conn != nil {
			return string(conn.DetectedProto)
		}
	case varStatusCode:
		if resp != nil {
			return strconv.Itoa(resp.StatusCode)
		}
	case varReqHeader:
		if req != nil && req.Headers != nil {
			return req.Headers.Get(seg.text)
		}
	case varServiceLabel:
		if conn != nil && conn.ServiceLabels != nil {
			return conn.ServiceLabels[seg.text]
		}
	}
	return ""
}
