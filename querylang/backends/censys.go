package backends

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/uncover/querylang"
)

// Censys Search v3 query language (https://search.censys.io/search/language):
// dotted `field: value` predicates, lowercase and/or/not, parentheses,
// range syntax `field: {start: a, end: b}` for numeric/date fields.
type censysBackend struct {
	caps querylang.Capabilities
}

// Censys builds the Censys backend.
func Censys() querylang.Backend {
	caps := querylang.Capabilities{
		SupportsNot:      true,
		SupportsNestedOr: true,
		Fields: map[string]querylang.FieldCapability{
			querylang.FieldDomain:          {Field: querylang.FieldDomain, SupportedOps: textOps, AlternativeNames: []string{"dns.names"}},
			querylang.FieldSubdomain:       {Field: querylang.FieldSubdomain, SupportedOps: textOps},
			querylang.FieldHostname:        {Field: querylang.FieldHostname, SupportedOps: textOps},
			querylang.FieldIP:              {Field: querylang.FieldIP, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpIn}, Note: "CIDR values use CIDR() pseudo-function"},
			querylang.FieldCIDR:            {Field: querylang.FieldCIDR, SupportedOps: eqNeq},
			querylang.FieldIPRange:         {Field: querylang.FieldIPRange, SupportedOps: []querylang.Operator{querylang.OpBetween}},
			querylang.FieldPort:            {Field: querylang.FieldPort, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpGreater, querylang.OpGreaterOrEqual, querylang.OpLess, querylang.OpLessOrEqual, querylang.OpIn}},
			querylang.FieldPortRange:       {Field: querylang.FieldPortRange, SupportedOps: []querylang.Operator{querylang.OpBetween}},
			querylang.FieldProtocol:        {Field: querylang.FieldProtocol, SupportedOps: eqNeq},
			querylang.FieldService:         {Field: querylang.FieldService, SupportedOps: eqNeq},
			querylang.FieldTitle:           {Field: querylang.FieldTitle, SupportedOps: containsOps},
			querylang.FieldHeader:          {Field: querylang.FieldHeader, SupportedOps: containsOps},
			querylang.FieldStatusCode:      {Field: querylang.FieldStatusCode, SupportedOps: orderedOps},
			querylang.FieldBody:            {Field: querylang.FieldBody, SupportedOps: containsOps},
			querylang.FieldCert:            {Field: querylang.FieldCert, SupportedOps: containsOps},
			querylang.FieldCertCN:          {Field: querylang.FieldCertCN, SupportedOps: textOps},
			querylang.FieldCertIssuer:      {Field: querylang.FieldCertIssuer, SupportedOps: textOps},
			querylang.FieldCertIssuerOrg:   {Field: querylang.FieldCertIssuerOrg, SupportedOps: textOps},
			querylang.FieldCertSubject:     {Field: querylang.FieldCertSubject, SupportedOps: textOps},
			querylang.FieldCertOrg:         {Field: querylang.FieldCertOrg, SupportedOps: textOps},
			querylang.FieldCertFingerprint: {Field: querylang.FieldCertFingerprint, SupportedOps: eqNeq},
			querylang.FieldFirstSeen:       {Field: querylang.FieldFirstSeen, SupportedOps: []querylang.Operator{querylang.OpGreater, querylang.OpGreaterOrEqual, querylang.OpLess, querylang.OpLessOrEqual, querylang.OpEqual, querylang.OpBetween}},
			querylang.FieldLastSeen:        {Field: querylang.FieldLastSeen, SupportedOps: []querylang.Operator{querylang.OpGreater, querylang.OpGreaterOrEqual, querylang.OpLess, querylang.OpLessOrEqual, querylang.OpEqual, querylang.OpBetween}},
			querylang.FieldASN:             {Field: querylang.FieldASN, SupportedOps: orderedOps},
			querylang.FieldOrg:             {Field: querylang.FieldOrg, SupportedOps: containsOps},
			querylang.FieldOS:              {Field: querylang.FieldOS, SupportedOps: eqNeq, Level: querylang.SupportAlternative, Note: "best-effort mapping to operating_system.product"},
			querylang.FieldProduct:         {Field: querylang.FieldProduct, SupportedOps: textOps},
			querylang.FieldCountry:         {Field: querylang.FieldCountry, SupportedOps: eqNeq},
			querylang.FieldRaw:             {Field: querylang.FieldRaw, SupportedOps: containsOps, Level: querylang.SupportAlternative, Note: "mapped to services.banner full-text"},
		},
	}
	return &censysBackend{caps: caps}
}

func (b *censysBackend) Name() string                         { return "censys" }
func (b *censysBackend) Capabilities() querylang.Capabilities { return b.caps }

func (b *censysBackend) Render(tree querylang.Node, drops []querylang.Degradation) (string, []querylang.AlternativeRendering, error) {
	r := &censysRenderer{drops: querylang.DropSet(drops)}
	text, err := r.node(tree)
	return text, r.alts, err
}

type censysRenderer struct {
	drops map[string]bool
	alts  []querylang.AlternativeRendering
}

func (r *censysRenderer) node(n querylang.Node) (string, error) {
	return r.nodeWithParent(n, -1)
}

func (r *censysRenderer) nodeWithParent(n querylang.Node, parentOp querylang.LogicalOp) (string, error) {
	switch t := n.(type) {
	case *querylang.LogicalNode:
		parts := make([]string, 0, len(t.Children))
		for _, ch := range t.Children {
			text, err := r.nodeWithParent(ch, t.Op)
			if err != nil {
				return "", err
			}
			if text == "" {
				continue
			}
			parts = append(parts, text)
		}
		if len(parts) == 0 {
			return "", nil
		}
		kw := "and"
		if t.Op == querylang.Or {
			kw = "or"
		}
		joined := strings.Join(parts, " "+kw+" ")
		if parentOp >= 0 && parentOp != t.Op {
			return "(" + joined + ")", nil
		}
		return joined, nil
	case *querylang.NotNode:
		text, err := r.nodeWithParent(t.Child, -1)
		if err != nil {
			return "", err
		}
		return "not (" + text + ")", nil
	case *querylang.LeafNode:
		if r.drops[t.String()] {
			return "", nil
		}
		return r.leaf(t)
	default:
		return "", fmt.Errorf("unknown node type %T", n)
	}
}

var censysFields = map[string]string{
	querylang.FieldDomain:          "dns.names",
	querylang.FieldSubdomain:       "dns.names",
	querylang.FieldHostname:        "dns.names",
	querylang.FieldIP:              "ip",
	querylang.FieldCIDR:            "ip",
	querylang.FieldIPRange:         "ip",
	querylang.FieldPort:            "services.port",
	querylang.FieldPortRange:       "services.port",
	querylang.FieldProtocol:        "services.transport_protocol",
	querylang.FieldService:         "services.service_name",
	querylang.FieldTitle:           "services.http.response.html_title",
	querylang.FieldHeader:          "services.http.response.headers",
	querylang.FieldStatusCode:      "services.http.response.status_code",
	querylang.FieldBody:            "services.http.response.body",
	querylang.FieldCert:            "services.tls.certificates.leaf_data",
	querylang.FieldCertCN:          "services.tls.certificates.leaf_data.subject.common_name",
	querylang.FieldCertIssuer:      "services.tls.certificates.leaf_data.issuer.common_name",
	querylang.FieldCertIssuerOrg:   "services.tls.certificates.leaf_data.issuer.organization",
	querylang.FieldCertSubject:     "services.tls.certificates.leaf_data.subject.common_name",
	querylang.FieldCertOrg:         "services.tls.certificates.leaf_data.subject.organization",
	querylang.FieldCertFingerprint: "services.tls.certificates.fingerprint",
	querylang.FieldFirstSeen:       "first_observed_at",
	querylang.FieldLastSeen:        "last_observed_at",
	querylang.FieldASN:             "autonomous_system.asn",
	querylang.FieldOrg:             "autonomous_system.name",
	querylang.FieldOS:              "operating_system.product",
	querylang.FieldProduct:         "services.software.product",
	querylang.FieldCountry:         "location.country",
	querylang.FieldRaw:             "services.banner",
}

func (r *censysRenderer) leaf(leaf *querylang.LeafNode) (string, error) {
	field := censysFields[leaf.Field]
	if field == "" {
		return "", fmt.Errorf("internal: no Censys mapping for field %q", leaf.Field)
	}

	// Range-capable numeric/date fields use the interval object.
	if leaf.Op == querylang.OpBetween {
		return r.rangeLeaf(field, leaf)
	}
	if leaf.Op == querylang.OpIn {
		list, _ := leaf.Value.([]string)
		parts := make([]string, 0, len(list))
		for _, v := range list {
			parts = append(parts, field+": "+r.scalar(leaf, v))
		}
		return "(" + strings.Join(parts, " or ") + ")", nil
	}

	// CIDR uses the CIDR() pseudo-function.
	if leaf.Kind == querylang.KindCIDR {
		prefix := "CIDR(" + leaf.RawValue + ")"
		if leaf.Op == querylang.OpNotEqual {
			return "not " + field + ": " + prefix, nil
		}
		return field + ": " + prefix, nil
	}

	op := censysCompare(leaf.Op)
	if op == "" {
		// Contains/regex map onto the bare predicate with quoted value.
		op = ":"
	}
	return field + op + " " + r.scalar(leaf, leaf.RawValue), nil
}

func (r *censysRenderer) rangeLeaf(field string, leaf *querylang.LeafNode) (string, error) {
	switch leaf.Kind {
	case querylang.KindPortRange:
		pr, _ := leaf.Value.(*querylang.PortRangeValue)
		return fmt.Sprintf("%s: {start: %d, end: %d}", field, pr.Low, pr.High), nil
	case querylang.KindIPRange:
		ipr, _ := leaf.Value.(*querylang.IPRangeValue)
		return fmt.Sprintf("ip: {start: %s, end: %s}", ipr.Start, ipr.End), nil
	case querylang.KindTimeRange:
		tr, _ := leaf.Value.(*querylang.TimeRangeValue)
		return fmt.Sprintf("%s: {start: %s, end: %s}", field, censysQuote(tr.From), censysQuote(tr.To)), nil
	default:
		return "", fmt.Errorf("unsupported BETWEEN kind %s", leaf.Kind)
	}
}

func (r *censysRenderer) scalar(leaf *querylang.LeafNode, raw string) string {
	if leaf.Kind == querylang.KindNumber {
		return fmt.Sprint(leaf.Value)
	}
	return censysQuote(raw)
}

func censysCompare(op querylang.Operator) string {
	switch op {
	case querylang.OpEqual, querylang.OpContains:
		return ":"
	case querylang.OpNotEqual, querylang.OpNotContains:
		return ": !"
	case querylang.OpGreater:
		return ": {"
	case querylang.OpGreaterOrEqual:
		return ": {"
	case querylang.OpLess:
		return ": {"
	case querylang.OpLessOrEqual:
		return ": {"
	default:
		return ""
	}
}

func censysQuote(s string) string {
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}
