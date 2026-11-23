package backends

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/uncover/querylang"
)

// FOFA query grammar (https://en.fofa.info/api): `field="value"` predicates
// joined by && / ||, parentheses, != supported, ranges via && inequalities.
func Fofa() querylang.Backend {
	fieldNames := map[string]string{
		querylang.FieldDomain:          "domain",
		querylang.FieldSubdomain:       "host",
		querylang.FieldHostname:        "host",
		querylang.FieldIP:              "ip",
		querylang.FieldCIDR:            "ip",
		querylang.FieldIPRange:         "ip",
		querylang.FieldPort:            "port",
		querylang.FieldPortRange:       "port",
		querylang.FieldProtocol:        "protocol",
		querylang.FieldService:         "app",
		querylang.FieldTitle:           "title",
		querylang.FieldHeader:          "header",
		querylang.FieldStatusCode:      "status_code",
		querylang.FieldBody:            "body",
		querylang.FieldCert:            "cert",
		querylang.FieldCertCN:          "cert.subject.cn",
		querylang.FieldCertIssuer:      "cert.issuer.cn",
		querylang.FieldCertIssuerOrg:   "cert.issuer.org",
		querylang.FieldCertSubject:     "cert.subject.cn",
		querylang.FieldCertOrg:         "cert.subject.org",
		querylang.FieldCertFingerprint: "cert",
		querylang.FieldFirstSeen:       "before/after",
		querylang.FieldLastSeen:        "before/after",
		querylang.FieldASN:             "asn",
		querylang.FieldOrg:             "org",
		querylang.FieldOS:              "os",
		querylang.FieldProduct:         "app",
		querylang.FieldCountry:         "country",
		querylang.FieldRaw:             "body",
	}
	caps := querylang.Capabilities{
		Engine:           "fofa",
		SupportsNot:      false,
		SupportsNestedOr: true,
		Fields: map[string]querylang.FieldCapability{
			querylang.FieldDomain:          {Field: querylang.FieldDomain, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpContains, querylang.OpNotContains}},
			querylang.FieldSubdomain:       {Field: querylang.FieldSubdomain, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpContains, querylang.OpNotContains}},
			querylang.FieldHostname:        {Field: querylang.FieldHostname, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpContains, querylang.OpNotContains}},
			querylang.FieldIP:              {Field: querylang.FieldIP, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpIn}},
			querylang.FieldCIDR:            {Field: querylang.FieldCIDR, SupportedOps: eqNeq},
			querylang.FieldIPRange:         {Field: querylang.FieldIPRange, SupportedOps: []querylang.Operator{querylang.OpBetween}, Note: "FOFA lacks an IP range filter; emitted as ip>=\"start\" && ip<=\"end\" inequalities on the string field"},
			querylang.FieldPort:            {Field: querylang.FieldPort, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpIn}},
			querylang.FieldPortRange:       {Field: querylang.FieldPortRange, SupportedOps: []querylang.Operator{querylang.OpBetween}},
			querylang.FieldProtocol:        {Field: querylang.FieldProtocol, SupportedOps: eqNeq},
			querylang.FieldService:         {Field: querylang.FieldService, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpContains, querylang.OpNotContains}, AlternativeNames: []string{"app"}},
			querylang.FieldTitle:           {Field: querylang.FieldTitle, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpContains, querylang.OpNotContains}},
			querylang.FieldHeader:          {Field: querylang.FieldHeader, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpContains, querylang.OpNotContains}},
			querylang.FieldStatusCode:      {Field: querylang.FieldStatusCode, SupportedOps: orderedOps},
			querylang.FieldBody:            {Field: querylang.FieldBody, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpContains, querylang.OpNotContains}},
			querylang.FieldCert:            {Field: querylang.FieldCert, SupportedOps: []querylang.Operator{querylang.OpContains, querylang.OpNotContains, querylang.OpEqual, querylang.OpNotEqual}},
			querylang.FieldCertCN:          {Field: querylang.FieldCertCN, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpContains, querylang.OpNotContains}},
			querylang.FieldCertIssuer:      {Field: querylang.FieldCertIssuer, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpContains, querylang.OpNotContains}},
			querylang.FieldCertIssuerOrg:   {Field: querylang.FieldCertIssuerOrg, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpContains, querylang.OpNotContains}},
			querylang.FieldCertSubject:     {Field: querylang.FieldCertSubject, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpContains, querylang.OpNotContains}},
			querylang.FieldCertOrg:         {Field: querylang.FieldCertOrg, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpContains, querylang.OpNotContains}},
			querylang.FieldCertFingerprint: {Field: querylang.FieldCertFingerprint, SupportedOps: eqNeq, Level: querylang.SupportDegradable, Note: "FOFA exposes certificate hashes only as generic cert= content matching; an exact fingerprint filter cannot be guaranteed"},
			querylang.FieldFirstSeen:       {Field: querylang.FieldFirstSeen, SupportedOps: []querylang.Operator{querylang.OpGreater, querylang.OpGreaterOrEqual, querylang.OpLess, querylang.OpLessOrEqual, querylang.OpBetween}},
			querylang.FieldLastSeen:        {Field: querylang.FieldLastSeen, SupportedOps: []querylang.Operator{querylang.OpGreater, querylang.OpGreaterOrEqual, querylang.OpLess, querylang.OpLessOrEqual, querylang.OpBetween}},
			querylang.FieldASN:             {Field: querylang.FieldASN, SupportedOps: orderedOps},
			querylang.FieldOrg:             {Field: querylang.FieldOrg, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpContains, querylang.OpNotContains}},
			querylang.FieldOS:              {Field: querylang.FieldOS, SupportedOps: eqNeq},
			querylang.FieldProduct:         {Field: querylang.FieldProduct, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpContains, querylang.OpNotContains}},
			querylang.FieldCountry:         {Field: querylang.FieldCountry, SupportedOps: eqNeq},
			querylang.FieldRaw:             {Field: querylang.FieldRaw, SupportedOps: []querylang.Operator{querylang.OpContains, querylang.OpNotContains, querylang.OpEqual, querylang.OpNotEqual}, AlternativeNames: []string{"body"}},
		},
		Notes: []string{"FOFA has no NOT-group syntax; negation is only available through per-field != operators, so NOT sub-expressions are rejected rather than rewritten loosely."},
	}

	d := querylang.Dialect{
		FieldNames:     fieldNames,
		AndToken:       "&&",
		OrToken:        "||",
		NotToken:       "",
		Quote:          '"',
		FieldSeparator: "=",
		Escape:         fofaEscape,
		RenderLeaf:     fofaLeaf,
	}
	return querylang.NewGenericBackend("fofa", caps, d)
}

func fofaEscape(s string, quote byte) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, string(quote), `\`+string(quote))
}

func fofaLeaf(leaf *querylang.LeafNode) (string, *querylang.AlternativeRendering, bool, error) {
	switch leaf.Op {
	case querylang.OpContains:
		return fofaField(leaf) + `*=` + fofaQuote(leaf.RawValue), nil, true, nil
	case querylang.OpNotContains:
		return fofaField(leaf) + `!*=` + fofaQuote(leaf.RawValue), nil, true, nil
	case querylang.OpNotEqual:
		return fofaField(leaf) + `!=` + fofaQuote(leaf.RawValue), nil, true, nil
	case querylang.OpIn:
		list, _ := leaf.Value.([]string)
		parts := make([]string, 0, len(list))
		for _, v := range list {
			parts = append(parts, fofaField(leaf)+"="+fofaQuote(v))
		}
		return "(" + strings.Join(parts, " || ") + ")", nil, true, nil
	case querylang.OpBetween:
		return fofaBetween(leaf)
	case querylang.OpGreater, querylang.OpGreaterOrEqual, querylang.OpLess, querylang.OpLessOrEqual:
		op := map[querylang.Operator]string{
			querylang.OpGreater: ">", querylang.OpGreaterOrEqual: ">=",
			querylang.OpLess: "<", querylang.OpLessOrEqual: "<=",
		}[leaf.Op]
		field := fofaField(leaf)
		if leaf.Field == querylang.FieldFirstSeen || leaf.Field == querylang.FieldLastSeen {
			// FOFA time: after="YYYY-MM-DD", before="YYYY-MM-DD"
			if op == ">" || op == ">=" {
				return `after=` + fofaQuote(leaf.RawValue), altFor(leaf, `after=`+fofaQuote(leaf.RawValue), "FOFA time filters use the after/before keywords"), true, nil
			}
			return `before=` + fofaQuote(leaf.RawValue), altFor(leaf, `before=`+fofaQuote(leaf.RawValue), "FOFA time filters use the after/before keywords"), true, nil
		}
		return field + op + fofaQuote(leaf.RawValue), nil, true, nil
	}
	// default equality
	switch leaf.Kind {
	case querylang.KindNumber:
		return fofaField(leaf) + "=" + fmt.Sprint(leaf.Value), nil, true, nil
	case querylang.KindCIDR:
		return `ip=` + fofaQuote(leaf.RawValue), nil, true, nil
	default:
		return fofaField(leaf) + "=" + fofaQuote(leaf.RawValue), nil, true, nil
	}
}

func fofaBetween(leaf *querylang.LeafNode) (string, *querylang.AlternativeRendering, bool, error) {
	return betweenWithNote(leaf, "FOFA")
}

// betweenWithNote renders an interval in the field="x" && field="y" dialect
// shared by FOFA and Hunter, tagging the explanation with the engine name so
// an alternative report never names the wrong product.
func betweenWithNote(leaf *querylang.LeafNode, engine string) (string, *querylang.AlternativeRendering, bool, error) {
	switch leaf.Kind {
	case querylang.KindPortRange:
		pr, _ := leaf.Value.(*querylang.PortRangeValue)
		emitted := fmt.Sprintf("(port>=\"%d\" && port<=\"%d\")", pr.Low, pr.High)
		return emitted, altFor(leaf, emitted, engine+" expresses intervals as two inequalities joined by &&"), true, nil
	case querylang.KindIPRange:
		ipr, _ := leaf.Value.(*querylang.IPRangeValue)
		emitted := fmt.Sprintf("(ip>=\"%s\" && ip<=\"%s\")", ipr.Start, ipr.End)
		return emitted, altFor(leaf, emitted, engine+" lacks a native range field; string inequalities approximate the address interval"), true, nil
	case querylang.KindTimeRange:
		tr, _ := leaf.Value.(*querylang.TimeRangeValue)
		emitted := fmt.Sprintf(`(after="%s" && before="%s")`, tr.From, tr.To)
		return emitted, altFor(leaf, emitted, engine+" time windows combine after and before"), true, nil
	default:
		return "", nil, false, fmt.Errorf("unsupported BETWEEN kind %s", leaf.Kind)
	}
}

func fofaField(leaf *querylang.LeafNode) string {
	if m := map[string]string{
		querylang.FieldCertFingerprint: "cert",
	}[leaf.Field]; m != "" {
		return m
	}
	return leaf.Field
}

func fofaQuote(s string) string {
	return `"` + fofaEscape(s, '"') + `"`
}

func altFor(leaf *querylang.LeafNode, emitted, explanation string) *querylang.AlternativeRendering {
	return &querylang.AlternativeRendering{Condition: leaf.String(), Emitted: emitted, Explanation: explanation}
}
