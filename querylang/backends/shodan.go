package backends

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/uncover/querylang"
)

// Shodan filters documented at https://docs.shodan.io/search-filters.
// Shodan's query grammar: `filter:value`, space-separated AND, OR groups in
// parentheses, NOT prefix, free text as bare quoted terms.
func Shodan() querylang.Backend {
	fieldNames := map[string]string{
		querylang.FieldDomain:          "hostname",
		querylang.FieldSubdomain:       "hostname",
		querylang.FieldHostname:        "hostname",
		querylang.FieldIP:              "net",
		querylang.FieldCIDR:            "net",
		querylang.FieldIPRange:         "net",
		querylang.FieldPort:            "port",
		querylang.FieldPortRange:       "port",
		querylang.FieldProtocol:        "proto",
		querylang.FieldService:         "_shodan.service",
		querylang.FieldTitle:           "http.title",
		querylang.FieldHeader:          "http.header",
		querylang.FieldStatusCode:      "http.status",
		querylang.FieldBody:            "http.html",
		querylang.FieldCert:            "ssl",
		querylang.FieldCertCN:          "ssl.cert.subject.cn",
		querylang.FieldCertIssuer:      "ssl.cert.issuer.cn",
		querylang.FieldCertIssuerOrg:   "ssl.cert.issuer.o",
		querylang.FieldCertSubject:     "ssl.cert.subject.cn",
		querylang.FieldCertOrg:         "ssl.cert.subject.o",
		querylang.FieldCertFingerprint: "ssl.cert.fingerprint",
		querylang.FieldFirstSeen:       "_shodan.first_seen",
		querylang.FieldLastSeen:        "_shodan.last_seen",
		querylang.FieldASN:             "asn",
		querylang.FieldOrg:             "org",
		querylang.FieldOS:              "os",
		querylang.FieldProduct:         "product",
		querylang.FieldCountry:         "country",
		querylang.FieldRaw:             "_shodan.raw",
	}

	caps := querylang.Capabilities{
		Engine:           "shodan",
		SupportsNot:      true,
		SupportsNestedOr: true,
		Fields: map[string]querylang.FieldCapability{
			querylang.FieldDomain:          {Field: querylang.FieldDomain, SupportedOps: textOps, AlternativeNames: []string{"hostname"}},
			querylang.FieldSubdomain:       {Field: querylang.FieldSubdomain, SupportedOps: textOps, Note: "mapped to hostname: sub-tree matches use hostname:domain"},
			querylang.FieldHostname:        {Field: querylang.FieldHostname, SupportedOps: textOps},
			querylang.FieldIP:              {Field: querylang.FieldIP, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpIn}, AlternativeNames: []string{"net"}},
			querylang.FieldCIDR:            {Field: querylang.FieldCIDR, SupportedOps: eqNeq},
			querylang.FieldIPRange:         {Field: querylang.FieldIPRange, SupportedOps: []querylang.Operator{querylang.OpBetween, querylang.OpEqual}, Note: "Shodan has no native start-end range; expanded to OR-joined net/IP terms by the compiler"},
			querylang.FieldPort:            {Field: querylang.FieldPort, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpIn}},
			querylang.FieldPortRange:       {Field: querylang.FieldPortRange, SupportedOps: []querylang.Operator{querylang.OpBetween}, Note: "expanded to an OR group of port terms because Shodan lacks a range operator"},
			querylang.FieldProtocol:        {Field: querylang.FieldProtocol, SupportedOps: eqNeq, AlternativeNames: []string{"proto"}},
			querylang.FieldService:         {Field: querylang.FieldService, SupportedOps: eqNeq},
			querylang.FieldTitle:           {Field: querylang.FieldTitle, SupportedOps: containsOps, AlternativeNames: []string{"http.title"}},
			querylang.FieldHeader:          {Field: querylang.FieldHeader, SupportedOps: containsOps},
			querylang.FieldStatusCode:      {Field: querylang.FieldStatusCode, SupportedOps: orderedOps, AlternativeNames: []string{"http.status"}},
			querylang.FieldBody:            {Field: querylang.FieldBody, SupportedOps: containsOps, AlternativeNames: []string{"http.html"}},
			querylang.FieldCert:            {Field: querylang.FieldCert, SupportedOps: containsOps, AlternativeNames: []string{"ssl"}},
			querylang.FieldCertCN:          {Field: querylang.FieldCertCN, SupportedOps: textOps},
			querylang.FieldCertIssuer:      {Field: querylang.FieldCertIssuer, SupportedOps: textOps},
			querylang.FieldCertIssuerOrg:   {Field: querylang.FieldCertIssuerOrg, SupportedOps: textOps},
			querylang.FieldCertSubject:     {Field: querylang.FieldCertSubject, SupportedOps: textOps},
			querylang.FieldCertOrg:         {Field: querylang.FieldCertOrg, SupportedOps: textOps},
			querylang.FieldCertFingerprint: {Field: querylang.FieldCertFingerprint, SupportedOps: eqNeq},
			querylang.FieldFirstSeen:       {Field: querylang.FieldFirstSeen, SupportedOps: []querylang.Operator{querylang.OpGreater, querylang.OpGreaterOrEqual, querylang.OpLess, querylang.OpLessOrEqual, querylang.OpEqual, querylang.OpBetween}, AlternativeNames: []string{"_shodan.first_seen"}},
			querylang.FieldLastSeen:        {Field: querylang.FieldLastSeen, SupportedOps: []querylang.Operator{querylang.OpGreater, querylang.OpGreaterOrEqual, querylang.OpLess, querylang.OpLessOrEqual, querylang.OpEqual, querylang.OpBetween}, AlternativeNames: []string{"_shodan.last_seen"}},
			querylang.FieldASN:             {Field: querylang.FieldASN, SupportedOps: orderedOps},
			querylang.FieldOrg:             {Field: querylang.FieldOrg, SupportedOps: containsOps},
			querylang.FieldOS:              {Field: querylang.FieldOS, SupportedOps: eqNeq},
			querylang.FieldProduct:         {Field: querylang.FieldProduct, SupportedOps: textOps},
			querylang.FieldCountry:         {Field: querylang.FieldCountry, SupportedOps: eqNeq},
			querylang.FieldRaw:             {Field: querylang.FieldRaw, SupportedOps: containsOps, Level: querylang.SupportAlternative, Note: "emitted as an unqualified quoted term (full-text search)"},
		},
		Notes: []string{"Shodan ignores unknown filters silently at the API; the compiler rejects them before the request is sent."},
	}

	d := querylang.Dialect{
		FieldNames:     fieldNames,
		AndToken:       "", // space-joined conjunction
		OrToken:        "OR",
		NotToken:       "NOT",
		Quote:          '"',
		FieldSeparator: ":",
		Escape:         shodanEscape,
		RenderLeaf:     shodanLeaf,
	}
	return querylang.NewGenericBackend("shodan", caps, d)
}

func shodanEscape(s string, quote byte) string {
	return strings.ReplaceAll(s, string(quote), "\\"+string(quote))
}

func shodanLeaf(leaf *querylang.LeafNode) (string, *querylang.AlternativeRendering, bool, error) {
	switch leaf.Field {
	case querylang.FieldRaw:
		// Full-text: no filter prefix.
		return shodanQuote(leaf.RawValue), &querylang.AlternativeRendering{
			Condition: leaf.String(), Emitted: shodanQuote(leaf.RawValue),
			Explanation: "Shodan free-text terms carry no field prefix",
		}, true, nil
	case querylang.FieldPortRange:
		pr, ok := leaf.Value.(*querylang.PortRangeValue)
		if !ok {
			return "", nil, false, fmt.Errorf("invalid port range value")
		}
		terms := make([]string, 0, pr.High-pr.Low+1)
		for p := pr.Low; p <= pr.High; p++ {
			terms = append(terms, fmt.Sprintf("port:%d", p))
		}
		return "(" + strings.Join(terms, " OR ") + ")", &querylang.AlternativeRendering{
			Condition: leaf.String(), Emitted: "(" + strings.Join(terms, " OR ") + ")",
			Explanation: "Shodan lacks a port-range operator; the interval is expanded into an OR group",
		}, true, nil
	case querylang.FieldIPRange:
		ipr, ok := leaf.Value.(*querylang.IPRangeValue)
		if !ok {
			return "", nil, false, fmt.Errorf("invalid ip range value")
		}
		// Shodan accepts CIDR only; expose the exact bounds as OR terms and
		// explain that full range coverage requires CIDR supernet expansion.
		emitted := fmt.Sprintf("(net:%s OR net:%s)", shodanQuote(ipr.Start), shodanQuote(ipr.End))
		return emitted, &querylang.AlternativeRendering{
			Condition: leaf.String(), Emitted: emitted,
			Explanation: "Shodan only filters by CIDR/host; range endpoints are emitted as OR terms and the limitation is reported rather than hidden",
		}, true, nil
	case querylang.FieldIP:
		if leaf.Op == querylang.OpIn {
			list, _ := leaf.Value.([]string)
			terms := make([]string, 0, len(list))
			for _, ip := range list {
				terms = append(terms, "net:"+shodanQuote(ip))
			}
			return "(" + strings.Join(terms, " OR ") + ")", nil, true, nil
		}
	case querylang.FieldPort:
		if leaf.Op == querylang.OpIn {
			list, _ := leaf.Value.([]string)
			terms := make([]string, 0, len(list))
			for _, p := range list {
				terms = append(terms, "port:"+p)
			}
			return "(" + strings.Join(terms, " OR ") + ")", nil, true, nil
		}
	case querylang.FieldFirstSeen, querylang.FieldLastSeen:
		native := "_shodan.first_seen"
		if leaf.Field == querylang.FieldLastSeen {
			native = "_shodan.last_seen"
		}
		if leaf.Op == querylang.OpBetween {
			tr, ok := leaf.Value.(*querylang.TimeRangeValue)
			if !ok {
				return "", nil, false, fmt.Errorf("invalid time range value")
			}
			emitted := fmt.Sprintf("(%s:%s AND %s:%s)",
				native, shodanQuote(tr.From), native, shodanQuote(tr.To))
			return emitted, &querylang.AlternativeRendering{
				Condition: leaf.String(), Emitted: emitted,
				Explanation: "Shodan lacks a range operator; the time window is emitted as two timestamp filters",
			}, true, nil
		}
		return native + ":" + shodanQuote(leaf.RawValue), nil, true, nil
	}
	// Generic path handles everything else.
	return "", nil, false, nil
}

func shodanQuote(s string) string {
	return "\"" + shodanEscape(s, '"') + "\""
}
