package backends

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/uncover/querylang"
)

// Quake 360 query language (https://quake.360.net): Lucene-like
// `field:"value"` predicates, AND/OR/NOT keywords, parentheses, ranges as
// `field:["a" TO "b"]`.
func Quake() querylang.Backend {
	fieldNames := map[string]string{
		querylang.FieldDomain:          "domain",
		querylang.FieldSubdomain:       "hostname",
		querylang.FieldHostname:        "hostname",
		querylang.FieldIP:              "ip",
		querylang.FieldCIDR:            "ip",
		querylang.FieldIPRange:         "ip",
		querylang.FieldPort:            "port",
		querylang.FieldPortRange:       "port",
		querylang.FieldProtocol:        "transport",
		querylang.FieldService:         "service.name",
		querylang.FieldTitle:           "service.http.title",
		querylang.FieldHeader:          "service.http.response_headers",
		querylang.FieldStatusCode:      "service.http.status_code",
		querylang.FieldBody:            "service.http.body",
		querylang.FieldCert:            "certificates",
		querylang.FieldCertCN:          "certificates.subject_cn",
		querylang.FieldCertIssuer:      "certificates.issuer_cn",
		querylang.FieldCertIssuerOrg:   "certificates.issuer_org",
		querylang.FieldCertSubject:     "certificates.subject_cn",
		querylang.FieldCertOrg:         "certificates.subject_org",
		querylang.FieldCertFingerprint: "certificates.fingerprint",
		querylang.FieldFirstSeen:       "starttime",
		querylang.FieldLastSeen:        "time",
		querylang.FieldASN:             "asn",
		querylang.FieldOrg:             "organization",
		querylang.FieldOS:              "os_name",
		querylang.FieldProduct:         "service.product",
		querylang.FieldCountry:         "location.country_cn",
		querylang.FieldRaw:             "service.banner",
	}
	caps := querylang.Capabilities{
		Engine:           "quake",
		SupportsNot:      true,
		SupportsNestedOr: true,
		Fields:           quakeCaps(),
	}
	d := querylang.Dialect{
		FieldNames:     fieldNames,
		AndToken:       "AND",
		OrToken:        "OR",
		NotToken:       "NOT",
		Quote:          '"',
		FieldSeparator: ":",
		Escape:         luceneEscape,
		RenderLeaf:     quakeLeaf,
	}
	return querylang.NewGenericBackend("quake", caps, d)
}

func quakeCaps() map[string]querylang.FieldCapability {
	fields := map[string]querylang.FieldCapability{}
	for _, f := range []string{
		querylang.FieldDomain, querylang.FieldSubdomain, querylang.FieldHostname,
		querylang.FieldTitle, querylang.FieldHeader, querylang.FieldBody,
		querylang.FieldCert, querylang.FieldCertCN, querylang.FieldCertIssuer,
		querylang.FieldCertIssuerOrg, querylang.FieldCertSubject, querylang.FieldCertOrg,
		querylang.FieldOrg, querylang.FieldProduct, querylang.FieldRaw,
	} {
		fields[f] = querylang.FieldCapability{Field: f, SupportedOps: containsOps}
	}
	fields[querylang.FieldIP] = querylang.FieldCapability{Field: querylang.FieldIP, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpIn}}
	fields[querylang.FieldCIDR] = querylang.FieldCapability{Field: querylang.FieldCIDR, SupportedOps: eqNeq}
	fields[querylang.FieldIPRange] = querylang.FieldCapability{Field: querylang.FieldIPRange, SupportedOps: []querylang.Operator{querylang.OpBetween}}
	fields[querylang.FieldPort] = querylang.FieldCapability{Field: querylang.FieldPort, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpIn, querylang.OpGreater, querylang.OpLess}}
	fields[querylang.FieldPortRange] = querylang.FieldCapability{Field: querylang.FieldPortRange, SupportedOps: []querylang.Operator{querylang.OpBetween}}
	fields[querylang.FieldProtocol] = querylang.FieldCapability{Field: querylang.FieldProtocol, SupportedOps: eqNeq}
	fields[querylang.FieldService] = querylang.FieldCapability{Field: querylang.FieldService, SupportedOps: eqNeq}
	fields[querylang.FieldStatusCode] = querylang.FieldCapability{Field: querylang.FieldStatusCode, SupportedOps: orderedOps}
	fields[querylang.FieldCertFingerprint] = querylang.FieldCapability{Field: querylang.FieldCertFingerprint, SupportedOps: eqNeq}
	fields[querylang.FieldFirstSeen] = querylang.FieldCapability{Field: querylang.FieldFirstSeen, SupportedOps: []querylang.Operator{querylang.OpGreater, querylang.OpGreaterOrEqual, querylang.OpLess, querylang.OpLessOrEqual, querylang.OpBetween}}
	fields[querylang.FieldLastSeen] = querylang.FieldCapability{Field: querylang.FieldLastSeen, SupportedOps: []querylang.Operator{querylang.OpGreater, querylang.OpGreaterOrEqual, querylang.OpLess, querylang.OpLessOrEqual, querylang.OpBetween}}
	fields[querylang.FieldASN] = querylang.FieldCapability{Field: querylang.FieldASN, SupportedOps: orderedOps}
	fields[querylang.FieldOS] = querylang.FieldCapability{Field: querylang.FieldOS, SupportedOps: eqNeq}
	fields[querylang.FieldCountry] = querylang.FieldCapability{Field: querylang.FieldCountry, SupportedOps: eqNeq}
	return fields
}

func quakeLeaf(leaf *querylang.LeafNode) (string, *querylang.AlternativeRendering, bool, error) {
	return luceneLeaf(leaf, quakeFieldName)
}

// luceneLeaf renders a leaf for any Lucene-dialect engine, resolving the
// native field name through the engine-specific mapper. Sharing the operator
// rendering while keeping the field tables separate is what prevents one
// engine's field name from leaking into another's query string.
func luceneLeaf(leaf *querylang.LeafNode, fieldName func(string) string) (string, *querylang.AlternativeRendering, bool, error) {
	native := fieldName(leaf.Field)
	switch leaf.Op {
	case querylang.OpBetween:
		return luceneRange(native, leaf)
	case querylang.OpIn:
		list, _ := leaf.Value.([]string)
		parts := make([]string, 0, len(list))
		for _, v := range list {
			parts = append(parts, native+":"+luceneQuote(v))
		}
		return "(" + strings.Join(parts, " OR ") + ")", nil, true, nil
	case querylang.OpNotEqual, querylang.OpNotContains:
		return "NOT " + native + ":" + luceneQuote(leaf.RawValue), nil, true, nil
	case querylang.OpGreater, querylang.OpGreaterOrEqual, querylang.OpLess, querylang.OpLessOrEqual:
		return native + luceneInequality(leaf), nil, true, nil
	default:
		if leaf.Kind == querylang.KindNumber {
			return native + ":" + fmt.Sprint(leaf.Value), nil, true, nil
		}
		return native + ":" + luceneQuote(leaf.RawValue), nil, true, nil
	}
}

func quakeFieldName(canonical string) string {
	return map[string]string{
		querylang.FieldDomain:          "domain",
		querylang.FieldSubdomain:       "hostname",
		querylang.FieldHostname:        "hostname",
		querylang.FieldIP:              "ip",
		querylang.FieldCIDR:            "ip",
		querylang.FieldIPRange:         "ip",
		querylang.FieldPort:            "port",
		querylang.FieldPortRange:       "port",
		querylang.FieldProtocol:        "transport",
		querylang.FieldService:         "service.name",
		querylang.FieldTitle:           "service.http.title",
		querylang.FieldHeader:          "service.http.response_headers",
		querylang.FieldStatusCode:      "service.http.status_code",
		querylang.FieldBody:            "service.http.body",
		querylang.FieldCert:            "certificates",
		querylang.FieldCertCN:          "certificates.subject_cn",
		querylang.FieldCertIssuer:      "certificates.issuer_cn",
		querylang.FieldCertIssuerOrg:   "certificates.issuer_org",
		querylang.FieldCertSubject:     "certificates.subject_cn",
		querylang.FieldCertOrg:         "certificates.subject_org",
		querylang.FieldCertFingerprint: "certificates.fingerprint",
		querylang.FieldFirstSeen:       "starttime",
		querylang.FieldLastSeen:        "time",
		querylang.FieldASN:             "asn",
		querylang.FieldOrg:             "organization",
		querylang.FieldOS:              "os_name",
		querylang.FieldProduct:         "service.product",
		querylang.FieldCountry:         "location.country_cn",
		querylang.FieldRaw:             "service.banner",
	}[canonical]
}

// ZoomEye v2 query language is Lucene-like as well: `field:"value"`,
// AND/OR/NOT, ranges `field:[low TO high]`.
func ZoomEye() querylang.Backend {
	fieldNames := map[string]string{
		querylang.FieldDomain:          "hostname",
		querylang.FieldSubdomain:       "hostname",
		querylang.FieldHostname:        "hostname",
		querylang.FieldIP:              "ip",
		querylang.FieldCIDR:            "ip",
		querylang.FieldIPRange:         "ip",
		querylang.FieldPort:            "port",
		querylang.FieldPortRange:       "port",
		querylang.FieldProtocol:        "service.transport",
		querylang.FieldService:         "service.name",
		querylang.FieldTitle:           "service.http.title",
		querylang.FieldHeader:          "service.http.header",
		querylang.FieldStatusCode:      "service.http.status_code",
		querylang.FieldBody:            "service.http.body",
		querylang.FieldCert:            "ssl.cert",
		querylang.FieldCertCN:          "ssl.cert.subject.cn",
		querylang.FieldCertIssuer:      "ssl.cert.issuer.cn",
		querylang.FieldCertIssuerOrg:   "ssl.cert.issuer.org",
		querylang.FieldCertSubject:     "ssl.cert.subject.cn",
		querylang.FieldCertOrg:         "ssl.cert.subject.organization",
		querylang.FieldCertFingerprint: "ssl.cert.fingerprint",
		querylang.FieldFirstSeen:       "time",
		querylang.FieldLastSeen:        "time",
		querylang.FieldASN:             "asn",
		querylang.FieldOrg:             "organization",
		querylang.FieldOS:              "os",
		querylang.FieldProduct:         "app",
		querylang.FieldCountry:         "geoinfo.country",
		querylang.FieldRaw:             "service.banner",
	}
	caps := querylang.Capabilities{
		Engine:           "zoomeye",
		SupportsNot:      true,
		SupportsNestedOr: true,
		Fields:           quakeCaps(), // same operator coverage, different names
		Notes:            []string{"ZoomEye's first-seen timestamp is not exposed separately; first_seen and last_seen both map to the time field."},
	}
	d := querylang.Dialect{
		FieldNames:     fieldNames,
		AndToken:       "AND",
		OrToken:        "OR",
		NotToken:       "NOT",
		Quote:          '"',
		FieldSeparator: ":",
		Escape:         luceneEscape,
		RenderLeaf: func(leaf *querylang.LeafNode) (string, *querylang.AlternativeRendering, bool, error) {
			return luceneLeaf(leaf, zoomeyeFieldName)
		},
	}
	return querylang.NewGenericBackend("zoomeye", caps, d)
}

func zoomeyeFieldName(canonical string) string {
	return map[string]string{
		querylang.FieldDomain:          "hostname",
		querylang.FieldSubdomain:       "hostname",
		querylang.FieldHostname:        "hostname",
		querylang.FieldIP:              "ip",
		querylang.FieldCIDR:            "ip",
		querylang.FieldIPRange:         "ip",
		querylang.FieldPort:            "port",
		querylang.FieldPortRange:       "port",
		querylang.FieldProtocol:        "service.transport",
		querylang.FieldService:         "service.name",
		querylang.FieldTitle:           "service.http.title",
		querylang.FieldHeader:          "service.http.header",
		querylang.FieldStatusCode:      "service.http.status_code",
		querylang.FieldBody:            "service.http.body",
		querylang.FieldCert:            "ssl.cert",
		querylang.FieldCertCN:          "ssl.cert.subject.cn",
		querylang.FieldCertIssuer:      "ssl.cert.issuer.cn",
		querylang.FieldCertIssuerOrg:   "ssl.cert.issuer.org",
		querylang.FieldCertSubject:     "ssl.cert.subject.cn",
		querylang.FieldCertOrg:         "ssl.cert.subject.organization",
		querylang.FieldCertFingerprint: "ssl.cert.fingerprint",
		querylang.FieldFirstSeen:       "time",
		querylang.FieldLastSeen:        "time",
		querylang.FieldASN:             "asn",
		querylang.FieldOrg:             "organization",
		querylang.FieldOS:              "os",
		querylang.FieldProduct:         "app",
		querylang.FieldCountry:         "geoinfo.country",
		querylang.FieldRaw:             "service.banner",
	}[canonical]
}

// Netlas Lucene query language: `field:value`, AND/OR/NOT, range queries.
func Netlas() querylang.Backend {
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
		querylang.FieldService:         "app_proto",
		querylang.FieldTitle:           "http.title",
		querylang.FieldHeader:          "http.headers",
		querylang.FieldStatusCode:      "http.status_code",
		querylang.FieldBody:            "http.body",
		querylang.FieldCert:            "certificate",
		querylang.FieldCertCN:          "certificate.subject.common_name",
		querylang.FieldCertIssuer:      "certificate.issuer.common_name",
		querylang.FieldCertIssuerOrg:   "certificate.issuer.organization",
		querylang.FieldCertSubject:     "certificate.subject.common_name",
		querylang.FieldCertOrg:         "certificate.subject.organization",
		querylang.FieldCertFingerprint: "certificate.fingerprint",
		querylang.FieldFirstSeen:       "last_updated",
		querylang.FieldLastSeen:        "last_updated",
		querylang.FieldASN:             "asn",
		querylang.FieldOrg:             "org",
		querylang.FieldOS:              "os",
		querylang.FieldProduct:         "software.name",
		querylang.FieldCountry:         "geo.country",
		querylang.FieldRaw:             "http.body",
	}
	caps := querylang.Capabilities{
		Engine:           "netlas",
		SupportsNot:      true,
		SupportsNestedOr: true,
		Fields:           quakeCaps(),
	}
	d := querylang.Dialect{
		FieldNames:     fieldNames,
		AndToken:       "AND",
		OrToken:        "OR",
		NotToken:       "NOT",
		Quote:          '"',
		FieldSeparator: ":",
		Escape:         luceneEscape,
		RenderLeaf: func(leaf *querylang.LeafNode) (string, *querylang.AlternativeRendering, bool, error) {
			return luceneLeaf(leaf, netlasFieldName)
		},
	}
	return querylang.NewGenericBackend("netlas", caps, d)
}

func netlasFieldName(canonical string) string {
	return map[string]string{
		querylang.FieldDomain:          "domain",
		querylang.FieldSubdomain:       "host",
		querylang.FieldHostname:        "host",
		querylang.FieldIP:              "ip",
		querylang.FieldCIDR:            "ip",
		querylang.FieldIPRange:         "ip",
		querylang.FieldPort:            "port",
		querylang.FieldPortRange:       "port",
		querylang.FieldProtocol:        "protocol",
		querylang.FieldService:         "app_proto",
		querylang.FieldTitle:           "http.title",
		querylang.FieldHeader:          "http.headers",
		querylang.FieldStatusCode:      "http.status_code",
		querylang.FieldBody:            "http.body",
		querylang.FieldCert:            "certificate",
		querylang.FieldCertCN:          "certificate.subject.common_name",
		querylang.FieldCertIssuer:      "certificate.issuer.common_name",
		querylang.FieldCertIssuerOrg:   "certificate.issuer.organization",
		querylang.FieldCertSubject:     "certificate.subject.common_name",
		querylang.FieldCertOrg:         "certificate.subject.organization",
		querylang.FieldCertFingerprint: "certificate.fingerprint",
		querylang.FieldFirstSeen:       "last_updated",
		querylang.FieldLastSeen:        "last_updated",
		querylang.FieldASN:             "asn",
		querylang.FieldOrg:             "org",
		querylang.FieldOS:              "os",
		querylang.FieldProduct:         "software.name",
		querylang.FieldCountry:         "geo.country",
		querylang.FieldRaw:             "http.body",
	}[canonical]
}

// Hunter (qianxin) grammar: `field="value"` joined by && / || like FOFA,
// with parenthesized groups and != operators.
func Hunter() querylang.Backend {
	fieldNames := map[string]string{
		querylang.FieldDomain:          "domain",
		querylang.FieldSubdomain:       "domain",
		querylang.FieldHostname:        "ip",
		querylang.FieldIP:              "ip",
		querylang.FieldCIDR:            "ip",
		querylang.FieldIPRange:         "ip",
		querylang.FieldPort:            "port",
		querylang.FieldPortRange:       "port",
		querylang.FieldProtocol:        "protocol",
		querylang.FieldService:         "app",
		querylang.FieldTitle:           "web.title",
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
		querylang.FieldFirstSeen:       "start_time",
		querylang.FieldLastSeen:        "end_time",
		querylang.FieldASN:             "asn",
		querylang.FieldOrg:             "company",
		querylang.FieldOS:              "os",
		querylang.FieldProduct:         "app",
		querylang.FieldCountry:         "country",
		querylang.FieldRaw:             "body",
	}
	caps := querylang.Capabilities{
		Engine:           "hunter",
		SupportsNot:      false,
		SupportsNestedOr: true,
		Fields:           hunterCaps(),
		Notes:            []string{"Hunter has no NOT-group syntax; only per-field != is available."},
	}
	d := querylang.Dialect{
		FieldNames:     fieldNames,
		AndToken:       "&&",
		OrToken:        "||",
		Quote:          '"',
		FieldSeparator: "=",
		Escape:         fofaEscape,
		RenderLeaf:     hunterLeaf,
	}
	return querylang.NewGenericBackend("hunter", caps, d)
}

func hunterCaps() map[string]querylang.FieldCapability {
	fields := map[string]querylang.FieldCapability{}
	for _, f := range []string{
		querylang.FieldDomain, querylang.FieldSubdomain, querylang.FieldTitle,
		querylang.FieldHeader, querylang.FieldBody, querylang.FieldCert,
		querylang.FieldCertCN, querylang.FieldCertIssuer, querylang.FieldCertIssuerOrg,
		querylang.FieldCertSubject, querylang.FieldCertOrg, querylang.FieldOrg,
		querylang.FieldProduct, querylang.FieldRaw,
	} {
		fields[f] = querylang.FieldCapability{Field: f, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpContains, querylang.OpNotContains}}
	}
	fields[querylang.FieldHostname] = querylang.FieldCapability{Field: querylang.FieldHostname, SupportedOps: eqNeq, Note: "Hunter search keys are IP-centric; hostname constraints map to ip/domain only"}
	fields[querylang.FieldIP] = querylang.FieldCapability{Field: querylang.FieldIP, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpIn}}
	fields[querylang.FieldCIDR] = querylang.FieldCapability{Field: querylang.FieldCIDR, SupportedOps: eqNeq}
	fields[querylang.FieldIPRange] = querylang.FieldCapability{Field: querylang.FieldIPRange, SupportedOps: []querylang.Operator{querylang.OpBetween}, Level: querylang.SupportDegradable, Note: "Hunter lacks an IP-range filter; only CIDR/single IP can be expressed"}
	fields[querylang.FieldPort] = querylang.FieldCapability{Field: querylang.FieldPort, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpIn}}
	fields[querylang.FieldPortRange] = querylang.FieldCapability{Field: querylang.FieldPortRange, SupportedOps: []querylang.Operator{querylang.OpBetween}}
	fields[querylang.FieldProtocol] = querylang.FieldCapability{Field: querylang.FieldProtocol, SupportedOps: eqNeq}
	fields[querylang.FieldService] = querylang.FieldCapability{Field: querylang.FieldService, SupportedOps: eqNeq}
	fields[querylang.FieldStatusCode] = querylang.FieldCapability{Field: querylang.FieldStatusCode, SupportedOps: orderedOps}
	fields[querylang.FieldCertFingerprint] = querylang.FieldCapability{Field: querylang.FieldCertFingerprint, SupportedOps: eqNeq, Level: querylang.SupportDegradable, Note: "Hunter only exposes generic cert content, not a dedicated fingerprint filter"}
	fields[querylang.FieldFirstSeen] = querylang.FieldCapability{Field: querylang.FieldFirstSeen, SupportedOps: []querylang.Operator{querylang.OpGreater, querylang.OpGreaterOrEqual, querylang.OpLess, querylang.OpLessOrEqual, querylang.OpBetween}}
	fields[querylang.FieldLastSeen] = querylang.FieldCapability{Field: querylang.FieldLastSeen, SupportedOps: []querylang.Operator{querylang.OpGreater, querylang.OpGreaterOrEqual, querylang.OpLess, querylang.OpLessOrEqual, querylang.OpBetween}}
	fields[querylang.FieldASN] = querylang.FieldCapability{Field: querylang.FieldASN, SupportedOps: orderedOps}
	fields[querylang.FieldOS] = querylang.FieldCapability{Field: querylang.FieldOS, SupportedOps: eqNeq}
	fields[querylang.FieldCountry] = querylang.FieldCapability{Field: querylang.FieldCountry, SupportedOps: eqNeq}
	return fields
}

func hunterLeaf(leaf *querylang.LeafNode) (string, *querylang.AlternativeRendering, bool, error) {
	native := hunterFieldName(leaf.Field)
	switch leaf.Op {
	case querylang.OpContains:
		return native + `*=` + fofaQuote(leaf.RawValue), nil, true, nil
	case querylang.OpNotContains:
		return native + `!*=` + fofaQuote(leaf.RawValue), nil, true, nil
	case querylang.OpNotEqual:
		return native + `!=` + fofaQuote(leaf.RawValue), nil, true, nil
	case querylang.OpIn:
		list, _ := leaf.Value.([]string)
		parts := make([]string, 0, len(list))
		for _, v := range list {
			parts = append(parts, native+"="+fofaQuote(v))
		}
		return "(" + strings.Join(parts, " || ") + ")", nil, true, nil
	case querylang.OpBetween:
		return hunterBetween(leaf)
	case querylang.OpGreater, querylang.OpGreaterOrEqual, querylang.OpLess, querylang.OpLessOrEqual:
		op := map[querylang.Operator]string{
			querylang.OpGreater: ">", querylang.OpGreaterOrEqual: ">=",
			querylang.OpLess: "<", querylang.OpLessOrEqual: "<=",
		}[leaf.Op]
		return native + op + fofaQuote(leaf.RawValue), nil, true, nil
	default:
		if leaf.Kind == querylang.KindNumber {
			return native + "=" + fmt.Sprint(leaf.Value), nil, true, nil
		}
		return native + "=" + fofaQuote(leaf.RawValue), nil, true, nil
	}
}

func hunterFieldName(canonical string) string {
	return map[string]string{
		querylang.FieldDomain:          "domain",
		querylang.FieldSubdomain:       "domain",
		querylang.FieldHostname:        "ip",
		querylang.FieldIP:              "ip",
		querylang.FieldCIDR:            "ip",
		querylang.FieldIPRange:         "ip",
		querylang.FieldPort:            "port",
		querylang.FieldPortRange:       "port",
		querylang.FieldProtocol:        "protocol",
		querylang.FieldService:         "app",
		querylang.FieldTitle:           "web.title",
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
		querylang.FieldFirstSeen:       "start_time",
		querylang.FieldLastSeen:        "end_time",
		querylang.FieldASN:             "asn",
		querylang.FieldOrg:             "company",
		querylang.FieldOS:              "os",
		querylang.FieldProduct:         "app",
		querylang.FieldCountry:         "country",
		querylang.FieldRaw:             "body",
	}[canonical]
}

// hunterBetween renders intervals in Hunter's dialect. Time windows use the
// engine's dedicated start_time/end_time fields rather than FOFA's
// after/before keywords; port/IP intervals reuse the && inequality shape.
func hunterBetween(leaf *querylang.LeafNode) (string, *querylang.AlternativeRendering, bool, error) {
	if leaf.Kind == querylang.KindTimeRange {
		tr, _ := leaf.Value.(*querylang.TimeRangeValue)
		emitted := fmt.Sprintf(`(start_time="%s" && end_time="%s")`, tr.From, tr.To)
		return emitted, altFor(leaf, emitted, "Hunter time windows use the start_time and end_time request fields"), true, nil
	}
	return betweenWithNote(leaf, "Hunter")
}

// GreyNoise GNQL grammar: `field:value` with AND/OR/NOT, small fixed field
// set. Everything outside the declared set is rejected so GNQL's quiet
// empty-result behavior on unknown terms can never masquerade as a real hit.
func GreyNoise() querylang.Backend {
	fieldNames := map[string]string{
		querylang.FieldIP:       "ip",
		querylang.FieldCIDR:     "ip",
		querylang.FieldPort:     "port",
		querylang.FieldProtocol: "transport_protocol",
		querylang.FieldService:  "actor",
		querylang.FieldOrg:      "organization",
		querylang.FieldCountry:  "country",
		querylang.FieldOS:       "os",
		querylang.FieldRaw:      "raw_data",
	}
	caps := querylang.Capabilities{
		Engine:           "greynoise",
		SupportsNot:      true,
		SupportsNestedOr: true,
		FreeTextOnly:     false,
		Fields: map[string]querylang.FieldCapability{
			querylang.FieldIP:       {Field: querylang.FieldIP, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpIn}},
			querylang.FieldCIDR:     {Field: querylang.FieldCIDR, SupportedOps: eqNeq},
			querylang.FieldPort:     {Field: querylang.FieldPort, SupportedOps: []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpIn}},
			querylang.FieldProtocol: {Field: querylang.FieldProtocol, SupportedOps: eqNeq},
			querylang.FieldService:  {Field: querylang.FieldService, SupportedOps: eqNeq, Note: "maps to GNQL actor classification, not a service banner"},
			querylang.FieldOrg:      {Field: querylang.FieldOrg, SupportedOps: containsOps},
			querylang.FieldCountry:  {Field: querylang.FieldCountry, SupportedOps: eqNeq},
			querylang.FieldOS:       {Field: querylang.FieldOS, SupportedOps: eqNeq},
			querylang.FieldRaw:      {Field: querylang.FieldRaw, SupportedOps: containsOps, AlternativeNames: []string{"raw_data"}},
		},
		Notes: []string{"GNQL returns an empty set for unknown fields without an error; the capability table rejects them client-side instead."},
	}
	d := querylang.Dialect{
		FieldNames:     fieldNames,
		AndToken:       "AND",
		OrToken:        "OR",
		NotToken:       "NOT",
		Quote:          '"',
		FieldSeparator: ":",
		Escape:         luceneEscape,
		RenderLeaf:     greynoiseLeaf,
	}
	return querylang.NewGenericBackend("greynoise", caps, d)
}

func greynoiseLeaf(leaf *querylang.LeafNode) (string, *querylang.AlternativeRendering, bool, error) {
	native := map[string]string{
		querylang.FieldIP: "ip", querylang.FieldCIDR: "ip", querylang.FieldPort: "port",
		querylang.FieldProtocol: "transport_protocol", querylang.FieldService: "actor",
		querylang.FieldOrg: "organization", querylang.FieldCountry: "country",
		querylang.FieldOS: "os", querylang.FieldRaw: "raw_data",
	}[leaf.Field]
	switch leaf.Op {
	case querylang.OpIn:
		list, _ := leaf.Value.([]string)
		parts := make([]string, 0, len(list))
		for _, v := range list {
			parts = append(parts, native+":"+luceneQuote(v))
		}
		return "(" + strings.Join(parts, " OR ") + ")", nil, true, nil
	case querylang.OpNotEqual, querylang.OpNotContains:
		return "NOT " + native + ":" + luceneQuote(leaf.RawValue), nil, true, nil
	default:
		if leaf.Kind == querylang.KindNumber {
			return native + ":" + fmt.Sprint(leaf.Value), nil, true, nil
		}
		return native + ":" + luceneQuote(leaf.RawValue), nil, true, nil
	}
}

// --- shared Lucene helpers ---

func luceneEscape(s string, quote byte) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, string(quote), `\`+string(quote))
}

func luceneQuote(s string) string {
	return `"` + luceneEscape(s, '"') + `"`
}

func luceneRange(native string, leaf *querylang.LeafNode) (string, *querylang.AlternativeRendering, bool, error) {
	switch leaf.Kind {
	case querylang.KindPortRange:
		pr, _ := leaf.Value.(*querylang.PortRangeValue)
		emitted := fmt.Sprintf("%s:[%d TO %d]", native, pr.Low, pr.High)
		return emitted, altFor(leaf, emitted, "Lucene inclusive range query [low TO high]"), true, nil
	case querylang.KindIPRange:
		ipr, _ := leaf.Value.(*querylang.IPRangeValue)
		emitted := fmt.Sprintf(`%s:["%s" TO "%s"]`, native, ipr.Start, ipr.End)
		return emitted, altFor(leaf, emitted, "Lucene inclusive range query over the string-form IP field"), true, nil
	case querylang.KindTimeRange:
		tr, _ := leaf.Value.(*querylang.TimeRangeValue)
		emitted := fmt.Sprintf(`%s:["%s" TO "%s"]`, native, tr.From, tr.To)
		return emitted, altFor(leaf, emitted, "Lucene inclusive time range"), true, nil
	default:
		return "", nil, false, fmt.Errorf("unsupported BETWEEN kind %s", leaf.Kind)
	}
}

func luceneInequality(leaf *querylang.LeafNode) string {
	switch leaf.Op {
	case querylang.OpGreater:
		return ":{" + luceneQuote(leaf.RawValue) + " TO *]"
	case querylang.OpGreaterOrEqual:
		return ":[" + luceneQuote(leaf.RawValue) + " TO *]"
	case querylang.OpLess:
		return ":[* TO " + luceneQuote(leaf.RawValue) + "}"
	case querylang.OpLessOrEqual:
		return ":[* TO " + luceneQuote(leaf.RawValue) + "]"
	default:
		return ":" + luceneQuote(leaf.RawValue)
	}
}
