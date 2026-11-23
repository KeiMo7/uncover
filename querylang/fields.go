package querylang

import "strings"

// Canonical fields defined by unified syntax v1. A field is a dimension a
// user can constrain; each backend maps these onto its own native field
// names. Keeping one canonical name per dimension is what makes the same
// query compile to equivalent constraints on every engine.
const (
	FieldDomain          = "domain"      // registered/parent domain, exact or sub-tree match per operator
	FieldSubdomain       = "subdomain"   // any label beneath the given domain
	FieldHostname        = "hostname"    // full host name
	FieldIP              = "ip"          // single address
	FieldCIDR            = "cidr"        // network segment
	FieldIPRange         = "ip_range"    // inclusive address range start-end
	FieldPort            = "port"        // single port
	FieldPortRange       = "port_range"  // inclusive port interval
	FieldProtocol        = "protocol"    // transport/network protocol, e.g. tcp, udp
	FieldService         = "service"     // service/application name, e.g. http, ssh, mysql
	FieldTitle           = "http.title"  // page title
	FieldHeader          = "http.header" // arbitrary response header content
	FieldStatusCode      = "http.status" // HTTP response status code
	FieldBody            = "http.body"   // response body content
	FieldCert            = "cert"        // any certificate field content
	FieldCertCN          = "cert.common_name"
	FieldCertIssuer      = "cert.issuer"
	FieldCertIssuerOrg   = "cert.issuer_org"
	FieldCertSubject     = "cert.subject"
	FieldCertOrg         = "cert.organization"
	FieldCertFingerprint = "cert.fingerprint" // SHA-1/SHA-256 fingerprint
	FieldFirstSeen       = "first_seen"       // time the asset was first observed
	FieldLastSeen        = "last_seen"        // time the asset was last observed
	FieldASN             = "asn"
	FieldOrg             = "organization" // hosting/network organization
	FieldOS              = "os"
	FieldProduct         = "product" // identified software product
	FieldCountry         = "country"
	FieldRaw             = "raw" // free-text full-text term
)

// fieldAliases maps every accepted spelling (including per-engine field names
// users already know) onto the canonical field. Alias resolution happens once
// at parse time, so compilers only ever deal with canonical fields.
//
// Adding an alias is always backward compatible; removing or retargeting one
// is not, and requires a syntax version bump.
var fieldAliases = map[string]string{
	// canonical self-entries
	FieldDomain: FieldDomain, FieldSubdomain: FieldSubdomain, FieldHostname: FieldHostname,
	FieldIP: FieldIP, FieldCIDR: FieldCIDR, FieldIPRange: FieldIPRange,
	FieldPort: FieldPort, FieldPortRange: FieldPortRange,
	FieldProtocol: FieldProtocol, FieldService: FieldService,
	FieldTitle: FieldTitle, FieldHeader: FieldHeader, FieldStatusCode: FieldStatusCode, FieldBody: FieldBody,
	FieldCert: FieldCert, FieldCertCN: FieldCertCN, FieldCertIssuer: FieldCertIssuer,
	FieldCertIssuerOrg: FieldCertIssuerOrg, FieldCertSubject: FieldCertSubject,
	FieldCertOrg: FieldCertOrg, FieldCertFingerprint: FieldCertFingerprint,
	FieldFirstSeen: FieldFirstSeen, FieldLastSeen: FieldLastSeen,
	FieldASN: FieldASN, FieldOrg: FieldOrg, FieldOS: FieldOS,
	FieldProduct: FieldProduct, FieldCountry: FieldCountry, FieldRaw: FieldRaw,

	// cross-engine aliases users naturally type
	"host":             FieldHostname,
	"host.name":        FieldHostname,
	"host_name":        FieldHostname,
	"name":             FieldHostname,
	"dom":              FieldDomain,
	"ip_address":       FieldIP,
	"ipaddr":           FieldIP,
	"address":          FieldIP,
	"net":              FieldCIDR,
	"network":          FieldCIDR,
	"ports":            FieldPort,
	"proto":            FieldProtocol,
	"transport":        FieldProtocol,
	"app":              FieldService,
	"app_proto":        FieldService,
	"banner":           FieldRaw,
	"html_title":       FieldTitle,
	"title":            FieldTitle,
	"http_title":       FieldTitle,
	"header":           FieldHeader,
	"status_code":      FieldStatusCode,
	"status":           FieldStatusCode,
	"body":             FieldBody,
	"html":             FieldBody,
	"ssl":              FieldCert,
	"tls":              FieldCert,
	"certificate":      FieldCert,
	"ssl.cert":         FieldCert,
	"cert.cn":          FieldCertCN,
	"common_name":      FieldCertCN,
	"cert.issuer_cn":   FieldCertIssuer,
	"issuer":           FieldCertIssuer,
	"issuer.org":       FieldCertIssuerOrg,
	"cert.subject_cn":  FieldCertSubject,
	"subject":          FieldCertSubject,
	"org_name":         FieldCertOrg,
	"cert.org":         FieldCertOrg,
	"fingerprint":      FieldCertFingerprint,
	"cert.sha1":        FieldCertFingerprint,
	"sha1":             FieldCertFingerprint,
	"sha256":           FieldCertFingerprint,
	"cert.sha256":      FieldCertFingerprint,
	"first_seen_time":  FieldFirstSeen,
	"last_seen_time":   FieldLastSeen,
	"time":             FieldLastSeen,
	"date":             FieldLastSeen,
	"asn_no":           FieldASN,
	"isp":              FieldOrg,
	"operating_system": FieldOS,
	"software":         FieldProduct,
	"country_name":     FieldCountry,
	"text":             FieldRaw,
	"q":                FieldRaw,
}

// resolveField normalizes a user-written field name to a canonical field.
// The returned ok is false for completely unknown fields; unknown fields are
// a parse error rather than being accepted and later ignored by an engine.
func resolveField(name string) (string, bool) {
	canonical, ok := fieldAliases[strings.ToLower(strings.TrimSpace(name))]
	return canonical, ok
}

// fieldValueKinds constrains which value shapes a field accepts. A leaf whose
// value kind is not listed here is a parse error, which catches mistakes like
// port = "nginx" before any engine sees the query.
var fieldValueKinds = map[string][]ValueKind{
	FieldDomain:          {KindString},
	FieldSubdomain:       {KindString},
	FieldHostname:        {KindString},
	FieldIP:              {KindIP, KindStringList},
	FieldCIDR:            {KindCIDR},
	FieldIPRange:         {KindIPRange},
	FieldPort:            {KindNumber, KindStringList},
	FieldPortRange:       {KindPortRange},
	FieldProtocol:        {KindString, KindStringList},
	FieldService:         {KindString},
	FieldTitle:           {KindString},
	FieldHeader:          {KindString},
	FieldStatusCode:      {KindNumber},
	FieldBody:            {KindString},
	FieldCert:            {KindString},
	FieldCertCN:          {KindString},
	FieldCertIssuer:      {KindString},
	FieldCertIssuerOrg:   {KindString},
	FieldCertSubject:     {KindString},
	FieldCertOrg:         {KindString},
	FieldCertFingerprint: {KindString},
	FieldFirstSeen:       {KindString, KindTimeRange},
	FieldLastSeen:        {KindString, KindTimeRange},
	FieldASN:             {KindNumber},
	FieldOrg:             {KindString},
	FieldOS:              {KindString},
	FieldProduct:         {KindString},
	FieldCountry:         {KindString},
	FieldRaw:             {KindString},
}

// fieldOperators constrains which operators make sense per field. An operator
// outside this set is rejected at parse time with a precise message.
var fieldOperators = map[string][]Operator{
	FieldDomain:    {OpEqual, OpNotEqual, OpContains, OpNotContains, OpRegex, OpIn},
	FieldSubdomain: {OpEqual, OpNotEqual, OpContains, OpNotContains, OpRegex},
	FieldHostname:  {OpEqual, OpNotEqual, OpContains, OpNotContains, OpRegex, OpIn},
	FieldIP:        {OpEqual, OpNotEqual, OpIn},
	FieldCIDR:      {OpEqual, OpNotEqual},
	FieldIPRange:   {OpBetween, OpEqual, OpNotEqual},
	FieldPort:      {OpEqual, OpNotEqual, OpGreater, OpGreaterOrEqual, OpLess, OpLessOrEqual, OpIn},
	FieldPortRange: {OpBetween, OpEqual},
	FieldProtocol:  {OpEqual, OpNotEqual, OpIn}, FieldService: {OpEqual, OpNotEqual, OpContains, OpNotContains, OpRegex, OpIn},
	FieldTitle:           {OpEqual, OpNotEqual, OpContains, OpNotContains, OpRegex},
	FieldHeader:          {OpEqual, OpNotEqual, OpContains, OpNotContains, OpRegex},
	FieldStatusCode:      {OpEqual, OpNotEqual, OpGreater, OpGreaterOrEqual, OpLess, OpLessOrEqual},
	FieldBody:            {OpEqual, OpNotEqual, OpContains, OpNotContains, OpRegex},
	FieldCert:            {OpContains, OpNotContains, OpEqual, OpNotEqual, OpRegex},
	FieldCertCN:          {OpEqual, OpNotEqual, OpContains, OpNotContains, OpRegex},
	FieldCertIssuer:      {OpEqual, OpNotEqual, OpContains, OpNotContains, OpRegex},
	FieldCertIssuerOrg:   {OpEqual, OpNotEqual, OpContains, OpNotContains, OpRegex},
	FieldCertSubject:     {OpEqual, OpNotEqual, OpContains, OpNotContains, OpRegex},
	FieldCertOrg:         {OpEqual, OpNotEqual, OpContains, OpNotContains, OpRegex},
	FieldCertFingerprint: {OpEqual, OpNotEqual},
	FieldFirstSeen:       {OpEqual, OpGreater, OpGreaterOrEqual, OpLess, OpLessOrEqual, OpBetween},
	FieldLastSeen:        {OpEqual, OpGreater, OpGreaterOrEqual, OpLess, OpLessOrEqual, OpBetween},
	FieldASN:             {OpEqual, OpNotEqual, OpGreater, OpGreaterOrEqual, OpLess, OpLessOrEqual},
	FieldOrg:             {OpEqual, OpNotEqual, OpContains, OpNotContains, OpRegex},
	FieldOS:              {OpEqual, OpNotEqual, OpContains, OpNotContains},
	FieldProduct:         {OpEqual, OpNotEqual, OpContains, OpNotContains, OpRegex},
	FieldCountry:         {OpEqual, OpNotEqual, OpIn},
	FieldRaw:             {OpContains, OpNotContains, OpEqual, OpNotEqual, OpRegex},
}

func allowsKind(field string, kind ValueKind) bool {
	for _, k := range fieldValueKinds[field] {
		if k == kind {
			return true
		}
	}
	return false
}

func allowsOperator(field string, op Operator) bool {
	for _, o := range fieldOperators[field] {
		if o == op {
			return true
		}
	}
	return false
}
