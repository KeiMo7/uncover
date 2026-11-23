package backends

import (
	"github.com/projectdiscovery/uncover/querylang"
)

// freeTextBackends accept a single raw text term and cannot express any
// structured field filter. Rather than pretending (which would silently
// widen the result set), their capability table rejects every structured
// leaf with a precise message, and raw:'term' compiles to the bare term.
var freeTextEngines = map[string]string{
	"publicwww":       "publicwww source-code search only accepts free-text terms",
	"google":          "custom-search engines only accept free-text query terms",
	"nerdydata":       "NerdyData accepts free-text source-code terms",
	"shodan-idb":      "Shodan InternetDB is a per-IP/CIDR lookup service with no search filters",
	"subdomaincenter": "SubdomainCenter takes a domain term only",
	"scanmalware":     "scanmalware takes a domain/IP term only",
	"binaryedge":      "the uncover BinaryEdge integration only forwards free-text terms",
	"onyphe":          "the uncover Onyphe integration only forwards free-text terms",
	"driftnet":        "the uncover Driftnet integration only forwards free-text terms",
	"daydaymap":       "the uncover DayDayMap integration only forwards free-text terms",
	"odin":            "the uncover Odin integration only forwards free-text terms",
	"criminalip":      "the uncover CriminalIP integration only forwards free-text terms",
	"hunterhow":       "the uncover HunterHow integration only forwards free-text terms",
}

type freeTextBackend struct {
	name string
	note string
	caps querylang.Capabilities
}

func (b *freeTextBackend) Name() string                         { return b.name }
func (b *freeTextBackend) Capabilities() querylang.Capabilities { return b.caps }

func (b *freeTextBackend) Render(tree querylang.Node, drops []querylang.Degradation) (string, []querylang.AlternativeRendering, error) {
	leaves := querylang.Leaves(tree)
	if len(leaves) != 1 || leaves[0].Field != querylang.FieldRaw {
		// Unreachable under compiler capability checks, kept as a guard.
		return "", nil, &querylang.CompileError{
			Engine: b.name,
			Reason: b.note + "; use raw:'term' for this engine",
		}
	}
	return leaves[0].RawValue, []querylang.AlternativeRendering{{
		Condition:   leaves[0].String(),
		Emitted:     leaves[0].RawValue,
		Explanation: b.note,
	}}, nil
}

// DefaultCompiler builds a compiler with every engine backend registered.
// mode controls degradation policy for engines that can only partially
// express a query; the default in callers should be DegradeReject.
func DefaultCompiler(mode querylang.DegradationMode) *querylang.Compiler {
	c := querylang.NewCompiler(mode)
	registerAll(c)
	return c
}

// CompilerForEngines builds a compiler containing only the named engines.
// Unknown names produce no backend (the caller validates engine names
// separately).
func CompilerForEngines(mode querylang.DegradationMode, engines []string) *querylang.Compiler {
	c := querylang.NewCompiler(mode)
	seen := map[string]bool{}
	for _, name := range engines {
		if seen[name] {
			continue
		}
		seen[name] = true
		if b := lookupBackend(name); b != nil {
			c.Register(b)
		}
	}
	return c
}

func lookupBackend(name string) querylang.Backend {
	switch name {
	case "shodan":
		return Shodan()
	case "censys":
		return Censys()
	case "fofa":
		return Fofa()
	case "quake":
		return Quake()
	case "zoomeye":
		return ZoomEye()
	case "netlas":
		return Netlas()
	case "hunter":
		return Hunter()
	case "greynoise":
		return GreyNoise()
	default:
		if note, ok := freeTextEngines[name]; ok {
			return newFreeTextBackend(name, note)
		}
		return nil
	}
}

func newFreeTextBackend(name, note string) querylang.Backend {
	caps := querylang.Capabilities{
		Engine:       name,
		FreeTextOnly: true,
		SupportsNot:  false,
		Fields: map[string]querylang.FieldCapability{
			querylang.FieldRaw: {
				Field:        querylang.FieldRaw,
				SupportedOps: []querylang.Operator{querylang.OpContains, querylang.OpEqual},
				Note:         note,
			},
		},
		Notes: []string{note},
	}
	return &freeTextBackend{name: name, note: note, caps: caps}
}

func registerAll(c *querylang.Compiler) {
	c.Register(Shodan())
	c.Register(Censys())
	c.Register(Fofa())
	c.Register(Quake())
	c.Register(ZoomEye())
	c.Register(Netlas())
	c.Register(Hunter())
	c.Register(GreyNoise())

	for name, note := range freeTextEngines {
		c.Register(newFreeTextBackend(name, note))
	}
}
