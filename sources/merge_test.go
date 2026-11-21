package sources

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeHostForms(t *testing.T) {
	tests := []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"Example.COM", "example.com", 0},
		{"https://Example.com/", "example.com", 443},
		{"http://example.com:8080/path", "example.com", 8080},
		{"example.com:8443", "example.com", 8443},
		{"example.com.", "example.com", 0},
		{"  EXAMPLE.com  ", "example.com", 0},
	}
	for _, tt := range tests {
		host, port := NormalizeHost(tt.in)
		require.Equal(t, tt.wantHost, host, "host of %q", tt.in)
		require.Equal(t, tt.wantPort, port, "port of %q", tt.in)
	}
}

func TestAssetKeyNormalization(t *testing.T) {
	// All of these describe the same asset in different engine formats and
	// must collapse to one identity.
	base := AssetKey(Result{Host: "example.com", Port: 443})
	require.Equal(t, base, AssetKey(Result{Host: "Example.COM", Port: 443}))
	require.Equal(t, base, AssetKey(Result{Host: "example.com:443"}))
	require.Equal(t, base, AssetKey(Result{Host: "https://example.com/"}))
	require.Equal(t, base, AssetKey(Result{Url: "https://example.com:443/login"}))
	require.Equal(t, base, AssetKey(Result{Url: "https://example.com"}))

	// Default port differs per scheme: http and https are different assets.
	require.NotEqual(t, AssetKey(Result{Url: "http://example.com"}), base)

	// IP results identify by ip:port, independent of host.
	require.Equal(t,
		AssetKey(Result{IP: "1.2.3.4", Port: 80}),
		AssetKey(Result{IP: "1.2.3.4", Port: 80, Host: "other.example"}))

	// No identity at all: malformed.
	require.Empty(t, AssetKey(Result{}))
}

func TestMergerMergesSameAssetKeepingSources(t *testing.T) {
	m := NewMerger()
	m.Add(Result{Source: "shodan", IP: "1.2.3.4", Port: 443})
	m.Add(Result{Source: "censys", IP: "1.2.3.4", Port: 443})
	m.Add(Result{Source: "fofa", IP: "1.2.3.4", Port: 443})
	// duplicate from the same engine must not inflate confidence
	m.Add(Result{Source: "fofa", IP: "1.2.3.4", Port: 443})
	m.Add(Result{Source: "shodan", IP: "9.9.9.9", Port: 53})

	merged := m.Finalize()
	require.Len(t, merged.Assets, 2)

	first := merged.Assets[0]
	require.Equal(t, 3, first.Confidence())
	require.Equal(t, []string{"censys", "fofa", "shodan"}, first.Sources)
	// original forms are preserved
	require.Len(t, first.Results, 4)

	second := merged.Assets[1]
	require.Equal(t, 1, second.Confidence())
	require.Equal(t, []string{"shodan"}, second.Sources)
}

func TestMergerOrdersByConfidenceThenKey(t *testing.T) {
	m := NewMerger()
	m.Add(Result{Source: "shodan", IP: "9.9.9.9", Port: 53})
	m.Add(Result{Source: "shodan", IP: "1.1.1.1", Port: 80})
	m.Add(Result{Source: "censys", IP: "1.1.1.1", Port: 80})
	m.Add(Result{Source: "fofa", IP: "8.8.8.8", Port: 53})
	m.Add(Result{Source: "quake", IP: "8.8.8.8", Port: 53})

	merged := m.Finalize()
	require.Len(t, merged.Assets, 3)
	// confidence 2 assets first, ordered by key between themselves
	require.Equal(t, 2, merged.Assets[0].Confidence())
	require.Equal(t, 2, merged.Assets[1].Confidence())
	require.Less(t, merged.Assets[0].Key, merged.Assets[1].Key)
	require.Equal(t, 1, merged.Assets[2].Confidence())
}

func TestMergerIsDeterministicAcrossInsertionOrders(t *testing.T) {
	build := func(order []Result) *MergeResult {
		m := NewMerger()
		for _, r := range order {
			m.Add(r)
		}
		return m.Finalize()
	}
	results := []Result{
		{Source: "shodan", IP: "1.1.1.1", Port: 80},
		{Source: "censys", IP: "1.1.1.1", Port: 80},
		{Source: "fofa", IP: "2.2.2.2", Port: 22},
		{Source: "quake", Host: "Example.com", Url: "https://example.com"},
		{Source: "shodan", Host: "example.com", Port: 443},
	}
	forward := build(results)
	reversed := build([]Result{results[4], results[3], results[2], results[1], results[0]})

	require.Equal(t, len(forward.Assets), len(reversed.Assets))
	for i := range forward.Assets {
		require.Equal(t, forward.Assets[i].Key, reversed.Assets[i].Key)
		require.Equal(t, forward.Assets[i].Sources, reversed.Assets[i].Sources)
	}
	// the two forms of example.com:443 merged into one asset
	require.Len(t, forward.Assets, 3)
}

func TestMergerSkipsAndCountsMalformed(t *testing.T) {
	m := NewMerger()
	m.Add(Result{Source: "shodan", IP: "1.1.1.1", Port: 80})
	m.Add(Result{Source: "shodan"}) // no ip, host or url: malformed
	m.Add(Result{Source: "shodan"}) // another one

	merged := m.Finalize()
	require.Len(t, merged.Assets, 1)
	require.Len(t, merged.Engines, 1)
	require.Equal(t, 2, merged.Engines[0].Malformed)
	require.Equal(t, 1, merged.Engines[0].Results)
	require.Equal(t, EngineStateOK, merged.Engines[0].State)
}

func TestMergerDistinguishesEmptyFromError(t *testing.T) {
	m := NewMerger()
	m.NoteEngineStart("shodan")
	m.NoteEngineStart("censys")
	m.NoteEngineStart("fofa")
	m.NoteEngineStart("quake")
	m.Add(Result{Source: "shodan", IP: "1.1.1.1", Port: 80})
	// censys started but streamed nothing: empty, not an error
	m.NoteEngineError("fofa", errTest)
	m.Add(Result{Source: "quake", Error: errTest})

	merged := m.Finalize()

	states := map[string]EngineReport{}
	for _, e := range merged.Engines {
		states[e.Name] = e
	}
	require.Equal(t, EngineStateOK, states["shodan"].State)
	require.Equal(t, EngineStateEmpty, states["censys"].State)
	require.Empty(t, states["censys"].Err)
	require.Equal(t, EngineStateError, states["fofa"].State)
	require.Equal(t, "test error", states["fofa"].Err)
	require.Equal(t, EngineStateError, states["quake"].State)
	require.False(t, merged.AllEnginesFailed())
}

var errTest = errorString("test error")

type errorString string

func (e errorString) Error() string { return string(e) }
