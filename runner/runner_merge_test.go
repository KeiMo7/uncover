package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/uncover"
	"github.com/projectdiscovery/uncover/sources"
	"github.com/stretchr/testify/require"
)

type stubAgent struct {
	name     string
	queryErr error
	results  []sources.Result
}

func (a *stubAgent) Name() string { return a.name }

func (a *stubAgent) Query(ctx context.Context, session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if a.queryErr != nil {
		return nil, a.queryErr
	}
	ch := make(chan sources.Result)
	go func() {
		defer close(ch)
		for _, r := range a.results {
			r.Source = a.name
			if !sources.SendResult(ctx, ch, r) {
				return
			}
		}
	}()
	return ch, nil
}

func newMergeRunner(t *testing.T, outputFile string, agents ...sources.Agent) *Runner {
	t.Helper()
	names := make([]string, 0, len(agents))
	for _, a := range agents {
		names = append(names, a.Name())
	}
	writer, err := NewOutputWriter()
	require.NoError(t, err)
	return &Runner{
		options: &Options{
			Merge:        true,
			OutputFile:   outputFile,
			OutputFields: "ip:port",
			Verbose:      true, // keep stdout out of the test; file is what we assert on
		},
		service: &uncover.Service{
			Agents:   agents,
			Options:  &uncover.Options{Agents: names, Queries: []string{"test"}},
			Provider: &sources.Provider{},
			Session:  &sources.Session{},
		},
		outputWriter: writer,
	}
}

func TestRunMergedWritesSourcesAndConfidence(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.txt")
	r := newMergeRunner(t, out,
		&stubAgent{name: "shodan-idb", results: []sources.Result{
			{IP: "1.1.1.1", Port: 80},
			{IP: "2.2.2.2", Port: 443},
		}},
		&stubAgent{name: "scanmalware", results: []sources.Result{
			{IP: "1.1.1.1", Port: 80},
		}},
	)

	require.NoError(t, r.Run(context.Background()))

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 2)
	// confidence 2 first, then confidence 1
	require.Equal(t, "1.1.1.1:80\tsources=scanmalware,shodan-idb\tconfidence=2", lines[0])
	require.Equal(t, "2.2.2.2:443\tsources=shodan-idb\tconfidence=1", lines[1])
	// no temp file left behind
	_, err = os.Stat(out + ".tmp")
	require.True(t, os.IsNotExist(err))
}

func TestRunMergedJSONKeepsStructuredSources(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.json")
	r := newMergeRunner(t, out,
		&stubAgent{name: "shodan-idb", results: []sources.Result{{IP: "1.1.1.1", Port: 80}}},
		&stubAgent{name: "scanmalware", results: []sources.Result{{IP: "1.1.1.1", Port: 80}}},
	)
	r.options.JSON = true

	require.NoError(t, r.Run(context.Background()))

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	line := strings.TrimSpace(string(data))
	require.Contains(t, line, `"sources":["scanmalware","shodan-idb"]`)
	require.Contains(t, line, `"confidence":2`)
	require.Contains(t, line, `"asset":"1.1.1.1:80"`)
}

func TestRunMergedAllEnginesFailLeavesExistingFileUntouched(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.txt")
	require.NoError(t, os.WriteFile(out, []byte("previous run\n"), 0o644))

	r := newMergeRunner(t, out,
		&stubAgent{name: "shodan-idb", queryErr: errors.New("timeout")},
		&stubAgent{name: "scanmalware", queryErr: errors.New("boom")},
	)

	err := r.Run(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "all engines failed")

	// the pre-existing output file is not truncated or half-overwritten
	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr)
	require.Equal(t, "previous run\n", string(data))
	_, statErr := os.Stat(out + ".tmp")
	require.True(t, os.IsNotExist(statErr))
}

func TestFormatResultFieldsMatchesLegacyRendering(t *testing.T) {
	require.Equal(t, "1.2.3.4:443", formatResultFields("ip:port", sources.Result{IP: "1.2.3.4", Port: 443}))
	// legacy fallback: no ip or port 0 with ip/port fields -> host
	require.Equal(t, "a.example", formatResultFields("ip:port", sources.Result{Host: "a.example"}))
	require.Equal(t, "https://1.2.3.4:443/x", formatResultFields("https://ip:port/x", sources.Result{IP: "1.2.3.4", Port: 443}))
}
