package uncover

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/projectdiscovery/uncover/sources"
	"github.com/stretchr/testify/require"
)

// TestExecuteQuotaOutputMatchesLegacy is the before/after comparison for the
// same input: with quota disabled the result stream is unchanged; with quota
// enabled the results are identical and the only new output is the report.
func TestExecuteQuotaOutputMatchesLegacy(t *testing.T) {
	collect := func(ch <-chan sources.Result) []string {
		var out []string
		for res := range ch {
			if res.Error != nil {
				continue
			}
			out = append(out, fmt.Sprintf("%s|%s|%d", res.Source, res.IP, res.Port))
		}
		sort.Strings(out)
		return out
	}

	legacyAgents := []*quotaMockAgent{{name: "shodan", results: 2}, {name: "fofa", results: 2}}
	legacy := newQuotaService(t, nil, []string{"test"}, legacyAgents...)
	legacyCh, err := legacy.Execute(context.Background())
	require.NoError(t, err)
	legacyResults := collect(legacyCh)
	require.NotNil(t, legacyResults)

	quotaAgents := []*quotaMockAgent{{name: "shodan", results: 2}, {name: "fofa", results: 2}}
	quotaService := newQuotaService(t, &sources.QuotaConfig{
		Engines: map[string]*sources.EngineQuota{
			"shodan": {Limit: intPtr(100)},
			"fofa":   {Limit: intPtr(100)},
		},
	}, []string{"test"}, quotaAgents...)
	quotaCh, err := quotaService.Execute(context.Background())
	require.NoError(t, err)
	quotaResults := collect(quotaCh)

	require.Equal(t, legacyResults, quotaResults, "result stream must be identical")

	// The difference is confined to the report, which only exists with quota on.
	require.Nil(t, legacy.Report())
	report := quotaService.Report()
	require.NotNil(t, report)
	require.Len(t, report.Engines, 2)
}
