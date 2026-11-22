package runner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/uncover/sources"
	"github.com/stretchr/testify/require"
)

func TestQuotaOptionsDisabledByDefault(t *testing.T) {
	options := &Options{Engine: []string{"shodan"}}
	cfg, err := options.QuotaOptions()
	require.NoError(t, err)
	require.Nil(t, cfg)
}

func TestQuotaOptionsEnableFlagWithoutFile(t *testing.T) {
	options := &Options{Engine: []string{"shodan"}, Quota: true}
	cfg, err := options.QuotaOptions()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	// No limits means the run uses the built-in defaults but still reports.
	manager, err := sources.NewQuotaManager(cfg, options.Engine)
	require.NoError(t, err)
	require.Nil(t, manager.Usage("shodan").Limit)
}

func TestQuotaOptionsLoadsAndValidatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "quota.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
engines:
  shodan:
    limit: 10
`), 0644))

	options := &Options{Engine: []string{"shodan"}, QuotaFile: path}
	cfg, err := options.QuotaOptions()
	require.NoError(t, err)
	require.NotNil(t, cfg)
}

func TestQuotaOptionsRejectsInvalidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "quota.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
engines:
  shodan:
    limit: -5
`), 0644))

	options := &Options{Engine: []string{"shodan"}, QuotaFile: path}
	_, err := options.QuotaOptions()
	require.Error(t, err)
	require.Contains(t, err.Error(), "engines.shodan.limit")
	require.Contains(t, err.Error(), path)
}

func TestQuotaOptionsRejectsUnknownEngine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "quota.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
engines:
  not-a-real-engine:
    limit: 1
`), 0644))

	options := &Options{Engine: []string{"shodan"}, QuotaFile: path}
	_, err := options.QuotaOptions()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown engine")
}
