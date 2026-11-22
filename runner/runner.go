package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/uncover"
	"github.com/projectdiscovery/uncover/sources"
	errorutil "github.com/projectdiscovery/utils/errors"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// Runner is an instance of the uncover enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options      *Options
	service      *uncover.Service
	outputWriter *OutputWriter
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists
// and setting up loggers, etc.
func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{options: options}
	appendAllQueries(options)

	quotaConfig, err := options.QuotaOptions()
	if err != nil {
		return nil, errorutil.New("invalid quota configuration: %s", err)
	}

	opts := uncover.Options{
		Agents:  options.Engine,
		Queries: options.Query,
		Limit:   options.Limit,
		Proxy:   options.Proxy,
		Quota:   quotaConfig,
	}
	service, err := uncover.New(&opts)
	if err != nil {
		return nil, err
	}
	runner.service = service

	runner.outputWriter, err = NewOutputWriter()
	if err != nil {
		return nil, err
	}

	if !options.Verbose {
		runner.outputWriter.AddWriters(os.Stdout)
	}
	if runner.options.OutputFile != "" {
		outputFile, err := os.Create(runner.options.OutputFile)
		if err != nil {
			return nil, errorutil.New("could not create output file %s: %s", options.OutputFile, err)
		}
		runner.outputWriter.AddWriters(outputFile)
	}
	return runner, nil
}

// RunEnumeration runs the subdomain enumeration flow on the targets specified
func (r *Runner) Run(ctx context.Context) error {
	resultCallback := func(result sources.Result) {
		optionFields := r.options.OutputFields
		switch {
		case result.Error != nil:
			gologger.Warning().Label(result.Source).Msgf("%s\n", result.Error.Error())
		case r.options.JSON:
			gologger.Verbose().Label(result.Source).Msgf("%s\n", result.JSON())
			r.outputWriter.WriteJsonData(result)
		case r.options.Raw:
			gologger.Verbose().Label(result.Source).Msgf("%s\n", result.RawData())
			r.outputWriter.WriteString(result.RawData())
		default:
			port := fmt.Sprint(result.Port)
			replacer := strings.NewReplacer(
				"ip", result.IP,
				"host", result.Host,
				"port", port,
				"url", result.Url,
			)
			if (result.IP == "" || port == "0") && stringsutil.ContainsAny(r.options.OutputFields, "ip", "port") {
				optionFields = "host"
			}
			outData := replacer.Replace(optionFields)
			searchFor := []string{result.IP, port}
			if result.Host != "" || r.options.OutputFile != "" {
				searchFor = append(searchFor, result.Host)
			}
			if stringsutil.ContainsAny(outData, searchFor...) && !r.outputWriter.findDuplicate(outData, false) {
				if r.options.Verbose {
					gologger.Info().Label(result.Source).Msg(outData)
				}
				r.outputWriter.WriteString(outData)
			}
		}
	}
	err := r.service.ExecuteWithCallback(ctx, resultCallback)
	r.logQuotaSummary()
	r.writeQuotaReport()
	return err
}

// logQuotaSummary prints a compact per-engine usage line when quota
// management is enabled, so the run is self-describing even without a report
// file. It is a no-op in legacy mode.
func (r *Runner) logQuotaSummary() {
	report := r.service.Report()
	if report == nil {
		return
	}
	for _, engine := range report.Engines {
		remaining := "unlimited"
		if engine.Remaining != nil {
			remaining = fmt.Sprintf("%d", *engine.Remaining)
		}
		switch engine.Status {
		case sources.StatusSkipped:
			gologger.Warning().Msgf("engine %s: skipped (%s) used=%d remaining=%s\n", engine.Engine, engine.Reason, engine.CallsUsed, remaining)
		case sources.StatusError:
			gologger.Warning().Msgf("engine %s: error (%s) used=%d remaining=%s\n", engine.Engine, engine.Error, engine.CallsUsed, remaining)
		default:
			gologger.Info().Msgf("engine %s: participated used=%d remaining=%s\n", engine.Engine, engine.CallsUsed, remaining)
		}
		if engine.FailOpen {
			gologger.Warning().Msgf("engine %s: quota accounting failed (%s); ran unlimited\n", engine.Engine, engine.FailOpenReason)
		}
	}
}

// writeQuotaReport persists the per-engine quota usage report when
// -quota-report was set. Errors are logged but do not change the exit code,
// because the report is diagnostic output, not a result.
func (r *Runner) writeQuotaReport() {
	path := r.options.QuotaReport
	if path == "" {
		return
	}
	report := r.service.Report()
	if report == nil {
		return
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		gologger.Error().Msgf("could not encode quota report: %s\n", err)
		return
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0644); err != nil {
		gologger.Error().Msgf("could not write quota report %s: %s\n", path, err)
		return
	}
	gologger.Info().Msgf("quota report written to %s\n", path)
}

// Close closes its resources
func (r *Runner) Close() {
	if r.outputWriter != nil {
		r.outputWriter.Close()
	}
}
