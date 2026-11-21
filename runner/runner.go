package runner

import (
	"context"
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

	opts := uncover.Options{
		Agents:  options.Engine,
		Queries: options.Query,
		Limit:   options.Limit,
		Proxy:   options.Proxy,
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
	// In merge mode the output file is written atomically at the end of the
	// run (temp file + rename), so it is not created eagerly here: a failed
	// run must not leave a truncated or empty file behind.
	if runner.options.OutputFile != "" && !runner.options.Merge {
		outputFile, err := os.Create(runner.options.OutputFile)
		if err != nil {
			return nil, errorutil.New("could not create output file %s: %s", options.OutputFile, err)
		}
		runner.outputWriter.AddWriters(outputFile)
	}
	return runner, nil
}

// formatResultFields renders the -field template for a result. It is the
// exact rendering the default output path has always used, extracted so the
// merged path renders the asset column identically.
func formatResultFields(outputFields string, result sources.Result) string {
	port := fmt.Sprint(result.Port)
	replacer := strings.NewReplacer(
		"ip", result.IP,
		"host", result.Host,
		"port", port,
		"url", result.Url,
	)
	if (result.IP == "" || port == "0") && stringsutil.ContainsAny(outputFields, "ip", "port") {
		outputFields = "host"
	}
	return replacer.Replace(outputFields)
}

// RunEnumeration runs the subdomain enumeration flow on the targets specified
func (r *Runner) Run(ctx context.Context) error {
	if r.options.Merge {
		return r.runMerged(ctx)
	}
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
			outData := formatResultFields(optionFields, result)
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
	return r.service.ExecuteWithCallback(ctx, resultCallback)
}

// runMerged executes all engines, merges their results keeping per-engine
// provenance, and writes the output only after every engine has finished.
// Output lines are ordered by confidence (engine count) descending and are
// byte-identical across runs with identical inputs.
func (r *Runner) runMerged(ctx context.Context) error {
	merged, err := r.service.ExecuteMerged(ctx)
	if merged != nil {
		r.reportEngines(merged)
	}
	if err != nil {
		// Total failure (e.g. all engines failed): report and write nothing.
		return err
	}

	var lines []string
	for i := range merged.Assets {
		asset := &merged.Assets[i]
		var line string
		if r.options.JSON {
			line = asset.JSON()
		} else {
			line = fmt.Sprintf("%s\tsources=%s\tconfidence=%d",
				formatResultFields(r.options.OutputFields, asset.Result),
				strings.Join(asset.Sources, ","),
				asset.Confidence(),
			)
		}
		lines = append(lines, line)
		if r.options.Verbose {
			gologger.Info().Label("merge").Msg(line)
		}
	}
	if len(lines) == 0 {
		return nil
	}
	data := []byte(strings.Join(lines, "\n") + "\n")
	if r.options.OutputFile != "" {
		// Write to a temp file in the same directory and rename, so a
		// failure mid-write never leaves a half-written output file.
		tmp := r.options.OutputFile + ".tmp"
		if writeErr := os.WriteFile(tmp, data, 0o644); writeErr != nil {
			return errorutil.New("could not write output file %s: %s", r.options.OutputFile, writeErr)
		}
		if renameErr := os.Rename(tmp, r.options.OutputFile); renameErr != nil {
			_ = os.Remove(tmp)
			return errorutil.New("could not move output file into place %s: %s", r.options.OutputFile, renameErr)
		}
	}
	if !r.options.Verbose {
		r.outputWriter.Write(data[:len(data)-1])
	}
	return nil
}

// reportEngines logs the per-engine outcome of a merged run to stderr,
// distinguishing "engine returned no results" from "engine failed".
func (r *Runner) reportEngines(merged *sources.MergeResult) {
	for _, engine := range merged.Engines {
		switch engine.State {
		case sources.EngineStateOK:
			gologger.Info().Label("merge").Msgf("engine %s: %d results", engine.Name, engine.Results)
		case sources.EngineStateEmpty:
			gologger.Info().Label("merge").Msgf("engine %s: no results", engine.Name)
		case sources.EngineStateError:
			gologger.Warning().Label("merge").Msgf("engine %s: error: %s", engine.Name, engine.Err)
		}
		if engine.Malformed > 0 {
			gologger.Warning().Label("merge").Msgf("engine %s: skipped %d malformed results", engine.Name, engine.Malformed)
		}
	}
}

// Close closes its resources
func (r *Runner) Close() {
	if r.outputWriter != nil {
		r.outputWriter.Close()
	}
}
