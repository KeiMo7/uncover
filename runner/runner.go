package runner

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/uncover"
	"github.com/projectdiscovery/uncover/querylang"
	"github.com/projectdiscovery/uncover/querylang/backends"
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
		Agents:       options.Engine,
		Queries:      options.Query,
		Limit:        options.Limit,
		Proxy:        options.Proxy,
		Unified:      options.UnifiedQuery,
		AllowDegrade: options.AllowDegrade,
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
		// Unified-mode non-asset stream entries: never print them as assets.
		// Errors stay warnings; diagnostics go to the log so the asset
		// output format and fields remain exactly compatible.
		if result.Status != sources.StatusAsset {
			switch result.Status {
			case sources.StatusEngineError, sources.StatusCompileRejected:
				gologger.Warning().Label(result.Source).Msgf("%s\n", result.Message)
			case sources.StatusEmpty:
				gologger.Info().Label(result.Source).Msgf("empty result set (query compiled and accepted): %s\n", result.EffectiveQuery)
			case sources.StatusDegraded:
				gologger.Warning().Label(result.Source).Msgf("degraded query: %s\n", strings.Join(result.DroppedConditions, "; "))
			case sources.ResultStatus("coverage"):
				gologger.Info().Label("coverage").Msgf("%s\n", result.Message)
			}
			return
		}
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
	return r.service.ExecuteWithCallback(ctx, resultCallback)
}

// Close closes its resources
func (r *Runner) Close() {
	if r.outputWriter != nil {
		r.outputWriter.Close()
	}
}

// Explain compiles every query for the selected (or all) engines and prints
// the cross-engine equivalence report without making any network call. It
// returns an error when a query cannot be parsed, so the position-bearing
// parse error is surfaced instead of a vague failure.
func (r *Runner) Explain() error {
	mode := querylang.DegradeReject
	if r.options.AllowDegrade {
		mode = querylang.DegradeTopLevelAND
	}
	var compiler *querylang.Compiler
	if len(r.options.Engine) > 0 {
		compiler = backends.CompilerForEngines(mode, r.options.Engine)
	} else {
		compiler = backends.DefaultCompiler(mode)
	}

	var report strings.Builder
	for _, q := range r.options.Query {
		tree, err := querylang.Parse(q)
		if err != nil {
			return errorutil.NewWithTag("uncover", "query %q: %v", q, err)
		}
		compiled, errs := compiler.CompileAll(tree)
		report.WriteString(fmt.Sprintf("unified query: %s\n", q))
		report.WriteString(fmt.Sprintf("syntax version: %s\n\n", querylang.SyntaxVersion))
		report.WriteString(querylang.Explain(compiled, errs))
		report.WriteString("\n")
	}
	fmt.Fprintln(os.Stdout, report.String())
	return nil
}
