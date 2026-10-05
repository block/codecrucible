// decision-eval runs frozen decisions without generating fresh scan findings.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/decisioneval"
	"github.com/block/codecrucible/internal/usage"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	input := flag.String("cases", "", "JSON fixed-case file")
	output := flag.String("out", "", "output JSON path; includes frozen source, keep private cases outside Git")
	live := flag.Bool("live", false, "make paid Jev requests; otherwise prepare cases and deterministic baselines only")
	model := flag.String("model", decision.Model, "pinned decision model")
	endpoint := flag.String("endpoint", "https://api.typesafe.ai/v1/systemone", "TypeSafe evaluation endpoint")
	flag.Parse()
	if *input == "" || *output == "" {
		return fmt.Errorf("-cases and -out are required")
	}
	data, err := os.ReadFile(*input)
	if err != nil {
		return err
	}
	var cases []decisioneval.Case
	if err = json.Unmarshal(data, &cases); err != nil {
		return err
	}
	if len(cases) == 0 || len(cases) > 1000 {
		return fmt.Errorf("expected 1-1000 cases")
	}
	seen := map[string]bool{}
	for _, c := range cases {
		if seen[c.ID] {
			return fmt.Errorf("duplicate case id %q", c.ID)
		}
		seen[c.ID] = true
		if _, _, err = decisioneval.Prepare(c, *model); err != nil {
			return err
		}
	}
	var evaluator decision.Evaluator
	if *live {
		evaluator, err = decision.New(decision.Options{URL: *endpoint, APIKey: os.Getenv("TYPESAFE_API_KEY"), Model: *model, Timeout: 30 * time.Second, MaxCalls: len(cases), Retries: 2, InputPrice: decision.InputPricePerMillion})
		if err != nil {
			return err
		}
	}
	// Refuse overwrite, and verify the private destination before paid calls.
	f, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ledger := usage.New()
	ctx = usage.WithLedger(ctx, ledger)
	started := time.Now()
	results := []decisioneval.Result{}
	var runErr error
	for _, c := range cases {
		r, err := decisioneval.Run(ctx, c, *model, evaluator)
		results = append(results, r)
		if err != nil {
			runErr = err
			break
		}
	}
	status := "completed"
	if runErr != nil {
		status = "cancelled"
	}
	report := struct {
		Live           bool                  `json:"live"`
		ElapsedSeconds float64               `json:"elapsed_seconds"`
		Results        []decisioneval.Result `json:"results"`
		Usage          usage.Report          `json:"usage"`
	}{*live, time.Since(started).Seconds(), results, ledger.Snapshot(status)}
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(report); err != nil {
		return err
	}
	return runErr
}
