package pipeline

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func TestPipelineSkipsDisabledUnsupportedAndRecordsWarnings(t *testing.T) {
	var ran []string
	result := &model.LookupResult{Type: model.QueryDomain}
	New(
		Step{
			NameValue:    "disabled",
			EnabledValue: false,
			EnrichFunc: func(context.Context, *model.LookupResult) error {
				ran = append(ran, "disabled")
				return nil
			},
		},
		Step{
			NameValue:    "unsupported",
			EnabledValue: true,
			SupportsFunc: func(*model.LookupResult) bool {
				return false
			},
			EnrichFunc: func(context.Context, *model.LookupResult) error {
				ran = append(ran, "unsupported")
				return nil
			},
		},
		Step{
			NameValue:    "ok",
			EnabledValue: true,
			EnrichFunc: func(context.Context, *model.LookupResult) error {
				ran = append(ran, "ok")
				return nil
			},
		},
		Step{
			NameValue:    "broken",
			EnabledValue: true,
			EnrichFunc: func(context.Context, *model.LookupResult) error {
				return errors.New("boom")
			},
		},
	).Run(context.Background(), result)

	if strings.Join(ran, ",") != "ok" {
		t.Fatalf("ran steps: %#v", ran)
	}
	if len(result.Meta.Warnings) != 1 || !strings.Contains(result.Meta.Warnings[0], "broken enrichment failed: boom") {
		t.Fatalf("warnings: %#v", result.Meta.Warnings)
	}
}

func TestPipelineAppliesStepTimeout(t *testing.T) {
	result := &model.LookupResult{Type: model.QueryDomain}
	var sawDeadline bool
	New(Step{
		NameValue:    "timed",
		EnabledValue: true,
		TimeoutValue: time.Millisecond,
		EnrichFunc: func(ctx context.Context, _ *model.LookupResult) error {
			_, sawDeadline = ctx.Deadline()
			return nil
		},
	}).Run(context.Background(), result)

	if !sawDeadline {
		t.Fatal("expected step context deadline")
	}
}
