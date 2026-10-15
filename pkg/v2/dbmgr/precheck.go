package dbmgr

import (
	"context"
	"fmt"
	"time"
)

// StageResult is the outcome of one pre-check stage (DEMAND section 7.3).
type StageResult struct {
	Stage    string        `json:"stage"`
	OK       bool          `json:"ok"`
	Skipped  bool          `json:"skipped,omitempty"`
	Duration time.Duration `json:"duration"`
	// Detail holds what the stage found (for example the TLS version) or why it failed.
	// It must never contain credentials.
	Detail string `json:"detail,omitempty"`
}

// CheckResult is the outcome of the pre-check of one source.
type CheckResult struct {
	// Source is DBSource.String(), so proxy credentials are hidden.
	Source    string        `json:"source"`
	OK        bool          `json:"ok"`
	StartedAt time.Time     `json:"started_at"`
	Duration  time.Duration `json:"duration"`
	Stages    []StageResult `json:"stages"`
}

// runStage runs one stage with its own timeout, inside ctx which carries the
// overall pre-check deadline. It appends the stage result and returns whether
// the stage passed. fn must stop when its context ends; every network call in
// a stage takes that context.
func runStage(ctx context.Context, result *CheckResult, stage string, timeout time.Duration,
	fn func(ctx context.Context) (string, error)) bool {
	stageCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	detail, err := fn(stageCtx)
	stageResult := StageResult{
		Stage:    stage,
		OK:       err == nil,
		Duration: time.Since(start),
		Detail:   detail,
	}

	if err != nil {
		switch {
		case ctx.Err() != nil:
			stageResult.Detail = fmt.Sprintf("overall pre-check deadline exceeded: %v", err)
		case stageCtx.Err() != nil:
			stageResult.Detail = fmt.Sprintf("stage timeout %s exceeded: %v", timeout, err)
		default:
			stageResult.Detail = err.Error()
		}
	}

	result.Stages = append(result.Stages, stageResult)
	return stageResult.OK
}
