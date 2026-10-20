package scanactivity

import (
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"
)

// scanWorkflow is the workflow side of INTEGRATION.md ("Activity options").
func scanWorkflow(ctx workflow.Context, input ScanInput) (ScanOutcome, error) {
	options := workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Minute,
		HeartbeatTimeout:    time.Minute,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    5 * time.Second,
			BackoffCoefficient: 2,
			MaximumInterval:    time.Minute,
			MaximumAttempts:    5,
			NonRetryableErrorTypes: []string{
				"invalid_request", "unauthorized", "image_not_found", "registry_auth_failed",
				"platform_not_found", "java_db_missing",
			},
		},
	}
	ctx = workflow.WithActivityOptions(ctx, options)
	var scanner *Scanner // nil: only names the activity
	var outcome ScanOutcome
	err := workflow.ExecuteActivity(ctx, scanner.ScanImage, input).Get(ctx, &outcome)
	return outcome, err
}

func TestScanWorkflow(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	var scanner *Scanner
	env.RegisterActivity(scanner.ScanImage)
	env.OnActivity(scanner.ScanImage, mock.Anything, ScanInput{Tag: "v1"}).Return(ScanOutcome{ScanID: "abc", Cached: true}, nil)

	env.ExecuteWorkflow(scanWorkflow, ScanInput{Tag: "v1"})

	if err := env.GetWorkflowError(); err != nil {
		t.Fatal(err)
	}
	var outcome ScanOutcome
	if err := env.GetWorkflowResult(&outcome); err != nil || outcome.ScanID != "abc" || !outcome.Cached {
		t.Fatalf("unexpected result %+v, %v", outcome, err)
	}
}
