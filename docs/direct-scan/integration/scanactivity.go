// Package scanactivity is an example Temporal activity that scans an image
// with the scanner's direct scan API (/api/v2). See ../INTEGRATION.md.
package scanactivity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/temporal"
)

// ScanInput is what the workflow asks for.
type ScanInput struct {
	Repository   string         `json:"repository"`
	Name         string         `json:"name"`
	Tag          string         `json:"tag"`
	CustomerIDs  []string       `json:"customer_ids"`
	CustomerData map[string]any `json:"customer_data,omitempty"`
	Platforms    []string       `json:"platforms"`
	Severity     []string       `json:"severity,omitempty"`
	MaxDBAge     string         `json:"max_db_age,omitempty"`
	Force        bool           `json:"force,omitempty"`
}

// ScanOutcome is what the activity returns.
type ScanOutcome struct {
	ScanID string `json:"scan_id"`
	// Stale is true when the result is the tag's previous result (the newest
	// scan failed) or when the DB was not fresh enough for max_db_age.
	Stale bool `json:"stale"`
	// Cached is true when the scanner answered from its cache (no new scan).
	Cached bool `json:"cached"`
	// FailureClass is set when Stale comes from a failed scan.
	FailureClass string `json:"failure_class,omitempty"`
	// Result is the scanner's answer: the result view, or the state view with
	// its "previous" block for a failed scan.
	Result json.RawMessage `json:"result"`
}

// Scanner calls the scanner. Register its ScanImage method as an activity.
type Scanner struct {
	BaseURL string // for example http://scanner:8080
	Token   string // SCANNER_V2_AUTH_TOKEN
	HTTP    *http.Client
	// MaxWait caps a Retry-After wait.
	MaxWait time.Duration
}

// requestIDChars are the characters the scanner accepts in request_id.
var requestIDChars = regexp.MustCompile(`[^A-Za-z0-9._:-]`)

// ScanImage scans one image tag and waits for the result. Temporal retries it
// on retryable errors; the scanner keeps one document per tag, so a retried
// POST finds the scan that is already queued or running.
func (s *Scanner) ScanImage(ctx context.Context, in ScanInput) (ScanOutcome, error) {
	info := activity.GetInfo(ctx)
	requestID := requestIDChars.ReplaceAllString(info.WorkflowExecution.ID+":"+info.ActivityID, "_")
	if len(requestID) > 128 {
		requestID = requestID[:128]
	}
	request := map[string]any{
		"request_id":    requestID,
		"image":         map[string]string{"repository": in.Repository, "name": in.Name, "tag": in.Tag},
		"customer_ids":  in.CustomerIDs,
		"customer_data": in.CustomerData,
		"platforms":     in.Platforms,
		"severity":      in.Severity,
		"max_db_age":    in.MaxDBAge,
		"force":         in.Force,
	}
	if in.CustomerData == nil {
		delete(request, "customer_data")
	}
	if in.MaxDBAge == "" {
		delete(request, "max_db_age")
	}
	if len(in.Severity) == 0 {
		delete(request, "severity")
	}
	body, err := json.Marshal(request)
	if err != nil {
		return ScanOutcome{}, temporal.NewNonRetryableApplicationError("encoding the request", "invalid_input", err)
	}

	for {
		status, header, answer, err := s.call(ctx, http.MethodPost, "/api/v2/scans", body)
		if err != nil {
			return ScanOutcome{}, err // network error: Temporal retries the activity
		}
		switch status {
		case http.StatusOK:
			if stateOf(answer) == "done" {
				return outcome(answer)
			}
			return s.poll(ctx, scanIDOf(answer)) // a covered scan is already queued or running
		case http.StatusAccepted:
			return s.poll(ctx, scanIDOf(answer))
		case http.StatusConflict, http.StatusTooManyRequests, http.StatusServiceUnavailable:
			// scan_in_progress, queue_full / too_many_requests, not_ready /
			// store_unavailable / registry_unavailable: wait and POST again.
			if err := s.wait(ctx, header, status); err != nil {
				return ScanOutcome{}, err
			}
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusBadGateway:
			// invalid_request, unauthorized, image_not_found, registry_auth_failed:
			// retrying does not help.
			return ScanOutcome{}, temporal.NewNonRetryableApplicationError(
				fmt.Sprintf("scanner answered %d: %s", status, answer), errorCodeOf(answer), nil)
		default:
			return ScanOutcome{}, fmt.Errorf("scanner answered %d: %s", status, answer)
		}
	}
}

// poll waits until the scan is done or failed, honouring Retry-After.
func (s *Scanner) poll(ctx context.Context, scanID string) (ScanOutcome, error) {
	for {
		status, header, answer, err := s.call(ctx, http.MethodGet, "/api/v2/scans/"+scanID, nil)
		if err != nil {
			return ScanOutcome{}, err
		}
		switch {
		case status == http.StatusOK && stateOf(answer) == "done":
			return outcome(answer)
		case status == http.StatusOK && stateOf(answer) == "failed":
			var failed struct {
				Error    struct{ Class string } `json:"error"`
				Previous *json.RawMessage       `json:"previous"`
			}
			_ = json.Unmarshal(answer, &failed)
			if failed.Previous != nil {
				// The tag's last good result is still there: use it, marked stale.
				return ScanOutcome{ScanID: scanID, Stale: true, FailureClass: failed.Error.Class, Result: answer}, nil
			}
			// No earlier result. The workflow's retry policy decides, by failure
			// class (for example do not retry platform_not_found or java_db_missing).
			return ScanOutcome{}, temporal.NewApplicationError("scan failed: "+failed.Error.Class, failed.Error.Class)
		case status == http.StatusOK: // queued or scanning
			if err := s.wait(ctx, header, status); err != nil {
				return ScanOutcome{}, err
			}
		case status == http.StatusNotFound:
			return ScanOutcome{}, fmt.Errorf("scan %s is not found any more; the activity retry POSTs again", scanID)
		default:
			if err := s.wait(ctx, header, status); err != nil {
				return ScanOutcome{}, err
			}
		}
	}
}

// wait sleeps for Retry-After (2 s when missing), capped by MaxWait, and
// records a heartbeat so Temporal knows the activity is alive.
func (s *Scanner) wait(ctx context.Context, header http.Header, status int) error {
	activity.RecordHeartbeat(ctx, status)
	delay := 2 * time.Second
	if seconds, err := strconv.Atoi(header.Get("Retry-After")); err == nil && seconds > 0 {
		delay = time.Duration(seconds) * time.Second
	}
	if s.MaxWait > 0 && delay > s.MaxWait {
		delay = s.MaxWait
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(delay):
		return nil
	}
}

func (s *Scanner) call(ctx context.Context, method, path string, body []byte) (int, http.Header, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, s.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	request.Header.Set("Authorization", "Bearer "+s.Token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := s.HTTP.Do(request)
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = response.Body.Close() }()
	var answer bytes.Buffer
	if _, err = answer.ReadFrom(response.Body); err != nil {
		return 0, nil, nil, err
	}
	return response.StatusCode, response.Header, answer.Bytes(), nil
}

func outcome(answer []byte) (ScanOutcome, error) {
	var view struct {
		ScanID string `json:"scan_id"`
		Cached bool   `json:"cached"`
		DB     struct {
			Freshness string `json:"freshness"`
		} `json:"db"`
	}
	if err := json.Unmarshal(answer, &view); err != nil {
		return ScanOutcome{}, fmt.Errorf("reading the scanner's answer: %w", err)
	}
	return ScanOutcome{ScanID: view.ScanID, Cached: view.Cached, Stale: view.DB.Freshness == "stale", Result: answer}, nil
}

func stateOf(answer []byte) string {
	var view struct{ State string }
	_ = json.Unmarshal(answer, &view)
	return view.State
}

func scanIDOf(answer []byte) string {
	var view struct {
		ScanID string `json:"scan_id"`
	}
	_ = json.Unmarshal(answer, &view)
	return view.ScanID
}

func errorCodeOf(answer []byte) string {
	var view struct {
		Error struct{ Code string } `json:"error"`
	}
	_ = json.Unmarshal(answer, &view)
	return view.Error.Code
}
