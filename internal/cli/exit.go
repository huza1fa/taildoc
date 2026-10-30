package cli

import "errors"

// ErrSeverityExceeded is returned when findings meet or exceed the --fail-on threshold.
var ErrSeverityExceeded = errors.New("findings met or exceeded --fail-on threshold")

// ErrDoctorFailed indicates that doctor completed its checks but found a
// problem. The command has already printed the individual diagnostics.
var ErrDoctorFailed = errors.New("doctor found problems")

// ErrPlanFailed is returned when a plan meets a --fail-on condition. The report
// has already been printed.
var ErrPlanFailed = errors.New("plan met --fail-on")

// ErrAccessDenied and ErrAccessUnknown carry an explain verdict to the exit
// code under --exit-code. The verdict has already been printed.
var (
	ErrAccessDenied  = errors.New("access denied")
	ErrAccessUnknown = errors.New("access cannot be determined")
)
