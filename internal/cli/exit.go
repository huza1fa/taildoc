package cli

import "errors"

// ErrSeverityExceeded is returned when findings meet or exceed the --fail-on threshold.
var ErrSeverityExceeded = errors.New("findings met or exceeded --fail-on threshold")

// ErrDoctorFailed indicates that doctor completed its checks but found a
// problem. The command has already printed the individual diagnostics.
var ErrDoctorFailed = errors.New("doctor found problems")
