package cli

import "errors"

// ErrSeverityExceeded is returned when findings meet or exceed the --fail-on threshold.
var ErrSeverityExceeded = errors.New("findings met or exceeded --fail-on threshold")
