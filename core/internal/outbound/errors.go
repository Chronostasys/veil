package outbound

import "errors"

// ErrRejected is returned when a rule or a reject outbound drops traffic.
var ErrRejected = errors.New("connection rejected")
