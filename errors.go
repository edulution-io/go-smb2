package smb2

import (
	"context"
	"fmt"

	. "github.com/edulution-io/go-smb2/internal/erref"
)

// TransportError represents a error come from net.Conn layer.
type TransportError struct {
	Err error
}

func (err *TransportError) Error() string {
	return fmt.Sprintf("connection error: %v", err.Err)
}

// InternalError represents internal error.
type InternalError struct {
	Message string
}

func (err *InternalError) Error() string {
	return fmt.Sprintf("internal error: %s", err.Message)
}

// InvalidResponseError represents a data sent by the server is corrupted or unexpected.
type InvalidResponseError struct {
	Message string
}

func (err *InvalidResponseError) Error() string {
	return fmt.Sprintf("invalid response error: %s", err.Message)
}

// ResponseError represents a error with a nt status code sent by the server.
// The NTSTATUS is defined in [MS-ERREF].
// https://msdn.microsoft.com/en-au/library/cc704588.aspx
type ResponseError struct {
	Code uint32 // NTSTATUS
	data [][]byte
}

func (err *ResponseError) Error() string {
	return fmt.Sprintf("response error: %v", NtStatus(err.Code))
}

// CreditError represents a request that could not be sent because the credits
// the connection was able to grant do not cover the payload the request has to
// send. Unlike InternalError this is a transient condition: the credit balance
// recovers as outstanding requests complete, so the call is worth retrying.
type CreditError struct {
	Granted   int // payload size the granted credits cover
	Requested int // payload size the request has to send
}

func (err *CreditError) Error() string {
	return fmt.Sprintf("credit error: granted credits cover %d bytes, less than the %d byte request payload", err.Granted, err.Requested)
}

// Temporary reports that the condition is transient, so that callers can tell a
// credit shortage apart from a permanent failure without matching on strings.
func (err *CreditError) Temporary() bool {
	return true
}

// ContextError wraps a context error to support os.IsTimeout function.
type ContextError struct {
	Err error
}

func (err *ContextError) Timeout() bool {
	return err.Err == context.DeadlineExceeded
}

func (err *ContextError) Error() string {
	return err.Err.Error()
}
