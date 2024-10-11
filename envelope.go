package smtpd

import (
	"go.uber.org/zap"
	"strings"
)

// MailAddress is defined by
type MailAddress interface {
	Email() string    // email address, as provided
	Hostname() string // canonical hostname, lowercase
	Local() string    // LHS
}

// Envelope defines the envelope of a message
type Envelope interface {
	From() MailAddress
	AddRecipient(rcpt MailAddress) error
	Recipients() []MailAddress
	BeginData() error
	Write(line []byte) error
	Close() error
}

// BasicEnvelope implements Envelope
type BasicEnvelope struct {
	session *Session
	rp      MailAddress
	rcpts   []MailAddress
}

func (e *BasicEnvelope) From() MailAddress {
	return e.rp
}

func (e *BasicEnvelope) Recipients() []MailAddress {
	return e.rcpts
}

var _ Envelope = &BasicEnvelope{}

// AddRecipient adds a recipient from a RCPT TO
func (e *BasicEnvelope) AddRecipient(rcpt MailAddress) error {
	e.session.logger.Info("recipient",
		zap.String("lhs", rcpt.Local()),
		zap.String("rhs", rcpt.Hostname()))

	e.rcpts = append(e.rcpts, rcpt)
	return nil
}

// BeginData handles the DATA command
func (e *BasicEnvelope) BeginData() error {
	if len(e.rcpts) == 0 {
		return SMTPError("554 5.5.1 Error: no valid recipients")
	}
	return nil
}

// Write takes a line from the body during DATA
func (e *BasicEnvelope) Write(_ []byte) error {
	// e.body = append(e.body, line...)
	return nil
}

// Close is called at the end of DATA, for delivery
func (e *BasicEnvelope) Close() error {
	return nil
}

type Address string

func (a Address) Email() string {
	return string(a)
}

func (a Address) Hostname() string {
	e := string(a)
	if idx := strings.Index(e, "@"); idx != -1 {
		return strings.ToLower(e[idx+1:])
	}
	return ""
}

func (a Address) Local() string {
	e := string(a)
	if idx := strings.Index(e, "@"); idx != -1 {
		return e[:idx]
	}
	return e
}
