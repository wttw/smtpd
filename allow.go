package smtpd

import (
	"crypto/tls"
	"fmt"
)

//go:generate enumer -json -trimprefix Severity -type Severity

type Severity int

const (
	SeverityDebug Severity = iota
	SeverityInfo
	SeverityWarn
	SeverityError
	SeverityFatal
	SeverityConnect
	SeverityClose
	SeverityRead
	SeverityWrite
)

type Allower interface {
	AllowConnect(session *Session) error
	AllowFrom(session *Session, from MailAddress) (Envelope, error)
	AllowTo(session *Session, e Envelope, to MailAddress) error
	AllowData(session *Session, e Envelope) error
	AllowTLS(session *Session, rawCerts [][]byte, state tls.ConnectionState) error
	LineRead(session *Session, line string)
	LineWritten(session *Session, line string)
	Warn(session *Session, sev Severity, e string)
	Close(session *Session)
}

type allowAll struct{}

func (a allowAll) AllowTo(_ *Session, e Envelope, to MailAddress) error {
	return e.AddRecipient(to)
}

func (a allowAll) AllowData(_ *Session, _ Envelope) error {
	return nil
}

func (a allowAll) AllowFrom(session *Session, from MailAddress) (Envelope, error) {
	return &BasicEnvelope{
		session: session,
		rp:      from,
		rcpts:   nil,
	}, nil
}

var _ Allower = allowAll{}

func (a allowAll) AllowConnect(_ *Session) error {
	return nil
}

func (a allowAll) LineRead(*Session, string)    {}
func (a allowAll) LineWritten(*Session, string) {}
func (a allowAll) Warn(_ *Session, sev Severity, e string) {
	fmt.Printf("%s: %s\n", sev, e)
}

func (a allowAll) AllowTLS(_ *Session, _ [][]byte, _ tls.ConnectionState) error {
	return nil
}

func (a allowAll) Close(_ *Session) {

}
