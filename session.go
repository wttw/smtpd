package smtpd

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
)

type Session struct {
	ID       int32
	UserData any
	srv      *Server
	rwc      net.Conn
	br       *bufio.Reader
	bw       *bufio.Writer

	logger    *zap.Logger
	env       Envelope
	Hello     string
	Hostname  string
	TLSConfig *tls.Config
	rawCerts  [][]byte
}

type ErrorClose struct {
	err error
}

func (e ErrorClose) Error() string {
	return e.err.Error()
}

func (s *Session) Warn(sev Severity, e string) {
	s.srv.Hooks.Warn(s, sev, e)
}

func (s *Server) newSession(c net.Conn) *Session {
	sess := &Session{
		srv:       s,
		rwc:       c,
		br:        bufio.NewReader(c),
		bw:        bufio.NewWriter(c),
		logger:    s.Logger.With(zap.String("local", c.LocalAddr().String()), zap.String("remote", c.RemoteAddr().String())),
		TLSConfig: s.TLSConfig.Clone(),
		ID:        s.sessionID.Add(1),
	}
	if s.TLSConfig != nil {
		sess.TLSConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			sess.rawCerts = rawCerts
			return nil
		}
		sess.TLSConfig.VerifyConnection = func(state tls.ConnectionState) error {
			return s.Hooks.AllowTLS(sess, sess.rawCerts, state)
		}
	}
	return sess
}

func (s *Session) Addr() net.Addr {
	return s.rwc.RemoteAddr()
}

func (s *Session) Serve() {
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			s.logger.Error("while closing connection", zap.Error(err))
		}
	}(s.rwc)

	err := s.srv.Hooks.AllowConnect(s)
	if err == nil {
		s.sendline(fmt.Sprintf("220 %s %s", s.srv.Hostname, s.srv.Appname))
	} else {
		s.sendSMTPError(err, "554 No service for you")
	}
	for {
		if s.srv.ReadTimeout != 0 {
			_ = s.rwc.SetReadDeadline(time.Now().Add(s.srv.ReadTimeout))
		}
		sl, err := s.br.ReadString('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.logger.Info("read error", zap.Error(err))
			}
			break
		}
		s.srv.Hooks.LineRead(s, sl)
		if strings.HasSuffix(sl, "\r\n") {
			sl = sl[:len(sl)-2]
		} else {
			sl = strings.TrimSuffix(strings.TrimSuffix(sl, "\n"), "\r")
			s.srv.Hooks.Warn(s, SeverityError, "Command doesn't end with CRLF")
		}
		parts := strings.SplitN(sl, " ", 2)
		verb := strings.ToUpper(parts[0])
		if verb != parts[0] {
			s.srv.Hooks.Warn(s, SeverityInfo, "Some mail servers (wrongly) require verbs be in upper case")
		}
		var args string
		if len(parts) > 1 {
			args = strings.TrimSpace(parts[1])
			if args != parts[1] {
				s.srv.Hooks.Warn(s, SeverityWarn, "Arguments have leading or trailing whitespace")
			}
		}

		switch verb {
		case "RSET", "DATA", "QUIT":
			if args != "" {
				s.srv.Hooks.Warn(s, SeverityError, fmt.Sprintf("%s SHOULD NOT have arguments", verb))
			}
		}
		switch verb {
		case "HELO", "EHLO":
			s.env = nil
			s.handleHello(verb, args)
		case "QUIT":
			s.sendline("221 2.0.0 Bye")
			return
		case "RSET":
			s.env = nil
			s.sendline("250 2.0.0 OK")
		case "NOOP":
			s.sendline("250 2.0.0 OK")
		case "MAIL":
			s.env = nil
			err = s.handleMail(args)
			s.sendResponse(err, "250 2.1.0 Ok")
		case "RCPT":
			err = s.handleRcpt(args)
			s.sendResponse(err, "250 2.1.0 Ok")
		case "DATA":
			err = s.handleData()
			s.sendResponse(err, "250 2.0.0 Ok: queued")
		case "STARTTLS":
			err = s.handleStarttls(args)
			if err != nil {
				s.sendSMTPError(err, "500 internal error")
			}
		}
		if errors.Is(err, ErrorClose{}) {
			return
		}
	}
}

func (s *Session) handleHello(verb string, args string) {
	s.Hello = verb
	s.env = nil
	parts := strings.SplitN(args, " ", 2)
	s.Hostname = parts[0]
	if len(parts) > 1 {
		s.srv.Hooks.Warn(s, SeverityInfo, "Additional parameters to HELO/EHLO are deprecated as of RFC 5321")
	}
	if verb == "HELO" {
		s.sendline("250 OK")
		return
	}
	extensions := []string{"250-" + s.srv.Hostname}
	if s.TLSConfig != nil {
		_, ok := s.rwc.(*tls.Conn)
		if !ok {
			extensions = append(extensions, "250-STARTTLS")
		}
	}
	extensions = append(extensions, "250-PIPELINING",
		"250-SIZE 10240000",
		"250-ENHANCEDSTATUSCODES",
		//"250-8BITMIME",
		"250 DSN")
	s.sendlines(extensions)
}

var mailFromRE = regexp.MustCompile(`^[Ff][Rr][Oo][Mm]:(\s*)(\S+)(.*)`)

func (s *Session) handleMail(args string) error {
	matches := mailFromRE.FindStringSubmatch(args)
	if matches == nil {
		return SMTPError("501 5.1.7 Bad sender address syntax")
	}
	if matches[1] != "" {
		s.Warn(SeverityWarn, "There shouldn't be whitespace between FROM: and the return path")
	}
	email := matches[2]
	if strings.HasPrefix(email, "<") && strings.HasSuffix(email, ">") {
		email = email[1 : len(email)-1]
	} else {
		s.Warn(SeverityError, "The return path MUST be surrounded by < and >")
	}
	//if len(matches[3]) > 0 {
	//	s.Warn(SeverityWarn, fmt.Sprintf("Unexpected parameters to MAIL FROM: '%s'", matches[3]))
	//}
	env, err := s.srv.Hooks.AllowFrom(s, Address(email))
	if err != nil {
		return err
	}
	s.env = env
	return nil
}

var rcptToRE = regexp.MustCompile(`^[Tt][Oo]:(\s*)(\S+)(.*)`)

func (s *Session) handleRcpt(args string) error {
	if s.env == nil {
		return SMTPError("503 5.5.1 Error: need MAIL command")
	}
	matches := rcptToRE.FindStringSubmatch(args)
	if matches == nil {
		return SMTPError("501 5.1.7 Bad recipient address syntax")
	}
	if matches[1] != "" {
		s.Warn(SeverityWarn, "There shouldn't be whitespace between TO: and the recipient")
	}
	email := matches[2]
	if strings.HasPrefix(email, "<") && strings.HasSuffix(email, ">") {
		email = email[1 : len(email)-1]
	} else {
		s.Warn(SeverityError, "The recipient MUST be surrounded by < and >")
	}
	return s.srv.Hooks.AllowTo(s, s.env, Address(email))
}

func (s *Session) handleData() error {
	if s.env == nil {
		return SMTPError("503 5.5.1 Error: need RCPT command")
	}
	err := s.srv.Hooks.AllowData(s, s.env)
	if err != nil {
		return err
	}
	err = s.env.BeginData()
	if err != nil {
		return err
	}
	s.sendline("354 Go ahead")
	for {
		sl, err := s.br.ReadSlice('\n')
		if err != nil {
			s.logger.Info("read error", zap.Error(err))
			return ErrorClose{err: err}
		}
		if bytes.Equal(sl, []byte(".\r\n")) {
			break
		}
		if sl[0] == '.' {
			sl = sl[1:]
		}
		err = s.env.Write(sl)
		if err != nil {
			return err
		}
	}
	if err := s.env.Close(); err != nil {
		return err
	}
	s.env = nil
	return nil
}

func (s *Session) handleStarttls(args string) error {
	_, ok := s.rwc.(*tls.Conn)
	if ok {
		return SMTPError("501 Syntax error (can't restart TLS)")
	}
	if args != "" {
		return SMTPError("501 Syntax error (no parameters allowed)")
	}
	if s.TLSConfig == nil {
		return SMTPError("454 TLS not available due to temporary reason")
	}
	s.sendline("220 2.0.0 Ready to start TLS")
	s.env = nil
	conn := tls.Server(s.rwc, s.TLSConfig)
	err := conn.Handshake()
	if err != nil {
		return fmt.Errorf("TLS negotiation failed: %w", err)
	}
	s.rwc = conn

	s.br = bufio.NewReader(s.rwc)
	s.bw = bufio.NewWriter(s.rwc)
	return nil
}

func (s *Session) sendline(line string) {
	if s.srv.WriteTimeout != 0 {
		err := s.rwc.SetWriteDeadline(time.Now().Add(s.srv.WriteTimeout))
		if err != nil {
			s.logger.Error("failed to set write deadline", zap.Error(err))
		}
	}
	s.srv.Hooks.LineWritten(s, line)
	fullLine := line + "\r\n"
	_, err := s.bw.WriteString(fullLine)
	if err != nil {
		s.logger.Error("failed to write response", zap.Error(err))
	}
	err = s.bw.Flush()
	if err != nil {
		s.logger.Error("failed to flush response", zap.Error(err))
	}
}

func (s *Session) sendlines(lines []string) {
	for _, line := range lines {
		s.sendline(line)
	}
}

func (s *Session) sendSMTPError(err error, deflt string) {
	var se SMTPError
	if errors.As(err, &se) {
		s.sendline(se.Error())
		return
	}
	s.sendline(deflt)
}

func (s *Session) sendResponse(err error, ok string) {
	if err == nil {
		s.sendline(ok)
		return
	}
	s.sendSMTPError(err, fmt.Sprintf("554 internal error: %s", err))
}
