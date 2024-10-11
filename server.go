package smtpd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// SMTPError is what it sounds like
type SMTPError string

func (e SMTPError) Error() string {
	return string(e)
}

type Server struct {
	sync.Mutex
	listeners    []net.Listener
	Logger       *zap.Logger
	shutdown     chan struct{}
	Hostname     string
	Appname      string
	Hooks        Allower
	ReadTimeout  time.Duration // optional read timeout
	WriteTimeout time.Duration // optional write timeout
	TLSConfig    *tls.Config
	sessionID    atomic.Int32
	WaitGroup    sync.WaitGroup
}

func New(logger *zap.Logger) *Server {
	s := &Server{
		listeners: nil,
		Logger:    logger,
		shutdown:  make(chan struct{}),
	}
	h, err := os.Hostname()
	if err != nil {
		s.Hostname = "unknown.hostname"
		s.Logger.Error("failed to retrieve hostname", zap.Error(err))
	}
	s.Hostname = h
	return s
}

func (s *Server) Listen(ctx context.Context, network, address string) error {
	cfg := &net.ListenConfig{}
	listener, err := cfg.Listen(ctx, network, address)
	if err != nil {
		return err
	}
	s.Lock()
	if s.Hooks == nil {
		s.Hooks = &allowAll{}
	}
	s.listeners = append(s.listeners, listener)
	s.WaitGroup.Add(1)
	s.Unlock()
	go func(l net.Listener) {
		defer s.WaitGroup.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				s.Logger.Error("accept failed", zap.Error(err), zap.String("address", l.Addr().String()))
				return
			}
			s.Lock()
			session := s.newSession(conn)
			s.Unlock()
			go session.Serve()
		}
	}(listener)
	return nil
}

func (s *Server) Serve(listeners []net.Listener) {
	s.Lock()
	if s.Hooks == nil {
		s.Hooks = &allowAll{}
	}
	s.listeners = append(s.listeners, listeners...)
	s.WaitGroup.Add(len(listeners))
	s.Unlock()
	for _, l := range listeners {
		go func(l net.Listener) {
			defer s.WaitGroup.Done()
			for {
				conn, err := l.Accept()
				if err != nil {
					if !errors.Is(err, net.ErrClosed) {
						s.Logger.Error("accept failed", zap.Error(err), zap.String("address", l.Addr().String()))
					}
					return
				}
				s.Lock()
				s.WaitGroup.Add(1)
				session := s.newSession(conn)
				s.Unlock()
				go func(session *Session) {
					session.Serve()
					s.WaitGroup.Done()
				}(session)
			}
		}(l)
	}
	s.WaitGroup.Wait()
}

func (s *Server) Shutdown() {
	for _, ln := range s.listeners {
		_ = ln.Close()
	}
}

func (s *Server) ListenTCP(ctx context.Context, addresses []string) error {
	for _, addr := range addresses {
		err := s.Listen(ctx, "tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to listen to %s: %w", addr, err)
		}
	}
	return nil
}
