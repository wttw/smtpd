package main

import (
	"context"
	"crypto/tls"
	"go.uber.org/zap"
	"turscar.ie/smtpd"
)

func main() {
	ctx := context.Background()
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	cert, err := tls.LoadX509KeyPair("snakeoil.crt", "snakeoil.key")
	if err != nil {
		panic(err)
	}
	srv := smtpd.New(logger)
	srv.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		// ClientAuth:         tls.RequireAnyClientCert,
		InsecureSkipVerify: true, //nolint:gosec
	}
	err = srv.Listen(ctx, "tcp", "127.0.0.1:2500")
	if err != nil {
		panic(err)
	}
	srv.WaitGroup.Wait()
}
