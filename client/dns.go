package client

import (
	"context"
	"errors"
	"net"
	"runtime"
	"time"
)

type DialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

var fallbackDNSServers = []string{"1.1.1.1:53", "8.8.8.8:53"}

func newDialContext() DialContextFunc {
	system := &net.Dialer{Timeout: 10 * time.Second}

	if runtime.GOOS != "ios" {
		return system.DialContext
	}

	systemAttempt := &net.Dialer{Timeout: 5 * time.Second}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := systemAttempt.DialContext(ctx, network, addr)
		if err == nil || !shouldRetryWithFallback(err) {
			return conn, err
		}

		return dialWithFallback(ctx, network, addr)
	}
}

func shouldRetryWithFallback(err error) bool {
	var dnsErr *net.DNSError

	return errors.As(err, &dnsErr) && !dnsErr.IsNotFound
}

func dialWithFallback(ctx context.Context, network, addr string) (net.Conn, error) {
	var lastErr error

	for _, server := range fallbackDNSServers {
		dialer := &net.Dialer{
			Timeout: 10 * time.Second,
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, server)
				},
			},
		}

		conn, err := dialer.DialContext(ctx, network, addr)
		if err == nil {
			return conn, nil
		}

		lastErr = err
		if !shouldRetryWithFallback(err) {
			return nil, err
		}
	}

	return nil, lastErr
}
