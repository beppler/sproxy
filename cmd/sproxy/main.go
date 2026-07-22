package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"

	"github.com/beppler/sproxy"
	"github.com/beppler/sproxy/middleware"
)

func main() {
	// configure options
	var address, configurationFile, pacFile string

	flag.StringVar(&address, "address", "localhost:1357", "address to listen on")
	flag.StringVar(&configurationFile, "configuration", "wg0.conf", "path to wireguard configuration file")
	flag.StringVar(&pacFile, "proxy-pac", "", "path to proxy.pac file")

	flag.Parse()

	logger := slog.New(middleware.NewRequestIdHandler(slog.Default().Handler()))

	logger.Info("starting proxy", "address", address, "configuration", configurationFile, "proxy-pac", pacFile)

	// configure sproxy handler, logging and request id middlewares
	proxy, err := sproxy.NewProxyFromFile(logger, configurationFile, pacFile)
	if err != nil {
		logger.Error("error configuring proxy", "error", err)
		os.Exit(1)
	}
	logging := middleware.NewLoggingMiddleware(proxy, logger)
	handler := middleware.NewRequestIdMiddleware(logging, false)

	server := &http.Server{
		Addr:         address,
		Handler:      handler,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	// handle gracefull stop
	serverStopped := make(chan any)

	go func() {
		stopAsked := make(chan os.Signal, 1)
		signal.Notify(stopAsked, os.Interrupt)
		<-stopAsked
		logger.Info("stopping proxy")
		if err := server.Shutdown(context.Background()); err != nil {
			logger.Error("error stopping proxy", "error", err)
		}
		close(serverStopped)
	}()

	// serve sproxy requests
	listener, err := net.Listen("tcp", address)
	if err != nil {
		logger.Error("error starting proxy", "error", err)
		os.Exit(1)
	}

	logger.Info("proxy started")

	if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		logger.Error("error running proxy", "error", err)
		os.Exit(1)
	}

	<-serverStopped
	logger.Info("proxy stopped")
}
