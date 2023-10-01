package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"

	"github.com/beppler/sproxy"
	"github.com/beppler/sproxy/middleware"
)

func main() {
	logger := slog.New(middleware.NewRequestIdHandler(slog.Default().Handler()))

	handler := middleware.NewRequestIdMiddleware(
		middleware.NewLoggingMiddleware(
			sproxy.NewProxy(
				logger,
			),
			logger,
		),
		false,
	)

	logger.Info("starting service")

	listener, err := net.Listen("tcp", "localhost:8076")
	if err != nil {
		logger.Error("error starting server", "error", err)
		os.Exit(1)
	}

	logger.Info("service started")

	server := &http.Server{
		Handler: handler,
	}

	serverStopped := make(chan any)

	go func() {
		stopAsked := make(chan os.Signal, 1)
		signal.Notify(stopAsked, os.Interrupt)
		<-stopAsked
		logger.Info("stopping server")
		if err := server.Shutdown(context.Background()); err != nil {
			logger.Error("error stopping server", "error", err)
		}
		close(serverStopped)
	}()

	if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		logger.Error("error running server", "error", err)
		os.Exit(1)
	}

	<-serverStopped
	logger.Info("service stopped")
}
