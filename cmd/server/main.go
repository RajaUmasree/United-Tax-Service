// Command server runs the UTS property-tax service.
//
// Environment:
//
//	PORT                   listen port (default 8080)
//	UTS_API_TOKENS         comma list of token:actor:role[:client_id]; tokens >= 16 chars
//	                       e.g. "s3cret-admin-token-0001:alice:admin,client-token-abcdef-01:acme-bot:client:acme"
//	AUDIT_LOG_PATH         optional file for the audit stream (default: same JSON stream as app logs)
//	TITLE_PLATFORM_URL     base URL of the title/closing platform (optional)
//	TITLE_PLATFORM_KEY     API key for the title platform
//	TAX_SYSTEM_URL         base URL of the downstream tax system (optional)
//	TAX_SYSTEM_KEY         API key for the tax system
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"uts-tax-service/internal/api"
	"uts-tax-service/internal/audit"
	"uts-tax-service/internal/integration"
	"uts-tax-service/internal/resilience"
	"uts-tax-service/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	tokens, err := api.ParseTokens(os.Getenv("UTS_API_TOKENS"))
	if err != nil {
		logger.Error("invalid UTS_API_TOKENS", "error", err.Error())
		os.Exit(1)
	}

	// Audit stream: dedicated file when requested, otherwise the main JSON log.
	auditLogger := logger
	if path := os.Getenv("AUDIT_LOG_PATH"); path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			logger.Error("cannot open audit log", "path", path, "error", err.Error())
			os.Exit(1)
		}
		defer f.Close()
		auditLogger = slog.New(slog.NewJSONHandler(f, nil))
	}
	rec := audit.SlogRecorder{Logger: auditLogger}

	dispatcher := &integration.Dispatcher{Audit: rec}
	retry := resilience.RetryConfig{MaxAttempts: 4, BaseDelay: 300 * time.Millisecond, MaxDelay: 6 * time.Second, PerAttemptTimeout: 8 * time.Second}
	if u := os.Getenv("TITLE_PLATFORM_URL"); u != "" {
		dispatcher.Title = integration.NewTitlePlatformClient(integration.HTTPConfig{
			BaseURL: u, APIKey: os.Getenv("TITLE_PLATFORM_KEY"), Retry: retry,
			Breaker: resilience.NewBreaker(5, 30*time.Second), Logger: logger,
		})
	}
	if u := os.Getenv("TAX_SYSTEM_URL"); u != "" {
		dispatcher.Tax = integration.NewTaxSystemClient(integration.HTTPConfig{
			BaseURL: u, APIKey: os.Getenv("TAX_SYSTEM_KEY"), Retry: retry,
			Breaker: resilience.NewBreaker(5, 30*time.Second), Logger: logger,
		})
	}

	srv := api.New(store.NewMemory(), dispatcher, rec, tokens, logger, api.Config{})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	httpSrv := &http.Server{
		Addr:              ":" + port,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		logger.Info("uts tax service listening", "addr", httpSrv.Addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "error", err.Error())
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	srv.Wait() // let in-flight integration calls finish
}
