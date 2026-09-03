package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Global Prometheus Metrics
var (
	metricPacketsProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "bamboo_packets_processed_total",
		Help: "The total number of processed packets",
	})
	
	metricAlertsGenerated = promauto.NewCounter(prometheus.CounterOpts{
		Name: "bamboo_alerts_generated_total",
		Help: "The total number of anomalies detected",
	})
	
	metricCurrentScore = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "bamboo_current_anomaly_score",
		Help: "The anomaly score of the most recently processed packet",
	})
	
	metricThreshold = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "bamboo_current_threshold",
		Help: "The dynamically computed log-normal threshold",
	})
)

// startMetricsServer initializes a minimal HTTP server exposing the /metrics endpoint.
// It returns the running *http.Server so it can be gracefully shut down later.
func startMetricsServer(port int) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go func() {
		slog.Info("Starting Prometheus metrics server", "port", port, "path", "/metrics")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Metrics server failed", "error", err)
		}
	}()

	return srv
}

// stopMetricsServer gracefully shuts down the HTTP server.
func stopMetricsServer(srv *http.Server) {
	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Failed to gracefully shutdown metrics server", "error", err)
	} else {
		slog.Info("Metrics server stopped")
	}
}
