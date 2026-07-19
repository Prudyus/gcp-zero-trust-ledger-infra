// Command server implements the ledger-api HTTP service.
//
// Deliberately stdlib-only: no external modules means an empty go.sum, a
// reproducible build, and no third-party CVEs in the Trivy gate. Metrics are
// emitted in Prometheus text format for the OTel collector to scrape at the
// annotation-declared :8080/metrics.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Injected at build time via -ldflags (see Dockerfile).
var (
	version = "dev"
	commit  = "unknown"
)

// Buckets straddle the 1s p99 threshold the alerting rules watch.
var latencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type metrics struct {
	mu       sync.Mutex
	byStatus map[string]uint64
	buckets  []uint64
	sum      float64
	count    uint64
}

func newMetrics() *metrics {
	return &metrics{
		byStatus: make(map[string]uint64),
		buckets:  make([]uint64, len(latencyBuckets)),
	}
}

func (m *metrics) observe(status string, d time.Duration) {
	secs := d.Seconds()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byStatus[status]++
	m.count++
	m.sum += secs
	for i, upper := range latencyBuckets {
		if secs <= upper {
			m.buckets[i]++
		}
	}
}

func (m *metrics) render() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	var b strings.Builder
	b.WriteString("# HELP http_requests_total Total HTTP requests by response status.\n")
	b.WriteString("# TYPE http_requests_total counter\n")
	statuses := make([]string, 0, len(m.byStatus))
	for s := range m.byStatus {
		statuses = append(statuses, s)
	}
	sort.Strings(statuses)
	for _, s := range statuses {
		fmt.Fprintf(&b, "http_requests_total{status=%q} %d\n", s, m.byStatus[s])
	}

	b.WriteString("# HELP http_request_duration_seconds Request latency in seconds.\n")
	b.WriteString("# TYPE http_request_duration_seconds histogram\n")
	for i, upper := range latencyBuckets {
		fmt.Fprintf(&b, "http_request_duration_seconds_bucket{le=\"%g\"} %d\n", upper, m.buckets[i])
	}
	fmt.Fprintf(&b, "http_request_duration_seconds_bucket{le=\"+Inf\"} %d\n", m.count)
	fmt.Fprintf(&b, "http_request_duration_seconds_sum %g\n", m.sum)
	fmt.Fprintf(&b, "http_request_duration_seconds_count %d\n", m.count)

	b.WriteString("# HELP ledger_api_build_info Build metadata (always 1).\n")
	b.WriteString("# TYPE ledger_api_build_info gauge\n")
	fmt.Fprintf(&b, "ledger_api_build_info{version=%q,commit=%q} 1\n", version, commit)

	return b.String()
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func instrument(m *metrics, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		m.observe(strconv.Itoa(rec.status), time.Since(start))
	})
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	m := newMetrics()
	var ready atomic.Bool

	mux := http.NewServeMux()

	// Liveness: process is up. Kubelet restarts the pod if this fails.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	// Readiness: gates endpoint membership, so it must fail during drain.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if !ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ready")
	})

	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprint(w, m.render())
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, "{\"service\":\"ledger-api\",\"version\":%q,\"commit\":%q}\n", version, commit)
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           instrument(m, mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		slog.Info("ledger-api starting",
			"version", version,
			"commit", commit,
			"port", port,
			"spanner_database", os.Getenv("SPANNER_DATABASE"),
			"spanner_database_role", os.Getenv("SPANNER_DATABASE_ROLE"),
		)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("listener failed", "error", err)
			os.Exit(1)
		}
	}()

	ready.Store(true)

	<-ctx.Done()

	// Fail readiness first so the mesh and LB stop sending new work, then
	// drain in-flight requests — matches the preStop sleep in the chart.
	ready.Store(false)
	slog.Info("shutdown signal received, draining")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	slog.Info("shutdown complete")
}
