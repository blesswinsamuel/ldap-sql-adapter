package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "ldap_sql_adapter_http_duration_seconds",
		Help: "Duration of HTTP requests.",
	}, []string{"path", "status"})
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (rec *statusRecorder) WriteHeader(code int) {
	rec.status = code
	rec.ResponseWriter.WriteHeader(code)
}

func prometheusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := mux.CurrentRoute(r)
		path, _ := route.GetPathTemplate()

		startTime := time.Now()

		rec := &statusRecorder{w, 200}
		next.ServeHTTP(rec, r)

		httpDuration.WithLabelValues(path, fmt.Sprint(rec.status)).Observe(time.Since(startTime).Seconds())
	})
}
