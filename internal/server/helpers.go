package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/blesswinsamuel/api-forward-auth/internal/provider"

	"github.com/rs/zerolog"
)

type HttpResponseError struct {
	message    string
	statusCode int
	err        error
}

func NewHttpResponseError(message string, statusCode int) error {
	return &HttpResponseError{message: message, statusCode: statusCode}
}

func NewHttpResponseErrorWithError(err error, message string, statusCode int) error {
	return &HttpResponseError{err: err, message: message, statusCode: statusCode}
}

func (e *HttpResponseError) Error() string {
	return fmt.Sprintf("%s: %s", e.message, e.err.Error())
}

func (e *HttpResponseError) Message() string {
	return e.message
}

func (e *HttpResponseError) Unwrap() error {
	return e.err
}

func writeErrorResponse(w http.ResponseWriter, message string, status int) {
	w.WriteHeader(status)
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{message})
}

func writeJsonResponse(w http.ResponseWriter, v interface{}, status int) {
	w.WriteHeader(status)
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func handleUpstreamHTTPError(w http.ResponseWriter, err error, logger zerolog.Logger, errmsg string) {
	httpErr := &provider.HttpError{}
	if errors.As(err, &httpErr) {
		w.WriteHeader(httpErr.Status())
		w.Header().Add("Content-Type", httpErr.Response().Header.Get("Content-Type"))
		w.Write(httpErr.Body())
		return
	}
	logger.Error().Err(err).Msg(errmsg)
	writeErrorResponse(w, "Service unavailable", 503)
}
