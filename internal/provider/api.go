package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type APIProvider struct {
	client *http.Client
	apiURL string
}

func NewAPIProvider(apiURL string) (*APIProvider, error) {
	client := &http.Client{}
	return &APIProvider{client: client, apiURL: apiURL}, nil
}

type HttpError struct {
	response *http.Response
	body     []byte
}

func NewHttpError(response *http.Response) *HttpError {
	return &HttpError{response: response, body: []byte(readBody(response.Body))}
}

func (ae *HttpError) Error() string {
	return fmt.Sprintf("http error: %s", ae.body)
}

func (ae *HttpError) Body() []byte {
	return ae.body
}

func (ae *HttpError) Status() int {
	return ae.response.StatusCode
}

func (ae *HttpError) Response() *http.Response {
	return ae.response
}

func (p *APIProvider) Authenticate(ctx context.Context, username string, password string) (User, error) {
	user := User{}
	_, err := p.request(ctx, "/authenticate", map[string]string{"username": username, "password": password}, &user)
	if err != nil {
		return nil, fmt.Errorf("Authenticate: %w", err)
	}
	return user, nil
}

func (p *APIProvider) FindByID(ctx context.Context, id string, ip string) (User, error) {
	user := User{}
	_, err := p.request(ctx, "/verify-user", map[string]string{"id": id, "ip": ip}, &user)
	if err != nil {
		return nil, fmt.Errorf("FindByID: %w", err)
	}
	return user, nil
}

func (p *APIProvider) ResetPasswordInitiate(ctx context.Context, email string) error {
	_, err := p.request(ctx, "/reset-password", map[string]string{"email": email}, nil)
	if err != nil {
		return fmt.Errorf("ResetPasswordInitiate: %w", err)
	}
	return nil
}

func (p *APIProvider) ResetPassword(ctx context.Context, email string, token string, newPassword string) error {
	_, err := p.request(ctx, "/reset-password", map[string]string{"email": email, "token": token, "password": newPassword}, nil)
	if err != nil {
		return fmt.Errorf("ResetPassword: %w", err)
	}
	return nil
}

func (p *APIProvider) request(ctx context.Context, url string, reqObj interface{}, respObj interface{}) (*http.Response, error) {
	buf := bytes.NewBuffer(nil)
	if err := json.NewEncoder(buf).Encode(reqObj); err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.apiURL, "/")+url, buf)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()
	if respObj != nil && resp.StatusCode == 200 {
		if err := json.NewDecoder(resp.Body).Decode(&respObj); err != nil {
			return nil, fmt.Errorf("request: %w", err)
		}
	}
	if resp.StatusCode != 200 {
		return nil, NewHttpError(resp)
	}
	return resp, nil
}

func readBody(body io.Reader) string {
	v, err := io.ReadAll(body)
	if err != nil {
		v = []byte("error: " + err.Error())
	}
	return string(v)
}
