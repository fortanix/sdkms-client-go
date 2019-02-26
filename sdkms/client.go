package sdkms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"
)

const (
	// DefaultAPIEndpoint is used if no Endpoint is specified in Client
	DefaultAPIEndpoint string = "https://apps.smartkey.io"
)

// Client is an SDKMS client
type Client struct {
	// SDKMS API endpoint, defaults to https://apps.smartkey.io
	Endpoint string
	// http.Client used for communicating to SDKMS backend
	HTTPClient *http.Client
	// Current authorization. If nil, no authorization header is set on requests.
	// This field is set by AuthenticateWith* and TerminateSession methods when establishing a session.
	Auth Authorization
}

func (c *Client) url(path string) string {
	if c.Endpoint != "" {
		return c.Endpoint + path
	}
	return DefaultAPIEndpoint + path
}

func (c *Client) fetchWithAuth(ctx context.Context, method, path string, body interface{}, response interface{}, auth Authorization) error {
	reqBody, err := prepareRequestBody(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, c.url(path), reqBody)
	if err != nil {
		return errors.Wrap(err, "failed to create request")
	}
	if auth != nil {
		auth.setAuthorization(&req.Header)
	}
	resp, err := c.HTTPClient.Do(req.WithContext(ctx))
	if err != nil {
		return errors.Wrap(err, "failed to make HTTP request")
	}
	return parseResponse(resp, response)
}

func (c *Client) fetch(ctx context.Context, method, path string, body interface{}, response interface{}) error {
	return c.fetchWithAuth(ctx, method, path, body, response, c.Auth)
}

func (c *Client) fetchNoAuth(ctx context.Context, method, path string, body interface{}, response interface{}) error {
	return c.fetchWithAuth(ctx, method, path, body, response, nil)
}

func prepareRequestBody(body interface{}) (io.Reader, error) {
	bodyBuf := &bytes.Buffer{}
	if body != nil {
		if err := json.NewEncoder(bodyBuf).Encode(body); err != nil {
			return nil, errors.Wrap(err, "failed to serialize request body")
		}
	}
	return bodyBuf, nil
}

func parseResponse(resp *http.Response, response interface{}) error {
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		buf, _ := ioutil.ReadAll(resp.Body)
		return newBackendError(resp.StatusCode, string(buf))
	}
	if response != nil {
		if err := json.NewDecoder(resp.Body).Decode(response); err != nil {
			return errors.Wrap(err, "failed to decode response body")
		}
	} else {
		// Consume response body so that it can be reused
		// See https://golang.org/pkg/net/http/#Response for documentation
		io.Copy(ioutil.Discard, resp.Body)
	}
	return nil
}

// BackendError is an error returned by SDKMS backend
type BackendError struct {
	StatusCode int
	Message    string
}

func newBackendError(StatusCode int, Message string) *BackendError {
	return &BackendError{
		StatusCode: StatusCode,
		Message:    Message,
	}
}

func (e *BackendError) Error() string {
	return fmt.Sprintf("Status: %v, Message: %s", e.StatusCode, e.Message)
}
