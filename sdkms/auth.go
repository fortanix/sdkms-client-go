/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package sdkms

import (
	"context"
	"encoding/base64"
	"net/http"
)

// Authorization provides an HTTP authorization header
type Authorization interface {
	setAuthorization(*http.Header)
}

// APIKey is used for app authentication
type APIKey string

func (a APIKey) setAuthorization(header *http.Header) {
	header.Set("Authorization", "Basic "+string(a))
}

// BasicAuth is used for user authentication
type BasicAuth struct {
	Username string
	Password string
}

func (a BasicAuth) setAuthorization(header *http.Header) {
	v := base64.StdEncoding.EncodeToString([]byte(a.Username + ":" + a.Password))
	header.Set("Authorization", "Basic "+v)
}

// BearerToken is used for established sessions
type BearerToken string

func (a BearerToken) setAuthorization(header *http.Header) {
	header.Set("Authorization", "Bearer "+string(a))
}

// AuthenticationResponse is the response returned by AuthenticateWith* APIs
type AuthenticationResponse struct {
	ExpiresIn   int32  `json:"expires_in"`
	AccessToken string `json:"access_token"`
	EntityID    string `json:"entity_id"`
}

func (c *Client) authenticate(ctx context.Context, auth Authorization) (*AuthenticationResponse, error) {
	var response AuthenticationResponse
	err := c.fetchWithAuth(ctx, http.MethodPost, "/sys/v1/session/auth", nil, &response, auth)
	if err != nil {
		return nil, err
	}
	c.Auth = BearerToken(response.AccessToken)
	return &response, nil
}

// AuthenticateWithUserPass authenticates a user
func (c *Client) AuthenticateWithUserPass(ctx context.Context, username, password string) (*AuthenticationResponse, error) {
	return c.authenticate(ctx, BasicAuth{Username: username, Password: password})
}

// AuthenticateWithAPIKey authenticates an app
func (c *Client) AuthenticateWithAPIKey(ctx context.Context, apiKey string) (*AuthenticationResponse, error) {
	return c.authenticate(ctx, APIKey(apiKey))
}

// TerminateSession terminates the current session
func (c *Client) TerminateSession(ctx context.Context) error {
	err := c.fetch(ctx, http.MethodPost, "/sys/v1/session/terminate", nil, nil)
	if err != nil {
		return err
	}
	c.Auth = nil
	return nil
}
