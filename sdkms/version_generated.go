/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package sdkms

import (
	"context"
	"net/http"
)

// Server mode.
type ServerMode string

// List of supported ServerMode values
const (
	ServerModeSoftware ServerMode = "Software"
	ServerModeSgx      ServerMode = "Sgx"
)

// Information about the service version.
type VersionResponse struct {
	// Server version. This is encoded as "major.minor.build".
	Version string `json:"version"`
	// The API version implemented by the server.
	APIVersion string     `json:"api_version"`
	ServerMode ServerMode `json:"server_mode"`
	// FIPS level at which the service in running. If this field is absent, then the service is
	// not running in FIPS compliant mode.
	FipsLevel *uint8 `json:"fips_level,omitempty"`
}

// Returns information about the  SDKMS server version and the client API version that it supports.
func (c *Client) Version(ctx context.Context) (*VersionResponse, error) {
	u := "/sys/v1/version"
	var r VersionResponse
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
