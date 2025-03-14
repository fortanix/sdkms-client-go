/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package sdkms

import (
    "context"
    "fmt"
    "net/http"
)

// Server execution mode.
type ServerMode string

// List of supported ServerMode values
const (
    ServerModeSoftware ServerMode = "Software"
    ServerModeSgx ServerMode = "Sgx"
)

type VersionParams struct {
    // Include FIPS-relevant info in the response. Currently that is `plugins_digest`.
    //
    // Only applicable to FIPS builds.
    DetailedFipsInfo *bool `json:"detailed_fips_info,omitempty"`
}
func (x VersionParams) urlEncode(v map[string][]string) error {
    if x.DetailedFipsInfo != nil {
        v["detailed_fips_info"] = []string{fmt.Sprintf("%v", *x.DetailedFipsInfo)}
    }
    return nil
}

// Information about the service version.
type VersionResponse struct {
    // Server version. This is encoded as "major.minor.build".
    Version string `json:"version"`
    // The API version implemented by the server.
    APIVersion string `json:"api_version"`
    ServerMode ServerMode `json:"server_mode"`
    // FIPS level at which the service in running. If this field is absent, then the service is
    // not running in FIPS compliant mode.
    FipsLevel *uint8 `json:"fips_level,omitempty"`
    // An opaque digest of all current plugins.
    //
    // Only present when the server is running in FIPS mode.
    PluginsDigest *Blob `json:"plugins_digest,omitempty"`
}

// Returns information about the DSM server version and the client
// API version that it supports.
func (c *Client) Version(ctx context.Context, queryParameters *VersionParams) (*VersionResponse, error) {
    u := "/sys/v1/version"
    if queryParameters != nil {
        q, err := encodeURLParams(queryParameters)
        if err != nil {
            return nil, err
        }
        u = fmt.Sprintf("%v?%v", u, q)
    }
    var r VersionResponse
    if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

