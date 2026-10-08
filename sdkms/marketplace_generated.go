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

type GetMarketplaceParams struct {
    RepoURL string `json:"repo_url"`
}
func (x GetMarketplaceParams) urlEncode(v map[string][]string) error {
    v["repo_url"] = []string{fmt.Sprintf("%v", x.RepoURL)}
    return nil
}

type MarketplacePlugin struct {
    Name string `json:"name"`
    Versions map[PluginVersion]*string `json:"versions"`
}

// Gets all the plugins from the input url.
func (c *Client) GetMarketplace(ctx context.Context, queryParameters *GetMarketplaceParams) ([]MarketplacePlugin, error) {
    u := "/sys/v1/marketplace"
    if queryParameters != nil {
        q, err := encodeURLParams(queryParameters)
        if err != nil {
            return nil, err
        }
        u = fmt.Sprintf("%v?%v", u, q)
    }
    var r []MarketplacePlugin
    if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
        return nil, err
    }
    return r, nil
}

