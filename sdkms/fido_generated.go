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

// Completes a pending authentication using a FIDO2 key.
func (c *Client) CompleteFido2Auth(ctx context.Context, body PublicKeyCredentialAuthenticatorAssertionResponse) error {
    u := "/sys/v1/session/auth/2fa/fido2"
    if err := c.fetch(ctx, http.MethodPost, u, &body, nil); err != nil {
        return err
    }
    return nil
}

// Get credential creation options as per the given request.
//
// The response of this API needs to be used with relevant API
// for the protocol.
// For U2F, it is `u2f.register()`.
// For FIDO2, it is `navigator.credentials.create()`.
func (c *Client) MfaNewChallenge(ctx context.Context, queryParameters *MfaChallengeParams) (*MfaChallengeResponse, error) {
    u := "/sys/v1/session/config_2fa/new_challenge"
    if queryParameters != nil {
        q, err := encodeURLParams(queryParameters)
        if err != nil {
            return nil, err
        }
        u = fmt.Sprintf("%v?%v", u, q)
    }
    var r MfaChallengeResponse
    if err := c.fetch(ctx, http.MethodPost, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

