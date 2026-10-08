/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package sdkms

import (
    "context"
    "net/http"
    "strings"
)

type AccountExtension struct {
    AcctID UUID `json:"acct_id"`
    CryptographicPolicy *CryptographicPolicy `json:"cryptographic_policy,omitempty"`
    KeyHistoryPolicy *KeyHistoryPolicy `json:"key_history_policy,omitempty"`
    KeyMetadataPolicy *KeyMetadataPolicy `json:"key_metadata_policy,omitempty"`
    CustomMetadata map[string]string `json:"custom_metadata"`
    CustomMetadataAttributes map[string]CustomAttributeSearchMetadata `json:"custom_metadata_attributes"`
    PluginCodeSigningPolicy *PluginCodeSigningPolicy `json:"plugin_code_signing_policy,omitempty"`
    MarkKeyDisabledWhenDeactivated bool `json:"mark_key_disabled_when_deactivated"`
}

// The model used to create a new account extension.
type AccountExtensionCreateRequest struct {
    CryptographicPolicy *CryptographicPolicy `json:"cryptographic_policy,omitempty"`
    KeyHistoryPolicy *KeyHistoryPolicy `json:"key_history_policy,omitempty"`
    KeyMetadataPolicy *KeyMetadataPolicy `json:"key_metadata_policy,omitempty"`
    CustomMetadata map[string]string `json:"custom_metadata"`
    CustomMetadataAttributes map[string]CustomAttributeSearchMetadata `json:"custom_metadata_attributes"`
    PluginCodeSigningPolicy *PluginCodeSigningPolicy `json:"plugin_code_signing_policy,omitempty"`
    MarkKeyDisabledWhenDeactivated bool `json:"mark_key_disabled_when_deactivated"`
}

type AccountExtensionRequest struct {
    CryptographicPolicy *Removable[CryptographicPolicy] `json:"cryptographic_policy,omitempty"`
    KeyHistoryPolicy *Removable[KeyHistoryPolicy] `json:"key_history_policy,omitempty"`
    KeyMetadataPolicy *Removable[KeyMetadataPolicy] `json:"key_metadata_policy,omitempty"`
    CustomMetadata *map[string]string `json:"custom_metadata,omitempty"`
    CustomMetadataAttributes *map[string]CustomAttributeSearchMetadata `json:"custom_metadata_attributes,omitempty"`
    PluginCodeSigningPolicy *Removable[PluginCodeSigningPolicy] `json:"plugin_code_signing_policy,omitempty"`
    MarkKeyDisabledWhenDeactivated *bool `json:"mark_key_disabled_when_deactivated,omitempty"`
}

// Create a new account extension.
func (c *Client) CreateAccountExtension(ctx context.Context, acct_id string, body AccountExtensionCreateRequest) (*AccountExtension, error) {
    u := "/sys/v1/account_extensions/:acct_id"
    u = strings.NewReplacer(":acct_id", acct_id).Replace(u)
    var r AccountExtension
    if err := c.fetch(ctx, http.MethodPut, u, &body, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Get info for a specific account extension.
func (c *Client) GetAccountExtension(ctx context.Context, acct_id string) (*AccountExtension, error) {
    u := "/sys/v1/account_extensions/:acct_id"
    u = strings.NewReplacer(":acct_id", acct_id).Replace(u)
    var r AccountExtension
    if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Update specific account extension.
func (c *Client) UpdateAccountExtension(ctx context.Context, acct_id string, body AccountExtensionRequest) (*AccountExtension, error) {
    u := "/sys/v1/account_extensions/:acct_id"
    u = strings.NewReplacer(":acct_id", acct_id).Replace(u)
    var r AccountExtension
    if err := c.fetch(ctx, http.MethodPatch, u, &body, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

