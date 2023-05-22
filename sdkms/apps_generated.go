/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package sdkms

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

// Operations allowed to be performed by an app.
type AppPermissions uint64

// List of supported AppPermissions values
const (
	AppPermissionsSign AppPermissions = 1 << iota
	AppPermissionsVerify
	AppPermissionsEncrypt
	AppPermissionsDecrypt
	AppPermissionsWrapkey
	AppPermissionsUnwrapkey
	AppPermissionsDerivekey
	AppPermissionsMacgenerate
	AppPermissionsMacverify
	AppPermissionsExport
	AppPermissionsManage
	AppPermissionsAgreekey
	AppPermissionsMaskdecrypt
)

// MarshalJSON converts AppPermissions to an array of strings
func (x AppPermissions) MarshalJSON() ([]byte, error) {
	s := make([]string, 0)
	if x&AppPermissionsSign == AppPermissionsSign {
		s = append(s, "SIGN")
	}
	if x&AppPermissionsVerify == AppPermissionsVerify {
		s = append(s, "VERIFY")
	}
	if x&AppPermissionsEncrypt == AppPermissionsEncrypt {
		s = append(s, "ENCRYPT")
	}
	if x&AppPermissionsDecrypt == AppPermissionsDecrypt {
		s = append(s, "DECRYPT")
	}
	if x&AppPermissionsWrapkey == AppPermissionsWrapkey {
		s = append(s, "WRAPKEY")
	}
	if x&AppPermissionsUnwrapkey == AppPermissionsUnwrapkey {
		s = append(s, "UNWRAPKEY")
	}
	if x&AppPermissionsDerivekey == AppPermissionsDerivekey {
		s = append(s, "DERIVEKEY")
	}
	if x&AppPermissionsMacgenerate == AppPermissionsMacgenerate {
		s = append(s, "MACGENERATE")
	}
	if x&AppPermissionsMacverify == AppPermissionsMacverify {
		s = append(s, "MACVERIFY")
	}
	if x&AppPermissionsExport == AppPermissionsExport {
		s = append(s, "EXPORT")
	}
	if x&AppPermissionsManage == AppPermissionsManage {
		s = append(s, "MANAGE")
	}
	if x&AppPermissionsAgreekey == AppPermissionsAgreekey {
		s = append(s, "AGREEKEY")
	}
	if x&AppPermissionsMaskdecrypt == AppPermissionsMaskdecrypt {
		s = append(s, "MASKDECRYPT")
	}
	return json.Marshal(s)
}

// UnmarshalJSON converts array of strings to AppPermissions
func (x *AppPermissions) UnmarshalJSON(data []byte) error {
	*x = 0
	var s []string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	for _, v := range s {
		switch v {
		case "SIGN":
			*x = *x | AppPermissionsSign
		case "VERIFY":
			*x = *x | AppPermissionsVerify
		case "ENCRYPT":
			*x = *x | AppPermissionsEncrypt
		case "DECRYPT":
			*x = *x | AppPermissionsDecrypt
		case "WRAPKEY":
			*x = *x | AppPermissionsWrapkey
		case "UNWRAPKEY":
			*x = *x | AppPermissionsUnwrapkey
		case "DERIVEKEY":
			*x = *x | AppPermissionsDerivekey
		case "MACGENERATE":
			*x = *x | AppPermissionsMacgenerate
		case "MACVERIFY":
			*x = *x | AppPermissionsMacverify
		case "EXPORT":
			*x = *x | AppPermissionsExport
		case "MANAGE":
			*x = *x | AppPermissionsManage
		case "AGREEKEY":
			*x = *x | AppPermissionsAgreekey
		case "MASKDECRYPT":
			*x = *x | AppPermissionsMaskdecrypt
		}
	}
	return nil
}

// OAuth settings for an app. If enabled, an app can request to act on behalf of a user.
type AppOauthConfig struct {
	Enabled  *AppOauthConfigEnabled
	Disabled *struct{}
}
type AppOauthConfigEnabled struct {
	RedirectUris []string `json:"redirect_uris"`
}

func (x AppOauthConfig) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers("AppOauthConfig", []bool{x.Enabled != nil, x.Disabled != nil}); err != nil {
		return nil, err
	}
	m := make(map[string]interface{})
	switch {
	case x.Enabled != nil:
		b, err := json.Marshal(x.Enabled)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		m["state"] = "enabled"
	case x.Disabled != nil:
		m["state"] = "disabled"
	}
	return json.Marshal(m)
}
func (x *AppOauthConfig) UnmarshalJSON(data []byte) error {
	x.Enabled = nil
	x.Disabled = nil
	var h struct {
		Tag string `json:"state"`
	}
	if err := json.Unmarshal(data, &h); err != nil {
		return errors.Errorf("not a valid AppOauthConfig")
	}
	switch h.Tag {
	case "enabled":
		var enabled AppOauthConfigEnabled
		if err := json.Unmarshal(data, &enabled); err != nil {
			return err
		}
		x.Enabled = &enabled
	case "disabled":
		x.Disabled = &struct{}{}
	default:
		return errors.Errorf("invalid tag value: %v", h.Tag)
	}
	return nil
}

// A trusted CA for app authentication.
type TrustAnchor struct {
	Subject       [][2]string `json:"subject"`
	CaCertificate Blob        `json:"ca_certificate"`
}

// App authentication mechanisms.
type AppCredential struct {
	Secret               *string
	Certificate          *Blob
	TrustedCa            *TrustAnchor
	GoogleServiceAccount *AppCredentialGoogleServiceAccount
	SignedJwt            *AppCredentialSignedJwt
}

// Key access justification reason.
type KeyAccessJustification string

// List of supported key access justifications.
const (
	KeyAccessJustificationCustomerInitiatedSupport               KeyAccessJustification = "CUSTOMER_INITIATED_SUPPORT"
	KeyAccessJustificationCustomerInitiatedAccess                KeyAccessJustification = "CUSTOMER_INITIATED_ACCESS"
	KeyAccessJustificationGoogleInitiatedService                 KeyAccessJustification = "GOOGLE_INITIATED_SERVICE"
	KeyAccessJustificationGoogleInitiatedReview                  KeyAccessJustification = "GOOGLE_INITIATED_REVIEW"
	KeyAccessJustificationGoogleInitiatedSystemOperation         KeyAccessJustification = "GOOGLE_INITIATED_SYSTEM_OPERATION"
	KeyAccessJustificationThirdPartyDataRequest                  KeyAccessJustification = "THIRD_PARTY_DATA_REQUEST"
	KeyAccessJustificationReasonUnspecified                      KeyAccessJustification = "REASON_UNSPECIFIED"
	KeyAccessJustificationReasonNotExpected                      KeyAccessJustification = "REASON_NOT_EXPECTED"
	KeyAccessJustificationModifiedCustomerInitiatedAccess        KeyAccessJustification = "MODIFIED_CUSTOMER_INITIATED_ACCESS"
	KeyAccessJustificationModifiedGoogleInitiatedSystemOperation KeyAccessJustification = "MODIFIED_GOOGLE_INITIATED_SYSTEM_OPERATION"
	KeyAccessJustificationGoogleResponseToProductionAlert        KeyAccessJustification = "GOOGLE_RESPONSE_TO_PRODUCTION_ALERT"
)

type AccessReasonPolicy struct {
	Allow              []KeyAccessJustification `json:"allow"`
	AllowMissingReason bool                     `json:"allow_missing_reason"`
}

type AppCredentialGoogleServiceAccount struct {
	Policy *AccessReasonPolicy `json:"access_reason_policy"`
}

type AppCredentialSignedJwt struct {
	ValidIssuers []string       `json:"valid_issuers"`
	SigningKeys  JwtSigningKeys `json:"signing_keys"`
}

func (x AppCredential) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers("AppCredential", []bool{x.Secret != nil, x.Certificate != nil, x.TrustedCa != nil, x.GoogleServiceAccount != nil, x.SignedJwt != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Secret               *string                            `json:"secret,omitempty"`
		Certificate          *Blob                              `json:"certificate,omitempty"`
		TrustedCa            *TrustAnchor                       `json:"trustedca,omitempty"`
		GoogleServiceAccount *AppCredentialGoogleServiceAccount `json:"googleserviceaccount,omitempty"`
		SignedJwt            *AppCredentialSignedJwt            `json:"signedjwt,omitempty"`
	}
	obj.Secret = x.Secret
	obj.Certificate = x.Certificate
	obj.TrustedCa = x.TrustedCa
	obj.GoogleServiceAccount = x.GoogleServiceAccount
	obj.SignedJwt = x.SignedJwt
	return json.Marshal(obj)
}
func (x *AppCredential) UnmarshalJSON(data []byte) error {
	x.Secret = nil
	x.Certificate = nil
	x.TrustedCa = nil
	x.GoogleServiceAccount = nil
	x.SignedJwt = nil
	var obj struct {
		Secret               *string                            `json:"secret,omitempty"`
		Certificate          *Blob                              `json:"certificate,omitempty"`
		TrustedCa            *TrustAnchor                       `json:"trustedca,omitempty"`
		GoogleServiceAccount *AppCredentialGoogleServiceAccount `json:"googleserviceaccount,omitempty"`
		SignedJwt            *AppCredentialSignedJwt            `json:"signedjwt,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.Secret = obj.Secret
	x.Certificate = obj.Certificate
	x.TrustedCa = obj.TrustedCa
	x.GoogleServiceAccount = obj.GoogleServiceAccount
	x.SignedJwt = obj.SignedJwt
	return nil
}

// Authentication method of an app.
type AppAuthType string

// List of supported AppAuthType values
const (
	AppAuthTypeSecret               AppAuthType = "Secret"
	AppAuthTypeCertificate          AppAuthType = "Certificate"
	AppAuthTypeTrustedCa            AppAuthType = "TrustedCa"
	AppAuthTypeGoogleServiceAccount AppAuthType = "GoogleServiceAccount"
	AppAuthTypeSignedJwt            AppAuthType = "SignedJwt"
)

type App struct {
	AcctID       UUID            `json:"acct_id"`
	AppID        UUID            `json:"app_id"`
	AppType      string          `json:"app_type"`
	AuthType     *AppAuthType    `json:"auth_type,omitempty"`
	CertNotAfter *Time           `json:"cert_not_after,omitempty"`
	CreatedAt    Time            `json:"created_at"`
	Creator      Principal       `json:"creator"`
	DefaultGroup *UUID           `json:"default_group,omitempty"`
	Description  *string         `json:"description,omitempty"`
	Enabled      bool            `json:"enabled"`
	Groups       AppGroups       `json:"groups"`
	Interface    *string         `json:"interface,omitempty"`
	LastusedAt   *Time           `json:"lastused_at,omitempty"`
	Name         string          `json:"name"`
	OauthConfig  *AppOauthConfig `json:"oauth_config,omitempty"`
}

type AppRequest struct {
	AddGroups    *AppGroups      `json:"add_groups,omitempty"`
	AppType      *string         `json:"app_type,omitempty"`
	Credential   *AppCredential  `json:"credential,omitempty"`
	DefaultGroup *UUID           `json:"default_group,omitempty"`
	DelGroups    *[]UUID         `json:"del_groups,omitempty"`
	Description  *string         `json:"description,omitempty"`
	Enabled      *bool           `json:"enabled,omitempty"`
	Interface    *string         `json:"interface,omitempty"`
	ModGroups    *AppGroups      `json:"mod_groups,omitempty"`
	Name         *string         `json:"name,omitempty"`
	OauthConfig  *AppOauthConfig `json:"oauth_config,omitempty"`
	SecretSize   *uint32         `json:"secret_size,omitempty"`
}

type AppResetSecretRequest struct {
	// Size of app's secret in bytes.
	SecretSize *uint32 `json:"secret_size,omitempty"`
}

// App credential response.
type AppCredentialResponse struct {
	AppID      UUID          `json:"app_id"`
	Credential AppCredential `json:"credential"`
}

type GetAppParams struct {
	GroupPermissions bool `json:"group_permissions"`
}

func (x GetAppParams) urlEncode(v map[string][]string) error {
	v["group_permissions"] = []string{fmt.Sprintf("%v", x.GroupPermissions)}
	return nil
}

type ListAppsParams struct {
	GroupID          *UUID   `json:"group_id,omitempty"`
	Limit            *uint   `json:"limit,omitempty"`
	Offset           *uint   `json:"offset,omitempty"`
	Sort             AppSort `json:"sort"`
	GroupPermissions bool    `json:"group_permissions"`
}

func (x ListAppsParams) urlEncode(v map[string][]string) error {
	if x.GroupID != nil {
		v["group_id"] = []string{fmt.Sprintf("%v", *x.GroupID)}
	}
	if x.Limit != nil {
		v["limit"] = []string{fmt.Sprintf("%v", *x.Limit)}
	}
	if x.Offset != nil {
		v["offset"] = []string{fmt.Sprintf("%v", *x.Offset)}
	}
	if err := x.Sort.urlEncode(v); err != nil {
		return err
	}
	v["group_permissions"] = []string{fmt.Sprintf("%v", x.GroupPermissions)}
	return nil
}

type AppSort struct {
	ByAppID *AppSortByAppId
}
type AppSortByAppId struct {
	Order Order `json:"order"`
	Start *UUID `json:"start,omitempty"`
}

func (x AppSort) urlEncode(v map[string][]string) error {
	if x.ByAppID != nil {
		v["sort"] = []string{"app_id" + string(x.ByAppID.Order)}
		if x.ByAppID.Start != nil {
			v["start"] = []string{fmt.Sprintf("%v", *x.ByAppID.Start)}
		}
	}
	return nil
}

// Get all apps accessible to the current user.
func (c *Client) ListApps(ctx context.Context, queryParameters *ListAppsParams) ([]App, error) {
	u := "/sys/v1/apps"
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	var r []App
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return r, nil
}

// Lookup an app by its ID.
func (c *Client) GetApp(ctx context.Context, id string, queryParameters *GetAppParams) (*App, error) {
	u := "/sys/v1/apps/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	var r App
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Create a new app.
func (c *Client) CreateApp(ctx context.Context, queryParameters *GetAppParams, body AppRequest) (*App, error) {
	u := "/sys/v1/apps"
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	var r App
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Update an app.
func (c *Client) UpdateApp(ctx context.Context, id string, queryParameters *GetAppParams, body AppRequest) (*App, error) {
	u := "/sys/v1/apps/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	var r App
	if err := c.fetch(ctx, http.MethodPatch, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Delete an app.
func (c *Client) DeleteApp(ctx context.Context, id string) error {
	u := "/sys/v1/apps/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
		return err
	}
	return nil
}

// Create a new API key for an app. An app may only have one valid API key at a time,
// so performing this action will invalidate all old API keys.
func (c *Client) ResetAppSecret(ctx context.Context, id string, queryParameters *GetAppParams, body AppResetSecretRequest) (*App, error) {
	u := "/sys/v1/apps/:id/reset_secret"
	u = strings.NewReplacer(":id", id).Replace(u)
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	var r App
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Retrieve the authentication credential (API key, certificate, etc.) for a particular app.
func (c *Client) GetAppCredential(ctx context.Context, id string) (*AppCredentialResponse, error) {
	u := "/sys/v1/apps/:id/credential"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r AppCredentialResponse
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToGetAppCredential(ctx context.Context, id string, description *string) (*ApprovalRequest, error) {
	u := "/sys/v1/apps/:id/credential"
	u = strings.NewReplacer(":id", id).Replace(u)
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodGet),
		Operation:   &u,
		Body:        nil,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}
