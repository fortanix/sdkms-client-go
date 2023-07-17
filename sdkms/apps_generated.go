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

type App struct {
	// The id of the Account that this application belongs to.
	AcctID UUID `json:"acct_id"`
	// Unique id to identify the application.
	AppID UUID `json:"app_id"`
	// The user-defined type of this application.
	AppType string `json:"app_type"`
	// The authentication mechanisms for an application.
	AuthType *AppAuthType `json:"auth_type,omitempty"`
	// Certificate expiration date.
	CertNotAfter *Time `json:"cert_not_after,omitempty"`
	// Client configurations that are set on the application level.
	// App level client configs override those set at group or account level.
	ClientConfigurations ClientConfigurations `json:"client_configurations"`
	// Timestamp when the application was created.
	CreatedAt Time `json:"created_at"`
	// Creator of this application.
	Creator Principal `json:"creator"`
	// The default group an application belongs to.
	DefaultGroup *UUID `json:"default_group,omitempty"`
	// Description of this application.
	Description *string `json:"description,omitempty"`
	// Whether this application is enabled.
	Enabled bool `json:"enabled"`
	// Mapping for all groups an application is part of and the permissions it has within each of those groups.
	Groups AppGroups `json:"groups"`
	// Interface used with this application (PKCS11, CNG, JCE, KMIP, etc).
	Interface *string `json:"interface,omitempty"`
	// The IPs that are allowed for an application. ipv4 or ipv6 both are acceptable types.
	IpAddressPolicy IpAddressPolicy           `json:"ip_address_policy"`
	LastOperations  LastAppOperationTimestamp `json:"last_operations"`
	// Timestamp when the application was most recently used.
	LastusedAt *Time `json:"lastused_at,omitempty"`
	// If a requester is updating an App or retrieving its credentials,
	// they must have the relevant permissions in all Groups that App has access to.
	// But for legacy Apps, requester is required to have relevant permissions
	// in any of the groups that App has access to.
	LegacyAccess bool `json:"legacy_access"`
	// Name of this application, which must be unique within an account.
	Name string `json:"name"`
	// OAuth settings for an app. If enabled, an app can request to act on behalf of a user.
	OauthConfig *AppOauthConfig `json:"oauth_config,omitempty"`
	// Application's role.
	Role AppRole `json:"role"`
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
	AppAuthTypeLdap                 AppAuthType = "Ldap"
	AppAuthTypeAwsIam               AppAuthType = "AwsIam"
	AppAuthTypeAwsXks               AppAuthType = "AwsXks"
)

// App authentication mechanisms.
type AppCredential struct {
	// Authenticating credentials of an App.
	Secret *string
	// PKI Certificate based authentication.
	Certificate *Blob
	// PKI certificate with Trusted CA based authentication.
	TrustedCa *TrustAnchor
	// An App's service account for communicating with Google APIs and Cloud. Google OAuth 2.0
	GoogleServiceAccount *AppCredentialGoogleServiceAccount
	// Authentication using a signed JWT directly as a bearer token.
	SignedJwt *AppCredentialSignedJwt
	// LDAP credentials of an App used for authentication.
	Ldap *UUID
	// Sign-in credentials to authenticate with AWS for it's services and resources.
	AwsIam *struct{}
	// SigV4 credentials used for AWS XKS APIs
	AwsXks *AppCredentialAwsXks
}

// An App's service account for communicating with Google APIs and Cloud. Google OAuth 2.0
type AppCredentialGoogleServiceAccount struct {
	// Policy specifying acceptable access reasons.
	AccessReasonPolicy *GoogleAccessReasonPolicy `json:"access_reason_policy,omitempty"`
}

// Authentication using a signed JWT directly as a bearer token.
type AppCredentialSignedJwt struct {
	ValidIssuers []string       `json:"valid_issuers"`
	SigningKeys  JwtSigningKeys `json:"signing_keys"`
}

// SigV4 credentials used for AWS XKS APIs
type AppCredentialAwsXks struct {
	AccessKeyID *string `json:"access_key_id,omitempty"`
	SecretKey   *string `json:"secret_key,omitempty"`
}

func (x AppCredential) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"AppCredential",
		[]bool{x.Secret != nil,
			x.Certificate != nil,
			x.TrustedCa != nil,
			x.GoogleServiceAccount != nil,
			x.SignedJwt != nil,
			x.Ldap != nil,
			x.AwsIam != nil,
			x.AwsXks != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Secret               *string                            `json:"secret,omitempty"`
		Certificate          *Blob                              `json:"certificate,omitempty"`
		TrustedCa            *TrustAnchor                       `json:"trustedca,omitempty"`
		GoogleServiceAccount *AppCredentialGoogleServiceAccount `json:"googleserviceaccount,omitempty"`
		SignedJwt            *AppCredentialSignedJwt            `json:"signedjwt,omitempty"`
		Ldap                 *UUID                              `json:"ldap,omitempty"`
		AwsIam               *struct{}                          `json:"awsiam,omitempty"`
		AwsXks               *AppCredentialAwsXks               `json:"awsxks,omitempty"`
	}
	obj.Secret = x.Secret
	obj.Certificate = x.Certificate
	obj.TrustedCa = x.TrustedCa
	obj.GoogleServiceAccount = x.GoogleServiceAccount
	obj.SignedJwt = x.SignedJwt
	obj.Ldap = x.Ldap
	obj.AwsIam = x.AwsIam
	obj.AwsXks = x.AwsXks
	return json.Marshal(obj)
}
func (x *AppCredential) UnmarshalJSON(data []byte) error {
	x.Secret = nil
	x.Certificate = nil
	x.TrustedCa = nil
	x.GoogleServiceAccount = nil
	x.SignedJwt = nil
	x.Ldap = nil
	x.AwsIam = nil
	x.AwsXks = nil
	var obj struct {
		Secret               *string                            `json:"secret,omitempty"`
		Certificate          *Blob                              `json:"certificate,omitempty"`
		TrustedCa            *TrustAnchor                       `json:"trustedca,omitempty"`
		GoogleServiceAccount *AppCredentialGoogleServiceAccount `json:"googleserviceaccount,omitempty"`
		SignedJwt            *AppCredentialSignedJwt            `json:"signedjwt,omitempty"`
		Ldap                 *UUID                              `json:"ldap,omitempty"`
		AwsIam               *struct{}                          `json:"awsiam,omitempty"`
		AwsXks               *AppCredentialAwsXks               `json:"awsxks,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.Secret = obj.Secret
	x.Certificate = obj.Certificate
	x.TrustedCa = obj.TrustedCa
	x.GoogleServiceAccount = obj.GoogleServiceAccount
	x.SignedJwt = obj.SignedJwt
	x.Ldap = obj.Ldap
	x.AwsIam = obj.AwsIam
	x.AwsXks = obj.AwsXks
	return nil
}

// App credential response.
type AppCredentialResponse struct {
	// Unique identifier of the App.
	AppID UUID `json:"app_id"`
	// Credential of an App which determine the App authentication mechanisms.
	Credential AppCredential `json:"credential"`
	// Expired app-credentials that may be valid during transitional period.
	PreviousCredential *PreviousCredential `json:"previous_credential,omitempty"`
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
	if err := checkEnumPointers(
		"AppOauthConfig",
		[]bool{x.Enabled != nil,
			x.Disabled != nil}); err != nil {
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

type AppRequest struct {
	// Groups an application wants to be part of. Should belong to atleast one.
	AddGroups *AppGroups `json:"add_groups,omitempty"`
	// The user-defined type of this application.
	AppType *string `json:"app_type,omitempty"`
	// Client configurations that are set on the application level.
	// App level client configs override those set at group or account level.
	ClientConfigurations *ClientConfigurationsRequest `json:"client_configurations,omitempty"`
	// Credential for an application which determine the App authentication mechanisms.
	Credential *AppCredential `json:"credential,omitempty"`
	// Migration period for which credentials(and its sessions) remain valid during api key regeneration.
	CredentialMigrationPeriod *uint32 `json:"credential_migration_period,omitempty"`
	// The default group an application belongs to.
	DefaultGroup *UUID `json:"default_group,omitempty"`
	// Groups an application no longer needs to be a part of. Array of UUID of groups.
	DelGroups *[]UUID `json:"del_groups,omitempty"`
	// Description of this application.
	Description *string `json:"description,omitempty"`
	// Whether this application is enabled.
	Enabled *bool `json:"enabled,omitempty"`
	// Interface used with this application (PKCS11, CNG, JCE, KMIP, etc).
	Interface *string `json:"interface,omitempty"`
	// The IPs that are allowed for an application. ipv4 or ipv6 both are acceptable types.
	IpAddressPolicy *IpAddressPolicy `json:"ip_address_policy,omitempty"`
	// Modify the permissions an application has in the groups it belongs to.
	ModGroups *AppGroups `json:"mod_groups,omitempty"`
	// Name of this application, which must be unique within an account.
	Name *string `json:"name,omitempty"`
	// OAuth settings for an app. If enabled, an app can request to act on behalf of a user.
	OauthConfig *AppOauthConfig `json:"oauth_config,omitempty"`
	// Application's role.
	Role *AppRole `json:"role,omitempty"`
	// Size in bytes of app's secret.
	SecretSize *uint32 `json:"secret_size,omitempty"`
}

// Request for resetting the app secret.
type AppResetSecretRequest struct {
	// Size of app's secret in bytes.
	SecretSize *uint32 `json:"secret_size,omitempty"`
	// Time until which previous credentials(or its sessions)
	// will not be invalidated as the API key gets regenerated.
	CredentialMigrationPeriod *uint32 `json:"credential_migration_period,omitempty"`
}

// App's role.
type AppRole string

// List of supported AppRole values
const (
	AppRoleAdmin  AppRole = "admin"
	AppRoleCrypto AppRole = "crypto"
)

// Sort apps as per given ordering.
type AppSort struct {
	// Sort apps on the basis of their app_id.
	ByAppID *AppSortByAppId
}

// Sort apps on the basis of their app_id.
type AppSortByAppId struct {
	// Ascending or Descending order.
	Order Order `json:"order"`
	// Starting from a particular app_id.
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

// Query params for individual App APIs
type GetAppParams struct {
	// Flag specifying if group permissions should be returned with the app group.
	GroupPermissions *bool `json:"group_permissions,omitempty"`
	// The App's role.
	Role *string `json:"role,omitempty"`
}

func (x GetAppParams) urlEncode(v map[string][]string) error {
	if x.GroupPermissions != nil {
		v["group_permissions"] = []string{fmt.Sprintf("%v", *x.GroupPermissions)}
	}
	if x.Role != nil {
		v["role"] = []string{fmt.Sprintf("%v", *x.Role)}
	}
	return nil
}

// The IPs that are allowed for an application. ipv4 or ipv6 both are acceptable types.
type IpAddressPolicy struct {
	AllowAll  *struct{}
	Whitelist *[]string
}

func (x IpAddressPolicy) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"IpAddressPolicy",
		[]bool{x.AllowAll != nil,
			x.Whitelist != nil}); err != nil {
		return nil, err
	}
	switch {
	case x.AllowAll != nil:
		return []byte(`"allow_all"`), nil
	}
	var obj struct {
		Whitelist *[]string `json:"whitelist,omitempty"`
	}
	obj.Whitelist = x.Whitelist
	return json.Marshal(obj)
}
func (x *IpAddressPolicy) UnmarshalJSON(data []byte) error {
	x.AllowAll = nil
	x.Whitelist = nil
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		switch str {
		case "allow_all":
			x.AllowAll = &struct{}{}
		default:
			return errors.Errorf("invalid value for IpAddressPolicy: %v", str)
		}
		return nil
	}
	var obj struct {
		Whitelist *[]string `json:"whitelist,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.Whitelist = obj.Whitelist
	return nil
}

type LastAppOperationTimestamp struct {
	Generic           *uint64 `json:"generic,omitempty"`
	Tokenization      *uint64 `json:"tokenization,omitempty"`
	Tep               *uint64 `json:"tep,omitempty"`
	Accelerator       *uint64 `json:"accelerator,omitempty"`
	SecretsManagement *uint64 `json:"secrets_management,omitempty"`
}

// Query params for Get all apps API
type ListAppsParams struct {
	// Group for which the associated apps should be retrived.
	GroupID *UUID `json:"group_id,omitempty"`
	// Maximum number of apps to return. Default limit is 1001.
	Limit *uint `json:"limit,omitempty"`
	// Number of apps to skip from the beginning/start.
	Offset *uint `json:"offset,omitempty"`
	// Sort apps by app_id in ascending or descending order.
	Sort AppSort `json:"sort"`
	// Flag specifying if group permissions should be returned with the apps.
	GroupPermissions *bool `json:"group_permissions,omitempty"`
	// Specify role of the apps.
	Role *AppRole `json:"role,omitempty"`
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
	if x.GroupPermissions != nil {
		v["group_permissions"] = []string{fmt.Sprintf("%v", *x.GroupPermissions)}
	}
	if x.Role != nil {
		v["role"] = []string{fmt.Sprintf("%v", *x.Role)}
	}
	return nil
}

// Expired app-credentials that are still valid for a transitional period.
type PreviousCredential struct {
	// App authentication mechanisms.
	Credential AppCredential `json:"credential"`
	// Validity period of the App credentials.
	ValidUntil Time `json:"valid_until"`
}

type SubjectGeneral struct {
	DirectoryName *[][2]string
	DnsName       *string
	IpAddress     *IpAddr
}

func (x SubjectGeneral) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"SubjectGeneral",
		[]bool{x.DirectoryName != nil,
			x.DnsName != nil,
			x.IpAddress != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		DirectoryName *[][2]string `json:"directory_name,omitempty"`
		DnsName       *string      `json:"dns_name,omitempty"`
		IpAddress     *IpAddr      `json:"ip_address,omitempty"`
	}
	obj.DirectoryName = x.DirectoryName
	obj.DnsName = x.DnsName
	obj.IpAddress = x.IpAddress
	return json.Marshal(obj)
}
func (x *SubjectGeneral) UnmarshalJSON(data []byte) error {
	x.DirectoryName = nil
	x.DnsName = nil
	x.IpAddress = nil
	var obj struct {
		DirectoryName *[][2]string `json:"directory_name,omitempty"`
		DnsName       *string      `json:"dns_name,omitempty"`
		IpAddress     *IpAddr      `json:"ip_address,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.DirectoryName = obj.DirectoryName
	x.DnsName = obj.DnsName
	x.IpAddress = obj.IpAddress
	return nil
}

// A trusted CA for app authentication.
type TrustAnchor struct {
	Subject       TrustAnchorSubject `json:"subject"`
	CaCertificate Blob               `json:"ca_certificate"`
}

func (x TrustAnchor) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	{ // Subject
		b, err := json.Marshal(&x.Subject)
		if err != nil {
			return nil, err
		}
		f := make(map[string]interface{})
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, err
		}
		for k, v := range f {
			m[k] = &v
		}
	}
	m["ca_certificate"] = &x.CaCertificate
	return json.Marshal(&m)
}
func (x *TrustAnchor) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &x.Subject); err != nil {
		return err
	}
	var r struct {
		CaCertificate Blob `json:"ca_certificate"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	x.CaCertificate = r.CaCertificate
	return nil
}

type TrustAnchorSubject struct {
	Subject        *[][2]string
	SubjectGeneral *SubjectGeneral
}

func (x TrustAnchorSubject) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"TrustAnchorSubject",
		[]bool{x.Subject != nil,
			x.SubjectGeneral != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Subject        *[][2]string    `json:"subject,omitempty"`
		SubjectGeneral *SubjectGeneral `json:"subject_general,omitempty"`
	}
	obj.Subject = x.Subject
	obj.SubjectGeneral = x.SubjectGeneral
	return json.Marshal(obj)
}
func (x *TrustAnchorSubject) UnmarshalJSON(data []byte) error {
	x.Subject = nil
	x.SubjectGeneral = nil
	var obj struct {
		Subject        *[][2]string    `json:"subject,omitempty"`
		SubjectGeneral *SubjectGeneral `json:"subject_general,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.Subject = obj.Subject
	x.SubjectGeneral = obj.SubjectGeneral
	return nil
}

// Create a new application with the specified properties.
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

// Delete an app.
func (c *Client) DeleteApp(ctx context.Context, id string) error {
	u := "/sys/v1/apps/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
		return err
	}
	return nil
}

// Lookup an application.
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

// Get an application's credential.
func (c *Client) GetAppCredential(ctx context.Context, id string) (*AppCredentialResponse, error) {
	u := "/sys/v1/apps/:id/credential"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r AppCredentialResponse
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToGetAppCredential(
	ctx context.Context,
	id string,
	description *string) (*ApprovalRequest, error) {
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

// Get configurations for various clients. This API can only be called by apps
//
// Client configurations can be set at account level, group level or app level.
// Client config set on the app itself overrides config set at group level and
// similarly group level config overrides account level config. This API returns
// the combined client config according to the above explanation.
func (c *Client) GetClientConfigs(ctx context.Context) (*ClientConfigurations, error) {
	u := "/sys/v1/apps/client_configs"
	var r ClientConfigurations
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Get details of all apps accessible to requester.
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

// Regenerate API key.
//
// This will invalidate all existing sessions of this app. Although,
// if `credential_migration_period` is set in request, previous
// credentials (or its sessions) won't invalidate until the given time.
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

func (c *Client) RequestApprovalToResetAppSecret(
	ctx context.Context,
	id string,
	queryParameters *GetAppParams,
	body AppResetSecretRequest,
	description *string) (*ApprovalRequest, error) {
	u := "/sys/v1/apps/:id/reset_secret"
	u = strings.NewReplacer(":id", id).Replace(u)
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Update app settings like groups, client config, etc.
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

func (c *Client) RequestApprovalToUpdateApp(
	ctx context.Context,
	id string,
	queryParameters *GetAppParams,
	body AppRequest,
	description *string) (*ApprovalRequest, error) {
	u := "/sys/v1/apps/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPatch),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}
