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

// Type of subscription.
type SubscriptionType struct {
	Trial      *SubscriptionTypeTrial
	Standard   *struct{}
	Enterprise *struct{}
	Custom     *SubscriptionTypeCustom
	OnPrem     *struct{}
	Reseller   *SubscriptionTypeReseller
}
type SubscriptionTypeTrial struct {
	ExpiresAt *Time `json:"expires_at,omitempty"`
}
type SubscriptionTypeCustom struct {
	MaxPlugin    *uint32 `json:"max_plugin,omitempty"`
	MaxOperation *uint64 `json:"max_operation,omitempty"`
}
type SubscriptionTypeReseller struct {
	MaxPlugin    *uint32 `json:"max_plugin,omitempty"`
	MaxOperation *uint64 `json:"max_operation,omitempty"`
	MaxTenant    *uint32 `json:"max_tenant,omitempty"`
}

func (x SubscriptionType) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers("SubscriptionType", []bool{x.Trial != nil, x.Standard != nil, x.Enterprise != nil, x.Custom != nil, x.OnPrem != nil, x.Reseller != nil}); err != nil {
		return nil, err
	}
	switch {
	case x.Standard != nil:
		return []byte(`"standard"`), nil
	case x.Enterprise != nil:
		return []byte(`"enterprise"`), nil
	case x.OnPrem != nil:
		return []byte(`"on_prem"`), nil
	}
	var obj struct {
		Trial    *SubscriptionTypeTrial    `json:"trial,omitempty"`
		Custom   *SubscriptionTypeCustom   `json:"custom,omitempty"`
		Reseller *SubscriptionTypeReseller `json:"reseller,omitempty"`
	}
	obj.Trial = x.Trial
	obj.Custom = x.Custom
	obj.Reseller = x.Reseller
	return json.Marshal(obj)
}
func (x *SubscriptionType) UnmarshalJSON(data []byte) error {
	x.Trial = nil
	x.Standard = nil
	x.Enterprise = nil
	x.Custom = nil
	x.OnPrem = nil
	x.Reseller = nil
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		switch str {
		case "standard":
			x.Standard = &struct{}{}
		case "enterprise":
			x.Enterprise = &struct{}{}
		case "on_prem":
			x.OnPrem = &struct{}{}
		default:
			return errors.Errorf("invalid value for SubscriptionType: %v", str)
		}
		return nil
	}
	var obj struct {
		Trial    *SubscriptionTypeTrial    `json:"trial,omitempty"`
		Custom   *SubscriptionTypeCustom   `json:"custom,omitempty"`
		Reseller *SubscriptionTypeReseller `json:"reseller,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.Trial = obj.Trial
	x.Custom = obj.Custom
	x.Reseller = obj.Reseller
	return nil
}

// A request to update subscription type.
type SubscriptionChangeRequest struct {
	Subscription SubscriptionType `json:"subscription"`
	Contact      *string          `json:"contact,omitempty"`
	Comment      *string          `json:"comment,omitempty"`
}

// Notification preferences.
type NotificationPref string

// List of supported NotificationPref values
const (
	NotificationPrefNone  NotificationPref = "None"
	NotificationPrefEmail NotificationPref = "Email"
	NotificationPrefPhone NotificationPref = "Phone"
	NotificationPrefBoth  NotificationPref = "Both"
)

// Password authentication settings.
type AuthConfigPassword struct {
	Require2fa         bool `json:"require_2fa"`
	AdministratorsOnly bool `json:"administrators_only"`
}

// OAuth single sign-on authentication settings.
type AuthConfigOauth struct {
	IdpName                  string    `json:"idp_name"`
	IdpIconURL               string    `json:"idp_icon_url"`
	IdpAuthorizationEndpoint string    `json:"idp_authorization_endpoint"`
	IdpTokenEndpoint         string    `json:"idp_token_endpoint"`
	IdpUserinfoEndpoint      *string   `json:"idp_userinfo_endpoint,omitempty"`
	IdpRequiresBasicAuth     bool      `json:"idp_requires_basic_auth"`
	TLS                      TlsConfig `json:"tls"`
	ClientID                 string    `json:"client_id"`
	ClientSecret             string    `json:"client_secret"`
}

// Credentials used by the service to authenticate itself to an LDAP server.
type LdapServiceAccount struct {
	Dn       string `json:"dn"`
	Password string `json:"password"`
}

// Distinguished Name (DN) resolution method. Given a user's email address, a DN resolution method
// is used to find the user's DN in an LDAP directory.
type LdapDnResolution struct {
	// Transform the user email through a pattern to derive the DN.
	Construct *LdapDnResolutionConstruct
	// Search the directory using the LDAP `mail` attribute matching user's email.
	SearchByMail *struct{}
	// Use email in place of DN. This method works with Active Directory if the userPrincipalName
	// attribute is set for the user. https://docs.microsoft.com/en-us/windows/desktop/ad/naming-properties
	UserPrincipalName *struct{}
}

// Transform the user email through a pattern to derive the DN.
type LdapDnResolutionConstruct struct {
	// For example: "example.com" => "uid={},ou=users,dc=example,dc=com".
	DomainFormat map[string]string `json:"domain_format"`
}

func (x LdapDnResolution) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers("LdapDnResolution", []bool{x.Construct != nil, x.SearchByMail != nil, x.UserPrincipalName != nil}); err != nil {
		return nil, err
	}
	m := make(map[string]interface{})
	switch {
	case x.Construct != nil:
		b, err := json.Marshal(x.Construct)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		m["method"] = "construct"
	case x.SearchByMail != nil:
		m["method"] = "search-by-mail"
	case x.UserPrincipalName != nil:
		m["method"] = "upn"
	}
	return json.Marshal(m)
}
func (x *LdapDnResolution) UnmarshalJSON(data []byte) error {
	x.Construct = nil
	x.SearchByMail = nil
	x.UserPrincipalName = nil
	var h struct {
		Tag string `json:"method"`
	}
	if err := json.Unmarshal(data, &h); err != nil {
		return errors.Errorf("not a valid LdapDnResolution")
	}
	switch h.Tag {
	case "construct":
		var construct LdapDnResolutionConstruct
		if err := json.Unmarshal(data, &construct); err != nil {
			return err
		}
		x.Construct = &construct
	case "search-by-mail":
		x.SearchByMail = &struct{}{}
	case "upn":
		x.UserPrincipalName = &struct{}{}
	default:
		return errors.Errorf("invalid tag value: %v", h.Tag)
	}
	return nil
}

// LDAP authorization settings.
type LdapAuthorizationConfig struct {
	// Number of seconds after which the authorization should be checked again.
	ValidFor uint64 `json:"valid_for"`
	// Distinguished name of an LDAP group. If specified, account members must be a member of this
	// LDAP group to be able to select the accout.
	RequireRole *string `json:"require_role,omitempty"`
}

// LDAP authentication settings.
type AuthConfigLdap struct {
	Name            string                   `json:"name"`
	IconURL         string                   `json:"icon_url"`
	LdapURL         string                   `json:"ldap_url"`
	DnResolution    LdapDnResolution         `json:"dn_resolution"`
	TLS             TlsConfig                `json:"tls"`
	BaseDn          *string                  `json:"base_dn,omitempty"`
	UserObjectClass *string                  `json:"user_object_class,omitempty"`
	ServiceAccount  *LdapServiceAccount      `json:"service_account,omitempty"`
	Authorization   *LdapAuthorizationConfig `json:"authorization,omitempty"`
}

// Signed JWT authentication settings.
type AuthConfigSignedJwt struct {
	ValidIssuers []string       `json:"valid_issuers"`
	SigningKeys  JwtSigningKeys `json:"signing_keys"`
}

// Counts of objects of various types in an account.
type ObjectCounts struct {
	Groups   uint64 `json:"groups"`
	Apps     uint64 `json:"apps"`
	Users    uint64 `json:"users"`
	Plugins  uint64 `json:"plugins"`
	Sobjects uint64 `json:"sobjects"`
}

// CA settings.
type CaConfig struct {
	CaSet  *CaSet
	Pinned *[]Blob
}

func (x CaConfig) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers("CaConfig", []bool{x.CaSet != nil, x.Pinned != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		CaSet  *CaSet  `json:"ca_set,omitempty"`
		Pinned *[]Blob `json:"pinned,omitempty"`
	}
	obj.CaSet = x.CaSet
	obj.Pinned = x.Pinned
	return json.Marshal(obj)
}
func (x *CaConfig) UnmarshalJSON(data []byte) error {
	x.CaSet = nil
	x.Pinned = nil
	var obj struct {
		CaSet  *CaSet  `json:"ca_set,omitempty"`
		Pinned *[]Blob `json:"pinned,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.CaSet = obj.CaSet
	x.Pinned = obj.Pinned
	return nil
}

// Predefined CA sets.
type CaSet string

// List of supported CaSet values
const (
	CaSetGlobalRoots CaSet = "global_roots"
)

// TLS settings.
type TlsConfig struct {
	Disabled      *struct{}
	Opportunistic *struct{}
	Required      *TlsConfigRequired
}
type TlsConfigRequired struct {
	ValidateHostname bool     `json:"validate_hostname"`
	Ca               CaConfig `json:"ca"`
}

func (x TlsConfig) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers("TlsConfig", []bool{x.Disabled != nil, x.Opportunistic != nil, x.Required != nil}); err != nil {
		return nil, err
	}
	m := make(map[string]interface{})
	switch {
	case x.Disabled != nil:
		m["mode"] = "disabled"
	case x.Opportunistic != nil:
		m["mode"] = "opportunistic"
	case x.Required != nil:
		b, err := json.Marshal(x.Required)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		m["mode"] = "required"
	}
	return json.Marshal(m)
}
func (x *TlsConfig) UnmarshalJSON(data []byte) error {
	x.Disabled = nil
	x.Opportunistic = nil
	x.Required = nil
	var h struct {
		Tag string `json:"mode"`
	}
	if err := json.Unmarshal(data, &h); err != nil {
		return errors.Errorf("not a valid TlsConfig")
	}
	switch h.Tag {
	case "disabled":
		x.Disabled = &struct{}{}
	case "opportunistic":
		x.Opportunistic = &struct{}{}
	case "required":
		var required TlsConfigRequired
		if err := json.Unmarshal(data, &required); err != nil {
			return err
		}
		x.Required = &required
	default:
		return errors.Errorf("invalid tag value: %v", h.Tag)
	}
	return nil
}

// Account approval policy.
type AccountApprovalPolicy struct {
	Policy       ApprovalPolicy `json:"policy"`
	ManageGroups bool           `json:"manage_groups"`
}

// Syslog facility.
type SyslogFacility string

// List of supported SyslogFacility values
const (
	SyslogFacilityUser   SyslogFacility = "User"
	SyslogFacilityLocal0 SyslogFacility = "Local0"
	SyslogFacilityLocal1 SyslogFacility = "Local1"
	SyslogFacilityLocal2 SyslogFacility = "Local2"
	SyslogFacilityLocal3 SyslogFacility = "Local3"
	SyslogFacilityLocal4 SyslogFacility = "Local4"
	SyslogFacilityLocal5 SyslogFacility = "Local5"
	SyslogFacilityLocal6 SyslogFacility = "Local6"
	SyslogFacilityLocal7 SyslogFacility = "Local7"
)

type Account struct {
	AcctID                           UUID                       `json:"acct_id"`
	ApprovalPolicy                   *AccountApprovalPolicy     `json:"approval_policy,omitempty"`
	ApprovalRequestExpiry            *uint64                    `json:"approval_request_expiry,omitempty"`
	AuthConfig                       *AuthConfig                `json:"auth_config,omitempty"`
	Country                          *string                    `json:"country,omitempty"`
	CreatedAt                        *Time                      `json:"created_at,omitempty"`
	CustomLogo                       *Blob                      `json:"custom_logo,omitempty"`
	CustomMetadata                   *map[string]string         `json:"custom_metadata,omitempty"`
	Description                      *string                    `json:"description,omitempty"`
	Enabled                          bool                       `json:"enabled"`
	InitialPurchaseAt                *Time                      `json:"initial_purchase_at,omitempty"`
	LoggingConfigs                   map[UUID]LoggingConfig     `json:"logging_configs"`
	MaxApp                           *uint32                    `json:"max_app,omitempty"`
	MaxGroup                         *uint32                    `json:"max_group,omitempty"`
	MaxOperation                     *uint64                    `json:"max_operation,omitempty"`
	MaxPlugin                        *uint32                    `json:"max_plugin,omitempty"`
	MaxSobj                          *uint32                    `json:"max_sobj,omitempty"`
	MaxUser                          *uint32                    `json:"max_user,omitempty"`
	Name                             string                     `json:"name"`
	NotificationPref                 *NotificationPref          `json:"notification_pref,omitempty"`
	Organization                     *string                    `json:"organization,omitempty"`
	ParentAcctID                     *UUID                      `json:"parent_acct_id,omitempty"`
	PendingSubscriptionChangeRequest *SubscriptionChangeRequest `json:"pending_subscription_change_request,omitempty"`
	Phone                            *string                    `json:"phone,omitempty"`
	PluginEnabled                    *bool                      `json:"plugin_enabled,omitempty"`
	Subscription                     SubscriptionType           `json:"subscription"`
	Totals                           *ObjectCounts              `json:"totals,omitempty"`
	TrialExpiresAt                   *Time                      `json:"trial_expires_at,omitempty"`
}

type AccountRequest struct {
	AddLdap                          *[]AuthConfigLdap              `json:"add_ldap,omitempty"`
	AddLoggingConfigs                *[]LoggingConfigRequest        `json:"add_logging_configs,omitempty"`
	ApprovalPolicy                   *AccountApprovalPolicy         `json:"approval_policy,omitempty"`
	ApprovalRequestExpiry            *uint64                        `json:"approval_request_expiry,omitempty"`
	AuthConfig                       *AuthConfig                    `json:"auth_config,omitempty"`
	Country                          *string                        `json:"country,omitempty"`
	CustomLogo                       *Blob                          `json:"custom_logo,omitempty"`
	CustomMetadata                   *map[string]string             `json:"custom_metadata,omitempty"`
	DelLdap                          *[]UUID                        `json:"del_ldap,omitempty"`
	DelLoggingConfigs                *[]UUID                        `json:"del_logging_configs,omitempty"`
	Description                      *string                        `json:"description,omitempty"`
	Enabled                          *bool                          `json:"enabled,omitempty"`
	ModLdap                          *map[UUID]AuthConfigLdap       `json:"mod_ldap,omitempty"`
	ModLoggingConfigs                *map[UUID]LoggingConfigRequest `json:"mod_logging_configs,omitempty"`
	Name                             *string                        `json:"name,omitempty"`
	NotificationPref                 *NotificationPref              `json:"notification_pref,omitempty"`
	Organization                     *string                        `json:"organization,omitempty"`
	ParentAcctID                     *UUID                          `json:"parent_acct_id,omitempty"`
	PendingSubscriptionChangeRequest *SubscriptionChangeRequest     `json:"pending_subscription_change_request,omitempty"`
	Phone                            *string                        `json:"phone,omitempty"`
	PluginEnabled                    *bool                          `json:"plugin_enabled,omitempty"`
	Subscription                     *SubscriptionType              `json:"subscription,omitempty"`
}

type GetAccountParams struct {
	WithTotals bool `json:"with_totals"`
}

func (x GetAccountParams) urlEncode(v map[string][]string) error {
	v["with_totals"] = []string{fmt.Sprintf("%v", x.WithTotals)}
	return nil
}

type CountParams struct {
	RangeFrom *uint64 `json:"range_from,omitempty"`
	RangeTo   *uint64 `json:"range_to,omitempty"`
}

func (x CountParams) urlEncode(v map[string][]string) error {
	if x.RangeFrom != nil {
		v["range_from"] = []string{fmt.Sprintf("%v", *x.RangeFrom)}
	}
	if x.RangeTo != nil {
		v["range_to"] = []string{fmt.Sprintf("%v", *x.RangeTo)}
	}
	return nil
}

// Splunk logging configuration.
type SplunkLoggingConfig struct {
	Enabled bool      `json:"enabled"`
	Host    string    `json:"host"`
	Port    uint16    `json:"port"`
	Index   string    `json:"index"`
	TLS     TlsConfig `json:"tls"`
}

// Stackdriver logging configuration.
type StackdriverLoggingConfig struct {
	Enabled bool `json:"enabled"`
	// The log ID that will recieve the log items (see https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry).
	LogID             string                  `json:"log_id"`
	ServiceAccountKey GoogleServiceAccountKey `json:"service_account_key"`
}

type StackdriverLoggingConfigRequest struct {
	Enabled *bool `json:"enabled,omitempty"`
	// The log ID that will recieve the log items (see https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry).
	LogID             *string                  `json:"log_id,omitempty"`
	ServiceAccountKey *GoogleServiceAccountKey `json:"service_account_key,omitempty"`
}

// A Google service account key object. See https://cloud.google.com/video-intelligence/docs/common/auth.
type GoogleServiceAccountKey struct {
	Type         string  `json:"type"`
	ProjectID    string  `json:"project_id"`
	PrivateKeyID string  `json:"private_key_id"`
	PrivateKey   *string `json:"private_key,omitempty"`
	ClientEmail  string  `json:"client_email"`
}

type SplunkLoggingConfigRequest struct {
	Enabled *bool   `json:"enabled,omitempty"`
	Host    *string `json:"host,omitempty"`
	Port    *uint16 `json:"port,omitempty"`
	// The Splunk index that will receive log items.
	Index *string `json:"index,omitempty"`
	// The Splunk authentication token.
	Token *string    `json:"token,omitempty"`
	TLS   *TlsConfig `json:"tls,omitempty"`
}

type SyslogLoggingConfig struct {
	Enabled  bool           `json:"enabled"`
	Host     string         `json:"host"`
	Port     uint16         `json:"port"`
	TLS      TlsConfig      `json:"tls"`
	Facility SyslogFacility `json:"facility"`
}

type SyslogLoggingConfigRequest struct {
	Enabled  *bool           `json:"enabled,omitempty"`
	Host     *string         `json:"host,omitempty"`
	Port     *uint16         `json:"port,omitempty"`
	TLS      *TlsConfig      `json:"tls,omitempty"`
	Facility *SyslogFacility `json:"facility,omitempty"`
}

type LoggingConfig struct {
	Splunk      *SplunkLoggingConfig
	Stackdriver *StackdriverLoggingConfig
	Syslog      *SyslogLoggingConfig
}

func (x LoggingConfig) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers("LoggingConfig", []bool{x.Splunk != nil, x.Stackdriver != nil, x.Syslog != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Splunk      *SplunkLoggingConfig      `json:"splunk,omitempty"`
		Stackdriver *StackdriverLoggingConfig `json:"stackdriver,omitempty"`
		Syslog      *SyslogLoggingConfig      `json:"syslog,omitempty"`
	}
	obj.Splunk = x.Splunk
	obj.Stackdriver = x.Stackdriver
	obj.Syslog = x.Syslog
	return json.Marshal(obj)
}
func (x *LoggingConfig) UnmarshalJSON(data []byte) error {
	x.Splunk = nil
	x.Stackdriver = nil
	x.Syslog = nil
	var obj struct {
		Splunk      *SplunkLoggingConfig      `json:"splunk,omitempty"`
		Stackdriver *StackdriverLoggingConfig `json:"stackdriver,omitempty"`
		Syslog      *SyslogLoggingConfig      `json:"syslog,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.Splunk = obj.Splunk
	x.Stackdriver = obj.Stackdriver
	x.Syslog = obj.Syslog
	return nil
}

type LoggingConfigRequest struct {
	Splunk      *SplunkLoggingConfigRequest
	Stackdriver *StackdriverLoggingConfigRequest
	Syslog      *SyslogLoggingConfigRequest
}

func (x LoggingConfigRequest) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers("LoggingConfigRequest", []bool{x.Splunk != nil, x.Stackdriver != nil, x.Syslog != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Splunk      *SplunkLoggingConfigRequest      `json:"splunk,omitempty"`
		Stackdriver *StackdriverLoggingConfigRequest `json:"stackdriver,omitempty"`
		Syslog      *SyslogLoggingConfigRequest      `json:"syslog,omitempty"`
	}
	obj.Splunk = x.Splunk
	obj.Stackdriver = x.Stackdriver
	obj.Syslog = x.Syslog
	return json.Marshal(obj)
}
func (x *LoggingConfigRequest) UnmarshalJSON(data []byte) error {
	x.Splunk = nil
	x.Stackdriver = nil
	x.Syslog = nil
	var obj struct {
		Splunk      *SplunkLoggingConfigRequest      `json:"splunk,omitempty"`
		Stackdriver *StackdriverLoggingConfigRequest `json:"stackdriver,omitempty"`
		Syslog      *SyslogLoggingConfigRequest      `json:"syslog,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.Splunk = obj.Splunk
	x.Stackdriver = obj.Stackdriver
	x.Syslog = obj.Syslog
	return nil
}

type GetUsageResponse struct {
	NumOperations uint64 `json:"num_operations"`
}

// Account authentication settings.
type AuthConfig struct {
	Password  *AuthConfigPassword     `json:"password,omitempty"`
	Saml      *string                 `json:"saml,omitempty"`
	Oauth     *AuthConfigOauth        `json:"oauth,omitempty"`
	Ldap      map[UUID]AuthConfigLdap `json:"ldap"`
	SignedJwt *AuthConfigSignedJwt    `json:"signed_jwt,omitempty"`
}

// Get all accounts accessible to the current user.
func (c *Client) ListAccounts(ctx context.Context, queryParameters GetAccountParams) ([]Account, error) {
	u := "/sys/v1/accounts"
	q, err := encodeURLParams(&queryParameters)
	if err != nil {
		return nil, err
	}
	u = fmt.Sprintf("%v?%v", u, q)
	var r []Account
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return r, nil
}

// Lookup an account by its ID.
func (c *Client) GetAccount(ctx context.Context, id string, queryParameters GetAccountParams) (*Account, error) {
	u := "/sys/v1/accounts/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	q, err := encodeURLParams(&queryParameters)
	if err != nil {
		return nil, err
	}
	u = fmt.Sprintf("%v?%v", u, q)
	var r Account
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Create a new account.
func (c *Client) CreateAccount(ctx context.Context, body AccountRequest) (*Account, error) {
	u := "/sys/v1/accounts"
	var r Account
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToCreateAccount(ctx context.Context, body AccountRequest, description *string) (*ApprovalRequest, error) {
	u := "/sys/v1/accounts"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Update an account.
func (c *Client) UpdateAccount(ctx context.Context, id string, body AccountRequest) (*Account, error) {
	u := "/sys/v1/accounts/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r Account
	if err := c.fetch(ctx, http.MethodPatch, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToUpdateAccount(ctx context.Context, id string, body AccountRequest, description *string) (*ApprovalRequest, error) {
	u := "/sys/v1/accounts/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPatch),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Delete an account.
func (c *Client) DeleteAccount(ctx context.Context, id string) error {
	u := "/sys/v1/accounts/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
		return err
	}
	return nil
}

// Get account usage information.
func (c *Client) AccountUsage(ctx context.Context, id string, queryParameters CountParams) (*GetUsageResponse, error) {
	u := "/sys/v1/accounts/:id/usage"
	u = strings.NewReplacer(":id", id).Replace(u)
	q, err := encodeURLParams(&queryParameters)
	if err != nil {
		return nil, err
	}
	u = fmt.Sprintf("%v?%v", u, q)
	var r GetUsageResponse
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
