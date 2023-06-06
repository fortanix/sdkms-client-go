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
)

type Account struct {
	AcctID         UUID                   `json:"acct_id"`
	ApprovalPolicy *AccountApprovalPolicy `json:"approval_policy,omitempty"`
	// Configurations for group-level or account-level approval requests.
	ApprovalRequestSettings  ApprovalRequestSettings                   `json:"approval_request_settings"`
	AuthConfig               *AuthConfig                               `json:"auth_config,omitempty"`
	ClientConfigurations     *ClientConfigurations                     `json:"client_configurations,omitempty"`
	Country                  *string                                   `json:"country,omitempty"`
	CreatedAt                *Time                                     `json:"created_at,omitempty"`
	CryptographicPolicy      *CryptographicPolicy                      `json:"cryptographic_policy,omitempty"`
	CustomLogo               *Blob                                     `json:"custom_logo,omitempty"`
	CustomMetadata           *map[string]string                        `json:"custom_metadata,omitempty"`
	CustomMetadataAttributes *map[string]CustomAttributeSearchMetadata `json:"custom_metadata_attributes,omitempty"`
	Description              *string                                   `json:"description,omitempty"`
	DisabledAt               *Time                                     `json:"disabled_at,omitempty"`
	Enabled                  bool                                      `json:"enabled"`
	InitialPurchaseAt        *Time                                     `json:"initial_purchase_at,omitempty"`
	KeyHistoryPolicy         *KeyHistoryPolicy                         `json:"key_history_policy,omitempty"`
	KeyMetadataPolicy        *KeyMetadataPolicy                        `json:"key_metadata_policy,omitempty"`
	LogBadRequests           *bool                                     `json:"log_bad_requests,omitempty"`
	LogRetentionDays         *uint64                                   `json:"log_retention_days,omitempty"`
	LoggingConfigs           map[UUID]LoggingConfig                    `json:"logging_configs"`
	// Enable the user to opt out from the current behaviour of key being marked as disabled at time of deactivation.
	MarkKeyDisableWhenDeactivated    bool                       `json:"mark_key_disable_when_deactivated"`
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
	Subscription                     Subscription               `json:"subscription"`
	Totals                           *ObjectCounts              `json:"totals,omitempty"`
	TrialExpiresAt                   *Time                      `json:"trial_expires_at,omitempty"`
	WorkspaceCseConfig               *WorkspaceCseConfig        `json:"workspace_cse_config,omitempty"`
}

func (x Account) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	{ // ApprovalRequestSettings
		b, err := json.Marshal(&x.ApprovalRequestSettings)
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
	m["acct_id"] = &x.AcctID
	m["approval_policy"] = &x.ApprovalPolicy
	m["auth_config"] = &x.AuthConfig
	m["client_configurations"] = &x.ClientConfigurations
	m["country"] = &x.Country
	m["created_at"] = &x.CreatedAt
	m["cryptographic_policy"] = &x.CryptographicPolicy
	m["custom_logo"] = &x.CustomLogo
	m["custom_metadata"] = &x.CustomMetadata
	m["custom_metadata_attributes"] = &x.CustomMetadataAttributes
	m["description"] = &x.Description
	m["disabled_at"] = &x.DisabledAt
	m["enabled"] = &x.Enabled
	m["initial_purchase_at"] = &x.InitialPurchaseAt
	m["key_history_policy"] = &x.KeyHistoryPolicy
	m["key_metadata_policy"] = &x.KeyMetadataPolicy
	m["log_bad_requests"] = &x.LogBadRequests
	m["log_retention_days"] = &x.LogRetentionDays
	m["logging_configs"] = &x.LoggingConfigs
	m["mark_key_disable_when_deactivated"] = &x.MarkKeyDisableWhenDeactivated
	m["max_app"] = &x.MaxApp
	m["max_group"] = &x.MaxGroup
	m["max_operation"] = &x.MaxOperation
	m["max_plugin"] = &x.MaxPlugin
	m["max_sobj"] = &x.MaxSobj
	m["max_user"] = &x.MaxUser
	m["name"] = &x.Name
	m["notification_pref"] = &x.NotificationPref
	m["organization"] = &x.Organization
	m["parent_acct_id"] = &x.ParentAcctID
	m["pending_subscription_change_request"] = &x.PendingSubscriptionChangeRequest
	m["phone"] = &x.Phone
	m["plugin_enabled"] = &x.PluginEnabled
	m["subscription"] = &x.Subscription
	m["totals"] = &x.Totals
	m["trial_expires_at"] = &x.TrialExpiresAt
	m["workspace_cse_config"] = &x.WorkspaceCseConfig
	return json.Marshal(&m)
}
func (x *Account) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &x.ApprovalRequestSettings); err != nil {
		return err
	}
	var r struct {
		AcctID                           UUID                                      `json:"acct_id"`
		ApprovalPolicy                   *AccountApprovalPolicy                    `json:"approval_policy,omitempty"`
		AuthConfig                       *AuthConfig                               `json:"auth_config,omitempty"`
		ClientConfigurations             *ClientConfigurations                     `json:"client_configurations,omitempty"`
		Country                          *string                                   `json:"country,omitempty"`
		CreatedAt                        *Time                                     `json:"created_at,omitempty"`
		CryptographicPolicy              *CryptographicPolicy                      `json:"cryptographic_policy,omitempty"`
		CustomLogo                       *Blob                                     `json:"custom_logo,omitempty"`
		CustomMetadata                   *map[string]string                        `json:"custom_metadata,omitempty"`
		CustomMetadataAttributes         *map[string]CustomAttributeSearchMetadata `json:"custom_metadata_attributes,omitempty"`
		Description                      *string                                   `json:"description,omitempty"`
		DisabledAt                       *Time                                     `json:"disabled_at,omitempty"`
		Enabled                          bool                                      `json:"enabled"`
		InitialPurchaseAt                *Time                                     `json:"initial_purchase_at,omitempty"`
		KeyHistoryPolicy                 *KeyHistoryPolicy                         `json:"key_history_policy,omitempty"`
		KeyMetadataPolicy                *KeyMetadataPolicy                        `json:"key_metadata_policy,omitempty"`
		LogBadRequests                   *bool                                     `json:"log_bad_requests,omitempty"`
		LogRetentionDays                 *uint64                                   `json:"log_retention_days,omitempty"`
		LoggingConfigs                   map[UUID]LoggingConfig                    `json:"logging_configs"`
		MarkKeyDisableWhenDeactivated    bool                                      `json:"mark_key_disable_when_deactivated"`
		MaxApp                           *uint32                                   `json:"max_app,omitempty"`
		MaxGroup                         *uint32                                   `json:"max_group,omitempty"`
		MaxOperation                     *uint64                                   `json:"max_operation,omitempty"`
		MaxPlugin                        *uint32                                   `json:"max_plugin,omitempty"`
		MaxSobj                          *uint32                                   `json:"max_sobj,omitempty"`
		MaxUser                          *uint32                                   `json:"max_user,omitempty"`
		Name                             string                                    `json:"name"`
		NotificationPref                 *NotificationPref                         `json:"notification_pref,omitempty"`
		Organization                     *string                                   `json:"organization,omitempty"`
		ParentAcctID                     *UUID                                     `json:"parent_acct_id,omitempty"`
		PendingSubscriptionChangeRequest *SubscriptionChangeRequest                `json:"pending_subscription_change_request,omitempty"`
		Phone                            *string                                   `json:"phone,omitempty"`
		PluginEnabled                    *bool                                     `json:"plugin_enabled,omitempty"`
		Subscription                     Subscription                              `json:"subscription"`
		Totals                           *ObjectCounts                             `json:"totals,omitempty"`
		TrialExpiresAt                   *Time                                     `json:"trial_expires_at,omitempty"`
		WorkspaceCseConfig               *WorkspaceCseConfig                       `json:"workspace_cse_config,omitempty"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	x.AcctID = r.AcctID
	x.ApprovalPolicy = r.ApprovalPolicy
	x.AuthConfig = r.AuthConfig
	x.ClientConfigurations = r.ClientConfigurations
	x.Country = r.Country
	x.CreatedAt = r.CreatedAt
	x.CryptographicPolicy = r.CryptographicPolicy
	x.CustomLogo = r.CustomLogo
	x.CustomMetadata = r.CustomMetadata
	x.CustomMetadataAttributes = r.CustomMetadataAttributes
	x.Description = r.Description
	x.DisabledAt = r.DisabledAt
	x.Enabled = r.Enabled
	x.InitialPurchaseAt = r.InitialPurchaseAt
	x.KeyHistoryPolicy = r.KeyHistoryPolicy
	x.KeyMetadataPolicy = r.KeyMetadataPolicy
	x.LogBadRequests = r.LogBadRequests
	x.LogRetentionDays = r.LogRetentionDays
	x.LoggingConfigs = r.LoggingConfigs
	x.MarkKeyDisableWhenDeactivated = r.MarkKeyDisableWhenDeactivated
	x.MaxApp = r.MaxApp
	x.MaxGroup = r.MaxGroup
	x.MaxOperation = r.MaxOperation
	x.MaxPlugin = r.MaxPlugin
	x.MaxSobj = r.MaxSobj
	x.MaxUser = r.MaxUser
	x.Name = r.Name
	x.NotificationPref = r.NotificationPref
	x.Organization = r.Organization
	x.ParentAcctID = r.ParentAcctID
	x.PendingSubscriptionChangeRequest = r.PendingSubscriptionChangeRequest
	x.Phone = r.Phone
	x.PluginEnabled = r.PluginEnabled
	x.Subscription = r.Subscription
	x.Totals = r.Totals
	x.TrialExpiresAt = r.TrialExpiresAt
	x.WorkspaceCseConfig = r.WorkspaceCseConfig
	return nil
}

// Account approval policy.
type AccountApprovalPolicy struct {
	Policy       QuorumPolicy `json:"policy"`
	ManageGroups *bool        `json:"manage_groups,omitempty"`
	// When this is true, changes to the account authentication methods require approval.
	ProtectAuthenticationMethods *bool `json:"protect_authentication_methods,omitempty"`
	// When this is true, changes to the account cryptographic policy requires approval.
	ProtectCryptographicPolicy *bool `json:"protect_cryptographic_policy,omitempty"`
	// When this is true, changes to logging configuration require approval.
	ProtectLoggingConfig *bool `json:"protect_logging_config,omitempty"`
	// When set to true, updating custom roles would require approval.
	ProtectCustomRoleUpdates *bool `json:"protect_custom_role_updates,omitempty"`
}

type AccountRequest struct {
	AddLdap           *[]AuthConfigLdap       `json:"add_ldap,omitempty"`
	AddLoggingConfigs *[]LoggingConfigRequest `json:"add_logging_configs,omitempty"`
	ApprovalPolicy    *AccountApprovalPolicy  `json:"approval_policy,omitempty"`
	// Configurations for group-level or account-level approval requests.
	ApprovalRequestSettings  *ApprovalRequestSettingsRequest           `json:"approval_request_settings,omitempty"`
	AuthConfig               *AuthConfig                               `json:"auth_config,omitempty"`
	ClientConfigurations     *ClientConfigurationsRequest              `json:"client_configurations,omitempty"`
	Country                  *string                                   `json:"country,omitempty"`
	CryptographicPolicy      *Removable[CryptographicPolicy]           `json:"cryptographic_policy,omitempty"`
	CustomLogo               *Blob                                     `json:"custom_logo,omitempty"`
	CustomMetadata           *map[string]string                        `json:"custom_metadata,omitempty"`
	CustomMetadataAttributes *map[string]CustomAttributeSearchMetadata `json:"custom_metadata_attributes,omitempty"`
	DelLdap                  *[]UUID                                   `json:"del_ldap,omitempty"`
	DelLoggingConfigs        *[]UUID                                   `json:"del_logging_configs,omitempty"`
	Description              *string                                   `json:"description,omitempty"`
	Enabled                  *bool                                     `json:"enabled,omitempty"`
	KeyHistoryPolicy         *Removable[KeyHistoryPolicy]              `json:"key_history_policy,omitempty"`
	KeyMetadataPolicy        *Removable[KeyMetadataPolicy]             `json:"key_metadata_policy,omitempty"`
	LogBadRequests           *bool                                     `json:"log_bad_requests,omitempty"`
	LogRetentionDays         *uint64                                   `json:"log_retention_days,omitempty"`
	// Enable the user to opt out from the current behaviour of key being marked as disabled at time of deactivation.
	MarkKeyDisableWhenDeactivated    *bool                          `json:"mark_key_disable_when_deactivated,omitempty"`
	ModLdap                          *map[UUID]AuthConfigLdap       `json:"mod_ldap,omitempty"`
	ModLoggingConfigs                *map[UUID]LoggingConfigRequest `json:"mod_logging_configs,omitempty"`
	Name                             *string                        `json:"name,omitempty"`
	NotificationPref                 *NotificationPref              `json:"notification_pref,omitempty"`
	Organization                     *string                        `json:"organization,omitempty"`
	ParentAcctID                     *UUID                          `json:"parent_acct_id,omitempty"`
	PendingSubscriptionChangeRequest *SubscriptionChangeRequest     `json:"pending_subscription_change_request,omitempty"`
	Phone                            *string                        `json:"phone,omitempty"`
	PluginEnabled                    *bool                          `json:"plugin_enabled,omitempty"`
	Subscription                     *Subscription                  `json:"subscription,omitempty"`
	WorkspaceCseConfig               *Removable[WorkspaceCseConfig] `json:"workspace_cse_config,omitempty"`
}

func (x *AccountRequest) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	{ // ApprovalRequestSettings
		b, err := json.Marshal(&x.ApprovalRequestSettings)
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
	m["add_ldap"] = &x.AddLdap
	m["add_logging_configs"] = &x.AddLoggingConfigs
	m["approval_policy"] = &x.ApprovalPolicy
	m["auth_config"] = &x.AuthConfig
	m["client_configurations"] = &x.ClientConfigurations
	m["country"] = &x.Country
	m["cryptographic_policy"] = &x.CryptographicPolicy
	m["custom_logo"] = &x.CustomLogo
	m["custom_metadata"] = &x.CustomMetadata
	m["custom_metadata_attributes"] = &x.CustomMetadataAttributes
	m["del_ldap"] = &x.DelLdap
	m["del_logging_configs"] = &x.DelLoggingConfigs
	m["description"] = &x.Description
	m["enabled"] = &x.Enabled
	m["key_history_policy"] = &x.KeyHistoryPolicy
	m["key_metadata_policy"] = &x.KeyMetadataPolicy

	m["log_bad_requests"] = &x.LogBadRequests
	m["log_retention_days"] = &x.LogRetentionDays
	m["mark_key_disable_when_deactivated"] = &x.MarkKeyDisableWhenDeactivated
	m["mod_ldap"] = &x.ModLdap
	m["mod_logging_configs"] = &x.ModLoggingConfigs
	m["name"] = &x.Name
	m["notification_pref"] = &x.NotificationPref
	m["organization"] = &x.Organization
	m["parent_acct_id"] = &x.ParentAcctID
	m["pending_subscription_change_request"] = &x.PendingSubscriptionChangeRequest
	m["phone"] = &x.Phone
	m["plugin_enabled"] = &x.PluginEnabled
	m["subscription"] = &x.Subscription
	m["workspace_cse_config"] = &x.WorkspaceCseConfig
	return json.Marshal(&m)
}

type AccountSort struct {
	ByAccountID *AccountSortByAccountId
}
type AccountSortByAccountId struct {
	Order Order `json:"order"`
}

func (x AccountSort) urlEncode(v map[string][]string) error {
	if x.ByAccountID != nil {
		v["sort_by"] = []string{"account_id" + string(x.ByAccountID.Order)}
	}
	return nil
}

type AppCreditsUsage struct {
	Generic            uint32 `json:"generic"`
	Tokenization       uint32 `json:"tokenization"`
	Tep                uint32 `json:"tep"`
	Accelerator        uint32 `json:"accelerator"`
	SecretsManagement  uint32 `json:"secrets_management"`
	AwsCloudAccounts   uint32 `json:"aws_cloud_accounts"`
	AzureCloudAccounts uint32 `json:"azure_cloud_accounts"`
}

// Settings that apply to quorum approval requests.
type ApprovalRequestSettings struct {
	// The number of seconds after which an approval request expires. If not
	// specified, the cluster-wide setting will be used (30 days by default).
	//
	// Upon creation, an approval request's expiry date is (time of creation +
	// expiry period). However, when the request is approved by all its approvers,
	// its expiry date will be changed to (time of approval + expiry period).
	ApprovalRequestExpiry *uint64 `json:"approval_request_expiry,omitempty"`
	// Whether or not expired approval requests should be kept. (Obviously, any
	// pending requests that have expired are no longer actionable!)
	//
	// This is only applicable for onprem clusters; the field is ignored in SaaS
	// environments.
	RetainExpiredRequests *bool `json:"retain_expired_requests,omitempty"`
	// Whether or not expiry of pending approval requests should be audit logged.
	//
	// This is only applicable for onprem clusters; the field is ignored in SaaS
	// environments.
	LogExpiredPendingRequests *bool `json:"log_expired_pending_requests,omitempty"`
}

// A request struct for modifying settings that apply to quorum approval requests.
type ApprovalRequestSettingsRequest struct {
	// The number of seconds after which an approval request expires. Changing this
	// setting will not change the expiry of existing approval requests, but it may
	// still affect the "updated" expiry period assigned to existing requests upon
	// their approval (see below for details).
	//
	// Upon creation, an approval request's expiry date is (time of creation +
	// expiry period). However, when the request is approved by all its approvers,
	// its expiry date will be changed to (time of approval + expiry period).
	ApprovalRequestExpiry *uint64 `json:"approval_request_expiry,omitempty"`
	// Whether or not expired approval requests should be kept. (Obviously, any
	// pending requests that have expired are no longer actionable!)
	//
	// This is only applicable for onprem clusters; the field is ignored in SaaS
	// environments.
	RetainExpiredRequests *bool `json:"retain_expired_requests,omitempty"`
	// Whether or not expiry of pending approval requests should be audit logged.
	// Changing this setting will not retroactively apply to existing expired
	// approval requests.
	//
	// This is only applicable for onprem clusters; the field is ignored in SaaS
	// environments.
	LogExpiredPendingRequests *bool `json:"log_expired_pending_requests,omitempty"`
}

// Account authentication settings.
type AuthConfig struct {
	Password  *AuthConfigPassword      `json:"password,omitempty"`
	Saml      *string                  `json:"saml,omitempty"`
	Oauth     *AuthConfigOauth         `json:"oauth,omitempty"`
	Ldap      *map[UUID]AuthConfigLdap `json:"ldap,omitempty"`
	SignedJwt *AuthConfigSignedJwt     `json:"signed_jwt,omitempty"`
	Vcd       *AuthConfigVcd           `json:"vcd,omitempty"`
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

// Password authentication settings.
type AuthConfigPassword struct {
	Require2fa         bool `json:"require_2fa"`
	AdministratorsOnly bool `json:"administrators_only"`
}

// Signed JWT authentication settings.
type AuthConfigSignedJwt struct {
	ValidIssuers []string       `json:"valid_issuers"`
	SigningKeys  JwtSigningKeys `json:"signing_keys"`
}

// Vcd single sign-on authentication settings.
type AuthConfigVcd struct {
	IdpName                  string    `json:"idp_name"`
	IdpAuthorizationEndpoint string    `json:"idp_authorization_endpoint"`
	Org                      string    `json:"org"`
	TLS                      TlsConfig `json:"tls"`
}

type CountParams struct {
	RangeFrom     *uint64 `json:"range_from,omitempty"`
	RangeTo       *uint64 `json:"range_to,omitempty"`
	DetailedUsage *bool   `json:"detailed_usage,omitempty"`
	SaasFullUsage *bool   `json:"saas_full_usage,omitempty"`
}

func (x CountParams) urlEncode(v map[string][]string) error {
	if x.RangeFrom != nil {
		v["range_from"] = []string{fmt.Sprintf("%v", *x.RangeFrom)}
	}
	if x.RangeTo != nil {
		v["range_to"] = []string{fmt.Sprintf("%v", *x.RangeTo)}
	}
	if x.DetailedUsage != nil {
		v["detailed_usage"] = []string{fmt.Sprintf("%v", *x.DetailedUsage)}
	}
	if x.SaasFullUsage != nil {
		v["saas_full_usage"] = []string{fmt.Sprintf("%v", *x.SaasFullUsage)}
	}
	return nil
}

type CustomAttributeSearchMetadata struct {
	Suggest *bool `json:"suggest,omitempty"`
}

// Custom subscription type
type CustomSubscriptionType struct {
	MaxPlugin                *uint32               `json:"max_plugin,omitempty"`
	MaxApp                   *uint32               `json:"max_app,omitempty"`
	MaxHsmg                  *uint32               `json:"max_hsmg,omitempty"`
	MaxOperation             *uint64               `json:"max_operation,omitempty"`
	MaxTokenizationOperation *uint64               `json:"max_tokenization_operation,omitempty"`
	CountTransientOps        *bool                 `json:"count_transient_ops,omitempty"`
	PackageName              *string               `json:"package_name,omitempty"`
	Features                 *SubscriptionFeatures `json:"features,omitempty"`
	AddOns                   *map[string]string    `json:"add_ons,omitempty"`
}

type FreemiumSubscriptionType struct {
	MaxApp                   *uint32 `json:"max_app,omitempty"`
	MaxHsmg                  *uint32 `json:"max_hsmg,omitempty"`
	MaxOperation             *uint64 `json:"max_operation,omitempty"`
	MaxTokenizationOperation *uint64 `json:"max_tokenization_operation,omitempty"`
	MaxPlugin                *uint32 `json:"max_plugin,omitempty"`
}

type GetAccountParams struct {
	WithTotals *bool       `json:"with_totals,omitempty"`
	PreviousID *UUID       `json:"previous_id,omitempty"`
	Limit      *uint       `json:"limit,omitempty"`
	SortBy     AccountSort `json:"sort_by"`
}

func (x GetAccountParams) urlEncode(v map[string][]string) error {
	if x.WithTotals != nil {
		v["with_totals"] = []string{fmt.Sprintf("%v", *x.WithTotals)}
	} else {
		v["with_totals"] = []string{"false"}
	}
	if x.PreviousID != nil {
		v["previous_id"] = []string{fmt.Sprintf("%v", *x.PreviousID)}
	}
	if x.Limit != nil {
		v["limit"] = []string{fmt.Sprintf("%v", *x.Limit)}
	}
	if err := x.SortBy.urlEncode(v); err != nil {
		return err
	}
	return nil
}

type GetUsageResponse struct {
	NumOperations            uint64             `json:"num_operations"`
	EncryptionOperations     *uint64            `json:"encryption_operations,omitempty"`
	DecryptionOperations     *uint64            `json:"decryption_operations,omitempty"`
	SignOperations           *uint64            `json:"sign_operations,omitempty"`
	VerifyOperations         *uint64            `json:"verify_operations,omitempty"`
	TokenizationOperations   *uint64            `json:"tokenization_operations,omitempty"`
	DetokenizationOperations *uint64            `json:"detokenization_operations,omitempty"`
	SecretsOperations        *uint64            `json:"secrets_operations,omitempty"`
	PluginInvokeOperations   *uint64            `json:"plugin_invoke_operations,omitempty"`
	Apps                     *AppCreditsUsage   `json:"apps,omitempty"`
	Plugin                   *uint32            `json:"plugin,omitempty"`
	Sobjects                 *uint64            `json:"sobjects,omitempty"`
	HsmGateway               *uint32            `json:"hsm_gateway,omitempty"`
	OperationTopApp          *map[string]uint64 `json:"operation_top_app,omitempty"`
	OperationTopSobject      *map[string]uint64 `json:"operation_top_sobject,omitempty"`
}

// A Google service account key object. See https://cloud.google.com/video-intelligence/docs/common/auth.
type GoogleServiceAccountKey struct {
	Type         string  `json:"type"`
	ProjectID    string  `json:"project_id"`
	PrivateKeyID string  `json:"private_key_id"`
	PrivateKey   *string `json:"private_key,omitempty"`
	ClientEmail  string  `json:"client_email"`
}

type LoggingConfig struct {
	Splunk      *SplunkLoggingConfig
	Stackdriver *StackdriverLoggingConfig
	Syslog      *SyslogLoggingConfig
}

func (x LoggingConfig) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"LoggingConfig",
		[]bool{x.Splunk != nil,
			x.Stackdriver != nil,
			x.Syslog != nil}); err != nil {
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
	if err := checkEnumPointers(
		"LoggingConfigRequest",
		[]bool{x.Splunk != nil,
			x.Stackdriver != nil,
			x.Syslog != nil}); err != nil {
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

// Notification preferences.
type NotificationPref string

// List of supported NotificationPref values
const (
	NotificationPrefNone  NotificationPref = "None"
	NotificationPrefEmail NotificationPref = "Email"
	NotificationPrefPhone NotificationPref = "Phone"
	NotificationPrefBoth  NotificationPref = "Both"
)

// Counts of objects of various types in an account.
type ObjectCounts struct {
	Groups        uint64 `json:"groups"`
	Apps          uint64 `json:"apps"`
	Users         uint64 `json:"users"`
	Plugins       uint64 `json:"plugins"`
	Sobjects      uint64 `json:"sobjects"`
	ChildAccounts uint64 `json:"child_accounts"`
}

// Reseller subscription type
type ResellerSubscriptionType struct {
	MaxPlugin          *uint32               `json:"max_plugin,omitempty"`
	MaxOperation       *uint64               `json:"max_operation,omitempty"`
	MaxTenant          *uint32               `json:"max_tenant,omitempty"`
	MaxTenantPlugin    *uint32               `json:"max_tenant_plugin,omitempty"`
	MaxTenantOperation *uint64               `json:"max_tenant_operation,omitempty"`
	PackageName        *string               `json:"package_name,omitempty"`
	Features           *SubscriptionFeatures `json:"features,omitempty"`
	AddOns             *map[string]string    `json:"add_ons,omitempty"`
	TenantFeatures     *SubscriptionFeatures `json:"tenant_features,omitempty"`
}

// Splunk logging configuration.
type SplunkLoggingConfig struct {
	Enabled bool      `json:"enabled"`
	Host    string    `json:"host"`
	Port    uint16    `json:"port"`
	Index   string    `json:"index"`
	TLS     TlsConfig `json:"tls"`
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

type Subscription struct {
	Memo                 *string                           `json:"memo,omitempty"`
	ExperimentalFeatures *SubscriptionExperimentalFeatures `json:"experimental_features,omitempty"`
	SubscriptionType     SubscriptionType                  `json:"subscription_type"`
}

func (x Subscription) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	{ // SubscriptionType
		b, err := json.Marshal(&x.SubscriptionType)
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
	m["memo"] = &x.Memo
	m["experimental_features"] = &x.ExperimentalFeatures
	return json.Marshal(&m)
}
func (x *Subscription) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &x.SubscriptionType); err != nil {
		return err
	}
	var r struct {
		Memo                 *string                           `json:"memo,omitempty"`
		ExperimentalFeatures *SubscriptionExperimentalFeatures `json:"experimental_features,omitempty"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	x.Memo = r.Memo
	x.ExperimentalFeatures = r.ExperimentalFeatures
	return nil
}

// A request to update subscription type.
type SubscriptionChangeRequest struct {
	Subscription Subscription `json:"subscription"`
	Contact      *string      `json:"contact,omitempty"`
	Comment      *string      `json:"comment,omitempty"`
}

type SubscriptionExperimentalFeatures struct {
}

// Features in subscription
type SubscriptionFeatures uint64

// List of supported SubscriptionFeatures values
const (
	SubscriptionFeaturesTokenization SubscriptionFeatures = 1 << iota
	SubscriptionFeaturesHmg
	SubscriptionFeaturesAwsbyok
	SubscriptionFeaturesAzurebyok
	SubscriptionFeaturesGcpbyok
)

// MarshalJSON converts SubscriptionFeatures to an array of strings
func (x SubscriptionFeatures) MarshalJSON() ([]byte, error) {
	s := make([]string, 0)
	if x&SubscriptionFeaturesTokenization == SubscriptionFeaturesTokenization {
		s = append(s, "TOKENIZATION")
	}
	if x&SubscriptionFeaturesHmg == SubscriptionFeaturesHmg {
		s = append(s, "HMG")
	}
	if x&SubscriptionFeaturesAwsbyok == SubscriptionFeaturesAwsbyok {
		s = append(s, "AWSBYOK")
	}
	if x&SubscriptionFeaturesAzurebyok == SubscriptionFeaturesAzurebyok {
		s = append(s, "AZUREBYOK")
	}
	if x&SubscriptionFeaturesGcpbyok == SubscriptionFeaturesGcpbyok {
		s = append(s, "GCPBYOK")
	}
	return json.Marshal(s)
}

// UnmarshalJSON converts array of strings to SubscriptionFeatures
func (x *SubscriptionFeatures) UnmarshalJSON(data []byte) error {
	*x = 0
	var s []string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	for _, v := range s {
		switch v {
		case "TOKENIZATION":
			*x = *x | SubscriptionFeaturesTokenization
		case "HMG":
			*x = *x | SubscriptionFeaturesHmg
		case "AWSBYOK":
			*x = *x | SubscriptionFeaturesAwsbyok
		case "AZUREBYOK":
			*x = *x | SubscriptionFeaturesAzurebyok
		case "GCPBYOK":
			*x = *x | SubscriptionFeaturesGcpbyok
		}
	}
	return nil
}

// Type of subscription.
type SubscriptionType struct {
	Trial      *SubscriptionTypeTrial
	Standard   *struct{}
	Enterprise *struct{}
	Custom     **CustomSubscriptionType
	Freemium   **FreemiumSubscriptionType
	OnPrem     *struct{}
	Reseller   **ResellerSubscriptionType
}
type SubscriptionTypeTrial struct {
	ExpiresAt *Time `json:"expires_at,omitempty"`
}

func (x SubscriptionType) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"SubscriptionType",
		[]bool{x.Trial != nil,
			x.Standard != nil,
			x.Enterprise != nil,
			x.Custom != nil,
			x.Freemium != nil,
			x.OnPrem != nil,
			x.Reseller != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Trial      *SubscriptionTypeTrial     `json:"trial,omitempty"`
		Standard   *struct{}                  `json:"standard,omitempty"`
		Enterprise *struct{}                  `json:"enterprise,omitempty"`
		Custom     **CustomSubscriptionType   `json:"custom,omitempty"`
		Freemium   **FreemiumSubscriptionType `json:"freemium,omitempty"`
		OnPrem     *struct{}                  `json:"on_prem,omitempty"`
		Reseller   **ResellerSubscriptionType `json:"reseller,omitempty"`
	}
	obj.Trial = x.Trial
	obj.Standard = x.Standard
	obj.Enterprise = x.Enterprise
	obj.Custom = x.Custom
	obj.Freemium = x.Freemium
	obj.OnPrem = x.OnPrem
	obj.Reseller = x.Reseller
	return json.Marshal(obj)
}
func (x *SubscriptionType) UnmarshalJSON(data []byte) error {
	x.Trial = nil
	x.Standard = nil
	x.Enterprise = nil
	x.Custom = nil
	x.Freemium = nil
	x.OnPrem = nil
	x.Reseller = nil
	var obj struct {
		Trial      *SubscriptionTypeTrial     `json:"trial,omitempty"`
		Standard   *struct{}                  `json:"standard,omitempty"`
		Enterprise *struct{}                  `json:"enterprise,omitempty"`
		Custom     **CustomSubscriptionType   `json:"custom,omitempty"`
		Freemium   **FreemiumSubscriptionType `json:"freemium,omitempty"`
		OnPrem     *struct{}                  `json:"on_prem,omitempty"`
		Reseller   **ResellerSubscriptionType `json:"reseller,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.Trial = obj.Trial
	x.Standard = obj.Standard
	x.Enterprise = obj.Enterprise
	x.Custom = obj.Custom
	x.Freemium = obj.Freemium
	x.OnPrem = obj.OnPrem
	x.Reseller = obj.Reseller
	return nil
}

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

// These settings will allow the service to validate the Google-issued
// authorization tokens used in Workspace CSE APIs.
//
// For example, the specific settings for CSE Docs & Drive are:
// - JWKS URL: https://www.googleapis.com/service_accounts/v1/jwk/gsuitecse-tokenissuer-drive@system.gserviceaccount.com
// - Issuer: gsuitecse-tokenissuer-drive@system.gserviceaccount.com
// - Audience: cse-authorization
type WorkspaceCseAuthorizationProvider struct {
	// Authorization provider's name
	Name string `json:"name"`
	// A URL pointing to the JWKS endpoint
	JwksURL string `json:"jwks_url"`
	// Number of seconds that the service is allowed to cache the fetched keys
	CacheDuration uint64 `json:"cache_duration"`
	// Acceptable values for the `iss` (issuer) field used in Google's
	// authorization tokens
	ValidIssuers []string `json:"valid_issuers"`
	// Acceptable values for the `aud` (audience) field used in Google's
	// authorization tokens
	ValidAudiences []string `json:"valid_audiences"`
}

// Workspace CSE API settings. Specifying these settings enables the CSE APIs
// for the account.
type WorkspaceCseConfig struct {
	// One or more Identity Providers (IdP) trusted to authenticate users.
	// Note that we don't check if Single Sign-On (SSO) settings exist for
	// each IdP listed here, but it is recommended to add these IdPs in SSO
	// settings as well (usually as OAuth/OIDC providers).
	IdentityProviders []WorkspaceCseIdentityProvider `json:"identity_providers"`
	// One or more authorization providers used to validate authorization
	// tokens. Different Workspace applications might require different
	// authorization settings.
	AuthorizationProviders []WorkspaceCseAuthorizationProvider `json:"authorization_providers"`
}

// An identity provider trusted to authenticate users for Workspace CSE APIs
type WorkspaceCseIdentityProvider struct {
	// Identity provider's name
	Name string `json:"name"`
	// The public key(s) used to validate the authentication tokens
	SigningKeys JwtSigningKeys `json:"signing_keys"`
	// Acceptable values for the `iss` (issuer) field used in authentication
	// tokens
	ValidIssuers []string `json:"valid_issuers"`
	// Acceptable values for the `aud` (audience) field used in authentication
	// tokens
	ValidAudiences []string `json:"valid_audiences"`
}

// Get account usage information. See input and output of this API
// for info on what it can return.
func (c *Client) AccountUsage(ctx context.Context, id string, queryParameters *CountParams) (*GetUsageResponse, error) {
	u := "/sys/v1/accounts/:id/usage"
	u = strings.NewReplacer(":id", id).Replace(u)
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	var r GetUsageResponse
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

func (c *Client) RequestApprovalToCreateAccount(
	ctx context.Context,
	body AccountRequest,
	description *string) (*ApprovalRequest, error) {
	u := "/sys/v1/accounts"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
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

// Get info for a specific account.
//
// A user can have access to multiple accounts and this API tries
// to look one up given by the input id.
func (c *Client) GetAccount(ctx context.Context, id string, queryParameters *GetAccountParams) (*Account, error) {
	u := "/sys/v1/accounts/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	var r Account
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Get info about all accounts.
//
// A user can have access to multiple accounts and this API gets
// all accounts the calling user has access to.
func (c *Client) ListAccounts(ctx context.Context, queryParameters *GetAccountParams) ([]Account, error) {
	u := "/sys/v1/accounts"
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	var r []Account
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return r, nil
}

// Update account settings such as authentication, logging, etc.
func (c *Client) UpdateAccount(ctx context.Context, id string, body AccountRequest) (*Account, error) {
	u := "/sys/v1/accounts/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r Account
	if err := c.fetch(ctx, http.MethodPatch, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToUpdateAccount(
	ctx context.Context,
	id string,
	body AccountRequest,
	description *string) (*ApprovalRequest, error) {
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
