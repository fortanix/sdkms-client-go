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
    //"net/url"
    "strings"
    "github.com/pkg/errors"
)

type Account struct {
    AcctID UUID `json:"acct_id"`
    ApprovalPolicy *AccountApprovalPolicy `json:"approval_policy,omitempty"`
    // Configurations for group-level or account-level approval requests.
    ApprovalRequestSettings ApprovalRequestSettings `json:"approval_request_settings"`
    AuthConfig *AuthConfig `json:"auth_config,omitempty"`
    ClientConfigurations *ClientConfigurations `json:"client_configurations,omitempty"`
    Country *string `json:"country,omitempty"`
    CreatedAt *Time `json:"created_at,omitempty"`
    CryptographicPolicy *CryptographicPolicy `json:"cryptographic_policy,omitempty"`
    CustomLogo *Blob `json:"custom_logo,omitempty"`
    CustomMetadata *map[string]string `json:"custom_metadata,omitempty"`
    CustomMetadataAttributes *map[string]CustomAttributeSearchMetadata `json:"custom_metadata_attributes,omitempty"`
    Description *string `json:"description,omitempty"`
    DisabledAt *Time `json:"disabled_at,omitempty"`
    Enabled bool `json:"enabled"`
    InitialPurchaseAt *Time `json:"initial_purchase_at,omitempty"`
    // Enable the customer to configure when to receive alerts through SIEM tools ahead of key deactivation time.
    KeyExpiryAlertConfig *KeyExpiryAlertConfig `json:"key_expiry_alert_config,omitempty"`
    KeyHistoryPolicy *KeyHistoryPolicy `json:"key_history_policy,omitempty"`
    KeyMetadataPolicy *KeyMetadataPolicy `json:"key_metadata_policy,omitempty"`
    LogBadRequests *bool `json:"log_bad_requests,omitempty"`
    LogRetentionDays *uint64 `json:"log_retention_days,omitempty"`
    LoggingConfigs map[UUID]LoggingConfig `json:"logging_configs"`
    // Enable the user to opt out from the current behaviour of key being marked as disabled at time of deactivation.
    MarkKeyDisableWhenDeactivated bool `json:"mark_key_disable_when_deactivated"`
    MaxApp *uint32 `json:"max_app,omitempty"`
    MaxGroup *uint32 `json:"max_group,omitempty"`
    MaxOperation *uint64 `json:"max_operation,omitempty"`
    MaxPlugin *uint32 `json:"max_plugin,omitempty"`
    MaxSobj *uint32 `json:"max_sobj,omitempty"`
    MaxUser *uint32 `json:"max_user,omitempty"`
    Name string `json:"name"`
    NotificationPref *NotificationPref `json:"notification_pref,omitempty"`
    Organization *string `json:"organization,omitempty"`
    // Indicates the original purpose of the account when it was first created.
    OriginalPurpose AccountPurposeType `json:"original_purpose"`
    ParentAcctID *UUID `json:"parent_acct_id,omitempty"`
    PendingSubscriptionChangeRequest *SubscriptionChangeRequest `json:"pending_subscription_change_request,omitempty"`
    Phone *string `json:"phone,omitempty"`
    // Plugin code signing policy allows account administrators to control the plugins that can
    // be added to the account. If a code signing policy is set, all requests to create new
    // plugins or update existing plugins (if updating the code) would need to provide a
    // valid signature.
    // 
    // NOTE: if the DSM cluster is running in FIPS mode, code signing is required for plugins.
    // Therefore, if a plugin code signing policy is not set for an account, no plugins can be
    // added in that account if the DSM cluster is running in FIPS mode.
    PluginCodeSigningPolicy *PluginCodeSigningPolicy `json:"plugin_code_signing_policy,omitempty"`
    PluginEnabled *bool `json:"plugin_enabled,omitempty"`
    // The purpose of the account. Unless the account is meant for backup purposes (like disaster recovery), the account is a standard account, which is the default value. Additionally, on DSM SaaS, all accounts are standard accounts. Replication accounts are only available for onprem clusters.
    // 
    // A standard account cannot be changed to a replication account. A replication account can transition into a standard account, but doing so will sever the replication relationship between the source and destination accounts, and hence the two accounts are allowed to "diverge." Additionally, replication accounts are, for all practical purposes, read-only; in order to make one fully writeable, the account must first be converted to a standard account.
    // 
    // When creating or updating a replication account, the only fields allowed in the AccountRequest are the following:
    // - this field itself, `purpose`
    // - `enabled`
    // - `name`
    // - `auth_config`, plus `add_ldap`, `mod_ldap`, and `del_ldap`
    // - `log_bad_requests`, `log_retention_days`, plus `add_logging_configs`, `mod_logging_configs`, and `del_logging_configs`
    // The replication process would preserve most of the other fields from the source account.
    // 
    // For a given source account, a destination cluster can have at most one account that is either currently replicating or has previously replicated the source account. This means that if a customer wants to "start afresh" with a new replication account, simply converting their current account to a standard account does not help; the account needs to be deleted outright.
    // 
    // Note that this field is independent of the account's subscription, which controls the _features_ available for the account.
    Purpose AccountPurpose `json:"purpose"`
    Subscription Subscription `json:"subscription"`
    Totals *ObjectCounts `json:"totals,omitempty"`
    TrialExpiresAt *Time `json:"trial_expires_at,omitempty"`
    WorkspaceCseConfig *WorkspaceCseConfig `json:"workspace_cse_config,omitempty"`
}
func (x Account) MarshalJSON() ([]byte, error) {
    m := make(map[string]interface{})
    { // x.ApprovalRequestSettings is flattened
        b, err := json.Marshal(&x.ApprovalRequestSettings)
        if err != nil {
            return nil, err
        }
        f := make(map[string]interface{})
        if err := json.Unmarshal(b, &f); err != nil {
            return nil, err
        }
        for k, v := range f {
            m[k] = v
        }
    }
    m["acct_id"] = x.AcctID
    if x.ApprovalPolicy != nil {
        m["approval_policy"] = x.ApprovalPolicy
    }
    if x.AuthConfig != nil {
        m["auth_config"] = x.AuthConfig
    }
    if x.ClientConfigurations != nil {
        m["client_configurations"] = x.ClientConfigurations
    }
    if x.Country != nil {
        m["country"] = x.Country
    }
    if x.CreatedAt != nil {
        m["created_at"] = x.CreatedAt
    }
    if x.CryptographicPolicy != nil {
        m["cryptographic_policy"] = x.CryptographicPolicy
    }
    if x.CustomLogo != nil {
        m["custom_logo"] = x.CustomLogo
    }
    if x.CustomMetadata != nil {
        m["custom_metadata"] = x.CustomMetadata
    }
    if x.CustomMetadataAttributes != nil {
        m["custom_metadata_attributes"] = x.CustomMetadataAttributes
    }
    if x.Description != nil {
        m["description"] = x.Description
    }
    if x.DisabledAt != nil {
        m["disabled_at"] = x.DisabledAt
    }
    m["enabled"] = x.Enabled
    if x.InitialPurchaseAt != nil {
        m["initial_purchase_at"] = x.InitialPurchaseAt
    }
    if x.KeyExpiryAlertConfig != nil {
        m["key_expiry_alert_config"] = x.KeyExpiryAlertConfig
    }
    if x.KeyHistoryPolicy != nil {
        m["key_history_policy"] = x.KeyHistoryPolicy
    }
    if x.KeyMetadataPolicy != nil {
        m["key_metadata_policy"] = x.KeyMetadataPolicy
    }
    if x.LogBadRequests != nil {
        m["log_bad_requests"] = x.LogBadRequests
    }
    if x.LogRetentionDays != nil {
        m["log_retention_days"] = x.LogRetentionDays
    }
    if x.LoggingConfigs != nil {
        m["logging_configs"] = x.LoggingConfigs
    }
    m["mark_key_disable_when_deactivated"] = x.MarkKeyDisableWhenDeactivated
    if x.MaxApp != nil {
        m["max_app"] = x.MaxApp
    }
    if x.MaxGroup != nil {
        m["max_group"] = x.MaxGroup
    }
    if x.MaxOperation != nil {
        m["max_operation"] = x.MaxOperation
    }
    if x.MaxPlugin != nil {
        m["max_plugin"] = x.MaxPlugin
    }
    if x.MaxSobj != nil {
        m["max_sobj"] = x.MaxSobj
    }
    if x.MaxUser != nil {
        m["max_user"] = x.MaxUser
    }
    m["name"] = x.Name
    if x.NotificationPref != nil {
        m["notification_pref"] = x.NotificationPref
    }
    if x.Organization != nil {
        m["organization"] = x.Organization
    }
    m["original_purpose"] = x.OriginalPurpose
    if x.ParentAcctID != nil {
        m["parent_acct_id"] = x.ParentAcctID
    }
    if x.PendingSubscriptionChangeRequest != nil {
        m["pending_subscription_change_request"] = x.PendingSubscriptionChangeRequest
    }
    if x.Phone != nil {
        m["phone"] = x.Phone
    }
    if x.PluginCodeSigningPolicy != nil {
        m["plugin_code_signing_policy"] = x.PluginCodeSigningPolicy
    }
    if x.PluginEnabled != nil {
        m["plugin_enabled"] = x.PluginEnabled
    }
    m["purpose"] = x.Purpose
    m["subscription"] = x.Subscription
    if x.Totals != nil {
        m["totals"] = x.Totals
    }
    if x.TrialExpiresAt != nil {
        m["trial_expires_at"] = x.TrialExpiresAt
    }
    if x.WorkspaceCseConfig != nil {
        m["workspace_cse_config"] = x.WorkspaceCseConfig
    }
    return json.Marshal(&m)
}
func (x *Account) UnmarshalJSON(data []byte) error {
    if err := json.Unmarshal(data, &x.ApprovalRequestSettings); err != nil {
        return err
    }
    var r struct {
    AcctID UUID `json:"acct_id"`
    ApprovalPolicy *AccountApprovalPolicy `json:"approval_policy,omitempty"`
    AuthConfig *AuthConfig `json:"auth_config,omitempty"`
    ClientConfigurations *ClientConfigurations `json:"client_configurations,omitempty"`
    Country *string `json:"country,omitempty"`
    CreatedAt *Time `json:"created_at,omitempty"`
    CryptographicPolicy *CryptographicPolicy `json:"cryptographic_policy,omitempty"`
    CustomLogo *Blob `json:"custom_logo,omitempty"`
    CustomMetadata *map[string]string `json:"custom_metadata,omitempty"`
    CustomMetadataAttributes *map[string]CustomAttributeSearchMetadata `json:"custom_metadata_attributes,omitempty"`
    Description *string `json:"description,omitempty"`
    DisabledAt *Time `json:"disabled_at,omitempty"`
    Enabled bool `json:"enabled"`
    InitialPurchaseAt *Time `json:"initial_purchase_at,omitempty"`
    KeyExpiryAlertConfig *KeyExpiryAlertConfig `json:"key_expiry_alert_config,omitempty"`
    KeyHistoryPolicy *KeyHistoryPolicy `json:"key_history_policy,omitempty"`
    KeyMetadataPolicy *KeyMetadataPolicy `json:"key_metadata_policy,omitempty"`
    LogBadRequests *bool `json:"log_bad_requests,omitempty"`
    LogRetentionDays *uint64 `json:"log_retention_days,omitempty"`
    LoggingConfigs map[UUID]LoggingConfig `json:"logging_configs"`
    MarkKeyDisableWhenDeactivated bool `json:"mark_key_disable_when_deactivated"`
    MaxApp *uint32 `json:"max_app,omitempty"`
    MaxGroup *uint32 `json:"max_group,omitempty"`
    MaxOperation *uint64 `json:"max_operation,omitempty"`
    MaxPlugin *uint32 `json:"max_plugin,omitempty"`
    MaxSobj *uint32 `json:"max_sobj,omitempty"`
    MaxUser *uint32 `json:"max_user,omitempty"`
    Name string `json:"name"`
    NotificationPref *NotificationPref `json:"notification_pref,omitempty"`
    Organization *string `json:"organization,omitempty"`
    OriginalPurpose AccountPurposeType `json:"original_purpose"`
    ParentAcctID *UUID `json:"parent_acct_id,omitempty"`
    PendingSubscriptionChangeRequest *SubscriptionChangeRequest `json:"pending_subscription_change_request,omitempty"`
    Phone *string `json:"phone,omitempty"`
    PluginCodeSigningPolicy *PluginCodeSigningPolicy `json:"plugin_code_signing_policy,omitempty"`
    PluginEnabled *bool `json:"plugin_enabled,omitempty"`
    Purpose AccountPurpose `json:"purpose"`
    Subscription Subscription `json:"subscription"`
    Totals *ObjectCounts `json:"totals,omitempty"`
    TrialExpiresAt *Time `json:"trial_expires_at,omitempty"`
    WorkspaceCseConfig *WorkspaceCseConfig `json:"workspace_cse_config,omitempty"`
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
    x.KeyExpiryAlertConfig = r.KeyExpiryAlertConfig
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
    x.OriginalPurpose = r.OriginalPurpose
    x.ParentAcctID = r.ParentAcctID
    x.PendingSubscriptionChangeRequest = r.PendingSubscriptionChangeRequest
    x.Phone = r.Phone
    x.PluginCodeSigningPolicy = r.PluginCodeSigningPolicy
    x.PluginEnabled = r.PluginEnabled
    x.Purpose = r.Purpose
    x.Subscription = r.Subscription
    x.Totals = r.Totals
    x.TrialExpiresAt = r.TrialExpiresAt
    x.WorkspaceCseConfig = r.WorkspaceCseConfig
    return nil
}

// Account approval policy.
type AccountApprovalPolicy struct {
    Policy QuorumPolicy `json:"policy"`
    ManageGroups *bool `json:"manage_groups,omitempty"`
    // When this is true, changes to the account authentication methods require approval.
    ProtectAuthenticationMethods *bool `json:"protect_authentication_methods,omitempty"`
    // When this is true, changes to the account cryptographic policy requires approval.
    ProtectCryptographicPolicy *bool `json:"protect_cryptographic_policy,omitempty"`
    // When this is true, changes to logging configuration require approval.
    ProtectLoggingConfig *bool `json:"protect_logging_config,omitempty"`
    // When set to true, updating custom roles would require approval.
    ProtectCustomRoleUpdates *bool `json:"protect_custom_role_updates,omitempty"`
}

// Describes the purpose of the account.
type AccountPurpose struct {
    // An ordinary account.
    Standard *struct{}
    // An account that replicates another account (e.g., for disaster
    // recovery purposes). Replication settings are contained here.
    AccountReplication *AccountReplicationConfiguration
}
func (x AccountPurpose) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "AccountPurpose", 
                  []bool{ x.Standard != nil,
                  x.AccountReplication != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.Standard != nil:
        m["$type"] = "Standard"
    case x.AccountReplication != nil:
        b, err := json.Marshal(x.AccountReplication)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["$type"] = "AccountReplication"
    }
    return json.Marshal(m)
}
func (x *AccountPurpose) UnmarshalJSON(data []byte) error {
    x.Standard = nil
    x.AccountReplication = nil
    var h struct {
        Tag string `json:"$type"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid AccountPurpose")
    }
    switch h.Tag {
    case "Standard":
        x.Standard = &struct{}{}
    case "AccountReplication":
        var accountReplication AccountReplicationConfiguration
        if err := json.Unmarshal(data, &accountReplication); err != nil {
            return err
        }
        x.AccountReplication = &accountReplication
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

// The purpose of the account (minus any configuration-related details).
type AccountPurposeType struct {
    // An ordinary account.
    Standard *struct{}
    // An account that replicates another account.
    AccountReplication *struct{}
}
func (x AccountPurposeType) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "AccountPurposeType", 
                  []bool{ x.Standard != nil,
                  x.AccountReplication != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.Standard != nil:
        m["$type"] = "Standard"
    case x.AccountReplication != nil:
        m["$type"] = "AccountReplication"
    }
    return json.Marshal(m)
}
func (x *AccountPurposeType) UnmarshalJSON(data []byte) error {
    x.Standard = nil
    x.AccountReplication = nil
    var h struct {
        Tag string `json:"$type"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid AccountPurposeType")
    }
    switch h.Tag {
    case "Standard":
        x.Standard = &struct{}{}
    case "AccountReplication":
        x.AccountReplication = &struct{}{}
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

type AccountReplicationConfiguration struct {
    // Settings for how DSM should connect to the source account to be replicated.
    ConnectionSettings AccountReplicationConnection `json:"connection_settings"`
    // Settings for how DSM should replicate objects from the source account, once a connection has
    // been established.
    ScanSettings AccountReplicationScanSettings `json:"scan_settings"`
}

// Settings for how a replication account should connect to a source cluster. This type does not
// handle configuration of a source-side admin app used in the replication process; such setup is
// handled by separate endpoints.
type AccountReplicationConnection struct {
    // The URL of the DSM cluster containing the account to back up. Only HTTPS is supported.
    URL string `json:"url"`
    // The ID of the currently-active replication credentials used to fetch objects from the source
    // account. In Create requests, this field should not be specified (since credential creation is
    // done via a separate endpoint), and in Update requests, this field can be omitted if no change
    // is desired for the field.
    ActiveReplicationCredential *ReplicationCredentialId `json:"active_replication_credential,omitempty"`
}

// Settings for how DSM should go about replicating objects from the source account once a connection
// has been established.
//
// Today, account replication is performed using "basic" replication, which exports key material in
// the clear (over a TLS connection).
type AccountReplicationScanSettings struct {
    // Settings for configuring how DSM periodically fetches information from the source. Today, the
    // only configurable setting is the frequency of scans.
    AutoScan AutoScanSettings `json:"auto_scan"`
}

type AccountRequest struct {
    AddLdap *[]AuthConfigLdap `json:"add_ldap,omitempty"`
    AddLoggingConfigs *[]LoggingConfigRequest `json:"add_logging_configs,omitempty"`
    ApprovalPolicy *AccountApprovalPolicy `json:"approval_policy,omitempty"`
    // Configurations for group-level or account-level approval requests.
    ApprovalRequestSettings *ApprovalRequestSettingsRequest `json:"approval_request_settings,omitempty"`
    AuthConfig *AuthConfig `json:"auth_config,omitempty"`
    ClientConfigurations *ClientConfigurationsRequest `json:"client_configurations,omitempty"`
    Country *string `json:"country,omitempty"`
    CryptographicPolicy *Removable[CryptographicPolicy] `json:"cryptographic_policy,omitempty"`
    CustomLogo *Blob `json:"custom_logo,omitempty"`
    CustomMetadata *map[string]string `json:"custom_metadata,omitempty"`
    CustomMetadataAttributes *map[string]CustomAttributeSearchMetadata `json:"custom_metadata_attributes,omitempty"`
    DelLdap *[]UUID `json:"del_ldap,omitempty"`
    DelLoggingConfigs *[]UUID `json:"del_logging_configs,omitempty"`
    Description *string `json:"description,omitempty"`
    Enabled *bool `json:"enabled,omitempty"`
    // Enable the customer to configure when to receive alerts through SIEM tools ahead of key deactivation time.
    KeyExpiryAlertConfig *KeyExpiryAlertConfigRequest `json:"key_expiry_alert_config,omitempty"`
    KeyHistoryPolicy *Removable[KeyHistoryPolicy] `json:"key_history_policy,omitempty"`
    KeyMetadataPolicy *Removable[KeyMetadataPolicy] `json:"key_metadata_policy,omitempty"`
    LogBadRequests *bool `json:"log_bad_requests,omitempty"`
    LogRetentionDays *uint64 `json:"log_retention_days,omitempty"`
    // Enable the user to opt out from the current behaviour of key being marked as disabled at time of deactivation.
    MarkKeyDisableWhenDeactivated *bool `json:"mark_key_disable_when_deactivated,omitempty"`
    ModLdap *map[UUID]AuthConfigLdap `json:"mod_ldap,omitempty"`
    ModLoggingConfigs *map[UUID]LoggingConfigRequest `json:"mod_logging_configs,omitempty"`
    Name *string `json:"name,omitempty"`
    NotificationPref *NotificationPref `json:"notification_pref,omitempty"`
    Organization *string `json:"organization,omitempty"`
    ParentAcctID *UUID `json:"parent_acct_id,omitempty"`
    PendingSubscriptionChangeRequest *SubscriptionChangeRequest `json:"pending_subscription_change_request,omitempty"`
    Phone *string `json:"phone,omitempty"`
    // Plugin code signing policy allows account administrators to control the plugins that can
    // be added to the account. If a code signing policy is set, all requests to create new
    // plugins or update existing plugins (if updating the code) would need to provide a
    // valid signature.
    // 
    // NOTE: if the DSM cluster is running in FIPS mode, code signing is required for plugins.
    // Therefore, if a plugin code signing policy is not set for an account, no plugins can be
    // added in that account if the DSM cluster is running in FIPS mode.
    PluginCodeSigningPolicy *Removable[PluginCodeSigningPolicy] `json:"plugin_code_signing_policy,omitempty"`
    PluginEnabled *bool `json:"plugin_enabled,omitempty"`
    // The purpose of the account. Unless the account is meant for backup purposes (like disaster recovery), the account is a standard account, which is the default value. Additionally, on DSM SaaS, all accounts are standard accounts. Replication accounts are only available for onprem clusters.
    // 
    // A standard account cannot be changed to a replication account. A replication account can transition into a standard account, but doing so will sever the replication relationship between the source and destination accounts, and hence the two accounts are allowed to "diverge." Additionally, replication accounts are, for all practical purposes, read-only; in order to make one fully writeable, the account must first be converted to a standard account.
    // 
    // When creating or updating a replication account, the only fields allowed in the AccountRequest are the following:
    // - this field itself, `purpose`
    // - `enabled`
    // - `name`
    // - `auth_config`, plus `add_ldap`, `mod_ldap`, and `del_ldap`
    // - `log_bad_requests`, `log_retention_days`, plus `add_logging_configs`, `mod_logging_configs`, and `del_logging_configs`
    // The replication process would preserve most of the other fields from the source account.
    // 
    // For a given source account, a destination cluster can have at most one account that is either currently replicating or has previously replicated the source account. This means that if a customer wants to "start afresh" with a new replication account, simply converting their current account to a standard account does not help; the account needs to be deleted outright.
    // 
    // Note that this field is independent of the account's subscription, which controls the _features_ available for the account.
    Purpose *AccountPurpose `json:"purpose,omitempty"`
    Subscription *Subscription `json:"subscription,omitempty"`
    WorkspaceCseConfig *Removable[WorkspaceCseConfig] `json:"workspace_cse_config,omitempty"`
}
func (x AccountRequest) MarshalJSON() ([]byte, error) {
    m := make(map[string]interface{})
    { // x.ApprovalRequestSettings is flattened
        b, err := json.Marshal(&x.ApprovalRequestSettings)
        if err != nil {
            return nil, err
        }
        f := make(map[string]interface{})
        if err := json.Unmarshal(b, &f); err != nil {
            return nil, err
        }
        for k, v := range f {
            m[k] = v
        }
    }
    if x.AddLdap != nil {
        m["add_ldap"] = x.AddLdap
    }
    if x.AddLoggingConfigs != nil {
        m["add_logging_configs"] = x.AddLoggingConfigs
    }
    if x.ApprovalPolicy != nil {
        m["approval_policy"] = x.ApprovalPolicy
    }
    if x.AuthConfig != nil {
        m["auth_config"] = x.AuthConfig
    }
    if x.ClientConfigurations != nil {
        m["client_configurations"] = x.ClientConfigurations
    }
    if x.Country != nil {
        m["country"] = x.Country
    }
    if x.CryptographicPolicy != nil {
        m["cryptographic_policy"] = x.CryptographicPolicy
    }
    if x.CustomLogo != nil {
        m["custom_logo"] = x.CustomLogo
    }
    if x.CustomMetadata != nil {
        m["custom_metadata"] = x.CustomMetadata
    }
    if x.CustomMetadataAttributes != nil {
        m["custom_metadata_attributes"] = x.CustomMetadataAttributes
    }
    if x.DelLdap != nil {
        m["del_ldap"] = x.DelLdap
    }
    if x.DelLoggingConfigs != nil {
        m["del_logging_configs"] = x.DelLoggingConfigs
    }
    if x.Description != nil {
        m["description"] = x.Description
    }
    if x.Enabled != nil {
        m["enabled"] = x.Enabled
    }
    if x.KeyExpiryAlertConfig != nil {
        m["key_expiry_alert_config"] = x.KeyExpiryAlertConfig
    }
    if x.KeyHistoryPolicy != nil {
        m["key_history_policy"] = x.KeyHistoryPolicy
    }
    if x.KeyMetadataPolicy != nil {
        m["key_metadata_policy"] = x.KeyMetadataPolicy
    }
    if x.LogBadRequests != nil {
        m["log_bad_requests"] = x.LogBadRequests
    }
    if x.LogRetentionDays != nil {
        m["log_retention_days"] = x.LogRetentionDays
    }
    if x.MarkKeyDisableWhenDeactivated != nil {
        m["mark_key_disable_when_deactivated"] = x.MarkKeyDisableWhenDeactivated
    }
    if x.ModLdap != nil {
        m["mod_ldap"] = x.ModLdap
    }
    if x.ModLoggingConfigs != nil {
        m["mod_logging_configs"] = x.ModLoggingConfigs
    }
    if x.Name != nil {
        m["name"] = x.Name
    }
    if x.NotificationPref != nil {
        m["notification_pref"] = x.NotificationPref
    }
    if x.Organization != nil {
        m["organization"] = x.Organization
    }
    if x.ParentAcctID != nil {
        m["parent_acct_id"] = x.ParentAcctID
    }
    if x.PendingSubscriptionChangeRequest != nil {
        m["pending_subscription_change_request"] = x.PendingSubscriptionChangeRequest
    }
    if x.Phone != nil {
        m["phone"] = x.Phone
    }
    if x.PluginCodeSigningPolicy != nil {
        m["plugin_code_signing_policy"] = x.PluginCodeSigningPolicy
    }
    if x.PluginEnabled != nil {
        m["plugin_enabled"] = x.PluginEnabled
    }
    if x.Purpose != nil {
        m["purpose"] = x.Purpose
    }
    if x.Subscription != nil {
        m["subscription"] = x.Subscription
    }
    if x.WorkspaceCseConfig != nil {
        m["workspace_cse_config"] = x.WorkspaceCseConfig
    }
    return json.Marshal(&m)
}
func (x *AccountRequest) UnmarshalJSON(data []byte) error {
    if err := json.Unmarshal(data, &x.ApprovalRequestSettings); err != nil {
        return err
    }
    var r struct {
    AddLdap *[]AuthConfigLdap `json:"add_ldap,omitempty"`
    AddLoggingConfigs *[]LoggingConfigRequest `json:"add_logging_configs,omitempty"`
    ApprovalPolicy *AccountApprovalPolicy `json:"approval_policy,omitempty"`
    AuthConfig *AuthConfig `json:"auth_config,omitempty"`
    ClientConfigurations *ClientConfigurationsRequest `json:"client_configurations,omitempty"`
    Country *string `json:"country,omitempty"`
    CryptographicPolicy *Removable[CryptographicPolicy] `json:"cryptographic_policy,omitempty"`
    CustomLogo *Blob `json:"custom_logo,omitempty"`
    CustomMetadata *map[string]string `json:"custom_metadata,omitempty"`
    CustomMetadataAttributes *map[string]CustomAttributeSearchMetadata `json:"custom_metadata_attributes,omitempty"`
    DelLdap *[]UUID `json:"del_ldap,omitempty"`
    DelLoggingConfigs *[]UUID `json:"del_logging_configs,omitempty"`
    Description *string `json:"description,omitempty"`
    Enabled *bool `json:"enabled,omitempty"`
    KeyExpiryAlertConfig *KeyExpiryAlertConfigRequest `json:"key_expiry_alert_config,omitempty"`
    KeyHistoryPolicy *Removable[KeyHistoryPolicy] `json:"key_history_policy,omitempty"`
    KeyMetadataPolicy *Removable[KeyMetadataPolicy] `json:"key_metadata_policy,omitempty"`
    LogBadRequests *bool `json:"log_bad_requests,omitempty"`
    LogRetentionDays *uint64 `json:"log_retention_days,omitempty"`
    MarkKeyDisableWhenDeactivated *bool `json:"mark_key_disable_when_deactivated,omitempty"`
    ModLdap *map[UUID]AuthConfigLdap `json:"mod_ldap,omitempty"`
    ModLoggingConfigs *map[UUID]LoggingConfigRequest `json:"mod_logging_configs,omitempty"`
    Name *string `json:"name,omitempty"`
    NotificationPref *NotificationPref `json:"notification_pref,omitempty"`
    Organization *string `json:"organization,omitempty"`
    ParentAcctID *UUID `json:"parent_acct_id,omitempty"`
    PendingSubscriptionChangeRequest *SubscriptionChangeRequest `json:"pending_subscription_change_request,omitempty"`
    Phone *string `json:"phone,omitempty"`
    PluginCodeSigningPolicy *Removable[PluginCodeSigningPolicy] `json:"plugin_code_signing_policy,omitempty"`
    PluginEnabled *bool `json:"plugin_enabled,omitempty"`
    Purpose *AccountPurpose `json:"purpose,omitempty"`
    Subscription *Subscription `json:"subscription,omitempty"`
    WorkspaceCseConfig *Removable[WorkspaceCseConfig] `json:"workspace_cse_config,omitempty"`
    }
    if err := json.Unmarshal(data, &r); err != nil {
        return err
    }
    x.AddLdap = r.AddLdap
    x.AddLoggingConfigs = r.AddLoggingConfigs
    x.ApprovalPolicy = r.ApprovalPolicy
    x.AuthConfig = r.AuthConfig
    x.ClientConfigurations = r.ClientConfigurations
    x.Country = r.Country
    x.CryptographicPolicy = r.CryptographicPolicy
    x.CustomLogo = r.CustomLogo
    x.CustomMetadata = r.CustomMetadata
    x.CustomMetadataAttributes = r.CustomMetadataAttributes
    x.DelLdap = r.DelLdap
    x.DelLoggingConfigs = r.DelLoggingConfigs
    x.Description = r.Description
    x.Enabled = r.Enabled
    x.KeyExpiryAlertConfig = r.KeyExpiryAlertConfig
    x.KeyHistoryPolicy = r.KeyHistoryPolicy
    x.KeyMetadataPolicy = r.KeyMetadataPolicy
    x.LogBadRequests = r.LogBadRequests
    x.LogRetentionDays = r.LogRetentionDays
    x.MarkKeyDisableWhenDeactivated = r.MarkKeyDisableWhenDeactivated
    x.ModLdap = r.ModLdap
    x.ModLoggingConfigs = r.ModLoggingConfigs
    x.Name = r.Name
    x.NotificationPref = r.NotificationPref
    x.Organization = r.Organization
    x.ParentAcctID = r.ParentAcctID
    x.PendingSubscriptionChangeRequest = r.PendingSubscriptionChangeRequest
    x.Phone = r.Phone
    x.PluginCodeSigningPolicy = r.PluginCodeSigningPolicy
    x.PluginEnabled = r.PluginEnabled
    x.Purpose = r.Purpose
    x.Subscription = r.Subscription
    x.WorkspaceCseConfig = r.WorkspaceCseConfig
    return nil
}

type AccountSort struct {
    ByAcctID *AccountSortByAcctId
}
type AccountSortByAcctId struct {
    Order Order `json:"order"`
}
func (x AccountSort) urlEncode(v map[string][]string) error {
    if x.ByAcctID != nil {
        v["sort_by"] = []string{"acct_id" + string(x.ByAcctID.Order)}
    }
    return nil
}

type AppCreditsUsage struct {
    Generic uint32 `json:"generic"`
    Tokenization uint32 `json:"tokenization"`
    Tep uint32 `json:"tep"`
    Accelerator uint32 `json:"accelerator"`
    SecretsManagement uint32 `json:"secrets_management"`
    AwsCloudAccounts uint32 `json:"aws_cloud_accounts"`
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
    // Whether or not the requester's access should be checked again when they
    // request to see the operation results for an approved quorum request with
    // sensitive data in the output. Sensitive data includes secret values such
    // as API keys, decrypted plaintext, exported key material etc. Note that
    // if the result is not deemed sensitive this setting does not apply, e.g.
    // approval request to sign a message (signatures are not deemed secret) or
    // encrypt data (ciphertext is not deemed secret). Here is the list of all
    // operations that are deemed sensitive (this list may be expanded in the
    // future):
    //
    // - Get App Credential: `GET /sys/v1/apps/${app_id}/credential`
    // - Decrypt:
    //   - Legacy version: `POST /crypto/v1/keys/${key_id}/decrypt`
    //   - New version: `POST /crypto/v1/decrypt`
    // - Export Object Value:
    //   - Legacy version: `GET /crypto/v1/keys/${key_id}/export`
    //   - New version: `POST /crypto/v1/keys/export`
    // - Batch: `POST /batch/v1` if any of the operations in the batch input is
    //   sensitive.
    //
    // This setting is introduced for backwards compatibility so that existing
    // approval request workflows are not broken. For new use cases, it is
    // recommended to leave this setting enabled.
    CheckAccessForSensitiveOperationResults *bool `json:"check_access_for_sensitive_operation_results,omitempty"`
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
    // Whether or not the requester's access should be checked again when they
    // request to see the operation results for an approved quorum request with
    // sensitive data in the output. Sensitive data includes secret values such
    // as API keys, decrypted plaintext, exported key material etc. Note that
    // if the result is not deemed sensitive this setting does not apply, e.g.
    // approval request to sign a message (signatures are not deemed secret) or
    // encrypt data (ciphertext is not deemed secret). Here is the list of all
    // operations that are deemed sensitive (this list may be expanded in the
    // future):
    //
    // - Get App Credential: `GET /sys/v1/apps/${app_id}/credential`
    // - Decrypt:
    //   - Legacy version: `POST /crypto/v1/keys/${key_id}/decrypt`
    //   - New version: `POST /crypto/v1/decrypt`
    // - Export Object Value:
    //   - Legacy version: `GET /crypto/v1/keys/${key_id}/export`
    //   - New version: `POST /crypto/v1/keys/export`
    // - Batch: `POST /batch/v1` if any of the operations in the batch input is
    //   sensitive.
    //
    // This setting is introduced for backwards compatibility so that existing
    // approval request workflows are not broken. For new use cases, it is
    // recommended to leave this setting enabled.
    CheckAccessForSensitiveOperationResults *bool `json:"check_access_for_sensitive_operation_results,omitempty"`
}

// Account authentication settings.
type AuthConfig struct {
    Password *AuthConfigPassword `json:"password,omitempty"`
    Saml *string `json:"saml,omitempty"`
    Oauth *AuthConfigOauth `json:"oauth,omitempty"`
    Ldap *map[UUID]AuthConfigLdap `json:"ldap,omitempty"`
    SignedJwt *AuthConfigSignedJwt `json:"signed_jwt,omitempty"`
    Vcd *AuthConfigVcd `json:"vcd,omitempty"`
}

// OAuth single sign-on authentication settings.
type AuthConfigOauth struct {
    IdpName string `json:"idp_name"`
    IdpIconURL string `json:"idp_icon_url"`
    IdpAuthorizationEndpoint string `json:"idp_authorization_endpoint"`
    IdpTokenEndpoint string `json:"idp_token_endpoint"`
    IdpUserinfoEndpoint *string `json:"idp_userinfo_endpoint,omitempty"`
    IdpRequiresBasicAuth bool `json:"idp_requires_basic_auth"`
    TLS TlsConfig `json:"tls"`
    ClientID string `json:"client_id"`
    ClientSecret ZeroizedString `json:"client_secret"`
    // Parameters to set when calling `idp_authorization_endpoint`
    AuthParams *OauthAuthenticationParameters `json:"auth_params,omitempty"`
}

// Password authentication settings.
type AuthConfigPassword struct {
    Require2fa bool `json:"require_2fa"`
    AdministratorsOnly bool `json:"administrators_only"`
}

// Signed JWT authentication settings.
type AuthConfigSignedJwt struct {
    ValidIssuers []string `json:"valid_issuers"`
    SigningKeys SigningKeys `json:"signing_keys"`
}

// Vcd single sign-on authentication settings.
type AuthConfigVcd struct {
    IdpName string `json:"idp_name"`
    IdpAuthorizationEndpoint string `json:"idp_authorization_endpoint"`
    Org string `json:"org"`
    TLS TlsConfig `json:"tls"`
}

type AzureLogAnalyticsLoggingConfig struct {
    Enabled bool `json:"enabled"`
    WorkspaceID UUID `json:"workspace_id"`
    SharedKey *ZeroizedBlob `json:"shared_key,omitempty"`
}

type AzureLogAnalyticsLoggingConfigRequest struct {
    Enabled *bool `json:"enabled,omitempty"`
    WorkspaceID *UUID `json:"workspace_id,omitempty"`
    SharedKey *ZeroizedBlob `json:"shared_key,omitempty"`
}

// Details about a certificate-based admin app credential used for account replication.
type CertificateReplicationCredential struct {
    // The ID of the source-side admin app that uses this credential.
    AppID *UUID `json:"app_id,omitempty"`
    // The ID assigned to the credential.
    CredentialID ReplicationCredentialId `json:"credential_id"`
    // The certificate chain associated with the credential. This is a list of DER-encoded
    // certificates, starting from the leaf certificate, and can consist of a single certificate if
    // no intermediate certificates are necessary when authenticating with the source cluster.
    CertificateChain *[]ZeroizedBlob `json:"certificate_chain,omitempty"`
}

type CountParams struct {
    RangeFrom *uint64 `json:"range_from,omitempty"`
    RangeTo *uint64 `json:"range_to,omitempty"`
    DetailedUsage *bool `json:"detailed_usage,omitempty"`
    SaasFullUsage *bool `json:"saas_full_usage,omitempty"`
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

// A request to create a new admin app credential for account replication
// purposes. Note that the result is not immediately usable; further steps
// are needed in order to configure this and set it as the account's active
// credential.
type CreateReplicationCredentialRequest struct {
    // Create a private key as part of a client certificate (or trusted CA)
    // admin app credential for account replication. A new self-signed cert
    // needs to be requested afterwards. (In the future, DSM will also allow
    // a CSR to be requested instead.)
    //
    // The exact details of the private key (e.g., object type, key size)
    // are an implementation detail, and may change between DSM versions.
    Certificate *struct{}
}
func (x CreateReplicationCredentialRequest) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "CreateReplicationCredentialRequest", 
                  []bool{ x.Certificate != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.Certificate != nil:
        m["$type"] = "Certificate"
    }
    return json.Marshal(m)
}
func (x *CreateReplicationCredentialRequest) UnmarshalJSON(data []byte) error {
    x.Certificate = nil
    var h struct {
        Tag string `json:"$type"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid CreateReplicationCredentialRequest")
    }
    switch h.Tag {
    case "Certificate":
        x.Certificate = &struct{}{}
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

// Custom subscription type
type CustomSubscriptionType struct {
    MaxPlugin *uint32 `json:"max_plugin,omitempty"`
    MaxApp *uint32 `json:"max_app,omitempty"`
    MaxHsmg *uint32 `json:"max_hsmg,omitempty"`
    MaxOperation *uint64 `json:"max_operation,omitempty"`
    MaxTokenizationOperation *uint64 `json:"max_tokenization_operation,omitempty"`
    CountTransientOps *bool `json:"count_transient_ops,omitempty"`
    PackageName *string `json:"package_name,omitempty"`
    Features *SubscriptionFeatures `json:"features,omitempty"`
    AddOns *map[string]string `json:"add_ons,omitempty"`
    SoftOpsPerSecondLimit *uint32 `json:"soft_ops_per_second_limit,omitempty"`
}

type DaysAhead struct {
    Days uint16 `json:"days"`
}

type FreemiumSubscriptionType struct {
    MaxApp *uint32 `json:"max_app,omitempty"`
    MaxHsmg *uint32 `json:"max_hsmg,omitempty"`
    MaxOperation *uint64 `json:"max_operation,omitempty"`
    MaxTokenizationOperation *uint64 `json:"max_tokenization_operation,omitempty"`
    MaxPlugin *uint32 `json:"max_plugin,omitempty"`
}

type GetAccountParams struct {
    WithTotals *bool `json:"with_totals,omitempty"`
    PreviousID *UUID `json:"previous_id,omitempty"`
    Limit *uint `json:"limit,omitempty"`
    SortBy AccountSort `json:"sort_by"`
}
func (x GetAccountParams) urlEncode(v map[string][]string) error {
    if x.WithTotals != nil {
        v["with_totals"] = []string{fmt.Sprintf("%v", *x.WithTotals)}
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
    NumOperations uint64 `json:"num_operations"`
    EncryptionOperations *uint64 `json:"encryption_operations,omitempty"`
    DecryptionOperations *uint64 `json:"decryption_operations,omitempty"`
    SignOperations *uint64 `json:"sign_operations,omitempty"`
    VerifyOperations *uint64 `json:"verify_operations,omitempty"`
    TokenizationOperations *uint64 `json:"tokenization_operations,omitempty"`
    DetokenizationOperations *uint64 `json:"detokenization_operations,omitempty"`
    SecretsOperations *uint64 `json:"secrets_operations,omitempty"`
    PluginInvokeOperations *uint64 `json:"plugin_invoke_operations,omitempty"`
    Apps *AppCreditsUsage `json:"apps,omitempty"`
    Plugin *uint32 `json:"plugin,omitempty"`
    // The total number of sobjects in the account, or
    // an approximation thereof. This field is present if
    // the `saas_full_usage` query parameter is specified
    // when retrieving account usage statistics.
    //
    // Note that all sobjects in the account are counted,
    // regardless of whether the user has access to them.
    Sobjects *uint64 `json:"sobjects,omitempty"`
    // The accuracy of the `sobjects` count (whether it
    // is an exact count or an approximate count).
    //
    // If the total number of sobjects in the account is
    // less than 5000, DSM will return an exact number.
    // Additionally, if DSM estimates the total number of
    // sobjects to be less than 10000, it will still attempt
    // to return an exact count. Otherwise, DSM will return
    // an approximation.
    //
    // These rules are subject to change in the future.
    SobjectsAccuracy *CountAccuracy `json:"sobjects_accuracy,omitempty"`
    HsmGateway *uint32 `json:"hsm_gateway,omitempty"`
    OperationTopApp *map[string]uint64 `json:"operation_top_app,omitempty"`
    OperationTopSobject *map[string]uint64 `json:"operation_top_sobject,omitempty"`
}

// A Google service account key object. See https://cloud.google.com/video-intelligence/docs/common/auth.
type GoogleServiceAccountKey struct {
    Type string `json:"type"`
    ProjectID string `json:"project_id"`
    PrivateKeyID string `json:"private_key_id"`
    PrivateKey *ZeroizedString `json:"private_key,omitempty"`
    ClientEmail string `json:"client_email"`
}

type KeyExpiryAlertConfig struct {
    Triggers map[UUID]KeyExpiryAlertTrigger `json:"triggers"`
    SiemToolConfigs map[UUID]KeyExpiryAlertSiemToolConfig `json:"siem_tool_configs"`
}

type KeyExpiryAlertConfigRequest struct {
    AddTriggers *[]KeyExpiryAlertTrigger `json:"add_triggers,omitempty"`
    ModTriggers *map[UUID]KeyExpiryAlertTrigger `json:"mod_triggers,omitempty"`
    DelTriggers *[]UUID `json:"del_triggers,omitempty"`
    AddSiemToolConfigs *[]KeyExpiryAlertSiemToolConfig `json:"add_siem_tool_configs,omitempty"`
    ModSiemToolConfigs *map[UUID]KeyExpiryAlertSiemToolConfig `json:"mod_siem_tool_configs,omitempty"`
    DelSiemToolConfigs *[]UUID `json:"del_siem_tool_configs,omitempty"`
}

type KeyExpiryAlertSiemToolConfig struct {
    MaxKeyInfoPerAlert *uint16 `json:"max_key_info_per_alert,omitempty"`
    Config LoggingConfig `json:"config"`
}

type KeyExpiryAlertTrigger struct {
    DaysAhead *DaysAhead
}
func (x KeyExpiryAlertTrigger) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "KeyExpiryAlertTrigger", 
                  []bool{ x.DaysAhead != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.DaysAhead != nil:
        b, err := json.Marshal(x.DaysAhead)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["$type"] = "DaysAhead"
    }
    return json.Marshal(m)
}
func (x *KeyExpiryAlertTrigger) UnmarshalJSON(data []byte) error {
    x.DaysAhead = nil
    var h struct {
        Tag string `json:"$type"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid KeyExpiryAlertTrigger")
    }
    switch h.Tag {
    case "DaysAhead":
        var daysAhead DaysAhead
        if err := json.Unmarshal(data, &daysAhead); err != nil {
            return err
        }
        x.DaysAhead = &daysAhead
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

// Response body for a GET call to retrieve all replication credentials.
type ListReplicationCredentialsResponse struct {
    // The list of replication credentials.
    Items []ReplicationCredential `json:"items"`
}

type LoggingConfig struct {
    Splunk *SplunkLoggingConfig
    Stackdriver *StackdriverLoggingConfig
    Syslog *SyslogLoggingConfig
    AzureLogAnalytics *AzureLogAnalyticsLoggingConfig
}
func (x LoggingConfig) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "LoggingConfig", 
                  []bool{ x.Splunk != nil,
                  x.Stackdriver != nil,
                  x.Syslog != nil,
                  x.AzureLogAnalytics != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Splunk *SplunkLoggingConfig `json:"splunk,omitempty"`
        Stackdriver *StackdriverLoggingConfig `json:"stackdriver,omitempty"`
        Syslog *SyslogLoggingConfig `json:"syslog,omitempty"`
        AzureLogAnalytics *AzureLogAnalyticsLoggingConfig `json:"azure_log_analytics,omitempty"`
    }
    obj.Splunk = x.Splunk
    obj.Stackdriver = x.Stackdriver
    obj.Syslog = x.Syslog
    obj.AzureLogAnalytics = x.AzureLogAnalytics
    return json.Marshal(obj)
}
func (x *LoggingConfig) UnmarshalJSON(data []byte) error {
    x.Splunk = nil
    x.Stackdriver = nil
    x.Syslog = nil
    x.AzureLogAnalytics = nil
    var obj struct {
        Splunk *SplunkLoggingConfig `json:"splunk,omitempty"`
        Stackdriver *StackdriverLoggingConfig `json:"stackdriver,omitempty"`
        Syslog *SyslogLoggingConfig `json:"syslog,omitempty"`
        AzureLogAnalytics *AzureLogAnalyticsLoggingConfig `json:"azure_log_analytics,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.Splunk = obj.Splunk
    x.Stackdriver = obj.Stackdriver
    x.Syslog = obj.Syslog
    x.AzureLogAnalytics = obj.AzureLogAnalytics
    return nil
}

type LoggingConfigRequest struct {
    Splunk *SplunkLoggingConfigRequest
    Stackdriver *StackdriverLoggingConfigRequest
    Syslog *SyslogLoggingConfigRequest
    AzureLogAnalytics *AzureLogAnalyticsLoggingConfigRequest
}
func (x LoggingConfigRequest) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "LoggingConfigRequest", 
                  []bool{ x.Splunk != nil,
                  x.Stackdriver != nil,
                  x.Syslog != nil,
                  x.AzureLogAnalytics != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Splunk *SplunkLoggingConfigRequest `json:"splunk,omitempty"`
        Stackdriver *StackdriverLoggingConfigRequest `json:"stackdriver,omitempty"`
        Syslog *SyslogLoggingConfigRequest `json:"syslog,omitempty"`
        AzureLogAnalytics *AzureLogAnalyticsLoggingConfigRequest `json:"azure_log_analytics,omitempty"`
    }
    obj.Splunk = x.Splunk
    obj.Stackdriver = x.Stackdriver
    obj.Syslog = x.Syslog
    obj.AzureLogAnalytics = x.AzureLogAnalytics
    return json.Marshal(obj)
}
func (x *LoggingConfigRequest) UnmarshalJSON(data []byte) error {
    x.Splunk = nil
    x.Stackdriver = nil
    x.Syslog = nil
    x.AzureLogAnalytics = nil
    var obj struct {
        Splunk *SplunkLoggingConfigRequest `json:"splunk,omitempty"`
        Stackdriver *StackdriverLoggingConfigRequest `json:"stackdriver,omitempty"`
        Syslog *SyslogLoggingConfigRequest `json:"syslog,omitempty"`
        AzureLogAnalytics *AzureLogAnalyticsLoggingConfigRequest `json:"azure_log_analytics,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.Splunk = obj.Splunk
    x.Stackdriver = obj.Stackdriver
    x.Syslog = obj.Syslog
    x.AzureLogAnalytics = obj.AzureLogAnalytics
    return nil
}

// Notification preferences.
type NotificationPref string

// List of supported NotificationPref values
const (
    NotificationPrefNone NotificationPref = "None"
    NotificationPrefEmail NotificationPref = "Email"
    NotificationPrefPhone NotificationPref = "Phone"
    NotificationPrefBoth NotificationPref = "Both"
)

// Counts of objects of various types in an account.
type ObjectCounts struct {
    Groups uint64 `json:"groups"`
    Apps uint64 `json:"apps"`
    Users uint64 `json:"users"`
    Plugins uint64 `json:"plugins"`
    // The total number of sobjects in the account, or
    // an approximation thereof.
    //
    // Note that all sobjects in the account are counted,
    // regardless of whether the user has access to them.
    Sobjects uint64 `json:"sobjects"`
    // The accuracy of the `sobjects` count (whether it
    // is an exact count or an approximate count).
    //
    // If the total number of sobjects in the account is
    // less than 5000, DSM will return an exact number.
    // Additionally, if DSM estimates the total number of
    // sobjects to be less than 10000, it will still attempt
    // to return an exact count. Otherwise, DSM will return
    // an approximation.
    //
    // These rules are subject to change in the future.
    SobjectsAccuracy CountAccuracy `json:"sobjects_accuracy"`
    ChildAccounts uint64 `json:"child_accounts"`
}

// A summary of the latest scans for a replication account.
type RecentScanSummary struct {
    // Information about any currently in-progress scan.
    InProgress *ReplicationScan `json:"in_progress,omitempty"`
    // Information about the last finished scan on the account, whether
    // successful or not.
    LastCompleted *ReplicationScan `json:"last_completed,omitempty"`
    // Information about the last finished scan on the account that finished
    // successfully.
    LastSuccessful *ReplicationScan `json:"last_successful,omitempty"`
}

// Details about the admin app credential used to replicate objects from the source account.
type ReplicationCredential struct {
    // A client certificate (or trusted CA) app credential. This is the only available option today.
    Certificate *CertificateReplicationCredential
}
func (x ReplicationCredential) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "ReplicationCredential", 
                  []bool{ x.Certificate != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.Certificate != nil:
        b, err := json.Marshal(x.Certificate)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["$type"] = "Certificate"
    }
    return json.Marshal(m)
}
func (x *ReplicationCredential) UnmarshalJSON(data []byte) error {
    x.Certificate = nil
    var h struct {
        Tag string `json:"$type"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid ReplicationCredential")
    }
    switch h.Tag {
    case "Certificate":
        var certificate CertificateReplicationCredential
        if err := json.Unmarshal(data, &certificate); err != nil {
            return err
        }
        x.Certificate = &certificate
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

// The ID of a replication credential.
type ReplicationCredentialId = string

// A request to generate a new self-signed certificate for a
// replication credential.
//
// For now, the default attributes will include the following:
// - Version 3 certificate
// - Subject:
//   - Common name is "<acct-id> replication credential <credential-id>",
//     where <acct-id> and <credential-id> are replaced with the actual IDs
//   - No other attributes in the subject
// - No expiry (represented by 99991231235959Z as per RFC 5280)
// - There will not be a basic constraints extension
type ReplicationCredentialSelfSignedCertRequest struct {
}

// Response from the endpoint to generate a new self-signed cert for a replication credential.
type ReplicationCredentialSelfSignedCertResponse struct {
    // The self-signed certificate generated by DSM.
    Certificate ZeroizedBlob `json:"certificate"`
}

// Information about a scan performed under a replication account.
type ReplicationScan struct {
    // The time the scan began.
    StartedAt Time `json:"started_at"`
    // The time the scan finished.
    FinishedAt *Time `json:"finished_at,omitempty"`
    // Any error message returned by the scan. If this field is empty, the
    // scan is either ongoing, or returned successfully.
    ErrorMessage *string `json:"error_message,omitempty"`
}

// Reseller subscription type
type ResellerSubscriptionType struct {
    MaxPlugin *uint32 `json:"max_plugin,omitempty"`
    MaxOperation *uint64 `json:"max_operation,omitempty"`
    MaxTenant *uint32 `json:"max_tenant,omitempty"`
    MaxTenantPlugin *uint32 `json:"max_tenant_plugin,omitempty"`
    MaxTenantOperation *uint64 `json:"max_tenant_operation,omitempty"`
    PackageName *string `json:"package_name,omitempty"`
    Features *SubscriptionFeatures `json:"features,omitempty"`
    AddOns *map[string]string `json:"add_ons,omitempty"`
    TenantFeatures *SubscriptionFeatures `json:"tenant_features,omitempty"`
}

// Splunk logging configuration.
type SplunkLoggingConfig struct {
    Enabled bool `json:"enabled"`
    Host string `json:"host"`
    Port uint16 `json:"port"`
    Index string `json:"index"`
    Token *ZeroizedString `json:"token,omitempty"`
    TLS TlsConfig `json:"tls"`
}

type SplunkLoggingConfigRequest struct {
    Enabled *bool `json:"enabled,omitempty"`
    Host *string `json:"host,omitempty"`
    Port *uint16 `json:"port,omitempty"`
    // The Splunk index that will receive log items.
    Index *string `json:"index,omitempty"`
    // The Splunk authentication token.
    Token *ZeroizedString `json:"token,omitempty"`
    TLS *TlsConfig `json:"tls,omitempty"`
}

// Stackdriver logging configuration.
type StackdriverLoggingConfig struct {
    Enabled bool `json:"enabled"`
    // The log ID that will receive the log items (see https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry).
    LogID string `json:"log_id"`
    ServiceAccountKey GoogleServiceAccountKey `json:"service_account_key"`
}

type StackdriverLoggingConfigRequest struct {
    Enabled *bool `json:"enabled,omitempty"`
    // The log ID that will receive the log items (see https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry).
    LogID *string `json:"log_id,omitempty"`
    ServiceAccountKey *GoogleServiceAccountKey `json:"service_account_key,omitempty"`
}

type Subscription struct {
    Memo *string `json:"memo,omitempty"`
    ExperimentalFeatures *SubscriptionExperimentalFeatures `json:"experimental_features,omitempty"`
    SubscriptionType SubscriptionType `json:"subscription_type"`
}
func (x Subscription) MarshalJSON() ([]byte, error) {
    m := make(map[string]interface{})
    { // x.SubscriptionType is flattened
        b, err := json.Marshal(&x.SubscriptionType)
        if err != nil {
            return nil, err
        }
        f := make(map[string]interface{})
        if err := json.Unmarshal(b, &f); err != nil {
            return nil, err
        }
        for k, v := range f {
            m[k] = v
        }
    }
    if x.Memo != nil {
        m["memo"] = x.Memo
    }
    if x.ExperimentalFeatures != nil {
        m["experimental_features"] = x.ExperimentalFeatures
    }
    return json.Marshal(&m)
}
func (x *Subscription) UnmarshalJSON(data []byte) error {
    if err := json.Unmarshal(data, &x.SubscriptionType); err != nil {
        return err
    }
    var r struct {
    Memo *string `json:"memo,omitempty"`
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
    Contact *string `json:"contact,omitempty"`
    Comment *string `json:"comment,omitempty"`
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
    SubscriptionFeaturesGcpekmcontrolplane
)

// MarshalJSON converts SubscriptionFeatures to an array of strings
func (x SubscriptionFeatures) MarshalJSON() ([]byte, error) {
    s := make([]string, 0)
    if x & SubscriptionFeaturesTokenization == SubscriptionFeaturesTokenization {
        s = append(s, "TOKENIZATION")
    }
    if x & SubscriptionFeaturesHmg == SubscriptionFeaturesHmg {
        s = append(s, "HMG")
    }
    if x & SubscriptionFeaturesAwsbyok == SubscriptionFeaturesAwsbyok {
        s = append(s, "AWSBYOK")
    }
    if x & SubscriptionFeaturesAzurebyok == SubscriptionFeaturesAzurebyok {
        s = append(s, "AZUREBYOK")
    }
    if x & SubscriptionFeaturesGcpbyok == SubscriptionFeaturesGcpbyok {
        s = append(s, "GCPBYOK")
    }
    if x & SubscriptionFeaturesGcpekmcontrolplane == SubscriptionFeaturesGcpekmcontrolplane {
        s = append(s, "GCPEKMCONTROLPLANE")
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
        case "GCPEKMCONTROLPLANE":
            *x = *x | SubscriptionFeaturesGcpekmcontrolplane
        }
    }
    return nil
}

// Type of subscription.
type SubscriptionType struct {
    Trial *SubscriptionTypeTrial
    Standard *struct{}
    Enterprise *struct{}
    Custom **CustomSubscriptionType
    Freemium **FreemiumSubscriptionType
    OnPrem *struct{}
    Reseller **ResellerSubscriptionType
}
type SubscriptionTypeTrial struct {
    ExpiresAt *Time `json:"expires_at,omitempty"`
}
func (x SubscriptionType) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "SubscriptionType", 
                  []bool{ x.Trial != nil,
                  x.Standard != nil,
                  x.Enterprise != nil,
                  x.Custom != nil,
                  x.Freemium != nil,
                  x.OnPrem != nil,
                  x.Reseller != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Trial *SubscriptionTypeTrial `json:"trial,omitempty"`
        Standard *struct{} `json:"standard,omitempty"`
        Enterprise *struct{} `json:"enterprise,omitempty"`
        Custom **CustomSubscriptionType `json:"custom,omitempty"`
        Freemium **FreemiumSubscriptionType `json:"freemium,omitempty"`
        OnPrem *struct{} `json:"on_prem,omitempty"`
        Reseller **ResellerSubscriptionType `json:"reseller,omitempty"`
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
        Trial *SubscriptionTypeTrial `json:"trial,omitempty"`
        Standard *struct{} `json:"standard,omitempty"`
        Enterprise *struct{} `json:"enterprise,omitempty"`
        Custom **CustomSubscriptionType `json:"custom,omitempty"`
        Freemium **FreemiumSubscriptionType `json:"freemium,omitempty"`
        OnPrem *struct{} `json:"on_prem,omitempty"`
        Reseller **ResellerSubscriptionType `json:"reseller,omitempty"`
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
    SyslogFacilityUser SyslogFacility = "User"
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
    Enabled bool `json:"enabled"`
    Host string `json:"host"`
    Port uint16 `json:"port"`
    TLS TlsConfig `json:"tls"`
    Facility SyslogFacility `json:"facility"`
}

type SyslogLoggingConfigRequest struct {
    Enabled *bool `json:"enabled,omitempty"`
    Host *string `json:"host,omitempty"`
    Port *uint16 `json:"port,omitempty"`
    TLS *TlsConfig `json:"tls,omitempty"`
    Facility *SyslogFacility `json:"facility,omitempty"`
}

// A request to update a certificate-based replication credential.
type UpdateCertificateReplicationCredentialRequest struct {
    // The app ID to associate with the credential. This should be the ID of
    // a source-side admin app.
    AppID *UUID `json:"app_id,omitempty"`
    // The certificate chain to associate with the credential. This is a
    // list of DER-encoded certificates, starting from the leaf certificate,
    // and may consist of a single certificate if no intermediate
    // certificates are necessary when authenticating with the source
    // cluster.
    CertificateChain *[]ZeroizedBlob `json:"certificate_chain,omitempty"`
}

// A request to update a replication credential (e.g., associating it with
// an app ID).
//
// Note that changing the credential from one type to another is disallowed;
// users should create a new credential instead.
type UpdateReplicationCredentialRequest struct {
    // Request to update a certificate-based credential.
    Certificate *UpdateCertificateReplicationCredentialRequest
}
func (x UpdateReplicationCredentialRequest) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "UpdateReplicationCredentialRequest", 
                  []bool{ x.Certificate != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.Certificate != nil:
        b, err := json.Marshal(x.Certificate)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["$type"] = "Certificate"
    }
    return json.Marshal(m)
}
func (x *UpdateReplicationCredentialRequest) UnmarshalJSON(data []byte) error {
    x.Certificate = nil
    var h struct {
        Tag string `json:"$type"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid UpdateReplicationCredentialRequest")
    }
    switch h.Tag {
    case "Certificate":
        var certificate UpdateCertificateReplicationCredentialRequest
        if err := json.Unmarshal(data, &certificate); err != nil {
            return err
        }
        x.Certificate = &certificate
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

// Authentication method for Google Workspace CSE, `User` (default choice) requires each CSE user
// to be registered as a DSM user, while `App` requires each CSE user to be represented by a DSM app.
//
// Note:
// For large organizations where lots of users use Google Workspace CSE but are not otherwise expected
// to be able to access DSM, App authentication method could be easier to implement.
type WorkspaceCseAuthMethod string

// List of supported WorkspaceCseAuthMethod values
const (
    // Each CSE user must be registered as a DSM user
    WorkspaceCseAuthMethodUser WorkspaceCseAuthMethod = "User"
    // Each CSE user is represented by a DSM app and only needs access to cse specific endpoints.
    WorkspaceCseAuthMethodApp WorkspaceCseAuthMethod = "App"
)

// These settings will allow the service to validate the Google-issued
// authorization tokens used in Workspace CSE APIs.
//
// For example, the specific settings for CSE Docs & Drive are:
// - JWKS URL: https://www.googleapis.com/service_accounts/v1/jwk/gsuitecse-tokenissuer-drive@system.gserviceaccount.com
// - Issuer: gsuitecse-tokenissuer-drive@system.gserviceaccount.com
// - Audience: cse-authorization
//
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
    // An accounts method of authenticating users via the CSE integration.
    AuthMethod *WorkspaceCseAuthMethod `json:"auth_method,omitempty"`
}

// An identity provider trusted to authenticate users for Workspace CSE APIs
type WorkspaceCseIdentityProvider struct {
    // Identity provider's name
    Name string `json:"name"`
    // The public key(s) used to validate the authentication tokens
    SigningKeys SigningKeys `json:"signing_keys"`
    // Acceptable values for the `iss` (issuer) field used in authentication
    // tokens
    ValidIssuers []string `json:"valid_issuers"`
    // Acceptable values for the `aud` (audience) field used in authentication
    // tokens
    ValidAudiences []string `json:"valid_audiences"`
}

// Get account usage information. See input and output of this API
// for info on what it can return.
func (c *Client) AccountUsage(ctx context.Context, acct_id string, queryParameters *CountParams) (*GetUsageResponse, error) {
    u := "/sys/v1/accounts/:acct_id/usage"
    u = strings.NewReplacer(":acct_id", acct_id).Replace(u)
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
        Method:      Some(http.MethodPost),
        Operation:   &u,
        Body:        &body,
        Description: description,
    }
    return c.CreateApprovalRequest(ctx, req)
}

// Create an admin app credential that can be used to perform
// account replication.
//
// Note that this does _not_ immediately create a usable credential;
// further processing is necessary before it can be actually used for
// account replication.
//
// Currently, a single replication account can store up to two
// replication credentials.
func (c *Client) CreateReplicationCredential(ctx context.Context, acct_id string, body CreateReplicationCredentialRequest) (*ReplicationCredential, error) {
    u := "/sys/v1/accounts/:acct_id/replication/credentials"
    u = strings.NewReplacer(":acct_id", acct_id).Replace(u)
    var r ReplicationCredential
    if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Delete an account.
func (c *Client) DeleteAccount(ctx context.Context, acct_id string) error {
    u := "/sys/v1/accounts/:acct_id"
    u = strings.NewReplacer(":acct_id", acct_id).Replace(u)
    if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
        return err
    }
    return nil
}

// Delete the specified replication credential.
func (c *Client) DeleteReplicationCredential(ctx context.Context, acct_id string, credential_id string) error {
    u := "/sys/v1/accounts/:acct_id/replication/credentials/:credential_id"
    u = strings.NewReplacer(":acct_id", acct_id, ":credential_id", credential_id).Replace(u)
    if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
        return err
    }
    return nil
}

// Get info for a specific account.
//
// A user can have access to multiple accounts and this API tries
// to look one up given by the input id.
func (c *Client) GetAccount(ctx context.Context, acct_id string, queryParameters *GetAccountParams) (*Account, error) {
    u := "/sys/v1/accounts/:acct_id"
    u = strings.NewReplacer(":acct_id", acct_id).Replace(u)
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

// Retrieve the specified replication credential.
func (c *Client) GetReplicationCredential(ctx context.Context, acct_id string, credential_id string) (*ReplicationCredential, error) {
    u := "/sys/v1/accounts/:acct_id/replication/credentials/:credential_id"
    u = strings.NewReplacer(":acct_id", acct_id, ":credential_id", credential_id).Replace(u)
    var r ReplicationCredential
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

// Retrieve all stored replication credentials under the account.
func (c *Client) ListReplicationCredentials(ctx context.Context, acct_id string) (*ListReplicationCredentialsResponse, error) {
    u := "/sys/v1/accounts/:acct_id/replication/credentials"
    u = strings.NewReplacer(":acct_id", acct_id).Replace(u)
    var r ListReplicationCredentialsResponse
    if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Fetch a summary of recent scans.
func (c *Client) RecentReplicationScanSummary(ctx context.Context, acct_id string) (*RecentScanSummary, error) {
    u := "/sys/v1/accounts/:acct_id/replication/recent_scan_summary"
    u = strings.NewReplacer(":acct_id", acct_id).Replace(u)
    var r RecentScanSummary
    if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Generate a self-signed cert for the specified credential.
//
// Note that this does _not_ immediately associate the certificate
// with the credential; the credential still needs to be updated
// afterwards.
func (c *Client) ReplicationCredentialSelfSignedCert(ctx context.Context, acct_id string, credential_id string, body ReplicationCredentialSelfSignedCertRequest) (*ReplicationCredentialSelfSignedCertResponse, error) {
    u := "/sys/v1/accounts/:acct_id/replication/credentials/:credential_id/self_sign"
    u = strings.NewReplacer(":acct_id", acct_id, ":credential_id", credential_id).Replace(u)
    var r ReplicationCredentialSelfSignedCertResponse
    if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Update account settings such as authentication, logging, etc.
func (c *Client) UpdateAccount(ctx context.Context, acct_id string, body AccountRequest) (*Account, error) {
    u := "/sys/v1/accounts/:acct_id"
    u = strings.NewReplacer(":acct_id", acct_id).Replace(u)
    var r Account
    if err := c.fetch(ctx, http.MethodPatch, u, &body, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

func (c *Client) RequestApprovalToUpdateAccount(
    ctx context.Context,    
acct_id string,    
body AccountRequest,
    description *string) (*ApprovalRequest, error) {
    u := "/sys/v1/accounts/:acct_id"
    u = strings.NewReplacer(":acct_id", acct_id).Replace(u)
    req := ApprovalRequestRequest{
        Method:      Some(http.MethodPatch),
        Operation:   &u,
        Body:        &body,
        Description: description,
    }
    return c.CreateApprovalRequest(ctx, req)
}

// Update the specified replication credential.
//
// This can be used to associate an app ID with the credential,
// and/or upload cert chains for the credential.
func (c *Client) UpdateReplicationCredential(ctx context.Context, acct_id string, credential_id string, body UpdateReplicationCredentialRequest) (*ReplicationCredential, error) {
    u := "/sys/v1/accounts/:acct_id/replication/credentials/:credential_id"
    u = strings.NewReplacer(":acct_id", acct_id, ":credential_id", credential_id).Replace(u)
    var r ReplicationCredential
    if err := c.fetch(ctx, http.MethodPatch, u, &body, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

