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
    // The type used to create, modify, or view the assigned account roles.
    AccountMembership *AppAccountMembership `json:"account_membership,omitempty"`
    // The id of the Account that this application belongs to.
    AcctID UUID `json:"acct_id"`
    // Unique id to identify the application.
    AppID UUID `json:"app_id"`
    // The user-defined type of this application.
    AppType string `json:"app_type"`
    // The authentication mechanisms for an application.
    AuthType *AppAuthType `json:"auth_type,omitempty"`
    // Certificate expiration date for apps that use client certificate or trusted CA auth.
    // 
    // For a client certificate app, this field is the expiry date of the client certifiate. For a trusted CA app, this field is the maximum expiry date among all configured root CA certs in the app's config.
    // 
    // For all other apps, this field is omitted.
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
    IpAddressPolicy IpAddressPolicy `json:"ip_address_policy"`
    LastOperations LastAppOperationTimestamp `json:"last_operations"`
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
func (x App) MarshalJSON() ([]byte, error) {
    m := make(map[string]interface{})
    { // x.AuthType is flattened
        b, err := json.Marshal(&x.AuthType)
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
    if x.AccountMembership != nil {
        m["account_membership"] = x.AccountMembership
    }
    m["acct_id"] = x.AcctID
    m["app_id"] = x.AppID
    m["app_type"] = x.AppType
    if x.CertNotAfter != nil {
        m["cert_not_after"] = x.CertNotAfter
    }
    m["client_configurations"] = x.ClientConfigurations
    m["created_at"] = x.CreatedAt
    m["creator"] = x.Creator
    if x.DefaultGroup != nil {
        m["default_group"] = x.DefaultGroup
    }
    if x.Description != nil {
        m["description"] = x.Description
    }
    m["enabled"] = x.Enabled
    m["groups"] = x.Groups
    if x.Interface != nil {
        m["interface"] = x.Interface
    }
    m["ip_address_policy"] = x.IpAddressPolicy
    m["last_operations"] = x.LastOperations
    if x.LastusedAt != nil {
        m["lastused_at"] = x.LastusedAt
    }
    m["legacy_access"] = x.LegacyAccess
    m["name"] = x.Name
    if x.OauthConfig != nil {
        m["oauth_config"] = x.OauthConfig
    }
    m["role"] = x.Role
    return json.Marshal(&m)
}
func (x *App) UnmarshalJSON(data []byte) error {
    if err := json.Unmarshal(data, &x.AuthType); err != nil {
        return err
    }
    var r struct {
    AccountMembership *AppAccountMembership `json:"account_membership,omitempty"`
    AcctID UUID `json:"acct_id"`
    AppID UUID `json:"app_id"`
    AppType string `json:"app_type"`
    CertNotAfter *Time `json:"cert_not_after,omitempty"`
    ClientConfigurations ClientConfigurations `json:"client_configurations"`
    CreatedAt Time `json:"created_at"`
    Creator Principal `json:"creator"`
    DefaultGroup *UUID `json:"default_group,omitempty"`
    Description *string `json:"description,omitempty"`
    Enabled bool `json:"enabled"`
    Groups AppGroups `json:"groups"`
    Interface *string `json:"interface,omitempty"`
    IpAddressPolicy IpAddressPolicy `json:"ip_address_policy"`
    LastOperations LastAppOperationTimestamp `json:"last_operations"`
    LastusedAt *Time `json:"lastused_at,omitempty"`
    LegacyAccess bool `json:"legacy_access"`
    Name string `json:"name"`
    OauthConfig *AppOauthConfig `json:"oauth_config,omitempty"`
    Role AppRole `json:"role"`
    }
    if err := json.Unmarshal(data, &r); err != nil {
        return err
    }
    x.AccountMembership = r.AccountMembership
    x.AcctID = r.AcctID
    x.AppID = r.AppID
    x.AppType = r.AppType
    x.CertNotAfter = r.CertNotAfter
    x.ClientConfigurations = r.ClientConfigurations
    x.CreatedAt = r.CreatedAt
    x.Creator = r.Creator
    x.DefaultGroup = r.DefaultGroup
    x.Description = r.Description
    x.Enabled = r.Enabled
    x.Groups = r.Groups
    x.Interface = r.Interface
    x.IpAddressPolicy = r.IpAddressPolicy
    x.LastOperations = r.LastOperations
    x.LastusedAt = r.LastusedAt
    x.LegacyAccess = r.LegacyAccess
    x.Name = r.Name
    x.OauthConfig = r.OauthConfig
    x.Role = r.Role
    return nil
}

type AppAccountMembership struct {
    Roles []AppAccountRoleDescriptor `json:"roles"`
}

type AppAccountRole string

// List of supported AppAccountRole values
const (
    AppAccountRoleAccountAdministrator AppAccountRole = "AccountAdministrator"
    AppAccountRoleAccountMember AppAccountRole = "AccountMember"
    AppAccountRoleAccountAuditor AppAccountRole = "AccountAuditor"
)

type AppAccountRoleDescriptor struct {
    SystemDefined *AppAccountRole
    Custom *UUID
}
func (x AppAccountRoleDescriptor) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "AppAccountRoleDescriptor", 
                  []bool{ x.SystemDefined != nil,
                  x.Custom != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Tag string `json:"$type"`
        Value any `json:"value,omitempty"`
    }
    if x.SystemDefined != nil {
        obj.Tag = "SystemDefined"
        obj.Value = x.SystemDefined
    } else if x.Custom != nil {
        obj.Tag = "Custom"
        obj.Value = x.Custom
    }
    return json.Marshal(obj)
}

func (x *AppAccountRoleDescriptor) UnmarshalJSON(data []byte) error {
    x.SystemDefined = nil
    x.Custom = nil

    var metadata struct {
        Tag string `json:"$type"`
        Value json.RawMessage `json:"value"`
    }

    if err := json.Unmarshal(data, &metadata); err != nil {
        return errors.Errorf("not a valid AppAccountRoleDescriptor")
    }

    switch metadata.Tag {
    case "SystemDefined":
        var systemDefined AppAccountRole
        if err := json.Unmarshal(metadata.Value, &systemDefined); err != nil {
            return err
        }
        x.SystemDefined = &systemDefined
    case "Custom":
        var custom UUID
        if err := json.Unmarshal(metadata.Value, &custom); err != nil {
            return err
        }
        x.Custom = &custom
    default:
         return errors.Errorf("invalid tag value: %v", metadata.Tag)
    }
    return nil
}

type AppAuthType struct {
    // The type of the credential configured on the app
    AuthType AppAuthTypeVariants `json:"auth_type"`
    // If `auth_type` is `all`, this field will include the list of individual auth
    // types for the app
    AuthTypeAll *[]OneAppAuthType `json:"auth_type_all,omitempty"`
}

type AppAuthTypeVariants struct {
    // App credential is `all`, with a combination of auth methods specified
    All *struct{}
    One *OneAppAuthType
}
func (x AppAuthTypeVariants) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "AppAuthTypeVariants", 
                  []bool{ x.All != nil,
                  x.One != nil });
                  err != nil {
        return nil, err
    }
    switch {
    case x.All != nil:
        return []byte(`"All"`), nil
    }
    var obj struct {
        One *OneAppAuthType `json:"One,omitempty"`
    }
    obj.One = x.One
    return json.Marshal(obj)
}
func (x *AppAuthTypeVariants) UnmarshalJSON(data []byte) error {
    x.All = nil
    x.One = nil
    var str string
    if err := json.Unmarshal(data, &str); err == nil {
        switch str {
        case "All":
            x.All = &struct{}{}
        default:
            return errors.Errorf("invalid value for AppAuthTypeVariants: %v", str)
        }
        return nil
    }
    var obj struct {
        One *OneAppAuthType `json:"One,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.One = obj.One
    return nil
}

type AppCredential struct {
    All *[]OneAppCredential
    One *OneAppCredential
}
func (x AppCredential) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "AppCredential", 
                  []bool{ x.All != nil,
                  x.One != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        All *[]OneAppCredential `json:"all,omitempty"`
        One *OneAppCredential `json:"one,omitempty"`
    }
    obj.All = x.All
    obj.One = x.One
    return json.Marshal(obj)
}
func (x *AppCredential) UnmarshalJSON(data []byte) error {
    x.All = nil
    x.One = nil
    var obj struct {
        All *[]OneAppCredential `json:"all,omitempty"`
        One *OneAppCredential `json:"one,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.All = obj.All
    x.One = obj.One
    return nil
}

type AppCredentialRequest struct {
    // Using `all`, clients can specify a combination of two credentials:
    // - one must be a mutual TLS credential (either `certificate` or `trustedca`),
    // - the other must be a general app credential (one of `secret`, `awsiam`, `signedjwt`, or `ldap`)
    //
    // Apps authenticating with this variant must present both forms of credentials,
    // i.e., they must present a client certificate during TLS handshake, and also
    // present the other form of credential in the HTTP request.
    All *[]OneAppCredentialRequest
    One *OneAppCredentialRequest
}
func (x AppCredentialRequest) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "AppCredentialRequest", 
                  []bool{ x.All != nil,
                  x.One != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        All *[]OneAppCredentialRequest `json:"all,omitempty"`
        One *OneAppCredentialRequest `json:"one,omitempty"`
    }
    obj.All = x.All
    obj.One = x.One
    return json.Marshal(obj)
}
func (x *AppCredentialRequest) UnmarshalJSON(data []byte) error {
    x.All = nil
    x.One = nil
    var obj struct {
        All *[]OneAppCredentialRequest `json:"all,omitempty"`
        One *OneAppCredentialRequest `json:"one,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.All = obj.All
    x.One = obj.One
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

type AppGroupMembership struct {
    GroupID UUID `json:"group_id"`
    Roles []AppGroupRoleDescriptor `json:"roles"`
}

type AppGroupRole string

// List of supported AppGroupRole values
const (
    AppGroupRoleGroupAuditor AppGroupRole = "GroupAuditor"
    AppGroupRoleGroupAdministrator AppGroupRole = "GroupAdministrator"
)

type AppGroupRoleDescriptor struct {
    SystemDefined *AppGroupRole
    Custom *UUID
}
func (x AppGroupRoleDescriptor) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "AppGroupRoleDescriptor", 
                  []bool{ x.SystemDefined != nil,
                  x.Custom != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Tag string `json:"$type"`
        Value any `json:"value,omitempty"`
    }
    if x.SystemDefined != nil {
        obj.Tag = "SystemDefined"
        obj.Value = x.SystemDefined
    } else if x.Custom != nil {
        obj.Tag = "Custom"
        obj.Value = x.Custom
    }
    return json.Marshal(obj)
}

func (x *AppGroupRoleDescriptor) UnmarshalJSON(data []byte) error {
    x.SystemDefined = nil
    x.Custom = nil

    var metadata struct {
        Tag string `json:"$type"`
        Value json.RawMessage `json:"value"`
    }

    if err := json.Unmarshal(data, &metadata); err != nil {
        return errors.Errorf("not a valid AppGroupRoleDescriptor")
    }

    switch metadata.Tag {
    case "SystemDefined":
        var systemDefined AppGroupRole
        if err := json.Unmarshal(metadata.Value, &systemDefined); err != nil {
            return err
        }
        x.SystemDefined = &systemDefined
    case "Custom":
        var custom UUID
        if err := json.Unmarshal(metadata.Value, &custom); err != nil {
            return err
        }
        x.Custom = &custom
    default:
         return errors.Errorf("invalid tag value: %v", metadata.Tag)
    }
    return nil
}

// OAuth settings for an app. If enabled, an app can request to act on behalf of a user.
type AppOauthConfig struct {
    Enabled *AppOauthConfigEnabled
    Disabled *struct{}
}
type AppOauthConfigEnabled struct {
    RedirectUris []string `json:"redirect_uris"`
}
func (x AppOauthConfig) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "AppOauthConfig", 
                  []bool{ x.Enabled != nil,
                  x.Disabled != nil });
                  err != nil {
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
    // The type used to create, modify, or view the assigned account roles.
    AccountMembership *AppAccountMembership `json:"account_membership,omitempty"`
    // Groups an application wants to be part of. Should belong to atleast one.
    AddGroups *AppGroups `json:"add_groups,omitempty"`
    // The user-defined type of this application.
    AppType *string `json:"app_type,omitempty"`
    // Client configurations that are set on the application level.
    // App level client configs override those set at group or account level.
    ClientConfigurations *ClientConfigurationsRequest `json:"client_configurations,omitempty"`
    // Credential for an application which determine the App authentication mechanisms.
    Credential *AppCredentialRequest `json:"credential,omitempty"`
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
    // Can perform similar actions to an account admin user, but not crypto ops.
    AppRoleAdmin AppRole = "admin"
    // Can perform crypto ops
    AppRoleCrypto AppRole = "crypto"
)

// Sort apps as per given ordering.
type AppSort struct {
    // Sort apps on the basis of their app_id.
    ByAppID *AppSortByAppId
    // Sort apps on the basis of their app_name.
    ByAppName *AppSortByAppName
}
// Sort apps on the basis of their app_id.
type AppSortByAppId struct {
    // Ascending or Descending order.
    Order Order `json:"order"`
    // Starting from a particular app_id.
    Start *UUID `json:"start,omitempty"`
}
// Sort apps on the basis of their app_name.
type AppSortByAppName struct {
    // Ascending or Descending order.
    Order Order `json:"order"`
    // Starting from a particular app_name.
    Start *string `json:"start,omitempty"`
}
func (x AppSort) urlEncode(v map[string][]string) error {
    if x.ByAppID != nil && x.ByAppName != nil {
        return errors.New("AppSort can be either ByAppId or ByAppName")
    }
    if x.ByAppID != nil {
        v["sort"] = []string{"app_id" + string(x.ByAppID.Order)}
        if x.ByAppID.Start != nil {
            v["start"] = []string{fmt.Sprintf("%v", *x.ByAppID.Start)}
        }
    }
    if x.ByAppName != nil {
        v["sort"] = []string{"app_name" + string(x.ByAppName.Order)}
        if x.ByAppName.Start != nil {
            v["start"] = []string{fmt.Sprintf("%v", *x.ByAppName.Start)}
        }
    }
    return nil
}

type AwsXksCredential struct {
    AccessKeyID string `json:"access_key_id"`
    SecretKey ZeroizedString `json:"secret_key"`
}

type AwsXksCredentialRequest struct {
    AccessKeyID *string `json:"access_key_id,omitempty"`
    SecretKey *ZeroizedString `json:"secret_key,omitempty"`
}

// Request for assigning a group membership to an (AppRole::Admin) app.
type CreateGroupMembership struct {
    // The id of the target group
    GroupID UUID `json:"group_id"`
    // The roles being assigned for the group.
    Membership AppGroupMembership `json:"membership"`
}

type GcpAppPermissions uint64

// List of supported GcpAppPermissions values
const (
    GcpAppPermissionsCryptoSpaceGetInfo GcpAppPermissions = 1 << iota
    GcpAppPermissionsCryptoSpaceGetPublicKey
)

// MarshalJSON converts GcpAppPermissions to an array of strings
func (x GcpAppPermissions) MarshalJSON() ([]byte, error) {
    s := make([]string, 0)
    if x & GcpAppPermissionsCryptoSpaceGetInfo == GcpAppPermissionsCryptoSpaceGetInfo {
        s = append(s, "CRYPTO_SPACE_GET_INFO")
    }
    if x & GcpAppPermissionsCryptoSpaceGetPublicKey == GcpAppPermissionsCryptoSpaceGetPublicKey {
        s = append(s, "CRYPTO_SPACE_GET_PUBLIC_KEY")
    }
    return json.Marshal(s)
}

// UnmarshalJSON converts array of strings to GcpAppPermissions
func (x *GcpAppPermissions) UnmarshalJSON(data []byte) error {
    *x = 0
    var s []string
    if err := json.Unmarshal(data, &s); err != nil {
        return err
    }
    for _, v := range s {
        switch v {
        case "CRYPTO_SPACE_GET_INFO":
            *x = *x | GcpAppPermissionsCryptoSpaceGetInfo
        case "CRYPTO_SPACE_GET_PUBLIC_KEY":
            *x = *x | GcpAppPermissionsCryptoSpaceGetPublicKey
        }
    }
    return nil
}

// The response for the GetAllGroupMembership endpoint
type GetAppGroupMemberships struct {
    // Additional information about the group(s)
    Metadata GroupMetaData `json:"metadata"`
    // The collection of group memberships the entity is a member in
    Items []AppGroupMembership `json:"items"`
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

type GoogleServiceAccountCredential struct {
    // Policy specifying acceptable access reasons.
    AccessReasonPolicy *GoogleAccessReasonPolicy `json:"access_reason_policy,omitempty"`
    // Mapping for all groups an application is part of and the Gcp specific permissions it has within each of those groups.
    Groups *map[UUID]GcpAppPermissions `json:"groups,omitempty"`
}

// Type for updating a group membership
type GroupMembershipRequest struct {
    // The set of roles to add
    AddGroupRoles *[]AppGroupRoleDescriptor `json:"add_group_roles,omitempty"`
    // The set of roles to remove
    DelGroupRoles *[]AppGroupRoleDescriptor `json:"del_group_roles,omitempty"`
}

// Additional information or context regarding the groups the entity
// holds membership in
type GroupMetaData struct {
    // Whether the entity has been assigned an exclusive "all groups role"
    AllGroups bool `json:"all_groups"`
}

// The IPs that are allowed for an application. ipv4 or ipv6 both are acceptable types.
type IpAddressPolicy struct {
    AllowAll *struct{}
    Whitelist *[]string
}
func (x IpAddressPolicy) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "IpAddressPolicy", 
                  []bool{ x.AllowAll != nil,
                  x.Whitelist != nil });
                  err != nil {
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
    Generic *uint64 `json:"generic,omitempty"`
    Tokenization *uint64 `json:"tokenization,omitempty"`
    Tep *uint64 `json:"tep,omitempty"`
    Accelerator *uint64 `json:"accelerator,omitempty"`
    SecretsManagement *uint64 `json:"secrets_management,omitempty"`
}

// Query params for Get all apps API
type ListAppsParams struct {
    // Group for which the associated apps should be retrieved.
    GroupID *UUID `json:"group_id,omitempty"`
    // Maximum number of apps to return. Default limit is 1001.
    Limit *uint `json:"limit,omitempty"`
    // Number of apps to skip from the beginning/start.
    Offset *uint `json:"offset,omitempty"`
    // Sort apps by app_id in ascending or descending order.
    Sort AppSort `json:"sort"`
    // Flag specifying if group permissions should be returned with the apps.
    GroupPermissions *bool `json:"group_permissions,omitempty"`
    // Specify role of the apps. If `role=admin` is specified, only admin apps are returned,
    // otherwise, only crypto apps are returned.
    Role *AppRole `json:"role,omitempty"`
    // User specified filter.
    //
    // The following fields can be referenced in the filter:
    // - `name`
    // - `app_type`
    // - `created_at`
    // - `auth_type`
    // - `description`
    // - `enabled`
    // - `interface`
    Filter *string `json:"filter,omitempty"`
    // Continuation token to continue getting results. It must be the same
    // token returned from the backend from a previous call, or empty.
    //
    // Existence of this query parameter controls the response
    // (and the backend behavior):
    // - If specified (including an empty value), the backend returns metadata alongside
    //   the collection of apps. The metadata will potentially contain a fresh `continuation_token`.
    //
    //   Note: If there is a `limit` specified in the request and DSM returns `limit`-many items in the
    //   response, it will still include a fresh continuation token if there are more items in the collection.
    //   Additionally, unlike other query parameters, `limit` is not required to remain unchanged in a chain of
    //   requests with `continuation_token`s.
    // - If omitted, the backend returns just a collection of apps with no metadata.
    ContinuationToken *string `json:"continuation_token,omitempty"`
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
    if x.Filter != nil {
        v["filter"] = []string{fmt.Sprintf("%v", *x.Filter)}
    }
    if x.ContinuationToken != nil {
        v["continuation_token"] = []string{fmt.Sprintf("%v", *x.ContinuationToken)}
    }
    return nil
}

// The response of the get all apps API
type ListAppsResponse struct {
    // A response that includes metadata
    WithMetadata *ListAppsResponseWithMetadata
    // A response that omits metadata
    WithoutMetadata *[]App
}
// A response that includes metadata
type ListAppsResponseWithMetadata struct {
    // The list of apps satisfying the request
    Items []App `json:"items"`
    // The metadata associated with the response
    Metadata CollectionMetadata `json:"metadata"`
}
func (x ListAppsResponse) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "ListAppsResponse", 
                  []bool{ x.WithMetadata != nil,
                  x.WithoutMetadata != nil });
                  err != nil {
        return nil, err
    }
    if x.WithMetadata != nil {
        return json.Marshal(x.WithMetadata)
    }
    if x.WithoutMetadata != nil {
        return json.Marshal(x.WithoutMetadata)
    }
    panic("unreachable")
}
func (x *ListAppsResponse) UnmarshalJSON(data []byte) error {
    x.WithMetadata = nil
    x.WithoutMetadata = nil
    var withMetadata ListAppsResponseWithMetadata
    if err := json.Unmarshal(data, &withMetadata); err == nil {
        x.WithMetadata = &withMetadata
        return nil
    }
    var withoutMetadata []App
    if err := json.Unmarshal(data, &withoutMetadata); err == nil {
        x.WithoutMetadata = &withoutMetadata
        return nil
    }
    return errors.Errorf("not a valid ListAppsResponse")
}

// Authentication method of an app.
type OneAppAuthType string

// List of supported OneAppAuthType values
const (
    OneAppAuthTypeSecret OneAppAuthType = "Secret"
    OneAppAuthTypeGoogleServiceAccount OneAppAuthType = "GoogleServiceAccount"
    OneAppAuthTypeSignedJwt OneAppAuthType = "SignedJwt"
    OneAppAuthTypeLdap OneAppAuthType = "Ldap"
    OneAppAuthTypeAwsIam OneAppAuthType = "AwsIam"
    OneAppAuthTypeAwsXks OneAppAuthType = "AwsXks"
    OneAppAuthTypeGoogleWorkspaceCSE OneAppAuthType = "GoogleWorkspaceCSE"
    OneAppAuthTypeCertificate OneAppAuthType = "Certificate"
    OneAppAuthTypeTrustedCa OneAppAuthType = "TrustedCa"
)

// App authentication mechanisms.
type OneAppCredential struct {
    // Authenticating credentials of an App.
    Secret *ZeroizedString
    // PKI Certificate based authentication.
    Certificate *ZeroizedBlob
    // PKI certificate with Trusted CA based authentication.
    TrustedCa *TrustedCaCredential
    // An App's service account for communicating with Google APIs and Cloud. Google OAuth 2.0
    GoogleServiceAccount *GoogleServiceAccountCredential
    // Authentication using a signed JWT directly as a bearer token.
    SignedJwt *SignedJwtCredential
    // LDAP credentials of an App used for authentication.
    Ldap *UUID
    // Sign-in credentials to authenticate with AWS for its services and resources.
    AwsIam *struct{}
    // SigV4 credentials used for AWS XKS APIs
    AwsXks *AwsXksCredential
    GoogleWorkspaceCse *struct{}
}
func (x OneAppCredential) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "OneAppCredential", 
                  []bool{ x.Secret != nil,
                  x.Certificate != nil,
                  x.TrustedCa != nil,
                  x.GoogleServiceAccount != nil,
                  x.SignedJwt != nil,
                  x.Ldap != nil,
                  x.AwsIam != nil,
                  x.AwsXks != nil,
                  x.GoogleWorkspaceCse != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Secret *ZeroizedString `json:"secret,omitempty"`
        Certificate *ZeroizedBlob `json:"certificate,omitempty"`
        TrustedCa *TrustedCaCredential `json:"trustedca,omitempty"`
        GoogleServiceAccount *GoogleServiceAccountCredential `json:"googleserviceaccount,omitempty"`
        SignedJwt *SignedJwtCredential `json:"signedjwt,omitempty"`
        Ldap *UUID `json:"ldap,omitempty"`
        AwsIam *struct{} `json:"awsiam,omitempty"`
        AwsXks *AwsXksCredential `json:"awsxks,omitempty"`
        GoogleWorkspaceCse *struct{} `json:"googleworkspacecse,omitempty"`
    }
    obj.Secret = x.Secret
    obj.Certificate = x.Certificate
    obj.TrustedCa = x.TrustedCa
    obj.GoogleServiceAccount = x.GoogleServiceAccount
    obj.SignedJwt = x.SignedJwt
    obj.Ldap = x.Ldap
    obj.AwsIam = x.AwsIam
    obj.AwsXks = x.AwsXks
    obj.GoogleWorkspaceCse = x.GoogleWorkspaceCse
    return json.Marshal(obj)
}
func (x *OneAppCredential) UnmarshalJSON(data []byte) error {
    x.Secret = nil
    x.Certificate = nil
    x.TrustedCa = nil
    x.GoogleServiceAccount = nil
    x.SignedJwt = nil
    x.Ldap = nil
    x.AwsIam = nil
    x.AwsXks = nil
    x.GoogleWorkspaceCse = nil
    var obj struct {
        Secret *ZeroizedString `json:"secret,omitempty"`
        Certificate *ZeroizedBlob `json:"certificate,omitempty"`
        TrustedCa *TrustedCaCredential `json:"trustedca,omitempty"`
        GoogleServiceAccount *GoogleServiceAccountCredential `json:"googleserviceaccount,omitempty"`
        SignedJwt *SignedJwtCredential `json:"signedjwt,omitempty"`
        Ldap *UUID `json:"ldap,omitempty"`
        AwsIam *struct{} `json:"awsiam,omitempty"`
        AwsXks *AwsXksCredential `json:"awsxks,omitempty"`
        GoogleWorkspaceCse *struct{} `json:"googleworkspacecse,omitempty"`
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
    x.GoogleWorkspaceCse = obj.GoogleWorkspaceCse
    return nil
}

type OneAppCredentialRequest struct {
    // Secret/API-key based authentication
    Secret *SecretCredentialRequest
    // PKI Certificate based authentication.
    Certificate *ZeroizedBlob
    // PKI certificate with Trusted CA based authentication.
    TrustedCa *TrustedCaCredential
    // An App's service account for communicating with Google APIs and Cloud. Google OAuth 2.0
    GoogleServiceAccount *GoogleServiceAccountCredential
    // Authentication using a signed JWT directly as a bearer token.
    SignedJwt *SignedJwtCredential
    // LDAP credentials of an App used for authentication.
    Ldap *UUID
    // Sign-in credentials to authenticate with AWS for its services and resources.
    AwsIam *struct{}
    // SigV4 credentials used for AWS XKS APIs
    AwsXks *AwsXksCredentialRequest
    GoogleWorkspaceCse *struct{}
}
func (x OneAppCredentialRequest) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "OneAppCredentialRequest", 
                  []bool{ x.Secret != nil,
                  x.Certificate != nil,
                  x.TrustedCa != nil,
                  x.GoogleServiceAccount != nil,
                  x.SignedJwt != nil,
                  x.Ldap != nil,
                  x.AwsIam != nil,
                  x.AwsXks != nil,
                  x.GoogleWorkspaceCse != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Secret *SecretCredentialRequest `json:"secret,omitempty"`
        Certificate *ZeroizedBlob `json:"certificate,omitempty"`
        TrustedCa *TrustedCaCredential `json:"trustedca,omitempty"`
        GoogleServiceAccount *GoogleServiceAccountCredential `json:"googleserviceaccount,omitempty"`
        SignedJwt *SignedJwtCredential `json:"signedjwt,omitempty"`
        Ldap *UUID `json:"ldap,omitempty"`
        AwsIam *struct{} `json:"awsiam,omitempty"`
        AwsXks *AwsXksCredentialRequest `json:"awsxks,omitempty"`
        GoogleWorkspaceCse *struct{} `json:"googleworkspacecse,omitempty"`
    }
    obj.Secret = x.Secret
    obj.Certificate = x.Certificate
    obj.TrustedCa = x.TrustedCa
    obj.GoogleServiceAccount = x.GoogleServiceAccount
    obj.SignedJwt = x.SignedJwt
    obj.Ldap = x.Ldap
    obj.AwsIam = x.AwsIam
    obj.AwsXks = x.AwsXks
    obj.GoogleWorkspaceCse = x.GoogleWorkspaceCse
    return json.Marshal(obj)
}
func (x *OneAppCredentialRequest) UnmarshalJSON(data []byte) error {
    x.Secret = nil
    x.Certificate = nil
    x.TrustedCa = nil
    x.GoogleServiceAccount = nil
    x.SignedJwt = nil
    x.Ldap = nil
    x.AwsIam = nil
    x.AwsXks = nil
    x.GoogleWorkspaceCse = nil
    var obj struct {
        Secret *SecretCredentialRequest `json:"secret,omitempty"`
        Certificate *ZeroizedBlob `json:"certificate,omitempty"`
        TrustedCa *TrustedCaCredential `json:"trustedca,omitempty"`
        GoogleServiceAccount *GoogleServiceAccountCredential `json:"googleserviceaccount,omitempty"`
        SignedJwt *SignedJwtCredential `json:"signedjwt,omitempty"`
        Ldap *UUID `json:"ldap,omitempty"`
        AwsIam *struct{} `json:"awsiam,omitempty"`
        AwsXks *AwsXksCredentialRequest `json:"awsxks,omitempty"`
        GoogleWorkspaceCse *struct{} `json:"googleworkspacecse,omitempty"`
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
    x.GoogleWorkspaceCse = obj.GoogleWorkspaceCse
    return nil
}

type PolicyDefinition struct {
    // A policy definition defined using the Rego policy language as outlined in
    // the [Open Policy Agent](https://www.openpolicyagent.org/docs/policy-language) docs.
    //
    // The DSM backend will pass an input to the Rego engine and the format is defined as such:
    // - A JSON object that nests the JWT body one level, where the root key is `jwt_body`.
    // - From the policy, this object is accessible via the `input` (OPA defined) variable.
    //
    // An example of the input object:
    // ```json
    // {
    //     "jwt_body": { < jwt body contents > }
    // }
    // ```
    //
    // An example policy indexing into the input:
    //
    // ```rego
    // package my_example
    //
    // default allow := false
    //
    // allow if {
    //     input.jwt_body.my_private_claims.employee == "Alice"
    // }
    // ```
    //
    // The expected policy format is defined as such:
    // - A **required** variable defined as `allow` of type boolean. This should be updated true or false based on any other processing done.
    // - An **optional** field defined as `additional_logging` if the client wishes to include other information not captured in existing audit logs for JWT auth apps.
    //     - Note: `additional_logging` is *limited to a max length of 128 UTF-8 bytes* and corresponds to the `client_provided_context` field on the `AuditLog` model.
    Rego *PolicyDefinitionRego
}
// A policy definition defined using the Rego policy language as outlined in
// the [Open Policy Agent](https://www.openpolicyagent.org/docs/policy-language) docs.
//
// The DSM backend will pass an input to the Rego engine and the format is defined as such:
// - A JSON object that nests the JWT body one level, where the root key is `jwt_body`.
// - From the policy, this object is accessible via the `input` (OPA defined) variable.
//
// An example of the input object:
// ```json
// {
//     "jwt_body": { < jwt body contents > }
// }
// ```
//
// An example policy indexing into the input:
//
// ```rego
// package my_example
//
// default allow := false
//
// allow if {
//     input.jwt_body.my_private_claims.employee == "Alice"
// }
// ```
//
// The expected policy format is defined as such:
// - A **required** variable defined as `allow` of type boolean. This should be updated true or false based on any other processing done.
// - An **optional** field defined as `additional_logging` if the client wishes to include other information not captured in existing audit logs for JWT auth apps.
//     - Note: `additional_logging` is *limited to a max length of 128 UTF-8 bytes* and corresponds to the `client_provided_context` field on the `AuditLog` model.
type PolicyDefinitionRego struct {
    Value string `json:"value"`
}
func (x PolicyDefinition) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "PolicyDefinition", 
                  []bool{ x.Rego != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.Rego != nil:
        b, err := json.Marshal(x.Rego)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["$type"] = "rego"
    }
    return json.Marshal(m)
}
func (x *PolicyDefinition) UnmarshalJSON(data []byte) error {
    x.Rego = nil
    var h struct {
        Tag string `json:"$type"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid PolicyDefinition")
    }
    switch h.Tag {
    case "rego":
        var rego PolicyDefinitionRego
        if err := json.Unmarshal(data, &rego); err != nil {
            return err
        }
        x.Rego = &rego
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
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

type PrivateClaimsPolicy struct {
    // Specifies the policy language and "source".
    Definition PolicyDefinition `json:"definition"`
}

type SecretCredentialRequest struct {
    // Use the existing secret (note that this must match the existing secret configured on the app)
    Value *ZeroizedString
    // Generate a new secret
    Generate *SecretCredentialRequestGenerate
}
// Generate a new secret
type SecretCredentialRequestGenerate struct {
    // Size of the secret to be generated in bytes
    Size *uint32 `json:"size,omitempty"`
}
func (x SecretCredentialRequest) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "SecretCredentialRequest", 
                  []bool{ x.Value != nil,
                  x.Generate != nil });
                  err != nil {
        return nil, err
    }
    if x.Value != nil {
        return json.Marshal(x.Value)
    }
    if x.Generate != nil {
        return json.Marshal(x.Generate)
    }
    panic("unreachable")
}
func (x *SecretCredentialRequest) UnmarshalJSON(data []byte) error {
    x.Value = nil
    x.Generate = nil
    var value ZeroizedString
    if err := json.Unmarshal(data, &value); err == nil {
        x.Value = &value
        return nil
    }
    var generate SecretCredentialRequestGenerate
    if err := json.Unmarshal(data, &generate); err == nil {
        x.Generate = &generate
        return nil
    }
    return errors.Errorf("not a valid SecretCredentialRequest")
}

type SignedJwtCredential struct {
    ValidIssuers []string `json:"valid_issuers"`
    SigningKeys SigningKeys `json:"signing_keys"`
    // If configured, specifies the policy for what *additional* validations
    // the backend should perform against (primarily) the "private claims" in a JWT.
    PrivateClaimsPolicy *PrivateClaimsPolicy `json:"private_claims_policy,omitempty"`
}

// A GeneralName that can be used as a [subject alternative name][SAN] in
// a certificate.
//
// Today, the directoryName, dNSName, and iPAddress choices are supported.
// Note that directoryName can also be used to represent the subject field
// in a certificate.
//
// [SAN]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
type SubjectGeneral struct {
    // A directoryName, which consists of a sequence of (type, value)
    // pairs, where type is an OID, and value is a DER-encoded ASN.1
    // value. (This represents a sequence of relative distinguished
    // names.)
    DirectoryName *[][2]string
    // A DNS name.
    DnsName *string
    // An IP address.
    IpAddress *IpAddr
}
func (x SubjectGeneral) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "SubjectGeneral", 
                  []bool{ x.DirectoryName != nil,
                  x.DnsName != nil,
                  x.IpAddress != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        DirectoryName *[][2]string `json:"directory_name,omitempty"`
        DnsName *string `json:"dns_name,omitempty"`
        IpAddress *IpAddr `json:"ip_address,omitempty"`
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
        DnsName *string `json:"dns_name,omitempty"`
        IpAddress *IpAddr `json:"ip_address,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.DirectoryName = obj.DirectoryName
    x.DnsName = obj.DnsName
    x.IpAddress = obj.IpAddress
    return nil
}

// Trust anchors (i.e., root CA certificates) for a [`TrustedCaCredential`].
type TrustAnchor struct {
    // A single root CA certificate.
    CaCertificate *ZeroizedBlob
    // Multiple root CA certificates. DSM currently supports up to 16 certs.
    CaCertificates *[]ZeroizedBlob
}
func (x TrustAnchor) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "TrustAnchor", 
                  []bool{ x.CaCertificate != nil,
                  x.CaCertificates != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        CaCertificate *ZeroizedBlob `json:"ca_certificate,omitempty"`
        CaCertificates *[]ZeroizedBlob `json:"ca_certificates,omitempty"`
    }
    obj.CaCertificate = x.CaCertificate
    obj.CaCertificates = x.CaCertificates
    return json.Marshal(obj)
}
func (x *TrustAnchor) UnmarshalJSON(data []byte) error {
    x.CaCertificate = nil
    x.CaCertificates = nil
    var obj struct {
        CaCertificate *ZeroizedBlob `json:"ca_certificate,omitempty"`
        CaCertificates *[]ZeroizedBlob `json:"ca_certificates,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.CaCertificate = obj.CaCertificate
    x.CaCertificates = obj.CaCertificates
    return nil
}

// Subjects or subject alternative names (SANs) for trusted CA auth.
// DSM will check the subject field and any SANs inside incoming
// client certificates and compare them against the subjects configured
// in the trusted CA auth config.
type TrustAnchorSubject struct {
    // A single subject as a list of OID/value string pairs
    // (representing a sequence of relative distinguished names), which
    // should appear in the client cert's subject field and/or as one
    // of its SANs.
    //
    // This legacy variant is retained for backcompat purposes, and is
    // equivalent to specifying a directoryName via the SubjectGeneral
    // variant.
    Subject *[][2]string
    // A GeneralName, which should appear in the client cert's subject
    // field and/or as one of its SANs.
    SubjectGeneral *SubjectGeneral
    // List of allowed GeneralName subjects. At least one of the values
    // in this list must appear in the client cert, under its subject
    // field and/or as one of its SANs.
    //
    // Currently, DSM supports at most 16 subjects.
    Subjects *[]SubjectGeneral
}
func (x TrustAnchorSubject) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "TrustAnchorSubject", 
                  []bool{ x.Subject != nil,
                  x.SubjectGeneral != nil,
                  x.Subjects != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Subject *[][2]string `json:"subject,omitempty"`
        SubjectGeneral *SubjectGeneral `json:"subject_general,omitempty"`
        Subjects *[]SubjectGeneral `json:"subjects,omitempty"`
    }
    obj.Subject = x.Subject
    obj.SubjectGeneral = x.SubjectGeneral
    obj.Subjects = x.Subjects
    return json.Marshal(obj)
}
func (x *TrustAnchorSubject) UnmarshalJSON(data []byte) error {
    x.Subject = nil
    x.SubjectGeneral = nil
    x.Subjects = nil
    var obj struct {
        Subject *[][2]string `json:"subject,omitempty"`
        SubjectGeneral *SubjectGeneral `json:"subject_general,omitempty"`
        Subjects *[]SubjectGeneral `json:"subjects,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.Subject = obj.Subject
    x.SubjectGeneral = obj.SubjectGeneral
    x.Subjects = obj.Subjects
    return nil
}

// `TrustedCa` app auth configuration.
type TrustedCaCredential struct {
    // The subject or subject alterative names (SANs) expected in the
    // client certificate. During authentication, DSM will check that
    // the client certificate presented contains at least one of the
    // subjects configured here.
    Subject TrustAnchorSubject `json:"subject"`
    // Trust anchors (root CA certificates) used for chain validation.
    // The client certificate chain presented during authentication
    // must validate successfully against one of the root CAs.
    TrustAnchors TrustAnchor `json:"trust_anchors"`
    // When `true`, revocation status of certificates is checked, and revoked
    // certificates are rejected
    CheckRevocation *bool `json:"check_revocation,omitempty"`
}
func (x TrustedCaCredential) MarshalJSON() ([]byte, error) {
    m := make(map[string]interface{})
    { // x.Subject is flattened
        b, err := json.Marshal(&x.Subject)
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
    { // x.TrustAnchors is flattened
        b, err := json.Marshal(&x.TrustAnchors)
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
    if x.CheckRevocation != nil {
        m["check_revocation"] = x.CheckRevocation
    }
    return json.Marshal(&m)
}
func (x *TrustedCaCredential) UnmarshalJSON(data []byte) error {
    if err := json.Unmarshal(data, &x.Subject); err != nil {
        return err
    }
    if err := json.Unmarshal(data, &x.TrustAnchors); err != nil {
        return err
    }
    var r struct {
    CheckRevocation *bool `json:"check_revocation,omitempty"`
    }
    if err := json.Unmarshal(data, &r); err != nil {
        return err
    }
    x.CheckRevocation = r.CheckRevocation
    return nil
}

// Assign the app a new group membership
func (c *Client) AddGroupMembership(ctx context.Context, app_id string, body CreateGroupMembership) (*AppGroupMembership, error) {
    u := "/sys/v1/apps/:app_id/groups"
    u = strings.NewReplacer(":app_id", app_id).Replace(u)
    var r AppGroupMembership
    if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
        return nil, err
    }
    return &r, nil
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
func (c *Client) DeleteApp(ctx context.Context, app_id string) error {
    u := "/sys/v1/apps/:app_id"
    u = strings.NewReplacer(":app_id", app_id).Replace(u)
    if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
        return err
    }
    return nil
}

// Remove an app's membership in a specific group
func (c *Client) DeleteGroupMembership(ctx context.Context, app_id string, group_id string) error {
    u := "/sys/v1/apps/:app_id/groups/:group_id"
    u = strings.NewReplacer(":app_id", app_id, ":group_id", group_id).Replace(u)
    if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
        return err
    }
    return nil
}

// Get all group memberships for the app
func (c *Client) GetAllGroupMemberships(ctx context.Context, app_id string, queryParameters *GetGroupsParams) (*GetAppGroupMemberships, error) {
    u := "/sys/v1/apps/:app_id/groups"
    u = strings.NewReplacer(":app_id", app_id).Replace(u)
    if queryParameters != nil {
        q, err := encodeURLParams(queryParameters)
        if err != nil {
            return nil, err
        }
        u = fmt.Sprintf("%v?%v", u, q)
    }
    var r GetAppGroupMemberships
    if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Lookup an application.
func (c *Client) GetApp(ctx context.Context, app_id string, queryParameters *GetAppParams) (*App, error) {
    u := "/sys/v1/apps/:app_id"
    u = strings.NewReplacer(":app_id", app_id).Replace(u)
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
//
// In FIPS mode this secret will be reset after 100 failed API key authentication
// attempts in a 24 hour period.
func (c *Client) GetAppCredential(ctx context.Context, app_id string) (*AppCredentialResponse, error) {
    u := "/sys/v1/apps/:app_id/credential"
    u = strings.NewReplacer(":app_id", app_id).Replace(u)
    var r AppCredentialResponse
    if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

func (c *Client) RequestApprovalToGetAppCredential(
    ctx context.Context,    
app_id string,
    description *string) (*ApprovalRequest, error) {
    u := "/sys/v1/apps/:app_id/credential"
    u = strings.NewReplacer(":app_id", app_id).Replace(u)
    req := ApprovalRequestRequest{
        Method:      Some(http.MethodGet),
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

// Get an app's group membership
func (c *Client) GetGroupMembership(ctx context.Context, app_id string, group_id string) (*AppGroupMembership, error) {
    u := "/sys/v1/apps/:app_id/groups/:group_id"
    u = strings.NewReplacer(":app_id", app_id, ":group_id", group_id).Replace(u)
    var r AppGroupMembership
    if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Get details of all apps accessible to requester.
func (c *Client) ListApps(ctx context.Context, queryParameters *ListAppsParams) (*ListAppsResponse, error) {
    u := "/sys/v1/apps"
    if queryParameters != nil {
        q, err := encodeURLParams(queryParameters)
        if err != nil {
            return nil, err
        }
        u = fmt.Sprintf("%v?%v", u, q)
    }
    var r ListAppsResponse
    if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Regenerate API key.
//
// This will invalidate all existing sessions of this app. Although,
// if `credential_migration_period` is set in request, previous
// credentials (or its sessions) won't invalidate until the given time.
func (c *Client) ResetAppSecret(ctx context.Context, app_id string, queryParameters *GetAppParams, body AppResetSecretRequest) (*App, error) {
    u := "/sys/v1/apps/:app_id/reset_secret"
    u = strings.NewReplacer(":app_id", app_id).Replace(u)
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
app_id string,    
queryParameters *GetAppParams,    
body AppResetSecretRequest,
    description *string) (*ApprovalRequest, error) {
    u := "/sys/v1/apps/:app_id/reset_secret"
    u = strings.NewReplacer(":app_id", app_id).Replace(u)
    if queryParameters != nil {
        q, err := encodeURLParams(queryParameters)
        if err != nil {
            return nil, err
        }
        u = fmt.Sprintf("%v?%v", u, q)
    }
    req := ApprovalRequestRequest{
        Method:      Some(http.MethodPost),
        Operation:   &u,
        Body:        &body,
        Description: description,
    }
    return c.CreateApprovalRequest(ctx, req)
}

// Update app settings like groups, client config, etc.
func (c *Client) UpdateApp(ctx context.Context, app_id string, queryParameters *GetAppParams, body AppRequest) (*App, error) {
    u := "/sys/v1/apps/:app_id"
    u = strings.NewReplacer(":app_id", app_id).Replace(u)
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
app_id string,    
queryParameters *GetAppParams,    
body AppRequest,
    description *string) (*ApprovalRequest, error) {
    u := "/sys/v1/apps/:app_id"
    u = strings.NewReplacer(":app_id", app_id).Replace(u)
    if queryParameters != nil {
        q, err := encodeURLParams(queryParameters)
        if err != nil {
            return nil, err
        }
        u = fmt.Sprintf("%v?%v", u, q)
    }
    req := ApprovalRequestRequest{
        Method:      Some(http.MethodPatch),
        Operation:   &u,
        Body:        &body,
        Description: description,
    }
    return c.CreateApprovalRequest(ctx, req)
}

// Update an app's particular group membership
func (c *Client) UpdateGroupMembership(ctx context.Context, app_id string, group_id string, body GroupMembershipRequest) (*AppGroupMembership, error) {
    u := "/sys/v1/apps/:app_id/groups/:group_id"
    u = strings.NewReplacer(":app_id", app_id, ":group_id", group_id).Replace(u)
    var r AppGroupMembership
    if err := c.fetch(ctx, http.MethodPatch, u, &body, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

