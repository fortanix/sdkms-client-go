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

// Authentication method of an app.
type AppAuthType string

// List of supported AppAuthType values
const (
    AppAuthTypeSecret AppAuthType = "Secret"
    AppAuthTypeCertificate AppAuthType = "Certificate"
    AppAuthTypeTrustedCa AppAuthType = "TrustedCa"
    AppAuthTypeGoogleServiceAccount AppAuthType = "GoogleServiceAccount"
    AppAuthTypeSignedJwt AppAuthType = "SignedJwt"
    AppAuthTypeLdap AppAuthType = "Ldap"
    AppAuthTypeAwsIam AppAuthType = "AwsIam"
    AppAuthTypeAwsXks AppAuthType = "AwsXks"
    AppAuthTypeGoogleWorkspaceCSE AppAuthType = "GoogleWorkspaceCSE"
)

// App authentication mechanisms.
type AppCredential struct {
    // Authenticating credentials of an App.
    Secret *ZeroizedString
    // PKI Certificate based authentication.
    Certificate *ZeroizedBlob
    // PKI certificate with Trusted CA based authentication.
    TrustedCa *TrustedCaCredential
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
    GoogleWorkspaceCse *struct{}
}
// An App's service account for communicating with Google APIs and Cloud. Google OAuth 2.0
type AppCredentialGoogleServiceAccount struct {
    // Policy specifying acceptable access reasons.
    AccessReasonPolicy *GoogleAccessReasonPolicy `json:"access_reason_policy,omitempty"`
    // Mapping for all groups an application is part of and the Gcp specific permissions it has within each of those groups.
    Groups *map[UUID]GcpAppPermissions `json:"groups,omitempty"`
}
// Authentication using a signed JWT directly as a bearer token.
type AppCredentialSignedJwt struct {
    ValidIssuers []string `json:"valid_issuers"`
    SigningKeys SigningKeys `json:"signing_keys"`
}
// SigV4 credentials used for AWS XKS APIs
type AppCredentialAwsXks struct {
    AccessKeyID *string `json:"access_key_id,omitempty"`
    SecretKey *ZeroizedString `json:"secret_key,omitempty"`
}
func (x AppCredential) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "AppCredential", 
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
        GoogleServiceAccount *AppCredentialGoogleServiceAccount `json:"googleserviceaccount,omitempty"`
        SignedJwt *AppCredentialSignedJwt `json:"signedjwt,omitempty"`
        Ldap *UUID `json:"ldap,omitempty"`
        AwsIam *struct{} `json:"awsiam,omitempty"`
        AwsXks *AppCredentialAwsXks `json:"awsxks,omitempty"`
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
func (x *AppCredential) UnmarshalJSON(data []byte) error {
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
        GoogleServiceAccount *AppCredentialGoogleServiceAccount `json:"googleserviceaccount,omitempty"`
        SignedJwt *AppCredentialSignedJwt `json:"signedjwt,omitempty"`
        Ldap *UUID `json:"ldap,omitempty"`
        AwsIam *struct{} `json:"awsiam,omitempty"`
        AwsXks *AppCredentialAwsXks `json:"awsxks,omitempty"`
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
        return errors.New("AppSort can be either ByAppID or ByAppName")
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
    //   requests with `coninutation_token`s.
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

// Expired app-credentials that are still valid for a transitional period.
type PreviousCredential struct {
    // App authentication mechanisms.
    Credential AppCredential `json:"credential"`
    // Validity period of the App credentials.
    ValidUntil Time `json:"valid_until"`
}

type SubjectGeneral struct {
    DirectoryName *[][2]string
    DnsName *string
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

type TrustAnchorSubject struct {
    Subject *[][2]string
    SubjectGeneral *SubjectGeneral
}
func (x TrustAnchorSubject) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "TrustAnchorSubject", 
                  []bool{ x.Subject != nil,
                  x.SubjectGeneral != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Subject *[][2]string `json:"subject,omitempty"`
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
        Subject *[][2]string `json:"subject,omitempty"`
        SubjectGeneral *SubjectGeneral `json:"subject_general,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.Subject = obj.Subject
    x.SubjectGeneral = obj.SubjectGeneral
    return nil
}

// `TrustedCa` app auth
type TrustedCaCredential struct {
    Subject TrustAnchorSubject `json:"subject"`
    CaCertificate ZeroizedBlob `json:"ca_certificate"`
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
    m["ca_certificate"] = x.CaCertificate
    if x.CheckRevocation != nil {
        m["check_revocation"] = x.CheckRevocation
    }
    return json.Marshal(&m)
}
func (x *TrustedCaCredential) UnmarshalJSON(data []byte) error {
    if err := json.Unmarshal(data, &x.Subject); err != nil {
        return err
    }
    var r struct {
    CaCertificate ZeroizedBlob `json:"ca_certificate"`
    CheckRevocation *bool `json:"check_revocation,omitempty"`
    }
    if err := json.Unmarshal(data, &r); err != nil {
        return err
    }
    x.CaCertificate = r.CaCertificate
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

