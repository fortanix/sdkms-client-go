/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package sdkms

import (
    //"context"
    "encoding/json"
    "fmt"
    //"net/http"
    //"net/url"
    //"strings"
    "github.com/pkg/errors"
)

type AccountPermissions uint64

// List of supported AccountPermissions values
const (
    //  Permission to manage logging integrations, and enable/disable error
    //  logging.
    AccountPermissionsManageLogging AccountPermissions = 1 << iota
    //  Permission to manage SSO and password policy.
    AccountPermissionsManageAuth
    //  Permission to manage Workspace CSE configuration.
    AccountPermissionsManageWorkspaceCse
    //  Permission required for Workspace CSE PrivilegedUnwrap API. Note
    //  that `UNWRAP_WORKSPACE_CSE` permission in the group where the key is
    //  stored is also required.
    AccountPermissionsUnwrapWorkspaceCsePrivileged
    //  Permission to manage account level client configurations.
    AccountPermissionsManageAccountClientConfigs
    //  Permission to manage plugin code signing policy.
    AccountPermissionsManagePluginCodeSigningPolicy
    //  Permission to create account-level approval policy. Note that
    //  updating/deleting the approval policy is protected by the approval
    //  policy itself.
    AccountPermissionsCreateAccountApprovalPolicy
    //  Permission to set approval request expiry for all approval requests
    //  created in the account.
    AccountPermissionsSetApprovalRequestExpiry
    //  Permission to manage all approval request settings including
    //  approval request expiry. Implies `SET_APPROVAL_REQUEST_EXPIRY`.
    AccountPermissionsManageApprovalRequestSettings
    //  Permission to update account's custom metadata attributes.
    AccountPermissionsUpdateAccountCustomMetadataAttributes
    //  Permission to manage account subscription (only relevant for SaaS
    //  accounts).
    AccountPermissionsManageAccountSubscription
    //  Permission to update account name, custom logo, and other profile
    //  information.
    AccountPermissionsManageAccountProfile
    //  Permission to delete the account.
    AccountPermissionsDeleteAccount
    //  Permission to create administrative apps. Implies `GET_ADMIN_APPS`.
    AccountPermissionsCreateAdminApps
    //  Permission to update administrative apps. Implies `GET_ADMIN_APPS`.
    AccountPermissionsUpdateAdminApps
    //  Permission to delete administrative apps. Implies `GET_ADMIN_APPS`.
    AccountPermissionsDeleteAdminApps
    //  Permission to retrieve administrative apps' secrets. Note that not
    //  all admin app credentials contain secrets. If an admin app's
    //  credential does not contain any secrets, `GET_ADMIN_APPS` permission
    //  is sufficient to call the `GetAppCredential` API. Implies
    //  `GET_ADMIN_APPS`.
    AccountPermissionsRetrieveAdminAppSecrets
    //  Currently implies `CREATE_ADMIN_APPS`, `UPDATE_ADMIN_APPS`,
    //  `DELETE_ADMIN_APPS`, `RETRIEVE_ADMIN_APP_SECRETS` and
    //  `GET_ADMIN_APPS` permissions.
    AccountPermissionsManageAdminApps
    //  Permission to create custom user roles. Implies `GET_CUSTOM_ROLES`.
    AccountPermissionsCreateCustomRoles
    //  Permission to update custom user roles. Implies `GET_CUSTOM_ROLES`.
    AccountPermissionsUpdateCustomRoles
    //  Permission to delete custom user roles. Implies `GET_CUSTOM_ROLES`.
    AccountPermissionsDeleteCustomRoles
    //  Currently implies `CREATE_CUSTOM_ROLES`, `UPDATE_CUSTOM_ROLES`,
    //  `DELETE_CUSTOM_ROLES` and `GET_CUSTOM_ROLES` permissions.
    AccountPermissionsManageCustomRoles
    //  Permission to invite users to the account. Implies `GET_ALL_USERS`.
    AccountPermissionsInviteUsersToAccount
    //  Permission to remove users from the account. Implies
    //  `GET_ALL_USERS`.
    AccountPermissionsDeleteUsersFromAccount
    //  Permission to change users' role in the account. Implies
    //  `GET_ALL_USERS`.
    AccountPermissionsUpdateUsersAccountRole
    //  Permission to enable/disable users in the account. Implies
    //  `GET_ALL_USERS`.
    AccountPermissionsUpdateUsersAccountEnabledState
    //  Currently implies `INVITE_USERS_TO_ACCOUNT`,
    //  `DELETE_USERS_FROM_ACCOUNT`, `UPDATE_USERS_ACCOUNT_ROLE`,
    //  `UPDATE_USERS_ACCOUNT_ENABLED_STATE` and `GET_ALL_USERS`
    //  permissions.
    AccountPermissionsManageAccountUsers
    //  Permission to create external roles. Implies `GET_EXTERNAL_ROLES`.
    AccountPermissionsCreateExternalRoles
    //  Permission to synchronize external roles. Implies
    //  `GET_EXTERNAL_ROLES`.
    AccountPermissionsSyncExternalRoles
    //  Permission to delete external roles. Implies `GET_EXTERNAL_ROLES`.
    AccountPermissionsDeleteExternalRoles
    //  Currently implies `CREATE_EXTERNAL_ROLES`, `SYNC_EXTERNAL_ROLES`,
    //  `DELETE_EXTERNAL_ROLES` and `GET_EXTERNAL_ROLES` permissions.
    AccountPermissionsManageExternalRoles
    //  Permission to create various account-level security object policies
    //  including cryptographic policy, key metadata policy and key history
    //  policy.
    AccountPermissionsCreateAccountSobjectPolicies
    //  Permission to update various account-level security object policies
    //  including cryptographic policy, key metadata policy and key history
    //  policy.
    AccountPermissionsUpdateAccountSobjectPolicies
    //  Permission to delete various account-level security object policies
    //  including cryptographic policy, key metadata policy and key history
    //  policy.
    AccountPermissionsDeleteAccountSobjectPolicies
    //  Currently implies `CREATE_ACCOUNT_SOBJECT_POLICIES`,
    //  `UPDATE_ACCOUNT_SOBJECT_POLICIES`, and
    //  `DELETE_ACCOUNT_SOBJECT_POLICIES` permissions.
    AccountPermissionsManageAccountSobjectPolicies
    //  Permission to create child accounts. Note that this is only
    //  applicable to SaaS accounts with reseller subscription. Implies
    //  `GET_CHILD_ACCOUNTS`.
    AccountPermissionsCreateChildAccounts
    //  Permission to update child accounts. Note that this is only
    //  applicable to SaaS accounts with reseller subscription. Implies
    //  `GET_CHILD_ACCOUNTS`.
    AccountPermissionsUpdateChildAccounts
    //  Permission to delete child accounts. Note that this is only
    //  applicable to SaaS accounts with reseller subscription. Implies
    //  `GET_CHILD_ACCOUNTS`.
    AccountPermissionsDeleteChildAccounts
    //  Permission to create users in child accounts. Note that this is only
    //  applicable to SaaS accounts with reseller subscription. Implies
    //  `GET_CHILD_ACCOUNTS` and `GET_CHILD_ACCOUNT_USERS`.
    AccountPermissionsCreateChildAccountUsers
    //  Permission to get child accounts. Note that this is only applicable
    //  to SaaS accounts with reseller subscription.
    AccountPermissionsGetChildAccounts
    //  Permission to get child account users. Note that this is only
    //  applicable to SaaS accounts with reseller subscription.
    AccountPermissionsGetChildAccountUsers
    //  Currently implies `CREATE_CHILD_ACCOUNTS`, `UPDATE_CHILD_ACCOUNTS`,
    //  `DELETE_CHILD_ACCOUNTS`, `CREATE_CHILD_ACCOUNT_USERS`,
    //  `GET_CHILD_ACCOUNTS`, and `GET_CHILD_ACCOUNT_USERS` permissions.
    AccountPermissionsManageChildAccounts
    //  Permission to create new local groups.
    AccountPermissionsCreateLocalGroups
    //  Permission to create new group backed by external HSM/KMS.
    AccountPermissionsCreateExternalGroups
    //  Controls if the user can act as an approval policy reviewer.
    AccountPermissionsAllowQuorumReviewer
    //  Controls if the user can act as a key custodian.
    AccountPermissionsAllowKeyCustodian
    //  Grants read access to **all** approval requests in the account. Note
    //  that there is a related group-level permission that is restricted to
    //  approval requests related to one group.
    AccountPermissionsGetAllApprovalRequests
    //  Permission to get administrative apps.
    AccountPermissionsGetAdminApps
    //  Permission to get custom user roles.
    AccountPermissionsGetCustomRoles
    //  Permission to get external roles.
    AccountPermissionsGetExternalRoles
    //  Permission to get all users. Note that users can always get
    //  themselves.
    AccountPermissionsGetAllUsers
    //  Grants access to accounts::GetAccountUsage API.
    AccountPermissionsGetAccountUsage
    //  Permission to manage key expiry alert configurations.
    AccountPermissionsManageKeyExpiryAlerts
    //  Permission to modify an account's `purpose` field (e.g., changing a
    //  replication account's settings), or to call any APIs involving
    //  replication credentials. If the account is not a replication account,
    //  this permission has no effect.
    AccountPermissionsManageReplication
)

// MarshalJSON converts AccountPermissions to an array of strings
func (x AccountPermissions) MarshalJSON() ([]byte, error) {
    s := make([]string, 0)
    if x & AccountPermissionsManageLogging == AccountPermissionsManageLogging {
        s = append(s, "MANAGE_LOGGING")
    }
    if x & AccountPermissionsManageAuth == AccountPermissionsManageAuth {
        s = append(s, "MANAGE_AUTH")
    }
    if x & AccountPermissionsManageWorkspaceCse == AccountPermissionsManageWorkspaceCse {
        s = append(s, "MANAGE_WORKSPACE_CSE")
    }
    if x & AccountPermissionsUnwrapWorkspaceCsePrivileged == AccountPermissionsUnwrapWorkspaceCsePrivileged {
        s = append(s, "UNWRAP_WORKSPACE_CSE_PRIVILEGED")
    }
    if x & AccountPermissionsManageAccountClientConfigs == AccountPermissionsManageAccountClientConfigs {
        s = append(s, "MANAGE_ACCOUNT_CLIENT_CONFIGS")
    }
    if x & AccountPermissionsManagePluginCodeSigningPolicy == AccountPermissionsManagePluginCodeSigningPolicy {
        s = append(s, "MANAGE_PLUGIN_CODE_SIGNING_POLICY")
    }
    if x & AccountPermissionsCreateAccountApprovalPolicy == AccountPermissionsCreateAccountApprovalPolicy {
        s = append(s, "CREATE_ACCOUNT_APPROVAL_POLICY")
    }
    if x & AccountPermissionsSetApprovalRequestExpiry == AccountPermissionsSetApprovalRequestExpiry {
        s = append(s, "SET_APPROVAL_REQUEST_EXPIRY")
    }
    if x & AccountPermissionsManageApprovalRequestSettings == AccountPermissionsManageApprovalRequestSettings {
        s = append(s, "MANAGE_APPROVAL_REQUEST_SETTINGS")
    }
    if x & AccountPermissionsUpdateAccountCustomMetadataAttributes == AccountPermissionsUpdateAccountCustomMetadataAttributes {
        s = append(s, "UPDATE_ACCOUNT_CUSTOM_METADATA_ATTRIBUTES")
    }
    if x & AccountPermissionsManageAccountSubscription == AccountPermissionsManageAccountSubscription {
        s = append(s, "MANAGE_ACCOUNT_SUBSCRIPTION")
    }
    if x & AccountPermissionsManageAccountProfile == AccountPermissionsManageAccountProfile {
        s = append(s, "MANAGE_ACCOUNT_PROFILE")
    }
    if x & AccountPermissionsDeleteAccount == AccountPermissionsDeleteAccount {
        s = append(s, "DELETE_ACCOUNT")
    }
    if x & AccountPermissionsCreateAdminApps == AccountPermissionsCreateAdminApps {
        s = append(s, "CREATE_ADMIN_APPS")
    }
    if x & AccountPermissionsUpdateAdminApps == AccountPermissionsUpdateAdminApps {
        s = append(s, "UPDATE_ADMIN_APPS")
    }
    if x & AccountPermissionsDeleteAdminApps == AccountPermissionsDeleteAdminApps {
        s = append(s, "DELETE_ADMIN_APPS")
    }
    if x & AccountPermissionsRetrieveAdminAppSecrets == AccountPermissionsRetrieveAdminAppSecrets {
        s = append(s, "RETRIEVE_ADMIN_APP_SECRETS")
    }
    if x & AccountPermissionsManageAdminApps == AccountPermissionsManageAdminApps {
        s = append(s, "MANAGE_ADMIN_APPS")
    }
    if x & AccountPermissionsCreateCustomRoles == AccountPermissionsCreateCustomRoles {
        s = append(s, "CREATE_CUSTOM_ROLES")
    }
    if x & AccountPermissionsUpdateCustomRoles == AccountPermissionsUpdateCustomRoles {
        s = append(s, "UPDATE_CUSTOM_ROLES")
    }
    if x & AccountPermissionsDeleteCustomRoles == AccountPermissionsDeleteCustomRoles {
        s = append(s, "DELETE_CUSTOM_ROLES")
    }
    if x & AccountPermissionsManageCustomRoles == AccountPermissionsManageCustomRoles {
        s = append(s, "MANAGE_CUSTOM_ROLES")
    }
    if x & AccountPermissionsInviteUsersToAccount == AccountPermissionsInviteUsersToAccount {
        s = append(s, "INVITE_USERS_TO_ACCOUNT")
    }
    if x & AccountPermissionsDeleteUsersFromAccount == AccountPermissionsDeleteUsersFromAccount {
        s = append(s, "DELETE_USERS_FROM_ACCOUNT")
    }
    if x & AccountPermissionsUpdateUsersAccountRole == AccountPermissionsUpdateUsersAccountRole {
        s = append(s, "UPDATE_USERS_ACCOUNT_ROLE")
    }
    if x & AccountPermissionsUpdateUsersAccountEnabledState == AccountPermissionsUpdateUsersAccountEnabledState {
        s = append(s, "UPDATE_USERS_ACCOUNT_ENABLED_STATE")
    }
    if x & AccountPermissionsManageAccountUsers == AccountPermissionsManageAccountUsers {
        s = append(s, "MANAGE_ACCOUNT_USERS")
    }
    if x & AccountPermissionsCreateExternalRoles == AccountPermissionsCreateExternalRoles {
        s = append(s, "CREATE_EXTERNAL_ROLES")
    }
    if x & AccountPermissionsSyncExternalRoles == AccountPermissionsSyncExternalRoles {
        s = append(s, "SYNC_EXTERNAL_ROLES")
    }
    if x & AccountPermissionsDeleteExternalRoles == AccountPermissionsDeleteExternalRoles {
        s = append(s, "DELETE_EXTERNAL_ROLES")
    }
    if x & AccountPermissionsManageExternalRoles == AccountPermissionsManageExternalRoles {
        s = append(s, "MANAGE_EXTERNAL_ROLES")
    }
    if x & AccountPermissionsCreateAccountSobjectPolicies == AccountPermissionsCreateAccountSobjectPolicies {
        s = append(s, "CREATE_ACCOUNT_SOBJECT_POLICIES")
    }
    if x & AccountPermissionsUpdateAccountSobjectPolicies == AccountPermissionsUpdateAccountSobjectPolicies {
        s = append(s, "UPDATE_ACCOUNT_SOBJECT_POLICIES")
    }
    if x & AccountPermissionsDeleteAccountSobjectPolicies == AccountPermissionsDeleteAccountSobjectPolicies {
        s = append(s, "DELETE_ACCOUNT_SOBJECT_POLICIES")
    }
    if x & AccountPermissionsManageAccountSobjectPolicies == AccountPermissionsManageAccountSobjectPolicies {
        s = append(s, "MANAGE_ACCOUNT_SOBJECT_POLICIES")
    }
    if x & AccountPermissionsCreateChildAccounts == AccountPermissionsCreateChildAccounts {
        s = append(s, "CREATE_CHILD_ACCOUNTS")
    }
    if x & AccountPermissionsUpdateChildAccounts == AccountPermissionsUpdateChildAccounts {
        s = append(s, "UPDATE_CHILD_ACCOUNTS")
    }
    if x & AccountPermissionsDeleteChildAccounts == AccountPermissionsDeleteChildAccounts {
        s = append(s, "DELETE_CHILD_ACCOUNTS")
    }
    if x & AccountPermissionsCreateChildAccountUsers == AccountPermissionsCreateChildAccountUsers {
        s = append(s, "CREATE_CHILD_ACCOUNT_USERS")
    }
    if x & AccountPermissionsGetChildAccounts == AccountPermissionsGetChildAccounts {
        s = append(s, "GET_CHILD_ACCOUNTS")
    }
    if x & AccountPermissionsGetChildAccountUsers == AccountPermissionsGetChildAccountUsers {
        s = append(s, "GET_CHILD_ACCOUNT_USERS")
    }
    if x & AccountPermissionsManageChildAccounts == AccountPermissionsManageChildAccounts {
        s = append(s, "MANAGE_CHILD_ACCOUNTS")
    }
    if x & AccountPermissionsCreateLocalGroups == AccountPermissionsCreateLocalGroups {
        s = append(s, "CREATE_LOCAL_GROUPS")
    }
    if x & AccountPermissionsCreateExternalGroups == AccountPermissionsCreateExternalGroups {
        s = append(s, "CREATE_EXTERNAL_GROUPS")
    }
    if x & AccountPermissionsAllowQuorumReviewer == AccountPermissionsAllowQuorumReviewer {
        s = append(s, "ALLOW_QUORUM_REVIEWER")
    }
    if x & AccountPermissionsAllowKeyCustodian == AccountPermissionsAllowKeyCustodian {
        s = append(s, "ALLOW_KEY_CUSTODIAN")
    }
    if x & AccountPermissionsGetAllApprovalRequests == AccountPermissionsGetAllApprovalRequests {
        s = append(s, "GET_ALL_APPROVAL_REQUESTS")
    }
    if x & AccountPermissionsGetAdminApps == AccountPermissionsGetAdminApps {
        s = append(s, "GET_ADMIN_APPS")
    }
    if x & AccountPermissionsGetCustomRoles == AccountPermissionsGetCustomRoles {
        s = append(s, "GET_CUSTOM_ROLES")
    }
    if x & AccountPermissionsGetExternalRoles == AccountPermissionsGetExternalRoles {
        s = append(s, "GET_EXTERNAL_ROLES")
    }
    if x & AccountPermissionsGetAllUsers == AccountPermissionsGetAllUsers {
        s = append(s, "GET_ALL_USERS")
    }
    if x & AccountPermissionsGetAccountUsage == AccountPermissionsGetAccountUsage {
        s = append(s, "GET_ACCOUNT_USAGE")
    }
    if x & AccountPermissionsManageKeyExpiryAlerts == AccountPermissionsManageKeyExpiryAlerts {
        s = append(s, "MANAGE_KEY_EXPIRY_ALERTS")
    }
    if x & AccountPermissionsManageReplication == AccountPermissionsManageReplication {
        s = append(s, "MANAGE_REPLICATION")
    }
    return json.Marshal(s)
}

// UnmarshalJSON converts array of strings to AccountPermissions
func (x *AccountPermissions) UnmarshalJSON(data []byte) error {
    *x = 0
    var s []string
    if err := json.Unmarshal(data, &s); err != nil {
        return err
    }
    for _, v := range s {
        switch v {
        case "MANAGE_LOGGING":
            *x = *x | AccountPermissionsManageLogging
        case "MANAGE_AUTH":
            *x = *x | AccountPermissionsManageAuth
        case "MANAGE_WORKSPACE_CSE":
            *x = *x | AccountPermissionsManageWorkspaceCse
        case "UNWRAP_WORKSPACE_CSE_PRIVILEGED":
            *x = *x | AccountPermissionsUnwrapWorkspaceCsePrivileged
        case "MANAGE_ACCOUNT_CLIENT_CONFIGS":
            *x = *x | AccountPermissionsManageAccountClientConfigs
        case "MANAGE_PLUGIN_CODE_SIGNING_POLICY":
            *x = *x | AccountPermissionsManagePluginCodeSigningPolicy
        case "CREATE_ACCOUNT_APPROVAL_POLICY":
            *x = *x | AccountPermissionsCreateAccountApprovalPolicy
        case "SET_APPROVAL_REQUEST_EXPIRY":
            *x = *x | AccountPermissionsSetApprovalRequestExpiry
        case "MANAGE_APPROVAL_REQUEST_SETTINGS":
            *x = *x | AccountPermissionsManageApprovalRequestSettings
        case "UPDATE_ACCOUNT_CUSTOM_METADATA_ATTRIBUTES":
            *x = *x | AccountPermissionsUpdateAccountCustomMetadataAttributes
        case "MANAGE_ACCOUNT_SUBSCRIPTION":
            *x = *x | AccountPermissionsManageAccountSubscription
        case "MANAGE_ACCOUNT_PROFILE":
            *x = *x | AccountPermissionsManageAccountProfile
        case "DELETE_ACCOUNT":
            *x = *x | AccountPermissionsDeleteAccount
        case "CREATE_ADMIN_APPS":
            *x = *x | AccountPermissionsCreateAdminApps
        case "UPDATE_ADMIN_APPS":
            *x = *x | AccountPermissionsUpdateAdminApps
        case "DELETE_ADMIN_APPS":
            *x = *x | AccountPermissionsDeleteAdminApps
        case "RETRIEVE_ADMIN_APP_SECRETS":
            *x = *x | AccountPermissionsRetrieveAdminAppSecrets
        case "MANAGE_ADMIN_APPS":
            *x = *x | AccountPermissionsManageAdminApps
        case "CREATE_CUSTOM_ROLES":
            *x = *x | AccountPermissionsCreateCustomRoles
        case "UPDATE_CUSTOM_ROLES":
            *x = *x | AccountPermissionsUpdateCustomRoles
        case "DELETE_CUSTOM_ROLES":
            *x = *x | AccountPermissionsDeleteCustomRoles
        case "MANAGE_CUSTOM_ROLES":
            *x = *x | AccountPermissionsManageCustomRoles
        case "INVITE_USERS_TO_ACCOUNT":
            *x = *x | AccountPermissionsInviteUsersToAccount
        case "DELETE_USERS_FROM_ACCOUNT":
            *x = *x | AccountPermissionsDeleteUsersFromAccount
        case "UPDATE_USERS_ACCOUNT_ROLE":
            *x = *x | AccountPermissionsUpdateUsersAccountRole
        case "UPDATE_USERS_ACCOUNT_ENABLED_STATE":
            *x = *x | AccountPermissionsUpdateUsersAccountEnabledState
        case "MANAGE_ACCOUNT_USERS":
            *x = *x | AccountPermissionsManageAccountUsers
        case "CREATE_EXTERNAL_ROLES":
            *x = *x | AccountPermissionsCreateExternalRoles
        case "SYNC_EXTERNAL_ROLES":
            *x = *x | AccountPermissionsSyncExternalRoles
        case "DELETE_EXTERNAL_ROLES":
            *x = *x | AccountPermissionsDeleteExternalRoles
        case "MANAGE_EXTERNAL_ROLES":
            *x = *x | AccountPermissionsManageExternalRoles
        case "CREATE_ACCOUNT_SOBJECT_POLICIES":
            *x = *x | AccountPermissionsCreateAccountSobjectPolicies
        case "UPDATE_ACCOUNT_SOBJECT_POLICIES":
            *x = *x | AccountPermissionsUpdateAccountSobjectPolicies
        case "DELETE_ACCOUNT_SOBJECT_POLICIES":
            *x = *x | AccountPermissionsDeleteAccountSobjectPolicies
        case "MANAGE_ACCOUNT_SOBJECT_POLICIES":
            *x = *x | AccountPermissionsManageAccountSobjectPolicies
        case "CREATE_CHILD_ACCOUNTS":
            *x = *x | AccountPermissionsCreateChildAccounts
        case "UPDATE_CHILD_ACCOUNTS":
            *x = *x | AccountPermissionsUpdateChildAccounts
        case "DELETE_CHILD_ACCOUNTS":
            *x = *x | AccountPermissionsDeleteChildAccounts
        case "CREATE_CHILD_ACCOUNT_USERS":
            *x = *x | AccountPermissionsCreateChildAccountUsers
        case "GET_CHILD_ACCOUNTS":
            *x = *x | AccountPermissionsGetChildAccounts
        case "GET_CHILD_ACCOUNT_USERS":
            *x = *x | AccountPermissionsGetChildAccountUsers
        case "MANAGE_CHILD_ACCOUNTS":
            *x = *x | AccountPermissionsManageChildAccounts
        case "CREATE_LOCAL_GROUPS":
            *x = *x | AccountPermissionsCreateLocalGroups
        case "CREATE_EXTERNAL_GROUPS":
            *x = *x | AccountPermissionsCreateExternalGroups
        case "ALLOW_QUORUM_REVIEWER":
            *x = *x | AccountPermissionsAllowQuorumReviewer
        case "ALLOW_KEY_CUSTODIAN":
            *x = *x | AccountPermissionsAllowKeyCustodian
        case "GET_ALL_APPROVAL_REQUESTS":
            *x = *x | AccountPermissionsGetAllApprovalRequests
        case "GET_ADMIN_APPS":
            *x = *x | AccountPermissionsGetAdminApps
        case "GET_CUSTOM_ROLES":
            *x = *x | AccountPermissionsGetCustomRoles
        case "GET_EXTERNAL_ROLES":
            *x = *x | AccountPermissionsGetExternalRoles
        case "GET_ALL_USERS":
            *x = *x | AccountPermissionsGetAllUsers
        case "GET_ACCOUNT_USAGE":
            *x = *x | AccountPermissionsGetAccountUsage
        case "MANAGE_KEY_EXPIRY_ALERTS":
            *x = *x | AccountPermissionsManageKeyExpiryAlerts
        case "MANAGE_REPLICATION":
            *x = *x | AccountPermissionsManageReplication
        }
    }
    return nil
}

type AesOptions struct {
    KeySizes *[]uint32 `json:"key_sizes,omitempty"`
    Fpe *FpeOptions `json:"fpe,omitempty"`
    TagLength *int32 `json:"tag_length,omitempty"`
    CipherMode *CipherMode `json:"cipher_mode,omitempty"`
    RandomIv *bool `json:"random_iv,omitempty"`
    IvLength *int32 `json:"iv_length,omitempty"`
}

type AesOptionsPolicy struct {
    KeySizes *[]uint32 `json:"key_sizes,omitempty"`
    RandomIv *bool `json:"random_iv,omitempty"`
    Fpe *FpeOptions `json:"fpe,omitempty"`
}

// A cryptographic algorithm.
type Algorithm string

// List of supported Algorithm values
const (
    AlgorithmAes Algorithm = "AES"
    AlgorithmAria Algorithm = "ARIA"
    AlgorithmDes Algorithm = "DES"
    AlgorithmDes3 Algorithm = "DES3"
    AlgorithmSeed Algorithm = "SEED"
    AlgorithmRsa Algorithm = "RSA"
    AlgorithmDsa Algorithm = "DSA"
    AlgorithmKcdsa Algorithm = "KCDSA"
    AlgorithmEc Algorithm = "EC"
    AlgorithmEcKcdsa Algorithm = "ECKCDSA"
    AlgorithmBip32 Algorithm = "BIP32"
    AlgorithmBls Algorithm = "BLS"
    AlgorithmLms Algorithm = "LMS"
    AlgorithmXmss Algorithm = "XMSS"
    AlgorithmMlDsaBeta Algorithm = "MLDSABETA"
    AlgorithmMlKemBeta Algorithm = "MLKEMBETA"
    AlgorithmHmac Algorithm = "HMAC"
    AlgorithmLedaBeta Algorithm = "LEDABETA"
    AlgorithmRound5Beta Algorithm = "ROUND5BETA"
    AlgorithmPbe Algorithm = "PBE"
)

// A helper enum with a single variant, All, which indicates that something should apply to an
// entire part. (This is here mainly to allow other untagged enums to work properly.)
type All string

// List of supported All values
const (
    AllAll All = "all"
)

type ApiPath struct {
    APIPath string `json:"api_path"`
    Method HyperHttpMethod `json:"method"`
    Context TepKeyContext `json:"context"`
    KeyPath string `json:"key_path"`
}

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
    AppPermissionsAudit
    AppPermissionsTransform
    AppPermissionsCreateSobjects
    AppPermissionsCopySobjects
    AppPermissionsRotateSobjects
    AppPermissionsActivateSobjects
    AppPermissionsRevokeSobjects
    AppPermissionsRevertSobjects
    AppPermissionsMoveSobjects
    AppPermissionsUpdateSobjectsProfile
    AppPermissionsUpdateSobjectsEnabledState
    AppPermissionsUpdateSobjectPolicies
    AppPermissionsUpdateKeyOps
    AppPermissionsDeleteKeyMaterial
    AppPermissionsDeleteSobjects
    AppPermissionsDestroySobjects
    AppPermissionsRestoreExternalSobjects
    AppPermissionsCalculateDigest
    AppPermissionsEncapsulate
    AppPermissionsDecapsulate
)

// MarshalJSON converts AppPermissions to an array of strings
func (x AppPermissions) MarshalJSON() ([]byte, error) {
    s := make([]string, 0)
    if x & AppPermissionsSign == AppPermissionsSign {
        s = append(s, "SIGN")
    }
    if x & AppPermissionsVerify == AppPermissionsVerify {
        s = append(s, "VERIFY")
    }
    if x & AppPermissionsEncrypt == AppPermissionsEncrypt {
        s = append(s, "ENCRYPT")
    }
    if x & AppPermissionsDecrypt == AppPermissionsDecrypt {
        s = append(s, "DECRYPT")
    }
    if x & AppPermissionsWrapkey == AppPermissionsWrapkey {
        s = append(s, "WRAPKEY")
    }
    if x & AppPermissionsUnwrapkey == AppPermissionsUnwrapkey {
        s = append(s, "UNWRAPKEY")
    }
    if x & AppPermissionsDerivekey == AppPermissionsDerivekey {
        s = append(s, "DERIVEKEY")
    }
    if x & AppPermissionsMacgenerate == AppPermissionsMacgenerate {
        s = append(s, "MACGENERATE")
    }
    if x & AppPermissionsMacverify == AppPermissionsMacverify {
        s = append(s, "MACVERIFY")
    }
    if x & AppPermissionsExport == AppPermissionsExport {
        s = append(s, "EXPORT")
    }
    if x & AppPermissionsManage == AppPermissionsManage {
        s = append(s, "MANAGE")
    }
    if x & AppPermissionsAgreekey == AppPermissionsAgreekey {
        s = append(s, "AGREEKEY")
    }
    if x & AppPermissionsMaskdecrypt == AppPermissionsMaskdecrypt {
        s = append(s, "MASKDECRYPT")
    }
    if x & AppPermissionsAudit == AppPermissionsAudit {
        s = append(s, "AUDIT")
    }
    if x & AppPermissionsTransform == AppPermissionsTransform {
        s = append(s, "TRANSFORM")
    }
    if x & AppPermissionsCreateSobjects == AppPermissionsCreateSobjects {
        s = append(s, "CREATE_SOBJECTS")
    }
    if x & AppPermissionsCopySobjects == AppPermissionsCopySobjects {
        s = append(s, "COPY_SOBJECTS")
    }
    if x & AppPermissionsRotateSobjects == AppPermissionsRotateSobjects {
        s = append(s, "ROTATE_SOBJECTS")
    }
    if x & AppPermissionsActivateSobjects == AppPermissionsActivateSobjects {
        s = append(s, "ACTIVATE_SOBJECTS")
    }
    if x & AppPermissionsRevokeSobjects == AppPermissionsRevokeSobjects {
        s = append(s, "REVOKE_SOBJECTS")
    }
    if x & AppPermissionsRevertSobjects == AppPermissionsRevertSobjects {
        s = append(s, "REVERT_SOBJECTS")
    }
    if x & AppPermissionsMoveSobjects == AppPermissionsMoveSobjects {
        s = append(s, "MOVE_SOBJECTS")
    }
    if x & AppPermissionsUpdateSobjectsProfile == AppPermissionsUpdateSobjectsProfile {
        s = append(s, "UPDATE_SOBJECTS_PROFILE")
    }
    if x & AppPermissionsUpdateSobjectsEnabledState == AppPermissionsUpdateSobjectsEnabledState {
        s = append(s, "UPDATE_SOBJECTS_ENABLED_STATE")
    }
    if x & AppPermissionsUpdateSobjectPolicies == AppPermissionsUpdateSobjectPolicies {
        s = append(s, "UPDATE_SOBJECT_POLICIES")
    }
    if x & AppPermissionsUpdateKeyOps == AppPermissionsUpdateKeyOps {
        s = append(s, "UPDATE_KEY_OPS")
    }
    if x & AppPermissionsDeleteKeyMaterial == AppPermissionsDeleteKeyMaterial {
        s = append(s, "DELETE_KEY_MATERIAL")
    }
    if x & AppPermissionsDeleteSobjects == AppPermissionsDeleteSobjects {
        s = append(s, "DELETE_SOBJECTS")
    }
    if x & AppPermissionsDestroySobjects == AppPermissionsDestroySobjects {
        s = append(s, "DESTROY_SOBJECTS")
    }
    if x & AppPermissionsRestoreExternalSobjects == AppPermissionsRestoreExternalSobjects {
        s = append(s, "RESTORE_EXTERNAL_SOBJECTS")
    }
    if x & AppPermissionsCalculateDigest == AppPermissionsCalculateDigest {
        s = append(s, "CALCULATE_DIGEST")
    }
    if x & AppPermissionsEncapsulate == AppPermissionsEncapsulate {
        s = append(s, "ENCAPSULATE")
    }
    if x & AppPermissionsDecapsulate == AppPermissionsDecapsulate {
        s = append(s, "DECAPSULATE")
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
        case "AUDIT":
            *x = *x | AppPermissionsAudit
        case "TRANSFORM":
            *x = *x | AppPermissionsTransform
        case "CREATE_SOBJECTS":
            *x = *x | AppPermissionsCreateSobjects
        case "COPY_SOBJECTS":
            *x = *x | AppPermissionsCopySobjects
        case "ROTATE_SOBJECTS":
            *x = *x | AppPermissionsRotateSobjects
        case "ACTIVATE_SOBJECTS":
            *x = *x | AppPermissionsActivateSobjects
        case "REVOKE_SOBJECTS":
            *x = *x | AppPermissionsRevokeSobjects
        case "REVERT_SOBJECTS":
            *x = *x | AppPermissionsRevertSobjects
        case "MOVE_SOBJECTS":
            *x = *x | AppPermissionsMoveSobjects
        case "UPDATE_SOBJECTS_PROFILE":
            *x = *x | AppPermissionsUpdateSobjectsProfile
        case "UPDATE_SOBJECTS_ENABLED_STATE":
            *x = *x | AppPermissionsUpdateSobjectsEnabledState
        case "UPDATE_SOBJECT_POLICIES":
            *x = *x | AppPermissionsUpdateSobjectPolicies
        case "UPDATE_KEY_OPS":
            *x = *x | AppPermissionsUpdateKeyOps
        case "DELETE_KEY_MATERIAL":
            *x = *x | AppPermissionsDeleteKeyMaterial
        case "DELETE_SOBJECTS":
            *x = *x | AppPermissionsDeleteSobjects
        case "DESTROY_SOBJECTS":
            *x = *x | AppPermissionsDestroySobjects
        case "RESTORE_EXTERNAL_SOBJECTS":
            *x = *x | AppPermissionsRestoreExternalSobjects
        case "CALCULATE_DIGEST":
            *x = *x | AppPermissionsCalculateDigest
        case "ENCAPSULATE":
            *x = *x | AppPermissionsEncapsulate
        case "DECAPSULATE":
            *x = *x | AppPermissionsDecapsulate
        }
    }
    return nil
}

// Authentication requirements for approval request reviewers.
type ApprovalAuthConfig struct {
    RequirePassword *bool `json:"require_password,omitempty"`
    Require2fa *bool `json:"require_2fa,omitempty"`
}

// Configurations for waiting for quorum approval.
type ApprovalWaitConfig struct {
    // Indicates whether waiting for quorum approval is activated or disabled
    Enabled bool `json:"enabled"`
    // Time interval in seconds for client lib to check quorum status.
    PollIntervalSecs *uint64 `json:"poll_interval_secs,omitempty"`
    // Maximum time in seconds for client lib to wait for quorum reply.
    MaxWaitForSecs *uint64 `json:"max_wait_for_secs,omitempty"`
}

type AriaOptions struct {
    KeySizes *[]uint32 `json:"key_sizes,omitempty"`
    TagLength *uint8 `json:"tag_length,omitempty"`
    CipherMode *CipherMode `json:"cipher_mode,omitempty"`
    RandomIv *bool `json:"random_iv,omitempty"`
    IvLength *uint8 `json:"iv_length,omitempty"`
}

type AriaOptionsPolicy struct {
    KeySizes *[]uint32 `json:"key_sizes,omitempty"`
    RandomIv *bool `json:"random_iv,omitempty"`
}

// <https://www.w3.org/TR/webauthn-2/#enum-attestation-convey>
// <https://www.w3.org/TR/webauthn-2/#sctn-attestation>
//
// If you really want to understand attestation, read the following:
//   <https://fidoalliance.org/fido-technotes-the-truth-about-attestation/>
//   <https://medium.com/webauthnworks/webauthn-fido2-demystifying-attestation-and-mds-efc3b3cb3651>
//
// This enum just specified how the attestation should be conveyed
// to the RP. You can see doc of the individual variants to understand
// various ways.
type AttestationConveyancePreference string

// List of supported AttestationConveyancePreference values
const (
    // When RP is not interested in attestation. In this case,
    // attestation statement is None and RP can't identify the
    // device.
    //
    // <https://www.w3.org/TR/webauthn-2/#sctn-none-attestation>
    //
    // This maybe good for UX as attestation may need user consent.
    AttestationConveyancePreferenceNone AttestationConveyancePreference = "none"
    // RP prefers getting attestation statement but allows client
    // to decide how to obtain it. (e.g., client may replace
    // authenticator generated statement with [Anonymization CA])
    //
    // [Anonymization CA]: <https://www.w3.org/TR/webauthn-2/#anonymization-ca>
    AttestationConveyancePreferenceIndirect AttestationConveyancePreference = "indirect"
    // RP wants attestation statement as generated by the authenticator.
    AttestationConveyancePreferenceDirect AttestationConveyancePreference = "direct"
    // RP wants attestation statement which can uniquely identify
    // the authenticator. Generally meant for enterpise use.
    // See spec for more info.
    AttestationConveyancePreferenceEnterprise AttestationConveyancePreference = "enterprise"
)

// LDAP authentication settings.
type AuthConfigLdap struct {
    Name string `json:"name"`
    IconURL string `json:"icon_url"`
    LdapURL string `json:"ldap_url"`
    DnResolution LdapDnResolution `json:"dn_resolution"`
    TLS TlsConfig `json:"tls"`
    BaseDn *string `json:"base_dn,omitempty"`
    UserObjectClass *string `json:"user_object_class,omitempty"`
    ServiceAccount *LdapServiceAccount `json:"service_account,omitempty"`
    Authorization *LdapAuthorizationConfig `json:"authorization,omitempty"`
}

// Extensions for webauthn. For every extension input, an
// output must be returned if the input was considered.
//
// https://www.w3.org/TR/webauthn-2/#dictdef-authenticationextensionsclientinputs
type AuthenticationExtensionsClientInputs struct {
    // This extension excludes authenticators during registration
    // based on legacy u2f key handles specified in "excludeCredentials".
    // If that key handle was created with that device, it is excluded.
    //
    // https://www.w3.org/TR/webauthn-2/#sctn-appid-exclude-extension
    AppidExclude *string `json:"appidExclude,omitempty"`
    // This extension allows RPs that have previously registered a cred
    // using legacy U2F APIs to request an assertion.
    //
    // https://www.w3.org/TR/webauthn-2/#sctn-appid-extension
    Appid *string `json:"appid,omitempty"`
    // Dummy extension used by conformance tests
    Example *bool `json:"example.extension.bool,omitempty"`
}

// This is the response of extension inputs. For every input,
// an output must be returned if the input was considered.
//
// <https://www.w3.org/TR/webauthn-2/#iface-authentication-extensions-client-outputs>
type AuthenticationExtensionsClientOutputs struct {
    // Response of `appidExclude` extension.
    // See [AuthenticationExtensionsClientInputs::appid_exclude].
    AppidExclude *bool `json:"appidExclude,omitempty"`
    // Response of `appid` extension.
    // See [AuthenticationExtensionsClientInputs::appid].
    Appid *bool `json:"appid,omitempty"`
}

// <https://www.w3.org/TR/webauthn-2/#iface-authenticatorassertionresponse>
type AuthenticatorAssertionResponse struct {
    // Base64url of client_data in JSON format.
    ClientDataJson Base64UrlSafe `json:"clientDataJSON"`
    // Data returned by authenticator.
    // <https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data>
    AuthenticatorData Base64UrlSafe `json:"authenticatorData"`
    // Raw signature returned by authenticator.
    // <https://www.w3.org/TR/webauthn-2/#sctn-op-get-assertion>
    Signature Base64UrlSafe `json:"signature"`
    // Corresponds to [PublicKeyCredentialUserEntity::id] sent during
    // credential creation.
    UserHandle *Base64UrlSafe `json:"userHandle,omitempty"`
}

// <https://www.w3.org/TR/webauthn-2/#enumdef-authenticatorattachment>
type AuthenticatorAttachment string

// List of supported AuthenticatorAttachment values
const (
    // An authenticator that is part of the client
    // device. Usually not removable from the client
    // device.
    AuthenticatorAttachmentPlatform AuthenticatorAttachment = "platform"
    // Authenticator that can be removed and used on various
    // devices via cross-platform transport protocols.
    AuthenticatorAttachmentCrossPlatform AuthenticatorAttachment = "cross-platform"
)

// Parameters for deciding which authenticators should be selected.
//
// <https://www.w3.org/TR/webauthn-2/#dictdef-authenticatorselectioncriteria>
type AuthenticatorSelectionCriteria struct {
    // Kind of authenticator attachment: attached to the
    // client device or a roaming authenticator.
    // See type level doc for more info.
    AuthenticatorAttachment *AuthenticatorAttachment `json:"authenticatorAttachment,omitempty"`
    // Preference about creating resident keys or not.
    // See type level doc for more info.
    ResidentKey *ResidentKeyRequirement `json:"residentKey,omitempty"`
    // Exists for backcompat with webauthn level 1.
    // By default it is false and should be set to true
    // if `residentKey` is set to `required`.
    RequireResidentKey *bool `json:"requireResidentKey,omitempty"`
    // Authenticator should support user verification by
    // ways like pin code, biometrics, etc.
    UserVerification *UserVerificationRequirement `json:"userVerification,omitempty"`
}

// Hints by relying party on how client should communicate
// with the authenticator.
//
// https://www.w3.org/TR/webauthn-2/#enum-transport
type AuthenticatorTransport struct {
    // Values known to the spec and DSM.
    Known *AuthenticatorTransportInner
    // Unknown values are stored as spec asks to do so.
    // As per the spec level 3 (which is draft):
    //   "The values SHOULD be members of AuthenticatorTransport
    //   but Relying Parties SHOULD accept and store unknown values."
    // See `[[transports]]` in https://w3c.github.io/webauthn/#iface-authenticatorattestationresponse
    //
    // Level 2 also says that but comparitively unclear.
    //   "The values SHOULD be members of AuthenticatorTransport but
    //   Relying Parties MUST ignore unknown values."
    // See `[[transports]]` in https://www.w3.org/TR/webauthn-2/#iface-authenticatorattestationresponse
    Unknown *string
}
func (x AuthenticatorTransport) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "AuthenticatorTransport", 
                  []bool{ x.Known != nil,
                  x.Unknown != nil });
                  err != nil {
        return nil, err
    }
    if x.Known != nil {
        return json.Marshal(x.Known)
    }
    if x.Unknown != nil {
        return json.Marshal(x.Unknown)
    }
    panic("unreachable")
}
func (x *AuthenticatorTransport) UnmarshalJSON(data []byte) error {
    x.Known = nil
    x.Unknown = nil
    var known AuthenticatorTransportInner
    if err := json.Unmarshal(data, &known); err == nil {
        x.Known = &known
        return nil
    }
    var unknown string
    if err := json.Unmarshal(data, &unknown); err == nil {
        x.Unknown = &unknown
        return nil
    }
    return errors.Errorf("not a valid AuthenticatorTransport")
}

// See [AuthenticatorTransport] type.
type AuthenticatorTransportInner string

// List of supported AuthenticatorTransportInner values
const (
    // Over removable USB.
    AuthenticatorTransportInnerUsb AuthenticatorTransportInner = "usb"
    // Over Near Field Communication (NFC).
    AuthenticatorTransportInnerNfc AuthenticatorTransportInner = "nfc"
    // Over Bluetooth Smart (Bluetooth Low Energy / BLE).
    AuthenticatorTransportInnerBle AuthenticatorTransportInner = "ble"
    // Indicates the respective authenticator is contacted using
    // a client device-specific transport, i.e., it is a platform
    // authenticator. These authenticators are not removable from
    // the client device.
    AuthenticatorTransportInnerInternal AuthenticatorTransportInner = "internal"
)

// Settings for automatic scanning in DSM-backed groups or replication accounts.
type AutoScanSettings struct {
    // The number of hours between successive automatic scans. Must be greater than 0.
    ScanIntervalHours uint8 `json:"scan_interval_hours"`
}

type AwsKeyRotationStatus struct {
    KeyRotationDisabled *struct{}
    KeyRotationEnabled *AwsKeyRotationStatusKeyRotationEnabled
}
type AwsKeyRotationStatusKeyRotationEnabled struct {
    RotationPeriodInDays *uint16 `json:"rotation_period_in_days,omitempty"`
}
func (x AwsKeyRotationStatus) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "AwsKeyRotationStatus", 
                  []bool{ x.KeyRotationDisabled != nil,
                  x.KeyRotationEnabled != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.KeyRotationDisabled != nil:
        m["type"] = "KeyRotationDisabled"
    case x.KeyRotationEnabled != nil:
        b, err := json.Marshal(x.KeyRotationEnabled)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["type"] = "KeyRotationEnabled"
    }
    return json.Marshal(m)
}
func (x *AwsKeyRotationStatus) UnmarshalJSON(data []byte) error {
    x.KeyRotationDisabled = nil
    x.KeyRotationEnabled = nil
    var h struct {
        Tag string `json:"type"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid AwsKeyRotationStatus")
    }
    switch h.Tag {
    case "KeyRotationDisabled":
        x.KeyRotationDisabled = &struct{}{}
    case "KeyRotationEnabled":
        var keyRotationEnabled AwsKeyRotationStatusKeyRotationEnabled
        if err := json.Unmarshal(data, &keyRotationEnabled); err != nil {
            return err
        }
        x.KeyRotationEnabled = &keyRotationEnabled
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

// Information and properties of AWS KMS resources.
type AwsKmsInfo struct {
    MultiRegion *AwsMultiRegionInfo `json:"multi_region,omitempty"`
    // Rotation setting of the AWS KMS key. Note that this is unrelated to
    // DSM key rotation/key rotation policy.
    //
    // See the [AWS documentation](https://docs.aws.amazon.com/kms/latest/APIReference/API_GetKeyRotationStatus.html)
    // for more information.
    AwsKeyRotationStatus *AwsKeyRotationStatus `json:"aws_key_rotation_status,omitempty"`
}

// This structure mentions various properties
// of AWS multi region keys.
// https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html
type AwsMultiRegionInfo struct {
    // Specifies the type of multi region key to be
    // either a Primary key or a Replica key.
    MultiRegionKeyType AwsMultiRegionKeyType `json:"multi_region_key_type"`
    // Specifies a replica key's primary key ARN.
    PrimaryKeyArn *string `json:"primary_key_arn,omitempty"`
    // Specifies ARNs of a primary key's replicas.
    ReplicaKeyArns *[]string `json:"replica_key_arns,omitempty"`
}

// Specifies the type of multi-Region keys.
// https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html#multi-region-concepts
type AwsMultiRegionKeyType string

// List of supported AwsMultiRegionKeyType values
const (
    AwsMultiRegionKeyTypePrimary AwsMultiRegionKeyType = "PRIMARY"
    AwsMultiRegionKeyTypeReplica AwsMultiRegionKeyType = "REPLICA"
)

// The BIP32 network
// The Testnet network is usually an actual network with nodes and miners, and
// free cryptocurrency. This provides a testing environment for developers.
type Bip32Network string

// List of supported Bip32Network values
const (
    Bip32NetworkMainnet Bip32Network = "mainnet"
    Bip32NetworkTestnet Bip32Network = "testnet"
)

type Bip32Options struct {
    // The BIP32 path, starting from master. Master key is Some([]).
    // Ex: m/42/42'/0 -> Some([42, 2**31 + 42, 0])
    DerivationPath *[]uint32 `json:"derivation_path,omitempty"`
    Network *Bip32Network `json:"network,omitempty"`
}

type Bip32OptionsPolicy struct {
}

type BlsOptions struct {
    Variant BlsVariant `json:"variant"`
}

type BlsOptionsPolicy struct {
}

// Signature/public-key size trade-off for BLS.
type BlsVariant string

// List of supported BlsVariant values
const (
    BlsVariantSmallSignatures BlsVariant = "small_signatures"
    BlsVariantSmallPublicKeys BlsVariant = "small_public_keys"
)

// CA settings.
type CaConfig struct {
    CaSet *CaSet
    Pinned *[]Blob
}
func (x CaConfig) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "CaConfig", 
                  []bool{ x.CaSet != nil,
                  x.Pinned != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        CaSet *CaSet `json:"ca_set,omitempty"`
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
        CaSet *CaSet `json:"ca_set,omitempty"`
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

type CertificateOptionsPolicy struct {
}

// Cipher mode used for symmetric key algorithms.
type CipherMode string

// List of supported CipherMode values
const (
    CipherModeEcb CipherMode = "ECB"
    CipherModeCbc CipherMode = "CBC"
    CipherModeCbcNoPad CipherMode = "CBCNOPAD"
    CipherModeCfb CipherMode = "CFB"
    CipherModeOfb CipherMode = "OFB"
    CipherModeCtr CipherMode = "CTR"
    CipherModeGcm CipherMode = "GCM"
    CipherModeCcm CipherMode = "CCM"
    CipherModeKw CipherMode = "KW"
    CipherModeKwp CipherMode = "KWP"
    CipherModeFf1 CipherMode = "FF1"
)

type ClientConfigurations struct {
    // NOTE: not all clients use `common` configurations.
    Common *CommonClientConfig `json:"common,omitempty"`
    Pkcs11 *Pkcs11ClientConfig `json:"pkcs11,omitempty"`
    Kmip *KmipClientConfig `json:"kmip,omitempty"`
    Tep *TepClientConfig `json:"tep,omitempty"`
}

type ClientConfigurationsRequest struct {
    Common *Removable[CommonClientConfig] `json:"common,omitempty"`
    Pkcs11 *Removable[Pkcs11ClientConfig] `json:"pkcs11,omitempty"`
    Kmip *Removable[KmipClientConfig] `json:"kmip,omitempty"`
    Tep *Removable[TepClientConfig] `json:"tep,omitempty"`
}

type ClientFileLogging struct {
    Enabled *ClientFileLoggingConfig
    Disabled *struct{}
}
func (x ClientFileLogging) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "ClientFileLogging", 
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
        m["mode"] = "enabled"
    case x.Disabled != nil:
        m["mode"] = "disabled"
    }
    return json.Marshal(m)
}
func (x *ClientFileLogging) UnmarshalJSON(data []byte) error {
    x.Enabled = nil
    x.Disabled = nil
    var h struct {
        Tag string `json:"mode"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid ClientFileLogging")
    }
    switch h.Tag {
    case "enabled":
        var enabled ClientFileLoggingConfig
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

type ClientFileLoggingConfig struct {
    Path *string `json:"path,omitempty"`
    FileSizeKb *uint64 `json:"file_size_kb,omitempty"`
    MaxFiles *uint32 `json:"max_files,omitempty"`
}

type ClientLogConfig struct {
    System *bool `json:"system,omitempty"`
    File *ClientFileLogging `json:"file,omitempty"`
    Level *string `json:"level,omitempty"`
}

type CollectionMetadata struct {
    // Continuation token to continue getting results. If the response contains a continuation_token,
    // the results returned are partial. In that case, the client can make the same request with this
    // continuation token to continue getting results.
    ContinuationToken *string `json:"continuation_token,omitempty"`
    // Count info about the items in the collection matching the request
    Count *ObjectCount `json:"count,omitempty"`
}
func (x CollectionMetadata) MarshalJSON() ([]byte, error) {
    m := make(map[string]interface{})
    { // x.Count is flattened
        b, err := json.Marshal(&x.Count)
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
    if x.ContinuationToken != nil {
        m["continuation_token"] = x.ContinuationToken
    }
    return json.Marshal(&m)
}
func (x *CollectionMetadata) UnmarshalJSON(data []byte) error {
    if err := json.Unmarshal(data, &x.Count); err != nil {
        return err
    }
    var r struct {
    ContinuationToken *string `json:"continuation_token,omitempty"`
    }
    if err := json.Unmarshal(data, &r); err != nil {
        return err
    }
    x.ContinuationToken = r.ContinuationToken
    return nil
}

type CommonClientConfig struct {
    RetryTimeoutMillis *uint64 `json:"retry_timeout_millis,omitempty"`
    CacheTtl *uint64 `json:"cache_ttl,omitempty"`
    Log *ClientLogConfig `json:"log,omitempty"`
    H2NumConnections *uint `json:"h2_num_connections,omitempty"`
    QuorumApproval *QuorumApprovalConfig `json:"quorum_approval,omitempty"`
}

// An indicator of how accurate a count of objects is.
type CountAccuracy struct {
    // An exact count of objects.
    Exact *struct{}
    // An approximate count of objects.
    Approximate *struct{}
}
func (x CountAccuracy) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "CountAccuracy", 
                  []bool{ x.Exact != nil,
                  x.Approximate != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.Exact != nil:
        m["$type"] = "Exact"
    case x.Approximate != nil:
        m["$type"] = "Approximate"
    }
    return json.Marshal(m)
}
func (x *CountAccuracy) UnmarshalJSON(data []byte) error {
    x.Exact = nil
    x.Approximate = nil
    var h struct {
        Tag string `json:"$type"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid CountAccuracy")
    }
    switch h.Tag {
    case "Exact":
        x.Exact = &struct{}{}
    case "Approximate":
        x.Approximate = &struct{}{}
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

// `CipherMode` or `RsaEncryptionPadding`, depending on the encryption algorithm.
type CryptMode struct {
    // Block cipher mode of operation
    Symmetric *CipherMode
    // RSA padding scheme
    Rsa *RsaEncryptionPadding
}
func (x CryptMode) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "CryptMode", 
                  []bool{ x.Symmetric != nil,
                  x.Rsa != nil });
                  err != nil {
        return nil, err
    }
    if x.Symmetric != nil {
        return json.Marshal(x.Symmetric)
    }
    if x.Rsa != nil {
        return json.Marshal(x.Rsa)
    }
    panic("unreachable")
}
func (x *CryptMode) UnmarshalJSON(data []byte) error {
    x.Symmetric = nil
    x.Rsa = nil
    var symmetric CipherMode
    if err := json.Unmarshal(data, &symmetric); err == nil {
        x.Symmetric = &symmetric
        return nil
    }
    var rsa RsaEncryptionPadding
    if err := json.Unmarshal(data, &rsa); err == nil {
        x.Rsa = &rsa
        return nil
    }
    return errors.Errorf("not a valid CryptMode")
}

type CryptographicPolicy struct {
    Aes *AesOptionsPolicy `json:"aes,omitempty"`
    Aria *AriaOptionsPolicy `json:"aria,omitempty"`
    Des3 *Des3OptionsPolicy `json:"des3,omitempty"`
    Rsa *RsaOptionsPolicy `json:"rsa,omitempty"`
    Hmac *HmacOptionsPolicy `json:"hmac,omitempty"`
    Ec *EcOptionsPolicy `json:"ec,omitempty"`
    LegacyPolicy *LegacyKeyPolicy `json:"legacy_policy,omitempty"`
    KeyOps *KeyOperations `json:"key_ops,omitempty"`
    Des *DesOptionsPolicy `json:"des,omitempty"`
    Seed *SeedOptionsPolicy `json:"seed,omitempty"`
    Dsa *DsaOptionsPolicy `json:"dsa,omitempty"`
    Kcdsa *KcdsaOptionsPolicy `json:"kcdsa,omitempty"`
    Eckcdsa *EcKcdsaOptionsPolicy `json:"eckcdsa,omitempty"`
    Lms *LmsOptionsPolicy `json:"lms,omitempty"`
    Xmss *XmssOptionsPolicy `json:"xmss,omitempty"`
    MldsaBeta *MlDsaBetaOptionsPolicy `json:"mldsa_beta,omitempty"`
    MlkemBeta *MlKemBetaOptionsPolicy `json:"mlkem_beta,omitempty"`
    Bip32 *Bip32OptionsPolicy `json:"bip32,omitempty"`
    Bls *BlsOptionsPolicy `json:"bls,omitempty"`
    Opaque *OpaqueOptionsPolicy `json:"opaque,omitempty"`
    Secret *SecretOptionsPolicy `json:"secret,omitempty"`
    Certificate *CertificateOptionsPolicy `json:"certificate,omitempty"`
}

type CustomAttributeSearchMetadata struct {
    Suggest *bool `json:"suggest,omitempty"`
}

type Des3Options struct {
    KeySizes *[]uint32 `json:"key_sizes,omitempty"`
    CipherMode *CipherMode `json:"cipher_mode,omitempty"`
    RandomIv *bool `json:"random_iv,omitempty"`
    IvLength *int32 `json:"iv_length,omitempty"`
}

// Cryptographic policy for triple DES objects. Setting `key_sizes: [168]`
// forbids two-key triple DES.
type Des3OptionsPolicy struct {
    KeySizes *[]uint32 `json:"key_sizes,omitempty"`
    RandomIv *bool `json:"random_iv,omitempty"`
}

type DesOptions struct {
    CipherMode *CipherMode `json:"cipher_mode,omitempty"`
    RandomIv *bool `json:"random_iv,omitempty"`
}

type DesOptionsPolicy struct {
    RandomIv *bool `json:"random_iv,omitempty"`
}

// A hash algorithm.
type DigestAlgorithm string

// List of supported DigestAlgorithm values
const (
    DigestAlgorithmBlake2b256 DigestAlgorithm = "BLAKE2B256"
    DigestAlgorithmBlake2b384 DigestAlgorithm = "BLAKE2B384"
    DigestAlgorithmBlake2b512 DigestAlgorithm = "BLAKE2B512"
    DigestAlgorithmBlake2s256 DigestAlgorithm = "BLAKE2S256"
    DigestAlgorithmRipemd160 DigestAlgorithm = "RIPEMD160"
    DigestAlgorithmSsl3 DigestAlgorithm = "SSL3"
    DigestAlgorithmSha1 DigestAlgorithm = "SHA1"
    DigestAlgorithmSha224 DigestAlgorithm = "SHA224"
    DigestAlgorithmSha256 DigestAlgorithm = "SHA256"
    DigestAlgorithmSha384 DigestAlgorithm = "SHA384"
    DigestAlgorithmSha512 DigestAlgorithm = "SHA512"
    DigestAlgorithmStreebog256 DigestAlgorithm = "STREEBOG256"
    DigestAlgorithmStreebog512 DigestAlgorithm = "STREEBOG512"
    DigestAlgorithmSha3_224 DigestAlgorithm = "SHA3_224"
    DigestAlgorithmSha3_256 DigestAlgorithm = "SHA3_256"
    DigestAlgorithmSha3_384 DigestAlgorithm = "SHA3_384"
    DigestAlgorithmSha3_512 DigestAlgorithm = "SHA3_512"
)

type DsaOptions struct {
    SubgroupSize *uint32 `json:"subgroup_size,omitempty"`
}

type DsaOptionsPolicy struct {
}

type EcKcdsaOptions struct {
    HashAlg *DigestAlgorithm `json:"hash_alg,omitempty"`
}

type EcKcdsaOptionsPolicy struct {
}

type EcOptionsPolicy struct {
    EllipticCurves *[]EllipticCurve `json:"elliptic_curves,omitempty"`
}

// Operations allowed to be performed on a given key by a given User or an app
type EffectiveKeyOperations uint64

// List of supported EffectiveKeyOperations values
const (
    //  If this is set, the key can be used for signing.
    EffectiveKeyOperationsSign EffectiveKeyOperations = 1 << iota
    //  If this is set, the key can used for verifying a signature.
    EffectiveKeyOperationsVerify
    //  If this is set, the key can be used for encryption.
    EffectiveKeyOperationsEncrypt
    //  If this is set, the key can be used for decryption.
    EffectiveKeyOperationsDecrypt
    //  If this is set, the key can be used wrapping other keys.
    //  The key being wrapped must have the EXPORT operation enabled.
    EffectiveKeyOperationsWrapkey
    //  If this is set, the key can be used to unwrap a wrapped key.
    EffectiveKeyOperationsUnwrapkey
    //  If this is set, the key can be used to derive another key.
    EffectiveKeyOperationsDerivekey
    //  If this is set, the key can be transformed.
    EffectiveKeyOperationsTransform
    //  If this is set, the key can be used to compute a cryptographic
    //  Message Authentication Code (MAC) on a message.
    EffectiveKeyOperationsMacgenerate
    //  If they is set, the key can be used to verify a MAC.
    EffectiveKeyOperationsMacverify
    //  If this is set, the value of the key can be retrieved
    //  with an authenticated request. This shouldn't be set unless
    //  required. It is more secure to keep the key's value inside DSM only.
    EffectiveKeyOperationsExport
    //  Without this operation, management operations like delete, destroy,
    //  rotate, activate, restore, revoke, revert, update, remove_private, etc.
    //  cannot be performed by a crypto App.
    //  A user with access or admin app can still perform these operations.
    //  This option is only relevant for crypto apps.
    EffectiveKeyOperationsAppmanageable
    //  If this is set, audit logs will not be recorded for the key.
    //   High volume here tries to signify a key that is being used a lot
    //   and will produce lots of logs. Setting this operation disables
    //   audit logs for the key.
    EffectiveKeyOperationsHighvolume
    //  If this is set, the key can be used for key agreement.
    //  Both the private and public key should have this option enabled
    //  to perform an agree operation.
    EffectiveKeyOperationsAgreekey
    //  If this is set, the key can be used for key encapsulation. The
    //  result is a new symmetric key and a ciphertext.
    EffectiveKeyOperationsEncapsulate
    //  If this is set, the key can be used for key decapsulation. If
    //  decapsulation succeeds, the result is a new symmetric key.
    EffectiveKeyOperationsDecapsulate
    //  If this is set, the key can be used for masked decryption only.
    EffectiveKeyOperationsMaskdecrypt
)

// MarshalJSON converts EffectiveKeyOperations to an array of strings
func (x EffectiveKeyOperations) MarshalJSON() ([]byte, error) {
    s := make([]string, 0)
    if x & EffectiveKeyOperationsSign == EffectiveKeyOperationsSign {
        s = append(s, "SIGN")
    }
    if x & EffectiveKeyOperationsVerify == EffectiveKeyOperationsVerify {
        s = append(s, "VERIFY")
    }
    if x & EffectiveKeyOperationsEncrypt == EffectiveKeyOperationsEncrypt {
        s = append(s, "ENCRYPT")
    }
    if x & EffectiveKeyOperationsDecrypt == EffectiveKeyOperationsDecrypt {
        s = append(s, "DECRYPT")
    }
    if x & EffectiveKeyOperationsWrapkey == EffectiveKeyOperationsWrapkey {
        s = append(s, "WRAPKEY")
    }
    if x & EffectiveKeyOperationsUnwrapkey == EffectiveKeyOperationsUnwrapkey {
        s = append(s, "UNWRAPKEY")
    }
    if x & EffectiveKeyOperationsDerivekey == EffectiveKeyOperationsDerivekey {
        s = append(s, "DERIVEKEY")
    }
    if x & EffectiveKeyOperationsTransform == EffectiveKeyOperationsTransform {
        s = append(s, "TRANSFORM")
    }
    if x & EffectiveKeyOperationsMacgenerate == EffectiveKeyOperationsMacgenerate {
        s = append(s, "MACGENERATE")
    }
    if x & EffectiveKeyOperationsMacverify == EffectiveKeyOperationsMacverify {
        s = append(s, "MACVERIFY")
    }
    if x & EffectiveKeyOperationsExport == EffectiveKeyOperationsExport {
        s = append(s, "EXPORT")
    }
    if x & EffectiveKeyOperationsAppmanageable == EffectiveKeyOperationsAppmanageable {
        s = append(s, "APPMANAGEABLE")
    }
    if x & EffectiveKeyOperationsHighvolume == EffectiveKeyOperationsHighvolume {
        s = append(s, "HIGHVOLUME")
    }
    if x & EffectiveKeyOperationsAgreekey == EffectiveKeyOperationsAgreekey {
        s = append(s, "AGREEKEY")
    }
    if x & EffectiveKeyOperationsEncapsulate == EffectiveKeyOperationsEncapsulate {
        s = append(s, "ENCAPSULATE")
    }
    if x & EffectiveKeyOperationsDecapsulate == EffectiveKeyOperationsDecapsulate {
        s = append(s, "DECAPSULATE")
    }
    if x & EffectiveKeyOperationsMaskdecrypt == EffectiveKeyOperationsMaskdecrypt {
        s = append(s, "MASKDECRYPT")
    }
    return json.Marshal(s)
}

// UnmarshalJSON converts array of strings to EffectiveKeyOperations
func (x *EffectiveKeyOperations) UnmarshalJSON(data []byte) error {
    *x = 0
    var s []string
    if err := json.Unmarshal(data, &s); err != nil {
        return err
    }
    for _, v := range s {
        switch v {
        case "SIGN":
            *x = *x | EffectiveKeyOperationsSign
        case "VERIFY":
            *x = *x | EffectiveKeyOperationsVerify
        case "ENCRYPT":
            *x = *x | EffectiveKeyOperationsEncrypt
        case "DECRYPT":
            *x = *x | EffectiveKeyOperationsDecrypt
        case "WRAPKEY":
            *x = *x | EffectiveKeyOperationsWrapkey
        case "UNWRAPKEY":
            *x = *x | EffectiveKeyOperationsUnwrapkey
        case "DERIVEKEY":
            *x = *x | EffectiveKeyOperationsDerivekey
        case "TRANSFORM":
            *x = *x | EffectiveKeyOperationsTransform
        case "MACGENERATE":
            *x = *x | EffectiveKeyOperationsMacgenerate
        case "MACVERIFY":
            *x = *x | EffectiveKeyOperationsMacverify
        case "EXPORT":
            *x = *x | EffectiveKeyOperationsExport
        case "APPMANAGEABLE":
            *x = *x | EffectiveKeyOperationsAppmanageable
        case "HIGHVOLUME":
            *x = *x | EffectiveKeyOperationsHighvolume
        case "AGREEKEY":
            *x = *x | EffectiveKeyOperationsAgreekey
        case "ENCAPSULATE":
            *x = *x | EffectiveKeyOperationsEncapsulate
        case "DECAPSULATE":
            *x = *x | EffectiveKeyOperationsDecapsulate
        case "MASKDECRYPT":
            *x = *x | EffectiveKeyOperationsMaskdecrypt
        }
    }
    return nil
}

// An aggregation of policies and permissions of the session creator for
// a security object.
type EffectiveKeyPolicy struct {
    // Indicates allowed key operations for the security key.
    KeyOps EffectiveKeyOperations `json:"key_ops"`
    // The effective export policy for the sobject. This takes both the sobject-level and group-level
    // export policies into account.
    //
    // This field will only be present if the request explicitly asks for it.
    //
    // Note: The wrapping keys in the effective export policy may be specified either by name or
    // by key id, and this may not correspond to how the wrapping key is specified either at the
    // sobject-level or group-level export policy.
    //
    // Note: presence of a wrapping key in effective export policy DOES NOT guarantee that the
    // wrapping key can be used by the current user/app to wrap the sobject for several reasons:
    // the wrapping key may not actually exist, it may not have the necessary permissions, the
    // user/app may not have access to the wrapping key, etc.
    ExportPolicy *ExportPolicy `json:"export_policy,omitempty"`
}

// Identifies a standardized elliptic curve.
type EllipticCurve string

// List of supported EllipticCurve values
const (
    EllipticCurveX25519 EllipticCurve = "X25519"
    EllipticCurveEd25519 EllipticCurve = "Ed25519"
    EllipticCurveX448 EllipticCurve = "X448"
    EllipticCurveSecP192K1 EllipticCurve = "SecP192K1"
    EllipticCurveSecP224K1 EllipticCurve = "SecP224K1"
    EllipticCurveSecP256K1 EllipticCurve = "SecP256K1"
    EllipticCurveNistP192 EllipticCurve = "NistP192"
    EllipticCurveNistP224 EllipticCurve = "NistP224"
    EllipticCurveNistP256 EllipticCurve = "NistP256"
    EllipticCurveNistP384 EllipticCurve = "NistP384"
    EllipticCurveNistP521 EllipticCurve = "NistP521"
    EllipticCurveGost256A EllipticCurve = "Gost256A"
)

type ExportPolicy struct {
    // The sobject can only be exported wrapped by a key as specified
    // by the `WrappingKeys`.
    Wrapped *ExportPolicyWrapped
    // The sobject can be exported unwrapped. This is the default policy
    // for groups and also sobjects that have the `EXPORT` permission but
    // do not specify an explicit export policy.
    Unrestricted *struct{}
}
// The sobject can only be exported wrapped by a key as specified
// by the `WrappingKeys`.
type ExportPolicyWrapped struct {
    By WrappingKeys `json:"by"`
}
func (x ExportPolicy) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "ExportPolicy", 
                  []bool{ x.Wrapped != nil,
                  x.Unrestricted != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.Wrapped != nil:
        b, err := json.Marshal(x.Wrapped)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["$type"] = "Wrapped"
    case x.Unrestricted != nil:
        m["$type"] = "Unrestricted"
    }
    return json.Marshal(m)
}
func (x *ExportPolicy) UnmarshalJSON(data []byte) error {
    x.Wrapped = nil
    x.Unrestricted = nil
    var h struct {
        Tag string `json:"$type"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid ExportPolicy")
    }
    switch h.Tag {
    case "Wrapped":
        var wrapped ExportPolicyWrapped
        if err := json.Unmarshal(data, &wrapped); err != nil {
            return err
        }
        x.Wrapped = &wrapped
    case "Unrestricted":
        x.Unrestricted = &struct{}{}
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

type ExternalKeyId struct {
    Pkcs11 *ExternalKeyIdPkcs11
    Fortanix *ExternalKeyIdFortanix
    AwsKms *ExternalKeyIdAwsKms
    AzureKeyVault *ExternalKeyIdAzureKeyVault
    GcpKeyRing *ExternalKeyIdGcpKeyRing
    Wrapped *struct{}
}
type ExternalKeyIdPkcs11 struct {
    ID Blob `json:"id"`
    Label Blob `json:"label"`
}
type ExternalKeyIdFortanix struct {
    ID UUID `json:"id"`
}
type ExternalKeyIdAwsKms struct {
    KeyArn string `json:"key_arn"`
    KeyID string `json:"key_id"`
}
type ExternalKeyIdAzureKeyVault struct {
    Version UUID `json:"version"`
    Label string `json:"label"`
}
type ExternalKeyIdGcpKeyRing struct {
    Version uint32 `json:"version"`
    Label string `json:"label"`
}
func (x ExternalKeyId) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "ExternalKeyId", 
                  []bool{ x.Pkcs11 != nil,
                  x.Fortanix != nil,
                  x.AwsKms != nil,
                  x.AzureKeyVault != nil,
                  x.GcpKeyRing != nil,
                  x.Wrapped != nil });
                  err != nil {
        return nil, err
    }
    if x.Pkcs11 != nil {
        return json.Marshal(x.Pkcs11)
    }
    if x.Fortanix != nil {
        return json.Marshal(x.Fortanix)
    }
    if x.AwsKms != nil {
        return json.Marshal(x.AwsKms)
    }
    if x.AzureKeyVault != nil {
        return json.Marshal(x.AzureKeyVault)
    }
    if x.GcpKeyRing != nil {
        return json.Marshal(x.GcpKeyRing)
    }
    if x.Wrapped != nil {
        return json.Marshal(x.Wrapped)
    }
    panic("unreachable")
}
func (x *ExternalKeyId) UnmarshalJSON(data []byte) error {
    x.Pkcs11 = nil
    x.Fortanix = nil
    x.AwsKms = nil
    x.AzureKeyVault = nil
    x.GcpKeyRing = nil
    x.Wrapped = nil
    var pkcs11 ExternalKeyIdPkcs11
    if err := json.Unmarshal(data, &pkcs11); err == nil {
        x.Pkcs11 = &pkcs11
        return nil
    }
    var fortanix ExternalKeyIdFortanix
    if err := json.Unmarshal(data, &fortanix); err == nil {
        x.Fortanix = &fortanix
        return nil
    }
    var awsKms ExternalKeyIdAwsKms
    if err := json.Unmarshal(data, &awsKms); err == nil {
        x.AwsKms = &awsKms
        return nil
    }
    var azureKeyVault ExternalKeyIdAzureKeyVault
    if err := json.Unmarshal(data, &azureKeyVault); err == nil {
        x.AzureKeyVault = &azureKeyVault
        return nil
    }
    var gcpKeyRing ExternalKeyIdGcpKeyRing
    if err := json.Unmarshal(data, &gcpKeyRing); err == nil {
        x.GcpKeyRing = &gcpKeyRing
        return nil
    }
    var wrapped struct{}
    if err := json.Unmarshal(data, &wrapped); err == nil {
        x.Wrapped = &wrapped
        return nil
    }
    return errors.Errorf("not a valid ExternalKeyId")
}

// Information specific to an external KMS. Currently, it only has AWS
// related information.
type ExternalKmsInfo struct {
    AWS *AwsKmsInfo
}
func (x ExternalKmsInfo) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "ExternalKmsInfo", 
                  []bool{ x.AWS != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.AWS != nil:
        b, err := json.Marshal(x.AWS)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["type"] = "AWS"
    }
    return json.Marshal(m)
}
func (x *ExternalKmsInfo) UnmarshalJSON(data []byte) error {
    x.AWS = nil
    var h struct {
        Tag string `json:"type"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid ExternalKmsInfo")
    }
    switch h.Tag {
    case "AWS":
        var aWS AwsKmsInfo
        if err := json.Unmarshal(data, &aWS); err != nil {
            return err
        }
        x.AWS = &aWS
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

// This describes an external object -- specifically, information about its source object.
type ExternalSobjectInfo struct {
    // The ID of the external object in the external HSM.
    ID ExternalKeyId `json:"id"`
    // The group which corresponds to the external HSM.
    HsmGroupID UUID `json:"hsm_group_id"`
    ExternalKmsInfo *ExternalKmsInfo `json:"external_kms_info,omitempty"`
}

// Fido2 options when requesting assertion or attestation to a device
type Fido2MfaChallengeResponse struct {
    // Attestation options
    Registration *PublicKeyCredentialCreationOptions
    // Assertion options
    Authentication *PublicKeyCredentialRequestOptions
}
func (x Fido2MfaChallengeResponse) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "Fido2MfaChallengeResponse", 
                  []bool{ x.Registration != nil,
                  x.Authentication != nil });
                  err != nil {
        return nil, err
    }
    if x.Registration != nil {
        return json.Marshal(x.Registration)
    }
    if x.Authentication != nil {
        return json.Marshal(x.Authentication)
    }
    panic("unreachable")
}
func (x *Fido2MfaChallengeResponse) UnmarshalJSON(data []byte) error {
    x.Registration = nil
    x.Authentication = nil
    var registration PublicKeyCredentialCreationOptions
    if err := json.Unmarshal(data, &registration); err == nil {
        x.Registration = &registration
        return nil
    }
    var authentication PublicKeyCredentialRequestOptions
    if err := json.Unmarshal(data, &authentication); err == nil {
        x.Authentication = &authentication
        return nil
    }
    return errors.Errorf("not a valid Fido2MfaChallengeResponse")
}

// The alphabet to use for an encrypted portion of a complex tokenization data type.
// Characters should be specified as a list of pairs, where each pair [a, b] represents the
// range of Unicode code points from a to b, with both bounds being inclusive. A single
// code point can be specified as [c, c].
//
// Normally, each character is assigned a numeric value for FF1. The first character is
// assigned a value of 0, and subsequent characters are assigned values of 1, 2, and so on,
// up to the size of the alphabet. Note that the order of the ranges matters; characters
// appearing in later ranges are assigned higher numerical values compared to earlier
// characters. For instance, in the FpeCharSet [['a', 'z'], ['0', '9']], the digits '0' to
// '9' are assigned values from 26 to 35, since they are listed after the 'a' to 'z' range.
//
// In any case, ranges should not overlap with each other, and should not contain surrogate
// code points.
type FpeCharSet = [][2]Char

// Structure of a compound portion of a complex tokenization data type, itself composed of
// smaller parts.
type FpeCompoundPart struct {
    // Represents an OR of multiple structures.
    //
    // Implementation note: an OR is _not_ a union of `FpeDataPart`s. Rather, when parsing
    // the input, the backend will simply choose the first subpart that matches the current
    // portion of the input, and tokenize/detokenize accordingly. If that choice results in
    // an invalid parse of the rest of the input, the backend ***will not backtrack*** and
    // will simply return with an error.
    Or *FpeCompoundPartOr
    // Represents a concatenation of multiple structures (in a particular order).
    Concat *FpeCompoundPartConcat
    // Indicates a part that is possibly repeated multiple times.
    //
    // Implementation note: the backend parser is locally "greedy" and will attempt to match
    // as many repetitions as possible. If this later results in an invalid parse of the rest
    // of the input, the backend ***will not backtrack*** and will simply return with an error.
    Multiple *FpeCompoundPartMultiple
}
// Represents an OR of multiple structures.
//
// Implementation note: an OR is _not_ a union of `FpeDataPart`s. Rather, when parsing
// the input, the backend will simply choose the first subpart that matches the current
// portion of the input, and tokenize/detokenize accordingly. If that choice results in
// an invalid parse of the rest of the input, the backend ***will not backtrack*** and
// will simply return with an error.
type FpeCompoundPartOr struct {
    // The actual subparts that make up this compound part.
    Or []FpeDataPart `json:"or"`
    // Additional constraints that the token type must satisfy.
    Constraints *FpeConstraints `json:"constraints,omitempty"`
    // Whether the entire OR should be preserved as-is (i.e., not tokenized). If this is
    // set, any descendant subparts cannot contain any preserve-related fields set.
    Preserve *bool `json:"preserve,omitempty"`
    // Whether the entire OR should be masked when doing masked decryption. If this is set,
    // any descendant subparts cannot contain any mask-related fields set.
    Mask *bool `json:"mask,omitempty"`
    // The minimum allowed length for this part (in chars).
    MinLength *uint32 `json:"min_length,omitempty"`
    // The maximum allowed length for this part (in chars).
    MaxLength *uint32 `json:"max_length,omitempty"`
}
// Represents a concatenation of multiple structures (in a particular order).
type FpeCompoundPartConcat struct {
    // The actual subparts that make up this compound part, in order.
    Concat []FpeDataPart `json:"concat"`
    // Additional constraints that the token type must satisfy.
    Constraints *FpeConstraints `json:"constraints,omitempty"`
    // Whether the entire concat should be preserved as-is (i.e., not tokenized). If this is
    // set, any descendant subparts cannot contain any preserve-related fields set.
    Preserve *bool `json:"preserve,omitempty"`
    // Whether the entire concat should be masked when doing masked decryption. If this is
    // set, any descendant subparts cannot contain any mask-related fields set.
    Mask *bool `json:"mask,omitempty"`
    // The minimum allowed length for this part (in chars).
    MinLength *uint32 `json:"min_length,omitempty"`
    // The maximum allowed length for this part (in chars).
    MaxLength *uint32 `json:"max_length,omitempty"`
}
// Indicates a part that is possibly repeated multiple times.
//
// Implementation note: the backend parser is locally "greedy" and will attempt to match
// as many repetitions as possible. If this later results in an invalid parse of the rest
// of the input, the backend ***will not backtrack*** and will simply return with an error.
type FpeCompoundPartMultiple struct {
    // The subpart that may be repeated.
    Multiple *FpeDataPart `json:"multiple"`
    // The minimum number of times the subpart may occur. (A value of 1 marks a single
    // occurrence.)
    MinRepetitions *uint `json:"min_repetitions,omitempty"`
    // The maximum number of times the subpart may occur. (A value of 1 marks a single
    // occurrence.)
    MaxRepetitions *uint `json:"max_repetitions,omitempty"`
    // Additional constraints that the token type must satisfy.
    Constraints *FpeConstraints `json:"constraints,omitempty"`
    // Whether the entire Multiple should be preserved as-is (i.e., not tokenized). If this
    // is set, the `multiple` subpart and its descendants cannot contain any preserve-related
    // fields set.
    Preserve *bool `json:"preserve,omitempty"`
    // Whether the entire Multiple should be masked when doing masked decryption. If this is
    // set, the `multiple` subpart and its descendants cannot contain any mask-related fields
    // set.
    Mask *bool `json:"mask,omitempty"`
    // The minimum allowed length for this part (in chars).
    MinLength *uint32 `json:"min_length,omitempty"`
    // The maximum allowed length for this part (in chars).
    MaxLength *uint32 `json:"max_length,omitempty"`
}
func (x FpeCompoundPart) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "FpeCompoundPart", 
                  []bool{ x.Or != nil,
                  x.Concat != nil,
                  x.Multiple != nil });
                  err != nil {
        return nil, err
    }
    if x.Or != nil {
        return json.Marshal(x.Or)
    }
    if x.Concat != nil {
        return json.Marshal(x.Concat)
    }
    if x.Multiple != nil {
        return json.Marshal(x.Multiple)
    }
    panic("unreachable")
}
func (x *FpeCompoundPart) UnmarshalJSON(data []byte) error {
    x.Or = nil
    x.Concat = nil
    x.Multiple = nil
    var or FpeCompoundPartOr
    if err := json.Unmarshal(data, &or); err == nil {
        x.Or = &or
        return nil
    }
    var concat FpeCompoundPartConcat
    if err := json.Unmarshal(data, &concat); err == nil {
        x.Concat = &concat
        return nil
    }
    var multiple FpeCompoundPartMultiple
    if err := json.Unmarshal(data, &multiple); err == nil {
        x.Multiple = &multiple
        return nil
    }
    return errors.Errorf("not a valid FpeCompoundPart")
}

// Constraints on a portion of a complex tokenization data type.
type FpeConstraints struct {
    // Whether the token part contains a checksum that satisfies the Luhn formula. It is an
    // error to apply this constraint to non-numeric parts, or to have an encrypted part be
    // under more than one Luhn check constraint. Also, if an encrypted part has a Luhn check
    // constraint applied to it and may contain at least one digit that is not preserved, it
    // must not specify any other constraints.
    LuhnCheck *bool `json:"luhn_check,omitempty"`
    // Number that the token part should be greater than.
    //
    // This constraint can only be specified on (non-compound) numeric encrypted parts
    // guaranteed to preserve either everything or nothing at all. (For example, if an
    // encrypted part consists of 5 to 10 digits, a `preserve` list that covers only the
    // first five digits is not guaranteed to preserve everything, because if the input
    // happens to be six or more digits long, there will be at least one digit that
    // remains unpreserved.)
    NumGt *uint `json:"num_gt,omitempty"`
    // Number that the token part should be smaller than.
    //
    // This constraint can only be specified on (non-compound) numeric encrypted parts
    // guaranteed to preserve either everything or nothing at all. (For example, if an
    // encrypted part consists of 5 to 10 digits, a `preserve` list that covers only the
    // first five digits is not guaranteed to preserve everything, because if the input
    // happens to be six or more digits long, there will be at least one digit that
    // remains unpreserved.)
    NumLt *uint `json:"num_lt,omitempty"`
    // Numbers that the token part should not be equal to. It is an error to apply this
    // constraint to non-numeric parts.
    NumNe *[]uint `json:"num_ne,omitempty"`
    // Specifies that this portion is supposed to represent a date, or part of one. If used,
    // no other constraints can be specified on this part.
    Date *FpeDateConstraint `json:"date,omitempty"`
    // The subparts to apply the constaints to. If not specified, the constraints will be
    // applied to all subparts (recursively).
    AppliesTo *FpeConstraintsApplicability `json:"applies_to,omitempty"`
}

// A structure indicating which subparts to which to apply a set of constraints.
type FpeConstraintsApplicability struct {
    // Indicates that the constraints apply to the entire part (i.e., all of its subparts),
    // including any descendants. This is the default value for this enum and the only option
    // available for FpeEncryptedPart, literal, and OR subparts.
    Simple *All
    // An object representing the individual subparts that the constraints should apply to. This
    // is a BTreeMap where for each key-value pair, the key represents the "index" of the subpart
    // (with the first subpart having index 0), and the value is an FpeConstraintsApplicability
    // instance. Note that a Multiple part only allows for one possible key-value pair, since it
    // only contains one subpart.
    //
    // This cannot be used with OR parts; instead, specify constraints individually on each
    // relevant subpart.
    BySubparts *map[FpeSubpartIndex]FpeConstraintsApplicability
}
func (x FpeConstraintsApplicability) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "FpeConstraintsApplicability", 
                  []bool{ x.Simple != nil,
                  x.BySubparts != nil });
                  err != nil {
        return nil, err
    }
    if x.Simple != nil {
        return json.Marshal(x.Simple)
    }
    if x.BySubparts != nil {
        return json.Marshal(x.BySubparts)
    }
    panic("unreachable")
}
func (x *FpeConstraintsApplicability) UnmarshalJSON(data []byte) error {
    x.Simple = nil
    x.BySubparts = nil
    var simple All
    if err := json.Unmarshal(data, &simple); err == nil {
        x.Simple = &simple
        return nil
    }
    var bySubparts map[FpeSubpartIndex]FpeConstraintsApplicability
    if err := json.Unmarshal(data, &bySubparts); err == nil {
        x.BySubparts = &bySubparts
        return nil
    }
    return errors.Errorf("not a valid FpeConstraintsApplicability")
}

// Structure for specifying (part of) a complex tokenization data type.
type FpeDataPart struct {
    // A portion of a data type consisting of characters that belong to a particular
    // alphabet (e.g., letters, numbers, etc.).
    Encrypted *FpeEncryptedPart
    // A section of the data type that is not to be tokenized (e.g., a delimiter).
    //
    // Unlike preserved characters, literal characters are not used for FF1 tweaks.
    Literal *FpeDataPartLiteral
    // A portion of a data type that consists of several smaller portions (e.g., an
    // `Encrypted` part followed by a `Literal`).
    Compound *FpeCompoundPart
}
// A section of the data type that is not to be tokenized (e.g., a delimiter).
//
// Unlike preserved characters, literal characters are not used for FF1 tweaks.
type FpeDataPartLiteral struct {
    // The list of possible strings that make up this literal portion of the token.
    // For example, if a delimiter can either be a space or a dash, the list would
    // be `[" ", "-"]`.
    //
    // Implementation note: the backend will pick the first choice that matches when
    // when parsing the input. If this results in an invalid parse of the rest of the
    // input, the backend ***will not backtrack*** and will simply return with an error.
    Literal []string `json:"literal"`
}
func (x FpeDataPart) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "FpeDataPart", 
                  []bool{ x.Encrypted != nil,
                  x.Literal != nil,
                  x.Compound != nil });
                  err != nil {
        return nil, err
    }
    if x.Encrypted != nil {
        return json.Marshal(x.Encrypted)
    }
    if x.Literal != nil {
        return json.Marshal(x.Literal)
    }
    if x.Compound != nil {
        return json.Marshal(x.Compound)
    }
    panic("unreachable")
}
func (x *FpeDataPart) UnmarshalJSON(data []byte) error {
    x.Encrypted = nil
    x.Literal = nil
    x.Compound = nil
    var encrypted FpeEncryptedPart
    if err := json.Unmarshal(data, &encrypted); err == nil {
        x.Encrypted = &encrypted
        return nil
    }
    var literal FpeDataPartLiteral
    if err := json.Unmarshal(data, &literal); err == nil {
        x.Literal = &literal
        return nil
    }
    var compound FpeCompoundPart
    if err := json.Unmarshal(data, &compound); err == nil {
        x.Compound = &compound
        return nil
    }
    return errors.Errorf("not a valid FpeDataPart")
}

// A structure for specifying a token part representing a date that occurs after a specified date
// and/or occurs before a specified date. Depending on the subparts that make up the date, one of
// the three options is used.
type FpeDate struct {
    // Represents a date that consists of a Month subpart, a Day subpart, and a Year subpart. The
    // Year part is allowed to be preserved, and the Day and Month parts are allowed to be
    // preserved together. (The Day part cannot be preserved if the Month part is not, and vice
    // versa.)
    DayMonthYear *FpeDateDayMonthYear
    // Represents a date that consists of a Month subpart and a Day subpart. It is an error to
    // preserve only the Month part or the Day part.
    MonthDay *FpeDateMonthDay
    // Represents a date that consists of a Month subpart and a Year subpart. The Year part is
    // allowed to be preserved; however, the Month part cannot be preserved by itself.
    MonthYear *FpeDateMonthYear
}
// Represents a date that consists of a Month subpart, a Day subpart, and a Year subpart. The
// Year part is allowed to be preserved, and the Day and Month parts are allowed to be
// preserved together. (The Day part cannot be preserved if the Month part is not, and vice
// versa.)
type FpeDateDayMonthYear struct {
    Before *FpeDayMonthYearDate `json:"before,omitempty"`
    After *FpeDayMonthYearDate `json:"after,omitempty"`
}
// Represents a date that consists of a Month subpart and a Day subpart. It is an error to
// preserve only the Month part or the Day part.
type FpeDateMonthDay struct {
    Before *FpeDayMonthDate `json:"before,omitempty"`
    After *FpeDayMonthDate `json:"after,omitempty"`
}
// Represents a date that consists of a Month subpart and a Year subpart. The Year part is
// allowed to be preserved; however, the Month part cannot be preserved by itself.
type FpeDateMonthYear struct {
    Before *FpeMonthYearDate `json:"before,omitempty"`
    After *FpeMonthYearDate `json:"after,omitempty"`
}
func (x FpeDate) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "FpeDate", 
                  []bool{ x.DayMonthYear != nil,
                  x.MonthDay != nil,
                  x.MonthYear != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        DayMonthYear *FpeDateDayMonthYear `json:"dmy_date,omitempty"`
        MonthDay *FpeDateMonthDay `json:"month_day_date,omitempty"`
        MonthYear *FpeDateMonthYear `json:"month_year_date,omitempty"`
    }
    obj.DayMonthYear = x.DayMonthYear
    obj.MonthDay = x.MonthDay
    obj.MonthYear = x.MonthYear
    return json.Marshal(obj)
}
func (x *FpeDate) UnmarshalJSON(data []byte) error {
    x.DayMonthYear = nil
    x.MonthDay = nil
    x.MonthYear = nil
    var obj struct {
        DayMonthYear *FpeDateDayMonthYear `json:"dmy_date,omitempty"`
        MonthDay *FpeDateMonthDay `json:"month_day_date,omitempty"`
        MonthYear *FpeDateMonthYear `json:"month_year_date,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.DayMonthYear = obj.DayMonthYear
    x.MonthDay = obj.MonthDay
    x.MonthYear = obj.MonthYear
    return nil
}

// Possible date-related constraint types for a portion of a complex tokenization data type.
type FpeDateConstraint struct {
    // Used to indicate that a token part represents a date, which should occur before and/or
    // after any specified bounds. The part should be a concatenation that contains either
    // - a Day part and a Month part
    // - a Month part and a Year part
    // - a Day part, a Month part, and a Year part
    // (with this constraint applying to those subparts). Each of the three choices above
    // corresponds to a particular FpeDate variant; using the wrong variant is an error.
    //
    // Furthermore, the individual Month, Day, and/or Year parts that comprise the date cannot
    // appear under Or or Multiple compound part descendants of the overall Date part (i.e.,
    // when applying the Date constraint, the "paths" from the Date part to the Month, Day,
    // and/or Year parts can only "go through" concatenations, and not "through" Or or Multiple
    // parts). Those parts also have additional restrictions on how they may be preserved; the
    // exact rules depend on the FpeDate variant.
    //
    // It is an error to "share" Day, Month, or Year parts across multiple dates.
    Date *FpeDate
    // Used to indicate that a token part represents a month, day, or year (either as part of a
    // date, or independently).
    //
    // The token part must be a (non-compound) numeric encrypted part guaranteed to preserve either
    // everything or nothing at all. (For example, if an encrypted part consists of 5 to 10 digits,
    // a `preserve` list that covers only the first five digits is not guaranteed to preserve
    // everything, because if the input happens to be six or more digits long, there will be at
    // least one digit that remains unpreserved.)
    //
    // Additionally, the token part cannot be involved in any Luhn-check constraints.
    DatePart *FpeDatePart
}
func (x FpeDateConstraint) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "FpeDateConstraint", 
                  []bool{ x.Date != nil,
                  x.DatePart != nil });
                  err != nil {
        return nil, err
    }
    if x.Date != nil {
        return json.Marshal(x.Date)
    }
    if x.DatePart != nil {
        return json.Marshal(x.DatePart)
    }
    panic("unreachable")
}
func (x *FpeDateConstraint) UnmarshalJSON(data []byte) error {
    x.Date = nil
    x.DatePart = nil
    var date FpeDate
    if err := json.Unmarshal(data, &date); err == nil {
        x.Date = &date
        return nil
    }
    var datePart FpeDatePart
    if err := json.Unmarshal(data, &datePart); err == nil {
        x.DatePart = &datePart
        return nil
    }
    return errors.Errorf("not a valid FpeDateConstraint")
}

// Possible date-related constraint types that do not form a complete date (by themselves) for a
// complex tokenization data type.
type FpeDatePart string

// List of supported FpeDatePart values
const (
    // Used to indicate that a token part represents a month. The part should be an integer from 1
    // to 12, have its min_length field be at least 1, and have its max_length field be 2. Any
    // leading zero should be removed (unless the part is always 2 digits long, in which case a
    // leading zero may be needed).
    FpeDatePartMonth FpeDatePart = "month"
    // Used to indicate that a token part represents a day. The part should be an integer from 1 to
    // 31, have its min_length field be at least 1, and have its max_length field be 2. Any
    // leading zero should be removed (unless the part is always 2 digits long, in which case a
    // leading zero may be needed). Further restrictions apply when the Day part occurs within a
    // date; for instance, a date of 2/29/2000 is fine, but 4/31 is not.
    FpeDatePartDay FpeDatePart = "day"
    // Used to indicate that a token part represents a year, with any zero value being treated as
    // a leap year. The part should be a two to five digit number.
    FpeDatePartYear FpeDatePart = "year"
)

// A structure for specifying a particular date consisting of a day and a month, for use in an
// FpeDate structure.
type FpeDayMonthDate struct {
    // The month, which should be an integer from 1 to 12.
    Month uint8 `json:"month"`
    // The day, which should be an integer from 1 to either 29, 30, or 31, depending on the month
    // and year. Here, February is treated as having 29 days.
    Day uint8 `json:"day"`
}

// A structure for specifying a particular date consisting of a day, month, and year, for use in
// an FpeDate structure.
type FpeDayMonthYearDate struct {
    // The year, which should be an integer less than 100000. Zero is treated as a leap year.
    Year uint32 `json:"year"`
    // The month, which should be an integer from 1 to 12.
    Month uint8 `json:"month"`
    // The day, which should be an integer from 1 to either 28, 29, 30, or 31, depending on the
    // month and year.
    Day uint8 `json:"day"`
}

// Structure of a tokenized portion of a complex tokenization data type.
//
// Implementation note: the backend parser is locally "greedy" and will attempt to match
// as many characters as possible. If this later results in an invalid parse of the rest
// of the input, the backend ***will not backtrack*** and will simply return with an error.
type FpeEncryptedPart struct {
    // The minimum allowed length for this part (in chars).
    MinLength uint32 `json:"min_length"`
    // The maximum allowed length for this part (in chars).
    MaxLength uint32 `json:"max_length"`
    // The alphabet to use for this part.
    CharSet FpeCharSet `json:"char_set"`
    // The output alphabet to use for this part. Defaults to `char_set` if not specified.
    // When specified, the cardinality of `cipher_char_set` must be the same as `char_set`.
    CipherCharSet *FpeCharSet `json:"cipher_char_set,omitempty"`
    // Additional constraints that the token type must satisfy.
    Constraints *FpeConstraints `json:"constraints,omitempty"`
    // The characters to be preserved while encrypting or decrypting.
    //
    // Any preserved characters will be concatenated together, and their UTF-8 bytes will be used
    // as an FF1 tweak. For example, if the input data is "abcd", and the first and last characters
    // are to be preserved, the FF1 tweak will be the bytes of the string "ad".
    Preserve *FpePreserveMask `json:"preserve,omitempty"`
    // The characters to be masked while performing masked decryption.
    Mask *FpePreserveMask `json:"mask,omitempty"`
}

// A structure for specifying a particular date consisting of a month and a year, for use in an
// FpeDate structure.
type FpeMonthYearDate struct {
    // The year, which should be an integer less than 100000. Zero is treated as a leap year.
    Year uint32 `json:"year"`
    // The month, which should be an integer from 1 to 12.
    Month uint8 `json:"month"`
}

// FPE-specific options (for specifying the format of the
// data to be encrypted)
type FpeOptions struct {
    // Basic FPE options, suitable for simple datatypes. See the
    // description of FpeOptionsBasic for more details.
    Basic *FpeOptionsBasic
    // Advanced FPE options. It is recommended to use this for
    // specifying any FPE options, as it is more expressive than
    // FpeOptionsBasic.
    Advanced *FpeOptionsAdvanced
}
// Advanced FPE options. It is recommended to use this for
// specifying any FPE options, as it is more expressive than
// FpeOptionsBasic.
type FpeOptionsAdvanced struct {
    // The structure of the data type.
    Format FpeDataPart `json:"format"`
    // The user-provided name for the data type.
    Description *string `json:"description,omitempty"`
}
func (x FpeOptions) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "FpeOptions", 
                  []bool{ x.Basic != nil,
                  x.Advanced != nil });
                  err != nil {
        return nil, err
    }
    if x.Basic != nil {
        return json.Marshal(x.Basic)
    }
    if x.Advanced != nil {
        return json.Marshal(x.Advanced)
    }
    panic("unreachable")
}
func (x *FpeOptions) UnmarshalJSON(data []byte) error {
    x.Basic = nil
    x.Advanced = nil
    var basic FpeOptionsBasic
    if err := json.Unmarshal(data, &basic); err == nil {
        x.Basic = &basic
        return nil
    }
    var advanced FpeOptionsAdvanced
    if err := json.Unmarshal(data, &advanced); err == nil {
        x.Advanced = &advanced
        return nil
    }
    return errors.Errorf("not a valid FpeOptions")
}

// Basic FPE-specific options. This is suitable for simple datatypes
// that consist of ASCII digits, or ASCII digits and uppercase letters.
type FpeOptionsBasic struct {
    // The FPE base for the input data (i.e., the size of the character
    // set of the datatype). This must be an integer from 2 to 36.
    //
    // This also implicitly defines the alphabet of the datatype. A base
    // from 2 to 10 implies ASCII digits (e.g., a radix of 3 can be used
    // to represent a ternary string), and a base from 11 to 36 implies
    // ASCII digits and uppercase letters (e.g., a radix of 16 can be
    Radix uint32 `json:"radix"`
    // The minimum allowed length for the input data.
    MinLength uint32 `json:"min_length"`
    // The maximum allowed length for the input data.
    MaxLength uint32 `json:"max_length"`
    // The list of indices of characters to be preserved while performing encryption/decryption.
    // Indices are Python-like; i.e., nonnegative indices index from the beginning of the input
    // (where 0 is the first character), and negative indices index from the end of the input.
    // (where -1 is the last character, -2 is second to last, and so on).
    //
    // Any preserved characters will be concatenated together and used as an FF1 tweak. For example,
    // if the input data is "abcd", and the first and last characters are to be preserved, the FF1
    // tweak will be the ASCII bytes of the string "ad".
    Preserve []int `json:"preserve"`
    // The list of indices of characters to be masked while performing masked decryption.
    // Indices are Python-like; i.e., nonnegative indices index from the beginning of the input
    // (where 0 is the first character), and negative indices index from the end of the input.
    // (where -1 is the last character, -2 is second to last, and so on).
    Mask *[]int `json:"mask,omitempty"`
    // Whether the encrypted/decrypted data contains a checksum digit that satisfies the Luhn
    // formula. (The output ciphertext/plaintext will also contain a Luhn checksum digit.)
    LuhnCheck *bool `json:"luhn_check,omitempty"`
    // The user-provided name for the data type that represents the input data.
    Name *string `json:"name,omitempty"`
}

// A structure indicating which indices in an encrypted part to mask or preserve.
type FpePreserveMask struct {
    // Indicates that the entire encrypted part is to be preserved or masked.
    Entire *All
    // Indicates that only certain characters are to be preserved or masked. Indices are
    // Python-like; i.e., negative indices index from the end of the token portion, with
    // index -1 denoting the last character. (Indicating that nothing should be preserved
    // or masked can be done via an empty list, which is the default value for this enum.)
    ByChars *[]int
}
func (x FpePreserveMask) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "FpePreserveMask", 
                  []bool{ x.Entire != nil,
                  x.ByChars != nil });
                  err != nil {
        return nil, err
    }
    if x.Entire != nil {
        return json.Marshal(x.Entire)
    }
    if x.ByChars != nil {
        return json.Marshal(x.ByChars)
    }
    panic("unreachable")
}
func (x *FpePreserveMask) UnmarshalJSON(data []byte) error {
    x.Entire = nil
    x.ByChars = nil
    var entire All
    if err := json.Unmarshal(data, &entire); err == nil {
        x.Entire = &entire
        return nil
    }
    var byChars []int
    if err := json.Unmarshal(data, &byChars); err == nil {
        x.ByChars = &byChars
        return nil
    }
    return errors.Errorf("not a valid FpePreserveMask")
}

// An index for listing subparts of a compound part to which certain constraints are to be applied.
// For Concat parts, this is the zero-based index of the subpart in the `concat` field, and for
// Multiple parts, this is always 0 (due to a Multiple having only one subpart).
type FpeSubpartIndex = uint

type GetGroupsParams struct {
    Limit *uint `json:"limit,omitempty"`
    SortBy *GroupSort `json:"sort_by,omitempty"`
    // If specified, only groups matching this `filter` are returned.
    //
    // The following fields can be referenced in the filter:
    // - `name`
    // - `created_at`
    // - `description`
    // - `wrapping_key_name`
    Filter *string `json:"filter,omitempty"`
    // Number of groups to skip
    Offset *uint `json:"offset,omitempty"`
    // Continuation token to continue getting results. It must be the same
    // token returned from the backend from a previous call, or empty.
    //
    // Existence of this query parameter controls the response (and the backend behavior):
    // - If specified (including an empty value), the backend returns metadata alongside
    //   the collection of groups. The metadata will potentially contain a fresh `continuation_token`.
    //
    //   Note: If there is a `limit` specified in the request and DSM returns `limit`-many items in the
    //   response, it will still include a fresh continuation token if there are more items in the collection.
    //   Additionally, unlike other query parameters, `limit` is not required to remain unchanged in a chain of
    //   requests with `coninutation_token`s.
    // - If omitted, the backend returns just a collection of groups with no metadata.
    ContinuationToken *string `json:"continuation_token,omitempty"`
}
func (x GetGroupsParams) urlEncode(v map[string][]string) error {
    if x.Limit != nil {
        v["limit"] = []string{fmt.Sprintf("%v", *x.Limit)}
    }
    if err := x.SortBy.urlEncode(v); err != nil {
        return err
    }
    if x.Filter != nil {
        v["filter"] = []string{fmt.Sprintf("%v", *x.Filter)}
    }
    if x.Offset != nil {
        v["offset"] = []string{fmt.Sprintf("%v", *x.Offset)}
    }
    if x.ContinuationToken != nil {
        v["continuation_token"] = []string{fmt.Sprintf("%v", *x.ContinuationToken)}
    }
    return nil
}

// An access reason provided by Google when making EKMS API calls.
type GoogleAccessReason string

// List of supported GoogleAccessReason values
const (
    // No reason is available for the access.
    GoogleAccessReasonReasonUnspecified GoogleAccessReason = "REASON_UNSPECIFIED"
    // Access Transparency Types, public documentation can be found at:
    // https://cloud.google.com/logging/docs/audit/reading-access-transparency-logs#justification-reason-codes
    GoogleAccessReasonCustomerInitiatedSupport GoogleAccessReason = "CUSTOMER_INITIATED_SUPPORT"
    GoogleAccessReasonGoogleInitiatedService GoogleAccessReason = "GOOGLE_INITIATED_SERVICE"
    GoogleAccessReasonThirdPartyDataRequest GoogleAccessReason = "THIRD_PARTY_DATA_REQUEST"
    GoogleAccessReasonGoogleInitiatedReview GoogleAccessReason = "GOOGLE_INITIATED_REVIEW"
    // Customer uses their own account or grants IAM permission to some
    // partner of theirs to perform any access to their own data which is
    // authorized by their own IAM policy.
    GoogleAccessReasonCustomerInitiatedAccess GoogleAccessReason = "CUSTOMER_INITIATED_ACCESS"
    // Google access to data to help optimize the data's structure or quality
    // for future uses by the customer. This includes but is not limited to
    // accesses for the purposes of indexing, structuring, precomputation,
    // hashing, sharding and caching. This also includes backing up data for disaster
    // recovery or data integrity reasons, and detecting errors that can be
    // remedied from that backup data.
    // Note that where the customer has delegated a managed control plane
    // operation to Google, such as the creation of a managed instance group,
    // all managed operations will show as system operations. Services such as
    // the managed instance group manager that trigger downstream decryption
    // operations do not have access to clear-text customer data.
    GoogleAccessReasonGoogleInitiatedSystemOperation GoogleAccessReason = "GOOGLE_INITIATED_SYSTEM_OPERATION"
    // No reason is expected for this key request as the service in
    // question has never integrated with Key Access Justifications, or is still
    // in Pre GA state and therefore may still have residual methods that call
    // the External Key Manager but still do not provide a justification.
    GoogleAccessReasonReasonNotExpected GoogleAccessReason = "REASON_NOT_EXPECTED"
    // A Customer uses their account to perform any access to their own data
    // which is authorized by their own IAM policy, however a Google
    // administrator has reset the superuser account associated with the user’s
    // Organization within the last 7 days.
    GoogleAccessReasonModifiedCustomerInitiatedAccess GoogleAccessReason = "MODIFIED_CUSTOMER_INITIATED_ACCESS"
    // Google accesses customer data to help optimize the structure of the data or quality for future uses by the customer.
    // These accesses can be for indexing, structuring, precomputation, hashing, sharding and caching customer data
    // This also includes backing up data for disaster recovery or data integrity reasons,
    // and detecting errors that the backup data could remedy. At the same time,
    // a Google-initiated breakglass operation has affected the accessed resource.
    GoogleAccessReasonModifiedGoogleInitiatedSystemOperation GoogleAccessReason = "MODIFIED_GOOGLE_INITIATED_SYSTEM_OPERATION"
    // Refers to Google-initiated access to maintain system reliability.
    // Google personnel can make this type of access for the following reasons:
    // - To investigate and confirm that a suspected service outage doesn't affect the customer.
    // - To ensure backup and recovery from outages and system failures.
    GoogleAccessReasonGoogleResponseToProductionAlert GoogleAccessReason = "GOOGLE_RESPONSE_TO_PRODUCTION_ALERT"
    GoogleAccessReasonCustomerAuthorizedWorkflowServicing GoogleAccessReason = "CUSTOMER_AUTHORIZED_WORKFLOW_SERVICING"
)

// Policy specifying acceptable access reasons
// by Google Service Account at App or Sobject level.
type GoogleAccessReasonPolicy struct {
    // Set of allowed Google Access reasons.
    Allow []GoogleAccessReason `json:"allow"`
    // Accept incoming requests which do not specify any access reasons.
    AllowMissingReason bool `json:"allow_missing_reason"`
}

type GroupPermissions uint64

// List of supported GroupPermissions values
const (
    //  Permission to create group-level approval policy. Note that
    //  updating/deleting the approval policy is protected by the approval
    //  policy itself. Implies `GET_GROUP`.
    GroupPermissionsCreateGroupApprovalPolicy GroupPermissions = 1 << iota
    //  Permission to update external HSM/KMS configurations. Note that this
    //  is only useful for groups backed by external HSM/KMS. Implies
    //  `GET_GROUP`.
    GroupPermissionsUpdateGroupExternalLinks
    //  Permission to manage group-level client configurations. Implies
    //  `GET_GROUP`.
    GroupPermissionsManageGroupClientConfigs
    //  Permission to update name, description and custom metadata of the
    //  group. Implies `GET_GROUP`.
    GroupPermissionsUpdateGroupProfile
    //  Permission to delete the group. Implies `GET_GROUP`.
    GroupPermissionsDeleteGroup
    //  Permission to map external roles to DSM groups for apps authorized
    //  through LDAP. Implies `GET_GROUP`.
    GroupPermissionsMapExternalRolesForApps
    //  Permission to map external roles to DSM groups for users authorized
    //  through LDAP. Implies `GET_GROUP`.
    GroupPermissionsMapExternalRolesForUsers
    //  Currently implies `MAP_EXTERNAL_ROLES_FOR_APPS`,
    //  `MAP_EXTERNAL_ROLES_FOR_USERS`, and `GET_GROUP` permissions.
    GroupPermissionsMapExternalRoles
    //  Permission to add users to the group.
    GroupPermissionsAddUsersToGroup
    //  Permission to remove users from the group.
    GroupPermissionsDeleteUsersFromGroup
    //  Permission to change users' role in the group.
    GroupPermissionsUpdateUsersGroupRole
    //  Currently implies `ADD_USERS_TO_GROUP`, `DELETE_USERS_FROM_GROUP`,
    //  and `UPDATE_USERS_GROUP_ROLE` permissions.
    GroupPermissionsManageGroupUsers
    //  Permission to create various group-level security object policies
    //  including cryptographic policy, key metadata policy and key history
    //  policy. Implies `GET_GROUP`.
    GroupPermissionsCreateGroupSobjectPolicies
    //  Permission to update various group-level security object policies
    //  including cryptographic policy, key metadata policy and key history
    //  policy. Implies `GET_GROUP`.
    GroupPermissionsUpdateGroupSobjectPolicies
    //  Permission to delete various group-level security object policies
    //  including cryptographic policy, key metadata policy and key history
    //  policy. Implies `GET_GROUP`.
    GroupPermissionsDeleteGroupSobjectPolicies
    //  Currently implies `CREATE_GROUP_SOBJECT_POLICIES`,
    //  `UPDATE_GROUP_SOBJECT_POLICIES`, `DELETE_GROUP_SOBJECT_POLICIES`,
    //  and `GET_GROUP` permissions.
    GroupPermissionsManageGroupSobjectPolicies
    //  Permission to create key custodian policy for the group. Implies
    //  `GET_GROUP`.
    GroupPermissionsCreateGroupCustodianPolicy
    //  Permission to update group's key custodian policy. Implies
    //  `GET_GROUP`.
    GroupPermissionsUpdateGroupCustodianPolicy
    //  Permission to delete group's key custodian policy. Implies
    //  `GET_GROUP`.
    GroupPermissionsDeleteGroupCustodianPolicy
    //  Currently implies `CREATE_GROUP_CUSTODIAN_POLICY`,
    //  `UPDATE_GROUP_CUSTODIAN_POLICY`, `DELETE_GROUP_CUSTODIAN_POLICY`,
    //  and `GET_GROUP` permissions.
    GroupPermissionsManageGroupCustodianPolicy
    //  Permission to create cryptographic apps. Implies `GET_APPS`.
    GroupPermissionsCreateApps
    //  Permission to update cryptographic apps. Implies `GET_APPS`.
    GroupPermissionsUpdateApps
    //  Permission to retrieve cryptographic apps' secrets. Note that not
    //  all cryptographic app credentials contain secrets. If a
    //  cryptographic app's credential does not contain any secrets,
    //  `GET_APPS` permission is sufficient to call the `GetAppCredential`
    //  API. Implies `GET_APPS`.
    GroupPermissionsRetrieveAppSecrets
    //  Permission to delete cryptographic apps. Implies `GET_APPS`.
    GroupPermissionsDeleteApps
    //  Currently implies `CREATE_APPS`, `UPDATE_APPS`,
    //  `RETRIEVE_APP_SECRETS`, `DELETE_APPS`, and `GET_APPS` permissions.
    GroupPermissionsManageApps
    //  Permission to create plugins. Implies `GET_PLUGINS`.
    //  For creating a plugin, following group permissions are also required
    //  in each group plugin is being added, to prevent privilege escalation:
    //  `CREATE_SOBJECTS`, `EXPORT_SOBJECTS`, `COPY_SOBJECTS`,
    //  `WRAP_SOBJECTS`, `UNWRAP_SOBJECTS`, `ENCAPSULATE_SOBJECTS`, `DECAPSULATE_SOBJECTS`,
    //  `DERIVE_SOBJECTS`, `TRANSFORM_SOBJECTS`, `UPDATE_SOBJECTS_ENABLED_STATE`,
    //  `ROTATE_SOBJECTS`, `DELETE_SOBJECTS`, `REVOKE_SOBJECTS`, `ACTIVATE_SOBJECTS`,
    //  `MOVE_SOBJECTS`, `UPDATE_KEY_OPS`, `UPDATE_SOBJECT_POLICIES`, `UPDATE_SOBJECTS_PROFILE`,
    //  `GET_GROUP`, `GET_SOBJECTS`, `GET_APPS`, `GET_PLUGINS`, `GET_AUDIT_LOGS`
    //  Following account permissions are required as well:
    //  `GET_ALL_USERS`
    GroupPermissionsCreatePlugins
    //  Permission to update plugins. Implies `GET_PLUGINS`.
    //  For updating a plugin, following group permissions are also required
    //  in each group plugin is being added, to prevent privilege escalation:
    //  `CREATE_SOBJECTS`, `EXPORT_SOBJECTS`, `COPY_SOBJECTS`, `WRAP_SOBJECTS`, `UNWRAP_SOBJECTS`,
    //  `ENCAPSULATE_SOBJECTS`, `DECAPSULATE_SOBJECTS`, `UPDATE_SOBJECTS_ENABLED_STATE`,
    //  `ROTATE_SOBJECTS`, `DELETE_SOBJECTS`, `REVOKE_SOBJECTS`, `ACTIVATE_SOBJECTS`,
    //  `MOVE_SOBJECTS`, `UPDATE_KEY_OPS`, `UPDATE_SOBJECT_POLICIES`, `UPDATE_SOBJECTS_PROFILE`,
    //  `GET_GROUP`, `GET_SOBJECTS`, `GET_APPS`, `GET_PLUGINS`, `GET_AUDIT_LOGS`
    //  Following account permissions are required as well while adding
    //  new groups:
    //  `GET_ALL_USERS`
    GroupPermissionsUpdatePlugins
    //  Permission to invoke plugins. Implies `GET_PLUGINS`.
    GroupPermissionsInvokePlugins
    //  Permission to delete plugins. Implies `GET_PLUGINS`.
    GroupPermissionsDeletePlugins
    //  Currently implies `CREATE_PLUGINS`, `UPDATE_PLUGINS`,
    //  `INVOKE_PLUGINS`, `DELETE_PLUGINS`, and `GET_PLUGINS` permissions.
    GroupPermissionsManagePlugins
    //  Permission to create security objects. This permission is required
    //  for APIs that result in creation of a new security object including:
    //  Generate, Import, Unwrap. Also required in destination group when
    //  moving a key to a different group or when copying a key. Implies
    //  `GET_SOBJECTS`.
    GroupPermissionsCreateSobjects
    //  Permission to export security objects. This permission is required
    //  for Export, ExportByComponents, Copy (depending on destination
    //  group), Restore, and Wrap (for wrapped security object) APIs.
    //  Implies `GET_SOBJECTS`.
    GroupPermissionsExportSobjects
    //  Permission to copy security objects. This permission is required in
    //  the source group when calling the Copy API. Implies `GET_SOBJECTS`.
    GroupPermissionsCopySobjects
    //  Permission to wrap security objects. This permission is required in
    //  the wrapping security object's group. Implies `GET_SOBJECTS`.
    GroupPermissionsWrapSobjects
    //  Permission to unwrap security objects. This permission is required
    //  in the unwrapping security object's group. Implies `GET_SOBJECTS`.
    GroupPermissionsUnwrapSobjects
    //  Permission to derive other security objects. Implies `GET_SOBJECTS`.
    GroupPermissionsDeriveSobjects
    //  Permission to transform security objects. Implies `GET_SOBJECTS`.
    GroupPermissionsTransformSobjects
    //  Permission to enable/disable security objects. Implies
    //  `GET_SOBJECTS`.
    GroupPermissionsUpdateSobjectsEnabledState
    //  Permission to rotate (a.k.a. "rekey") security objects. Implies
    //  `GET_SOBJECTS`.
    GroupPermissionsRotateSobjects
    //  Permission to delete security objects. Implies `GET_SOBJECTS`.
    GroupPermissionsDeleteSobjects
    //  Permission to destroy security objects. Implies `GET_SOBJECTS`.
    GroupPermissionsDestroySobjects
    //  Permission to revoke security objects, i.e. mark security objects as
    //  deactivated or compromised. Implies `GET_SOBJECTS`.
    GroupPermissionsRevokeSobjects
    //  Permission to activate security objects. Implies `GET_SOBJECTS`.
    GroupPermissionsActivateSobjects
    //  Permission to revert changes to security objects. Implies
    //  `GET_SOBJECTS`.
    GroupPermissionsRevertSobjects
    //  Permission to delete key material including removing the private key
    //  part of an asymmetric key pair and removing key material of security
    //  objects backed by external HSM/KMS. Implies `GET_SOBJECTS`.
    GroupPermissionsDeleteKeyMaterial
    //  Permission to move security objects. This permission is required for
    //  changing the group of a security object in the source group. Note
    //  that changing the group of a security object also requires
    //  `CREATE_SOBJECTS` permission in the destination group. Implies
    //  `GET_SOBJECTS`.
    GroupPermissionsMoveSobjects
    //  Permission to update key operations of security objects. Implies
    //  `GET_SOBJECTS`.
    GroupPermissionsUpdateKeyOps
    //  Permission to update individual security objects' policies. This
    //  permission allows updating RSA options, as well as Google access
    //  reason policy (for use with Google EKM APIs) defined on the security
    //  object itself. Implies `GET_SOBJECTS`.
    GroupPermissionsUpdateSobjectPolicies
    //  Permission to update name, description, custom metadata, key links
    //  (currently only create parent link), and publish public key settings
    //  of security objects. Implies `GET_SOBJECTS`.
    GroupPermissionsUpdateSobjectsProfile
    //  Permission to scan for security objects in external HSM/KMS. Implies
    //  `GET_SOBJECTS`.
    GroupPermissionsScanExternalSobjects
    //  Permission to restore key material of security objects backed by
    //  external HSM/KMS. Note that calling the Restore API needs this
    //  permission in the destination group as well as `EXPORT_SOBJECTS`
    //  permission in the source group (where the object was copied from
    //  originally). Implies `GET_SOBJECTS`.
    GroupPermissionsRestoreExternalSobjects
    //  Permission to call Workspace CSE Wrap API.
    GroupPermissionsWrapWorkspaceCse
    //  Permission to call Workspace CSE Unwrap API.
    GroupPermissionsUnwrapWorkspaceCse
    GroupPermissionsWorkspaceCse
    //  Permission to get information about the group.
    GroupPermissionsGetGroup
    //  Permission to get security objects stored in the group.
    GroupPermissionsGetSobjects
    //  Permission to get cryptographic apps in the group.
    GroupPermissionsGetApps
    //  Permission to get plugin in the group.
    GroupPermissionsGetPlugins
    //  Permission to get approval requests related to the group.
    GroupPermissionsGetGroupApprovalRequests
    //  Permission to get audit logs related to the group.
    GroupPermissionsGetAuditLogs
    //  Permission to update or remove wrapping key of the  group
    GroupPermissionsManageGroupWrappingKey
    //  Permission to encapsulate security objects. Implies `CREATE_SOBJECTS`.
    GroupPermissionsEncapsulateSobjects
    //  Permission to decapsulate security objects. Implies `CREATE_SOBJECTS`.
    GroupPermissionsDecapsulateSobjects
)

// MarshalJSON converts GroupPermissions to an array of strings
func (x GroupPermissions) MarshalJSON() ([]byte, error) {
    s := make([]string, 0)
    if x & GroupPermissionsCreateGroupApprovalPolicy == GroupPermissionsCreateGroupApprovalPolicy {
        s = append(s, "CREATE_GROUP_APPROVAL_POLICY")
    }
    if x & GroupPermissionsUpdateGroupExternalLinks == GroupPermissionsUpdateGroupExternalLinks {
        s = append(s, "UPDATE_GROUP_EXTERNAL_LINKS")
    }
    if x & GroupPermissionsManageGroupClientConfigs == GroupPermissionsManageGroupClientConfigs {
        s = append(s, "MANAGE_GROUP_CLIENT_CONFIGS")
    }
    if x & GroupPermissionsUpdateGroupProfile == GroupPermissionsUpdateGroupProfile {
        s = append(s, "UPDATE_GROUP_PROFILE")
    }
    if x & GroupPermissionsDeleteGroup == GroupPermissionsDeleteGroup {
        s = append(s, "DELETE_GROUP")
    }
    if x & GroupPermissionsMapExternalRolesForApps == GroupPermissionsMapExternalRolesForApps {
        s = append(s, "MAP_EXTERNAL_ROLES_FOR_APPS")
    }
    if x & GroupPermissionsMapExternalRolesForUsers == GroupPermissionsMapExternalRolesForUsers {
        s = append(s, "MAP_EXTERNAL_ROLES_FOR_USERS")
    }
    if x & GroupPermissionsMapExternalRoles == GroupPermissionsMapExternalRoles {
        s = append(s, "MAP_EXTERNAL_ROLES")
    }
    if x & GroupPermissionsAddUsersToGroup == GroupPermissionsAddUsersToGroup {
        s = append(s, "ADD_USERS_TO_GROUP")
    }
    if x & GroupPermissionsDeleteUsersFromGroup == GroupPermissionsDeleteUsersFromGroup {
        s = append(s, "DELETE_USERS_FROM_GROUP")
    }
    if x & GroupPermissionsUpdateUsersGroupRole == GroupPermissionsUpdateUsersGroupRole {
        s = append(s, "UPDATE_USERS_GROUP_ROLE")
    }
    if x & GroupPermissionsManageGroupUsers == GroupPermissionsManageGroupUsers {
        s = append(s, "MANAGE_GROUP_USERS")
    }
    if x & GroupPermissionsCreateGroupSobjectPolicies == GroupPermissionsCreateGroupSobjectPolicies {
        s = append(s, "CREATE_GROUP_SOBJECT_POLICIES")
    }
    if x & GroupPermissionsUpdateGroupSobjectPolicies == GroupPermissionsUpdateGroupSobjectPolicies {
        s = append(s, "UPDATE_GROUP_SOBJECT_POLICIES")
    }
    if x & GroupPermissionsDeleteGroupSobjectPolicies == GroupPermissionsDeleteGroupSobjectPolicies {
        s = append(s, "DELETE_GROUP_SOBJECT_POLICIES")
    }
    if x & GroupPermissionsManageGroupSobjectPolicies == GroupPermissionsManageGroupSobjectPolicies {
        s = append(s, "MANAGE_GROUP_SOBJECT_POLICIES")
    }
    if x & GroupPermissionsCreateGroupCustodianPolicy == GroupPermissionsCreateGroupCustodianPolicy {
        s = append(s, "CREATE_GROUP_CUSTODIAN_POLICY")
    }
    if x & GroupPermissionsUpdateGroupCustodianPolicy == GroupPermissionsUpdateGroupCustodianPolicy {
        s = append(s, "UPDATE_GROUP_CUSTODIAN_POLICY")
    }
    if x & GroupPermissionsDeleteGroupCustodianPolicy == GroupPermissionsDeleteGroupCustodianPolicy {
        s = append(s, "DELETE_GROUP_CUSTODIAN_POLICY")
    }
    if x & GroupPermissionsManageGroupCustodianPolicy == GroupPermissionsManageGroupCustodianPolicy {
        s = append(s, "MANAGE_GROUP_CUSTODIAN_POLICY")
    }
    if x & GroupPermissionsCreateApps == GroupPermissionsCreateApps {
        s = append(s, "CREATE_APPS")
    }
    if x & GroupPermissionsUpdateApps == GroupPermissionsUpdateApps {
        s = append(s, "UPDATE_APPS")
    }
    if x & GroupPermissionsRetrieveAppSecrets == GroupPermissionsRetrieveAppSecrets {
        s = append(s, "RETRIEVE_APP_SECRETS")
    }
    if x & GroupPermissionsDeleteApps == GroupPermissionsDeleteApps {
        s = append(s, "DELETE_APPS")
    }
    if x & GroupPermissionsManageApps == GroupPermissionsManageApps {
        s = append(s, "MANAGE_APPS")
    }
    if x & GroupPermissionsCreatePlugins == GroupPermissionsCreatePlugins {
        s = append(s, "CREATE_PLUGINS")
    }
    if x & GroupPermissionsUpdatePlugins == GroupPermissionsUpdatePlugins {
        s = append(s, "UPDATE_PLUGINS")
    }
    if x & GroupPermissionsInvokePlugins == GroupPermissionsInvokePlugins {
        s = append(s, "INVOKE_PLUGINS")
    }
    if x & GroupPermissionsDeletePlugins == GroupPermissionsDeletePlugins {
        s = append(s, "DELETE_PLUGINS")
    }
    if x & GroupPermissionsManagePlugins == GroupPermissionsManagePlugins {
        s = append(s, "MANAGE_PLUGINS")
    }
    if x & GroupPermissionsCreateSobjects == GroupPermissionsCreateSobjects {
        s = append(s, "CREATE_SOBJECTS")
    }
    if x & GroupPermissionsExportSobjects == GroupPermissionsExportSobjects {
        s = append(s, "EXPORT_SOBJECTS")
    }
    if x & GroupPermissionsCopySobjects == GroupPermissionsCopySobjects {
        s = append(s, "COPY_SOBJECTS")
    }
    if x & GroupPermissionsWrapSobjects == GroupPermissionsWrapSobjects {
        s = append(s, "WRAP_SOBJECTS")
    }
    if x & GroupPermissionsUnwrapSobjects == GroupPermissionsUnwrapSobjects {
        s = append(s, "UNWRAP_SOBJECTS")
    }
    if x & GroupPermissionsDeriveSobjects == GroupPermissionsDeriveSobjects {
        s = append(s, "DERIVE_SOBJECTS")
    }
    if x & GroupPermissionsTransformSobjects == GroupPermissionsTransformSobjects {
        s = append(s, "TRANSFORM_SOBJECTS")
    }
    if x & GroupPermissionsUpdateSobjectsEnabledState == GroupPermissionsUpdateSobjectsEnabledState {
        s = append(s, "UPDATE_SOBJECTS_ENABLED_STATE")
    }
    if x & GroupPermissionsRotateSobjects == GroupPermissionsRotateSobjects {
        s = append(s, "ROTATE_SOBJECTS")
    }
    if x & GroupPermissionsDeleteSobjects == GroupPermissionsDeleteSobjects {
        s = append(s, "DELETE_SOBJECTS")
    }
    if x & GroupPermissionsDestroySobjects == GroupPermissionsDestroySobjects {
        s = append(s, "DESTROY_SOBJECTS")
    }
    if x & GroupPermissionsRevokeSobjects == GroupPermissionsRevokeSobjects {
        s = append(s, "REVOKE_SOBJECTS")
    }
    if x & GroupPermissionsActivateSobjects == GroupPermissionsActivateSobjects {
        s = append(s, "ACTIVATE_SOBJECTS")
    }
    if x & GroupPermissionsRevertSobjects == GroupPermissionsRevertSobjects {
        s = append(s, "REVERT_SOBJECTS")
    }
    if x & GroupPermissionsDeleteKeyMaterial == GroupPermissionsDeleteKeyMaterial {
        s = append(s, "DELETE_KEY_MATERIAL")
    }
    if x & GroupPermissionsMoveSobjects == GroupPermissionsMoveSobjects {
        s = append(s, "MOVE_SOBJECTS")
    }
    if x & GroupPermissionsUpdateKeyOps == GroupPermissionsUpdateKeyOps {
        s = append(s, "UPDATE_KEY_OPS")
    }
    if x & GroupPermissionsUpdateSobjectPolicies == GroupPermissionsUpdateSobjectPolicies {
        s = append(s, "UPDATE_SOBJECT_POLICIES")
    }
    if x & GroupPermissionsUpdateSobjectsProfile == GroupPermissionsUpdateSobjectsProfile {
        s = append(s, "UPDATE_SOBJECTS_PROFILE")
    }
    if x & GroupPermissionsScanExternalSobjects == GroupPermissionsScanExternalSobjects {
        s = append(s, "SCAN_EXTERNAL_SOBJECTS")
    }
    if x & GroupPermissionsRestoreExternalSobjects == GroupPermissionsRestoreExternalSobjects {
        s = append(s, "RESTORE_EXTERNAL_SOBJECTS")
    }
    if x & GroupPermissionsWrapWorkspaceCse == GroupPermissionsWrapWorkspaceCse {
        s = append(s, "WRAP_WORKSPACE_CSE")
    }
    if x & GroupPermissionsUnwrapWorkspaceCse == GroupPermissionsUnwrapWorkspaceCse {
        s = append(s, "UNWRAP_WORKSPACE_CSE")
    }
    if x & GroupPermissionsWorkspaceCse == GroupPermissionsWorkspaceCse {
        s = append(s, "WORKSPACE_CSE")
    }
    if x & GroupPermissionsGetGroup == GroupPermissionsGetGroup {
        s = append(s, "GET_GROUP")
    }
    if x & GroupPermissionsGetSobjects == GroupPermissionsGetSobjects {
        s = append(s, "GET_SOBJECTS")
    }
    if x & GroupPermissionsGetApps == GroupPermissionsGetApps {
        s = append(s, "GET_APPS")
    }
    if x & GroupPermissionsGetPlugins == GroupPermissionsGetPlugins {
        s = append(s, "GET_PLUGINS")
    }
    if x & GroupPermissionsGetGroupApprovalRequests == GroupPermissionsGetGroupApprovalRequests {
        s = append(s, "GET_GROUP_APPROVAL_REQUESTS")
    }
    if x & GroupPermissionsGetAuditLogs == GroupPermissionsGetAuditLogs {
        s = append(s, "GET_AUDIT_LOGS")
    }
    if x & GroupPermissionsManageGroupWrappingKey == GroupPermissionsManageGroupWrappingKey {
        s = append(s, "MANAGE_GROUP_WRAPPING_KEY")
    }
    if x & GroupPermissionsEncapsulateSobjects == GroupPermissionsEncapsulateSobjects {
        s = append(s, "ENCAPSULATE_SOBJECTS")
    }
    if x & GroupPermissionsDecapsulateSobjects == GroupPermissionsDecapsulateSobjects {
        s = append(s, "DECAPSULATE_SOBJECTS")
    }
    return json.Marshal(s)
}

// UnmarshalJSON converts array of strings to GroupPermissions
func (x *GroupPermissions) UnmarshalJSON(data []byte) error {
    *x = 0
    var s []string
    if err := json.Unmarshal(data, &s); err != nil {
        return err
    }
    for _, v := range s {
        switch v {
        case "CREATE_GROUP_APPROVAL_POLICY":
            *x = *x | GroupPermissionsCreateGroupApprovalPolicy
        case "UPDATE_GROUP_EXTERNAL_LINKS":
            *x = *x | GroupPermissionsUpdateGroupExternalLinks
        case "MANAGE_GROUP_CLIENT_CONFIGS":
            *x = *x | GroupPermissionsManageGroupClientConfigs
        case "UPDATE_GROUP_PROFILE":
            *x = *x | GroupPermissionsUpdateGroupProfile
        case "DELETE_GROUP":
            *x = *x | GroupPermissionsDeleteGroup
        case "MAP_EXTERNAL_ROLES_FOR_APPS":
            *x = *x | GroupPermissionsMapExternalRolesForApps
        case "MAP_EXTERNAL_ROLES_FOR_USERS":
            *x = *x | GroupPermissionsMapExternalRolesForUsers
        case "MAP_EXTERNAL_ROLES":
            *x = *x | GroupPermissionsMapExternalRoles
        case "ADD_USERS_TO_GROUP":
            *x = *x | GroupPermissionsAddUsersToGroup
        case "DELETE_USERS_FROM_GROUP":
            *x = *x | GroupPermissionsDeleteUsersFromGroup
        case "UPDATE_USERS_GROUP_ROLE":
            *x = *x | GroupPermissionsUpdateUsersGroupRole
        case "MANAGE_GROUP_USERS":
            *x = *x | GroupPermissionsManageGroupUsers
        case "CREATE_GROUP_SOBJECT_POLICIES":
            *x = *x | GroupPermissionsCreateGroupSobjectPolicies
        case "UPDATE_GROUP_SOBJECT_POLICIES":
            *x = *x | GroupPermissionsUpdateGroupSobjectPolicies
        case "DELETE_GROUP_SOBJECT_POLICIES":
            *x = *x | GroupPermissionsDeleteGroupSobjectPolicies
        case "MANAGE_GROUP_SOBJECT_POLICIES":
            *x = *x | GroupPermissionsManageGroupSobjectPolicies
        case "CREATE_GROUP_CUSTODIAN_POLICY":
            *x = *x | GroupPermissionsCreateGroupCustodianPolicy
        case "UPDATE_GROUP_CUSTODIAN_POLICY":
            *x = *x | GroupPermissionsUpdateGroupCustodianPolicy
        case "DELETE_GROUP_CUSTODIAN_POLICY":
            *x = *x | GroupPermissionsDeleteGroupCustodianPolicy
        case "MANAGE_GROUP_CUSTODIAN_POLICY":
            *x = *x | GroupPermissionsManageGroupCustodianPolicy
        case "CREATE_APPS":
            *x = *x | GroupPermissionsCreateApps
        case "UPDATE_APPS":
            *x = *x | GroupPermissionsUpdateApps
        case "RETRIEVE_APP_SECRETS":
            *x = *x | GroupPermissionsRetrieveAppSecrets
        case "DELETE_APPS":
            *x = *x | GroupPermissionsDeleteApps
        case "MANAGE_APPS":
            *x = *x | GroupPermissionsManageApps
        case "CREATE_PLUGINS":
            *x = *x | GroupPermissionsCreatePlugins
        case "UPDATE_PLUGINS":
            *x = *x | GroupPermissionsUpdatePlugins
        case "INVOKE_PLUGINS":
            *x = *x | GroupPermissionsInvokePlugins
        case "DELETE_PLUGINS":
            *x = *x | GroupPermissionsDeletePlugins
        case "MANAGE_PLUGINS":
            *x = *x | GroupPermissionsManagePlugins
        case "CREATE_SOBJECTS":
            *x = *x | GroupPermissionsCreateSobjects
        case "EXPORT_SOBJECTS":
            *x = *x | GroupPermissionsExportSobjects
        case "COPY_SOBJECTS":
            *x = *x | GroupPermissionsCopySobjects
        case "WRAP_SOBJECTS":
            *x = *x | GroupPermissionsWrapSobjects
        case "UNWRAP_SOBJECTS":
            *x = *x | GroupPermissionsUnwrapSobjects
        case "DERIVE_SOBJECTS":
            *x = *x | GroupPermissionsDeriveSobjects
        case "TRANSFORM_SOBJECTS":
            *x = *x | GroupPermissionsTransformSobjects
        case "UPDATE_SOBJECTS_ENABLED_STATE":
            *x = *x | GroupPermissionsUpdateSobjectsEnabledState
        case "ROTATE_SOBJECTS":
            *x = *x | GroupPermissionsRotateSobjects
        case "DELETE_SOBJECTS":
            *x = *x | GroupPermissionsDeleteSobjects
        case "DESTROY_SOBJECTS":
            *x = *x | GroupPermissionsDestroySobjects
        case "REVOKE_SOBJECTS":
            *x = *x | GroupPermissionsRevokeSobjects
        case "ACTIVATE_SOBJECTS":
            *x = *x | GroupPermissionsActivateSobjects
        case "REVERT_SOBJECTS":
            *x = *x | GroupPermissionsRevertSobjects
        case "DELETE_KEY_MATERIAL":
            *x = *x | GroupPermissionsDeleteKeyMaterial
        case "MOVE_SOBJECTS":
            *x = *x | GroupPermissionsMoveSobjects
        case "UPDATE_KEY_OPS":
            *x = *x | GroupPermissionsUpdateKeyOps
        case "UPDATE_SOBJECT_POLICIES":
            *x = *x | GroupPermissionsUpdateSobjectPolicies
        case "UPDATE_SOBJECTS_PROFILE":
            *x = *x | GroupPermissionsUpdateSobjectsProfile
        case "SCAN_EXTERNAL_SOBJECTS":
            *x = *x | GroupPermissionsScanExternalSobjects
        case "RESTORE_EXTERNAL_SOBJECTS":
            *x = *x | GroupPermissionsRestoreExternalSobjects
        case "WRAP_WORKSPACE_CSE":
            *x = *x | GroupPermissionsWrapWorkspaceCse
        case "UNWRAP_WORKSPACE_CSE":
            *x = *x | GroupPermissionsUnwrapWorkspaceCse
        case "WORKSPACE_CSE":
            *x = *x | GroupPermissionsWorkspaceCse
        case "GET_GROUP":
            *x = *x | GroupPermissionsGetGroup
        case "GET_SOBJECTS":
            *x = *x | GroupPermissionsGetSobjects
        case "GET_APPS":
            *x = *x | GroupPermissionsGetApps
        case "GET_PLUGINS":
            *x = *x | GroupPermissionsGetPlugins
        case "GET_GROUP_APPROVAL_REQUESTS":
            *x = *x | GroupPermissionsGetGroupApprovalRequests
        case "GET_AUDIT_LOGS":
            *x = *x | GroupPermissionsGetAuditLogs
        case "MANAGE_GROUP_WRAPPING_KEY":
            *x = *x | GroupPermissionsManageGroupWrappingKey
        case "ENCAPSULATE_SOBJECTS":
            *x = *x | GroupPermissionsEncapsulateSobjects
        case "DECAPSULATE_SOBJECTS":
            *x = *x | GroupPermissionsDecapsulateSobjects
        }
    }
    return nil
}

type GroupSort struct {
    ByGroupID *GroupSortByGroupId
    ByGroupName *GroupSortByGroupName
}
type GroupSortByGroupId struct {
    Order Order `json:"order"`
    PreviousID *UUID `json:"previous_id,omitempty"`
}
type GroupSortByGroupName struct {
    Order Order `json:"order"`
    PreviousSortValue *string `json:"previous_sort_value,omitempty"`
}
func (x GroupSort) urlEncode(v map[string][]string) error {
    if x.ByGroupID != nil && x.ByGroupName != nil {
        return errors.New("GroupSort can be either ByGroupID or ByGroupName")
    }
    if x.ByGroupID != nil {
        v["sort_by"] = []string{"group_id" + string(x.ByGroupID.Order)}
        if x.ByGroupID.PreviousID != nil {
            v["previous_id"] = []string{fmt.Sprintf("%v", *x.ByGroupID.PreviousID)}
        }
    }
    if x.ByGroupName != nil {
        v["sort_by"] = []string{"group_name" + string(x.ByGroupName.Order)}
        if x.ByGroupName.PreviousSortValue != nil {
            v["previous_sort_value"] = []string{fmt.Sprintf("%v", *x.ByGroupName.PreviousSortValue)}
        }
    }
    return nil
}

type HistoryItem struct {
    ID UUID `json:"id"`
    State HistoryItemState `json:"state"`
    CreatedAt Time `json:"created_at"`
    Expiry Time `json:"expiry"`
}

type HistoryItemState struct {
    ActivationDate *Time `json:"activation_date,omitempty"`
    ActivationUndoWindow *Secs `json:"activation_undo_window,omitempty"`
    RevocationReason *RevocationReason `json:"revocation_reason,omitempty"`
    CompromiseDate *Time `json:"compromise_date,omitempty"`
    DeactivationDate *Time `json:"deactivation_date,omitempty"`
    DeactivationUndoWindow *Secs `json:"deactivation_undo_window,omitempty"`
    DestructionDate *Time `json:"destruction_date,omitempty"`
    DeletionDate *Time `json:"deletion_date,omitempty"`
    State SobjectState `json:"state"`
    KeyOps KeyOperations `json:"key_ops"`
    PublicOnly bool `json:"public_only"`
    HasKey bool `json:"has_key"`
    RotationPolicy *RotationPolicy `json:"rotation_policy,omitempty"`
    GroupID *UUID `json:"group_id,omitempty"`
}

type HmacOptionsPolicy struct {
    MinimumKeyLength *uint32 `json:"minimum_key_length,omitempty"`
}

type KcdsaOptions struct {
    SubgroupSize *uint32 `json:"subgroup_size,omitempty"`
    HashAlg *DigestAlgorithm `json:"hash_alg,omitempty"`
}

type KcdsaOptionsPolicy struct {
}

// Methods for calculating a Key Checksum Value.
type KcvMethod string

// List of supported KcvMethod values
const (
    // This is calculated by encrypting an all-zero block using the key
    // and taking the leftmost 24 bits of the output.
    KcvMethodEncrypt KcvMethod = "Encrypt"
    // This is calculated by computing the CMAC (Cipher-based Message Authentication Code)
    // on an all-zero block using the key, then taking the leftmost 40 bits
    // of the output.
    KcvMethodCmac KcvMethod = "Cmac"
)

type KeyHistoryPolicy struct {
    UndoTimeWindow Secs `json:"undo_time_window"`
}

// Linked security objects.
type KeyLinks struct {
    Replacement *UUID `json:"replacement,omitempty"`
    Replaced *UUID `json:"replaced,omitempty"`
    CopiedFrom *UUID `json:"copiedFrom,omitempty"`
    CopiedTo *[]UUID `json:"copiedTo,omitempty"`
    Subkeys *[]UUID `json:"subkeys,omitempty"`
    Parent *UUID `json:"parent,omitempty"`
    // Wrapping key used to wrap this security object
    WrappingKey *UUID `json:"wrappingKey,omitempty"`
}

type KeyMetadataPolicy struct {
    // Applies to all objects.
    Base MetadataPolicyItem `json:"base"`
    // Each entry in this map fully overrides `base` for a particular object type.
    ForObjType map[ObjectType]MetadataPolicyItem `json:"for_obj_type"`
    // What to do with legacy objects that are not compliant with this policy.
    // Note that objects are not allowed to be created/updated if the result is
    // not compliant with the policy. Non-compliant legacy objects can only be
    // updated to comply with the policy (e.g. by adding missing required metadata).
    LegacyObjects LegacyKeyPolicy `json:"legacy_objects"`
}

// Operations allowed to be performed on a given key.
type KeyOperations uint64

// List of supported KeyOperations values
const (
    //  If this is set, the key can be used to for signing.
    KeyOperationsSign KeyOperations = 1 << iota
    //  If this is set, the key can used for verifying a signature.
    KeyOperationsVerify
    //  If this is set, the key can be used for encryption.
    KeyOperationsEncrypt
    //  If this is set, the key can be used for decryption.
    KeyOperationsDecrypt
    //  If this is set, the key can be used wrapping other keys.
    //  The key being wrapped must have the EXPORT operation enabled.
    KeyOperationsWrapkey
    //  If this is set, the key can be used to unwrap a wrapped key.
    KeyOperationsUnwrapkey
    //  If this is set, the key can be used to derive another key.
    KeyOperationsDerivekey
    //  If this is set, the key can be transformed.
    KeyOperationsTransform
    //  If this is set, the key can be used to compute a cryptographic
    //  Message Authentication Code (MAC) on a message.
    KeyOperationsMacgenerate
    //  If they is set, the key can be used to verify a MAC.
    KeyOperationsMacverify
    //  If this is set, the value of the key can be retrieved
    //  with an authenticated request. This shouldn't be set unless
    //  required. It is more secure to keep the key's value inside DSM only.
    KeyOperationsExport
    //  Without this operation, management operations like delete, destroy,
    //  rotate, activate, restore, revoke, revert, update, remove_private, etc.
    //  cannot be performed by a crypto App.
    //  A user with access or admin app can still perform these operations.
    //  This option is only relevant for crypto apps.
    KeyOperationsAppmanageable
    //  If this is set, audit logs will not be recorded for the key.
    //   High volume here tries to signify a key that is being used a lot
    //   and will produce lots of logs. Setting this operation disables
    //   audit logs for the key.
    KeyOperationsHighvolume
    //  If this is set, the key can be used for key agreement.
    //  Both the private and public key should have this option enabled
    //  to perform an agree operation.
    KeyOperationsAgreekey
    //  If this is set, the key can be used for key encapsulation. The
    //  result is a new symmetric key and a ciphertext.
    KeyOperationsEncapsulate
    //  If this is set, the key can be used for key decapsulation. If
    //  decapsulation succeeds, the result is a new symmetric key.
    KeyOperationsDecapsulate
)

// MarshalJSON converts KeyOperations to an array of strings
func (x KeyOperations) MarshalJSON() ([]byte, error) {
    s := make([]string, 0)
    if x & KeyOperationsSign == KeyOperationsSign {
        s = append(s, "SIGN")
    }
    if x & KeyOperationsVerify == KeyOperationsVerify {
        s = append(s, "VERIFY")
    }
    if x & KeyOperationsEncrypt == KeyOperationsEncrypt {
        s = append(s, "ENCRYPT")
    }
    if x & KeyOperationsDecrypt == KeyOperationsDecrypt {
        s = append(s, "DECRYPT")
    }
    if x & KeyOperationsWrapkey == KeyOperationsWrapkey {
        s = append(s, "WRAPKEY")
    }
    if x & KeyOperationsUnwrapkey == KeyOperationsUnwrapkey {
        s = append(s, "UNWRAPKEY")
    }
    if x & KeyOperationsDerivekey == KeyOperationsDerivekey {
        s = append(s, "DERIVEKEY")
    }
    if x & KeyOperationsTransform == KeyOperationsTransform {
        s = append(s, "TRANSFORM")
    }
    if x & KeyOperationsMacgenerate == KeyOperationsMacgenerate {
        s = append(s, "MACGENERATE")
    }
    if x & KeyOperationsMacverify == KeyOperationsMacverify {
        s = append(s, "MACVERIFY")
    }
    if x & KeyOperationsExport == KeyOperationsExport {
        s = append(s, "EXPORT")
    }
    if x & KeyOperationsAppmanageable == KeyOperationsAppmanageable {
        s = append(s, "APPMANAGEABLE")
    }
    if x & KeyOperationsHighvolume == KeyOperationsHighvolume {
        s = append(s, "HIGHVOLUME")
    }
    if x & KeyOperationsAgreekey == KeyOperationsAgreekey {
        s = append(s, "AGREEKEY")
    }
    if x & KeyOperationsEncapsulate == KeyOperationsEncapsulate {
        s = append(s, "ENCAPSULATE")
    }
    if x & KeyOperationsDecapsulate == KeyOperationsDecapsulate {
        s = append(s, "DECAPSULATE")
    }
    return json.Marshal(s)
}

// UnmarshalJSON converts array of strings to KeyOperations
func (x *KeyOperations) UnmarshalJSON(data []byte) error {
    *x = 0
    var s []string
    if err := json.Unmarshal(data, &s); err != nil {
        return err
    }
    for _, v := range s {
        switch v {
        case "SIGN":
            *x = *x | KeyOperationsSign
        case "VERIFY":
            *x = *x | KeyOperationsVerify
        case "ENCRYPT":
            *x = *x | KeyOperationsEncrypt
        case "DECRYPT":
            *x = *x | KeyOperationsDecrypt
        case "WRAPKEY":
            *x = *x | KeyOperationsWrapkey
        case "UNWRAPKEY":
            *x = *x | KeyOperationsUnwrapkey
        case "DERIVEKEY":
            *x = *x | KeyOperationsDerivekey
        case "TRANSFORM":
            *x = *x | KeyOperationsTransform
        case "MACGENERATE":
            *x = *x | KeyOperationsMacgenerate
        case "MACVERIFY":
            *x = *x | KeyOperationsMacverify
        case "EXPORT":
            *x = *x | KeyOperationsExport
        case "APPMANAGEABLE":
            *x = *x | KeyOperationsAppmanageable
        case "HIGHVOLUME":
            *x = *x | KeyOperationsHighvolume
        case "AGREEKEY":
            *x = *x | KeyOperationsAgreekey
        case "ENCAPSULATE":
            *x = *x | KeyOperationsEncapsulate
        case "DECAPSULATE":
            *x = *x | KeyOperationsDecapsulate
        }
    }
    return nil
}

type KeyOpsOverride struct {
    // The operations to add to any key creation request (only supported in KMIP).
    //
    // The following operations can be specified:
    // - `EXPORT`
    // - `APPMANAGEABLE`
    // - `HIGHVOLUME`
    //
    // The operations specified cannot conflict with what's specified in the
    // `key_ops` field of account and/or group policies (where applicable).
    //
    // **Note**: This is only enforced on (KMIP) creation requests since we assume
    // updates removing key operations are intentional.
    AddKeyOps *KeyOperations `json:"add_key_ops,omitempty"`
}

type KmipClientConfig struct {
    // Use `ignore_unknown_key_ops_for` with [SECRET] instead of `ignore_unknown_key_ops_for_secrets``
    IgnoreUnknownKeyOpsForSecrets *bool `json:"ignore_unknown_key_ops_for_secrets,omitempty"`
    IgnoreUnknownKeyOpsFor *ObjectTypeFilter `json:"ignore_unknown_key_ops_for,omitempty"`
    KeyOpsOverride *KeyOpsOverride `json:"key_ops_override,omitempty"`
}

// Role of a user or app in an account for the purpose of LDAP configurations.
type LdapAccountRole struct {
    Legacy *LegacyLdapAccountRole
    Custom *UUID
}
func (x LdapAccountRole) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "LdapAccountRole", 
                  []bool{ x.Legacy != nil,
                  x.Custom != nil });
                  err != nil {
        return nil, err
    }
    if x.Legacy != nil {
        return json.Marshal(x.Legacy)
    }
    if x.Custom != nil {
        return json.Marshal(x.Custom)
    }
    panic("unreachable")
}
func (x *LdapAccountRole) UnmarshalJSON(data []byte) error {
    x.Legacy = nil
    x.Custom = nil
    var legacy LegacyLdapAccountRole
    if err := json.Unmarshal(data, &legacy); err == nil {
        x.Legacy = &legacy
        return nil
    }
    var custom UUID
    if err := json.Unmarshal(data, &custom); err == nil {
        x.Custom = &custom
        return nil
    }
    return errors.Errorf("not a valid LdapAccountRole")
}

// LDAP authorization settings.
type LdapAuthorizationConfig struct {
    // Number of seconds after which the authorization should be checked again.
    ValidFor uint64 `json:"valid_for"`
    // A map from account roles to distinguished names of LDAP groups.
    // If a DN is specified for an account role, entities with that role
    // must be a member of the specified LDAP group.
    RequireRole *map[LdapAccountRole]string `json:"require_role,omitempty"`
    // User self-provisioning settings for the LDAP integration.
    UserSelfProvisioning *LdapUserSelfProvisioningConfig `json:"user_self_provisioning,omitempty"`
    // How to resolve group role assignment conflicts for users authorized
    // through LDAP.
    RoleConflictResolution *LdapRoleConflictResolution `json:"role_conflict_resolution,omitempty"`
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
    if err := checkEnumPointers(
                  "LdapDnResolution", 
                  []bool{ x.Construct != nil,
                  x.SearchByMail != nil,
                  x.UserPrincipalName != nil });
                  err != nil {
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

// Controls how we resolve conflicting role assignments with LDAP authorization.
//
// When users are authorized through LDAP, their DSM group memberships are
// determined by their LDAP groups and the external role mappings created in
// DSM. For example, if the user belongs to 3 LDAP groups A, B and C, and these
// LDAP groups are mapped to DSM groups G1 and G2 in the following way:
// - A -> G1 as "group auditor"
// - B -> G1 as "group administrator"
// - C -> G2 as "group administrator"
//   Then which role should be assigned to this user in G1?
//
// The answer to this question used to be simple before the introduction of
// custom user roles in DSM: we took the maximum of the roles. Note that the
// legacy roles (group admin/auditor) formed a strict "more powerful than"
// relation, i.e. group administrator is strictly more powerful than group
// auditor (and same is true for legacy account roles). However, custom user
// roles do not have that relationship anymore. Moreover, the legacy behavior
// is not quite square with the role exclusivity rules either since the legacy
// behavior can also be regarded as assigning multiple exclusive roles in the
// same group.
//
// After the introduction of custom user roles, we allow a user to have
// multiple roles in one group as long as none of the roles are marked as
// exclusive. That rule is easily enforceable in the user Invite API. With LDAP
// authorization, the group memberships are computed dynamically when the
// Select Account API is called and it is possible that we run into conflicting
// role assignments due to user's LDAP group membership and current mappings
// between external roles (i.e. LDAP groups) and DSM groups.
type LdapRoleConflictResolution string

// List of supported LdapRoleConflictResolution values
const (
    // In this mode (which cannot be selected for new LDAP integrations and is
    // only meant for LDAP integrations that existed before custom roles), DSM
    // rejects any external role mapping involving custom roles and in case of
    // conflicting role assignments it takes the maximal legacy role.
    LdapRoleConflictResolutionBackcompatLegacyRolesOnly LdapRoleConflictResolution = "backcompat_legacy_roles_only"
    // In case of a role conflict, all role assignments where the role is
    // marked as exclusive are ignored and the rest are assigned to the user.
    // Note that legacy roles are all marked as exclusive. For example:
    // - LDAP group A is mapped to DSM group G1 with role R1
    // - LDAP group B is mapped to DSM group G1 with role R2
    // - LDAP group C is mapped to DSM group G1 with role R3
    // - Role R2 is marked exclusive
    //
    // A user that belongs to LDAP groups A, B and C will become a member of
    // DSM group G1 with role R1 + R3.
    LdapRoleConflictResolutionDisregardExclusiveRoles LdapRoleConflictResolution = "disregard_exclusive_roles"
)

// Credentials used by the service to authenticate itself to an LDAP server.
type LdapServiceAccount struct {
    Dn string `json:"dn"`
    Password ZeroizedString `json:"password"`
}

// LDAP user self-provisioning settings. Currently, the only
// setting available for configuration is the mapping from
// LDAP users to DSM account roles.
type LdapUserSelfProvisioningConfig struct {
    // The mapping that determines which roles will be assigned
    // to self-provisioned users.
    RoleAssignment LdapUserSelfProvisioningRole `json:"role_assignment"`
}

// A structure indicating how self-provisioned LDAP users will
// be assigned account roles.
type LdapUserSelfProvisioningRole struct {
    // Map all self-provisioned users to a single specified account role.
    // (Note that this setting only determines the role that a self-
    // provisioned user starts with; an account admin can change any user's
    // role at a later time.) A "state enabled" flag will be implicitly added,
    // and any specified "pending invite" flag will be removed.
    Fixed *LdapUserSelfProvisioningRoleFixed
}
// Map all self-provisioned users to a single specified account role.
// (Note that this setting only determines the role that a self-
// provisioned user starts with; an account admin can change any user's
// role at a later time.) A "state enabled" flag will be implicitly added,
// and any specified "pending invite" flag will be removed.
type LdapUserSelfProvisioningRoleFixed struct {
    Role UserAccountFlags `json:"role"`
}
func (x LdapUserSelfProvisioningRole) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "LdapUserSelfProvisioningRole", 
                  []bool{ x.Fixed != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.Fixed != nil:
        b, err := json.Marshal(x.Fixed)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["$type"] = "Fixed"
    }
    return json.Marshal(m)
}
func (x *LdapUserSelfProvisioningRole) UnmarshalJSON(data []byte) error {
    x.Fixed = nil
    var h struct {
        Tag string `json:"$type"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid LdapUserSelfProvisioningRole")
    }
    switch h.Tag {
    case "Fixed":
        var fixed LdapUserSelfProvisioningRoleFixed
        if err := json.Unmarshal(data, &fixed); err != nil {
            return err
        }
        x.Fixed = &fixed
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

type LegacyKeyPolicy string

// List of supported LegacyKeyPolicy values
const (
    // The key can be used for all purposes.
    LegacyKeyPolicyAllowed LegacyKeyPolicy = "allowed"
    // The key cannot be used for any crypto operations until it becomes compliant.
    LegacyKeyPolicyProhibited LegacyKeyPolicy = "prohibited"
    // The key can only be used for these crypto operations:
    // - DECRYPT
    // - VERIFY
    // - MACVERIFY
    // - UNWRAPKEY
    LegacyKeyPolicyUnprotectOnly LegacyKeyPolicy = "unprotect_only"
)

// Role of a user or app in an account for the purpose of LDAP configurations.
type LegacyLdapAccountRole string

// List of supported LegacyLdapAccountRole values
const (
    LegacyLdapAccountRoleAdminUser LegacyLdapAccountRole = "ADMIN_USER"
    LegacyLdapAccountRoleMemberUser LegacyLdapAccountRole = "MEMBER_USER"
    LegacyLdapAccountRoleAuditorUser LegacyLdapAccountRole = "AUDITOR_USER"
    LegacyLdapAccountRoleAdminApp LegacyLdapAccountRole = "ADMIN_APP"
    LegacyLdapAccountRoleCryptoApp LegacyLdapAccountRole = "CRYPTO_APP"
)

// Legacy user account role
type LegacyUserAccountRole string

// List of supported LegacyUserAccountRole values
const (
    LegacyUserAccountRoleAccountAdministrator LegacyUserAccountRole = "ACCOUNTADMINISTRATOR"
    LegacyUserAccountRoleAccountMember LegacyUserAccountRole = "ACCOUNTMEMBER"
    LegacyUserAccountRoleAccountAuditor LegacyUserAccountRole = "ACCOUNTAUDITOR"
)

// Legacy user group role
type LegacyUserGroupRole string

// List of supported LegacyUserGroupRole values
const (
    LegacyUserGroupRoleGroupAuditor LegacyUserGroupRole = "GROUPAUDITOR"
    LegacyUserGroupRoleGroupAdministrator LegacyUserGroupRole = "GROUPADMINISTRATOR"
)

// Legacy user group role name or custom role id
type LegacyUserGroupRoleOrRoleId struct {
    LegacyRole *LegacyUserGroupRole
    RoleID *UUID
}
func (x LegacyUserGroupRoleOrRoleId) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "LegacyUserGroupRoleOrRoleId", 
                  []bool{ x.LegacyRole != nil,
                  x.RoleID != nil });
                  err != nil {
        return nil, err
    }
    if x.LegacyRole != nil {
        return json.Marshal(x.LegacyRole)
    }
    if x.RoleID != nil {
        return json.Marshal(x.RoleID)
    }
    panic("unreachable")
}
func (x *LegacyUserGroupRoleOrRoleId) UnmarshalJSON(data []byte) error {
    x.LegacyRole = nil
    x.RoleID = nil
    var legacyRole LegacyUserGroupRole
    if err := json.Unmarshal(data, &legacyRole); err == nil {
        x.LegacyRole = &legacyRole
        return nil
    }
    var roleId UUID
    if err := json.Unmarshal(data, &roleId); err == nil {
        x.RoleID = &roleId
        return nil
    }
    return errors.Errorf("not a valid LegacyUserGroupRoleOrRoleId")
}

// LMS specific options
type LmsOptions struct {
    // The height of the top level tree. This field will be deprecated in v2.
    L1Height *uint32 `json:"l1_height,omitempty"`
    // The height of the secondary tree. This field will be deprecated in v2.
    L2Height *uint32 `json:"l2_height,omitempty"`
    // The hash function to use
    Digest *DigestAlgorithm `json:"digest,omitempty"`
    // Heights of the trees in each level.
    Heights *[]uint `json:"heights,omitempty"`
    // Amount of bytes associated to each node (the 'm' parameter)
    NodeSize *uint `json:"node_size,omitempty"`
}

type LmsOptionsPolicy struct {
}

type Metadata struct {
    TotalCount *uint `json:"total_count,omitempty"`
    FilteredCount *uint `json:"filtered_count,omitempty"`
}

type MetadataDurationConstraint struct {
    Forbidden *struct{}
    Required *MetadataDurationConstraintRequired
}
type MetadataDurationConstraintRequired struct {
    // If specified, the value (typically a date) is restricted to be in a
    // range expressed in terms of duration with respect to some known point
    // in time. For example, if we specify min = 30 days and max = 180 days
    // for `deactivation_date`, then the user must specify a deactivation date
    // that is within 30 and 180 days of security object's creation time.
    AllowedValues *RestrictedDuration `json:"allowed_values,omitempty"`
}
func (x MetadataDurationConstraint) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "MetadataDurationConstraint", 
                  []bool{ x.Forbidden != nil,
                  x.Required != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Forbidden *struct{} `json:"forbidden,omitempty"`
        Required *MetadataDurationConstraintRequired `json:"required,omitempty"`
    }
    obj.Forbidden = x.Forbidden
    obj.Required = x.Required
    return json.Marshal(obj)
}
func (x *MetadataDurationConstraint) UnmarshalJSON(data []byte) error {
    x.Forbidden = nil
    x.Required = nil
    var obj struct {
        Forbidden *struct{} `json:"forbidden,omitempty"`
        Required *MetadataDurationConstraintRequired `json:"required,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.Forbidden = obj.Forbidden
    x.Required = obj.Required
    return nil
}

type MetadataPolicyItem struct {
    CustomMetadata map[string]MetadataStringConstraint `json:"custom_metadata"`
    Description *MetadataStringConstraint `json:"description,omitempty"`
    // If a restricted duration is specified, it is enforced w.r.t object creation time.
    DeactivationDate *MetadataDurationConstraint `json:"deactivation_date,omitempty"`
    // If a restricted duration is specified, it is enforced w.r.t object creation time.
    // NOTE: Specifying a minimum duration for this field may not be a good
    // idea since it would not be possible to create a key and start using it
    // immediately in the affected group(s).
    ActivationDate *MetadataDurationConstraint `json:"activation_date,omitempty"`
}

type MetadataStringConstraint struct {
    Forbidden *struct{}
    Required *MetadataStringConstraintRequired
}
type MetadataStringConstraintRequired struct {
    // If set to `true`, the value must have a length > 0 after trimming
    // leading and trailing whitespace characters.
    NonEmptyAfterTrim *bool `json:"non_empty_after_trim,omitempty"`
    // If not specified or empty, it will not impose any restrictions on the value.
    AllowedValues *[]string `json:"allowed_values,omitempty"`
}
func (x MetadataStringConstraint) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "MetadataStringConstraint", 
                  []bool{ x.Forbidden != nil,
                  x.Required != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Forbidden *struct{} `json:"forbidden,omitempty"`
        Required *MetadataStringConstraintRequired `json:"required,omitempty"`
    }
    obj.Forbidden = x.Forbidden
    obj.Required = x.Required
    return json.Marshal(obj)
}
func (x *MetadataStringConstraint) UnmarshalJSON(data []byte) error {
    x.Forbidden = nil
    x.Required = nil
    var obj struct {
        Forbidden *struct{} `json:"forbidden,omitempty"`
        Required *MetadataStringConstraintRequired `json:"required,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.Forbidden = obj.Forbidden
    x.Required = obj.Required
    return nil
}

// Params for Mfa challenge.
type MfaChallengeParams struct {
    // Protocol for the Mfa request. U2f is default
    // for backcompat.
    Protocol MfaProtocol `json:"protocol"`
}
func (x MfaChallengeParams) urlEncode(v map[string][]string) error {
    v["protocol"] = []string{fmt.Sprintf("%v", x.Protocol)}
    return nil
}

type MfaChallengeResponse struct {
    LegacyU2f *U2fMfaChallengeResponse
    Fido2 *Fido2MfaChallengeResponse
}
func (x MfaChallengeResponse) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "MfaChallengeResponse", 
                  []bool{ x.LegacyU2f != nil,
                  x.Fido2 != nil });
                  err != nil {
        return nil, err
    }
    if x.LegacyU2f != nil {
        return json.Marshal(x.LegacyU2f)
    }
    if x.Fido2 != nil {
        return json.Marshal(x.Fido2)
    }
    panic("unreachable")
}
func (x *MfaChallengeResponse) UnmarshalJSON(data []byte) error {
    x.LegacyU2f = nil
    x.Fido2 = nil
    var legacyU2f U2fMfaChallengeResponse
    if err := json.Unmarshal(data, &legacyU2f); err == nil {
        x.LegacyU2f = &legacyU2f
        return nil
    }
    var fido2 Fido2MfaChallengeResponse
    if err := json.Unmarshal(data, &fido2); err == nil {
        x.Fido2 = &fido2
        return nil
    }
    return errors.Errorf("not a valid MfaChallengeResponse")
}

// A FIDO device that may be used for second factor authentication.
type MfaDevice struct {
    // Name given to the FIDO device.
    Name string `json:"name"`
    // Type of the device, should be either fido2 or u2f
    Type MfaDeviceType `json:"type"`
    // Origin of the FIDO device.
    Origin *string `json:"origin,omitempty"`
}

// Type of MFA device
type MfaDeviceType string

// List of supported MfaDeviceType values
const (
    MfaDeviceTypeU2f MfaDeviceType = "U2f"
    MfaDeviceTypeFido2 MfaDeviceType = "Fido2"
)

// Protocols for MFA.
type MfaProtocol string

// List of supported MfaProtocol values
const (
    // U2f protocol. (deprecated)
    MfaProtocolU2f MfaProtocol = "u2f"
    // FIDO2 protocol.
    MfaProtocolFido2 MfaProtocol = "fido2"
)

// Specifies the Mask Generating Function (MGF) to use.
type Mgf struct {
    // MGF1 algorithm
    Mgf1 *Mgf1
}
// MGF1 algorithm
type Mgf1 struct {
    Hash DigestAlgorithm `json:"hash"`
}
func (x Mgf) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "Mgf", 
                  []bool{ x.Mgf1 != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Mgf1 *Mgf1 `json:"mgf1,omitempty"`
    }
    obj.Mgf1 = x.Mgf1
    return json.Marshal(obj)
}
func (x *Mgf) UnmarshalJSON(data []byte) error {
    x.Mgf1 = nil
    var obj struct {
        Mgf1 *Mgf1 `json:"mgf1,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.Mgf1 = obj.Mgf1
    return nil
}

// MGF policy.
type MgfPolicy struct {
    Mgf1 *MgfPolicyMgf1
}
type MgfPolicyMgf1 struct {
    Hash *DigestAlgorithm `json:"hash,omitempty"`
}
func (x MgfPolicy) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "MgfPolicy", 
                  []bool{ x.Mgf1 != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Mgf1 *MgfPolicyMgf1 `json:"mgf1,omitempty"`
    }
    obj.Mgf1 = x.Mgf1
    return json.Marshal(obj)
}
func (x *MgfPolicy) UnmarshalJSON(data []byte) error {
    x.Mgf1 = nil
    var obj struct {
        Mgf1 *MgfPolicyMgf1 `json:"mgf1,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.Mgf1 = obj.Mgf1
    return nil
}

// ML-DSA specific options
type MlDsaBetaOptions struct {
    ParamSet MlDsaParamSet `json:"param_set"`
}

type MlDsaBetaOptionsPolicy struct {
}

// ML-DSA parameter sets
type MlDsaParamSet string

// List of supported MlDsaParamSet values
const (
    MlDsaParamSetMlDsa44 MlDsaParamSet = "MlDsa44"
    MlDsaParamSetMlDsa65 MlDsaParamSet = "MlDsa65"
    MlDsaParamSetMlDsa87 MlDsaParamSet = "MlDsa87"
)

// ML-KEM specific options
type MlKemBetaOptions struct {
    ParamSet *MlKemParamSet `json:"param_set,omitempty"`
}

type MlKemBetaOptionsPolicy struct {
}

// ML-KEM parameter sets
type MlKemParamSet string

// List of supported MlKemParamSet values
const (
    MlKemParamSetMlKem512 MlKemParamSet = "MlKem512"
    MlKemParamSetMlKem768 MlKemParamSet = "MlKem768"
    MlKemParamSetMlKem1024 MlKemParamSet = "MlKem1024"
)

// Corresponds to the `display` parameter in
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type OauthAuthParamDisplay string

// List of supported OauthAuthParamDisplay values
const (
    // The Authorization Server SHOULD display the authentication and consent UI consistent with a full User Agent page view
    OauthAuthParamDisplayPage OauthAuthParamDisplay = "page"
    // The Authorization Server SHOULD display the authentication and consent UI consistent with a popup User Agent window.
    // The popup User Agent window should be of an appropriate size for a login-focused dialog and should not obscure the entire window that it is popping up over.
    OauthAuthParamDisplayPopup OauthAuthParamDisplay = "popup"
    // The Authorization Server SHOULD display the authentication and consent UI consistent with a device that leverages a touch interface.
    OauthAuthParamDisplayTouch OauthAuthParamDisplay = "touch"
    // The Authorization Server SHOULD display the authentication and consent UI consistent with a "feature phone" type display.
    OauthAuthParamDisplayWap OauthAuthParamDisplay = "wap"
)

// Corresponds to the `prompt` parameter in
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type OauthAuthParamPrompt string

// List of supported OauthAuthParamPrompt values
const (
    // The Authorization Server SHOULD prompt the End-User for reauthentication.
    // If it cannot reauthenticate the End-User, it MUST return an error, typically login_required.
    OauthAuthParamPromptLogin OauthAuthParamPrompt = "login"
    // The Authorization Server MUST NOT display any authentication or consent user interface pages.
    // An error is returned if an End-User is not already authenticated or the Client does not have pre-configured consent for the requested Claims or does not fulfill other conditions for processing the request.
    // The error code will typically be login_required, interaction_required, or another code defined in Section 3.1.2.6.
    // This can be used as a method to check for existing authentication and/or consent.
    OauthAuthParamPromptNone OauthAuthParamPrompt = "none"
    // The Authorization Server SHOULD prompt the End-User for consent before returning information to the Client.
    // If it cannot obtain consent, it MUST return an error, typically consent_required.
    OauthAuthParamPromptConsent OauthAuthParamPrompt = "consent"
    // The Authorization Server SHOULD prompt the End-User to select a user account.
    // This enables an End-User who has multiple accounts at the Authorization Server to select amongst the multiple accounts that they might have current sessions for.
    // If it cannot obtain an account selection choice made by the End-User, it MUST return an error, typically account_selection_required.
    OauthAuthParamPromptSelectAccount OauthAuthParamPrompt = "select_account"
)

// Parameters for the OpenID Connect Authentication Request
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type OauthAuthenticationParameters struct {
    // Specifies whether the Authorization Server prompts the End-User for reauthentication and consent
    Prompt *[]OauthAuthParamPrompt `json:"prompt,omitempty"`
    // Specifies how the Authorization Server displays the authentication and consent user interface pages to the End-User
    Display *OauthAuthParamDisplay `json:"display,omitempty"`
    // Specifies the allowable elapsed time in seconds since the last time the End-User was actively authenticated by the OP.
    // If the elapsed time is greater than this value, the OP MUST attempt to actively re-authenticate the End-User
    MaxAge *uint64 `json:"max_age,omitempty"`
}

// OAuth scope.
type OauthScope string

// List of supported OauthScope values
const (
    OauthScopeApp OauthScope = "app"
    OauthScopeOpenID OauthScope = "openid"
    OauthScopeEmail OauthScope = "email"
    OauthScopeProfile OauthScope = "profile"
)

type ObjectCount struct {
    // Count of the items in the collection matching the request
    Count uint64 `json:"count"`
    // accuracy of the count returned
    CountAccuracy CountAccuracy `json:"count_accuracy"`
}

// The origin of a security object - where it was created / generated.
type ObjectOrigin string

// List of supported ObjectOrigin values
const (
    ObjectOriginFortanixHSM ObjectOrigin = "FortanixHSM"
    ObjectOriginTransient ObjectOrigin = "Transient"
    ObjectOriginExternal ObjectOrigin = "External"
)

// Type of security object.
type ObjectType string

// List of supported ObjectType values
const (
    ObjectTypeAes ObjectType = "AES"
    ObjectTypeAria ObjectType = "ARIA"
    ObjectTypeDes ObjectType = "DES"
    ObjectTypeDes3 ObjectType = "DES3"
    ObjectTypeSeed ObjectType = "SEED"
    ObjectTypeRsa ObjectType = "RSA"
    ObjectTypeDsa ObjectType = "DSA"
    ObjectTypeEc ObjectType = "EC"
    ObjectTypeKcdsa ObjectType = "KCDSA"
    ObjectTypeEcKcdsa ObjectType = "ECKCDSA"
    ObjectTypeBip32 ObjectType = "BIP32"
    ObjectTypeBls ObjectType = "BLS"
    ObjectTypeOpaque ObjectType = "OPAQUE"
    ObjectTypeHmac ObjectType = "HMAC"
    ObjectTypeLedaBeta ObjectType = "LEDABETA"
    ObjectTypeRound5Beta ObjectType = "ROUND5BETA"
    ObjectTypeSecret ObjectType = "SECRET"
    ObjectTypeLms ObjectType = "LMS"
    ObjectTypeXmss ObjectType = "XMSS"
    ObjectTypeMlDsaBeta ObjectType = "MLDSABETA"
    ObjectTypeMlKemBeta ObjectType = "MLKEMBETA"
    ObjectTypeCertificate ObjectType = "CERTIFICATE"
    ObjectTypePbe ObjectType = "PBE"
)

type ObjectTypeFilter struct {
    All *struct{}
    Selection *ObjectTypeFilterSelection
}
type ObjectTypeFilterSelection struct {
    Selection []ObjectType `json:"selection"`
}
func (x ObjectTypeFilter) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "ObjectTypeFilter", 
                  []bool{ x.All != nil,
                  x.Selection != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.All != nil:
        m["$type"] = "All"
    case x.Selection != nil:
        b, err := json.Marshal(x.Selection)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["$type"] = "Selection"
    }
    return json.Marshal(m)
}
func (x *ObjectTypeFilter) UnmarshalJSON(data []byte) error {
    x.All = nil
    x.Selection = nil
    var h struct {
        Tag string `json:"$type"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid ObjectTypeFilter")
    }
    switch h.Tag {
    case "All":
        x.All = &struct{}{}
    case "Selection":
        var selection ObjectTypeFilterSelection
        if err := json.Unmarshal(data, &selection); err != nil {
            return err
        }
        x.Selection = &selection
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

type OpaqueOptionsPolicy struct {
}

type Pkcs11ClientConfig struct {
    FakeRsaX931KeygenSupport *bool `json:"fake_rsa_x9_31_keygen_support,omitempty"`
    SigningAesKeyAsHmac *bool `json:"signing_aes_key_as_hmac,omitempty"`
    ExactKeyOps *bool `json:"exact_key_ops,omitempty"`
    PreventDuplicateOpaqueObjects *bool `json:"prevent_duplicate_opaque_objects,omitempty"`
    OpaqueObjectsAreNotCertificates *bool `json:"opaque_objects_are_not_certificates,omitempty"`
    MaxConcurrentRequestsPerSlot *uint `json:"max_concurrent_requests_per_slot,omitempty"`
}

// Plugin code signing policy.
//
// When a code signing policy is set, all requests to create new plugins or
// update existing plugins (if updating the code) would need to provide a valid
// signature.
type PluginCodeSigningPolicy struct {
    // The public key(s) used to verify plugin code signatures.
    SigningKeys SigningKeys `json:"signing_keys"`
}

// A security principal.
type Principal struct {
    App *UUID
    User *UUID
    Plugin *UUID
    // UserViaApp signifies a user authorizing some app to act on its behalf through OAuth.
    UserViaApp *PrincipalUserViaApp
    // System signifies DSM itself performing certain actions, like automatic key scans.
    // This cannot be used for things like approval requests or session creation.
    System *struct{}
    // An unregistered user.
    UnregisteredUser *struct{}
}
// UserViaApp signifies a user authorizing some app to act on its behalf through OAuth.
type PrincipalUserViaApp struct {
    UserID UUID `json:"user_id"`
    Scopes []OauthScope `json:"scopes"`
}
func (x Principal) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "Principal", 
                  []bool{ x.App != nil,
                  x.User != nil,
                  x.Plugin != nil,
                  x.UserViaApp != nil,
                  x.System != nil,
                  x.UnregisteredUser != nil });
                  err != nil {
        return nil, err
    }
    switch {
    case x.System != nil:
        return []byte(`"system"`), nil
    case x.UnregisteredUser != nil:
        return []byte(`"unregistereduser"`), nil
    }
    var obj struct {
        App *UUID `json:"app,omitempty"`
        User *UUID `json:"user,omitempty"`
        Plugin *UUID `json:"plugin,omitempty"`
        UserViaApp *PrincipalUserViaApp `json:"userviaapp,omitempty"`
    }
    obj.App = x.App
    obj.User = x.User
    obj.Plugin = x.Plugin
    obj.UserViaApp = x.UserViaApp
    return json.Marshal(obj)
}
func (x *Principal) UnmarshalJSON(data []byte) error {
    x.App = nil
    x.User = nil
    x.Plugin = nil
    x.UserViaApp = nil
    x.System = nil
    x.UnregisteredUser = nil
    var str string
    if err := json.Unmarshal(data, &str); err == nil {
        switch str {
        case "system":
            x.System = &struct{}{}
        case "unregistereduser":
            x.UnregisteredUser = &struct{}{}
        default:
            return errors.Errorf("invalid value for Principal: %v", str)
        }
        return nil
    }
    var obj struct {
        App *UUID `json:"app,omitempty"`
        User *UUID `json:"user,omitempty"`
        Plugin *UUID `json:"plugin,omitempty"`
        UserViaApp *PrincipalUserViaApp `json:"userviaapp,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.App = obj.App
    x.User = obj.User
    x.Plugin = obj.Plugin
    x.UserViaApp = obj.UserViaApp
    return nil
}

// <https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions>
type PublicKeyCredentialCreationOptions struct {
    // Additional relying party's attributes. See type level
    // doc for more info.
    Rp PublicKeyCredentialEntityForRp `json:"rp"`
    // Additional user's attributes. See type level doc for
    // more info.
    User PublicKeyCredentialEntityForUser `json:"user"`
    // A random base64url encoded string. This can be min 16 bytes
    // and max 64 bytes.
    Challenge Base64UrlSafe `json:"challenge"`
    // This member contains information about the desired properties of the
    // credential to be created. The sequence is ordered from most preferred
    // to least preferred.
    PubKeyCredParams []PublicKeyCredentialParameters `json:"pubKeyCredParams"`
    // The time for which response from the authenticator
    // would be awaited. This should only be a hint as per the spec.
    // This is in milliseconds.
    Timeout *uint64 `json:"timeout,omitempty"`
    // The existing creds mapped to the current user. This tells
    // the authenticator to not create multiple creds for the same
    // user.
    // NOTE: This isn't for U2F authenticators. For that, `appidExclude`
    // needs to be set instead.
    ExcludeCredentials []PublicKeyCredentialDescriptor `json:"excludeCredentials"`
    // The selection criteria that should be used for selecting
    // an authenticator.
    AuthenticatorSelection *AuthenticatorSelectionCriteria `json:"authenticatorSelection,omitempty"`
    // The way attestation should be conveyed to RP.
    // See type level doc for more info.
    Attestation AttestationConveyancePreference `json:"attestation"`
    // Registration extensions returns by DSM and should
    // be used as inputs to `navigator.credentials.create()`.
    //
    // Extensions are optional and can be ignored by clients
    // or authenticator. But as per the spec, if the extensions
    // are ignored, response of extensions must be empty and
    // if not ignored, then, response must not be empty.
    Extensions *AuthenticationExtensionsClientInputs `json:"extensions,omitempty"`
}

// Used to in registration response (telling about existing creds) to prevent
// creation of duplicate creds on the same authenticator.
// Used in authentication as the allowed creds.
type PublicKeyCredentialDescriptor struct {
    // Type of credential.
    Type PublicKeyCredentialType `json:"type"`
    // Credential ID of the public key credential the
    // caller is referring to.
    ID Base64UrlSafe `json:"id"`
    // Hints by relying party on what transport client should
    // use to communicate with authenticator.
    Transports *[]AuthenticatorTransport `json:"transports,omitempty"`
}

// https://www.w3.org/TR/webauthn-2/#dictionary-credential-params
type PublicKeyCredentialParameters struct {
    // Type of credential.
    Type PublicKeyCredentialType `json:"type"`
    // An algorithm from IANA COSE Algorithms registry supported
    // by DSM as well.Upgrade to use this branch
    Alg COSEAlgorithmIdentifier `json:"alg"`
}

// <https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options>
type PublicKeyCredentialRequestOptions struct {
    // This member contains the base64url encoding of the challenge
    // provided by the Relying Party
    Challenge Base64UrlSafe `json:"challenge"`
    // The time for which response from the authenticator
    // would be awaited. This should only be a hint as per the spec.
    // This is in milliseconds.
    Timeout *uint64 `json:"timeout,omitempty"`
    // This optional member specifies the relying party identifier
    // claimed by the caller. If omitted, its value will be the
    // CredentialsContainer object’s relevant settings object's
    // origin's effective domain.
    RpID *string `json:"rpId,omitempty"`
    // This OPTIONAL member contains a list of [PublicKeyCredentialDescriptor]
    // objects representing public key credentials acceptable to the caller,
    // in descending order of the caller’s preference (the first item in the
    // list is the most preferred credential, and so on down the list).
    AllowCredentials *[]PublicKeyCredentialDescriptor `json:"allowCredentials,omitempty"`
    // Authenticator should support user verification by
    // ways like pin code, biometrics, etc.
    UserVerification *UserVerificationRequirement `json:"userVerification,omitempty"`
    // Authentication extensions returned by DSM and should
    // be used as inputs to `navigator.credentials.get()`.
    //
    // Extensions are optional and can be ignored by clients
    // or authenticator. But as per the spec, if the extensions
    // are ignored, response of extensions must be empty and
    // if not ignored, then, response must not be empty.
    Extensions *AuthenticationExtensionsClientInputs `json:"extensions,omitempty"`
}

// <https://www.w3.org/TR/webauthn-2/#dictionary-rp-credential-params>
type PublicKeyCredentialRpEntity struct {
    // A unique identifier for the Relying Party entity, which sets the RP ID.
    //
    // <https://www.w3.org/TR/webauthn-2/#CreateCred-DetermineRpId>
    ID *string `json:"id,omitempty"`
}

// https://www.w3.org/TR/webauthn-2/#enum-credentialType
//
// This enum defines valid cred types.
type PublicKeyCredentialType string

// List of supported PublicKeyCredentialType values
const (
    // Public key credential.
    PublicKeyCredentialTypePublicKey PublicKeyCredentialType = "public-key"
)

// <https://www.w3.org/TR/webauthn-2/#dictionary-user-credential-params>
type PublicKeyCredentialUserEntity struct {
    // This is uuid of the user in DSM. But here, it is
    // in base64url format as required by fido server conformance
    // spec.
    ID Base64UrlSafe `json:"id"`
    // Human friendly name intended only for display.
    DisplayName string `json:"displayName"`
}

// If enabled, the public key will be available publicly (without authentication) through the GetPublicKey API.
type PublishPublicKeyConfig struct {
    Enabled *PublishPublicKeyConfigEnabled
    Disabled *struct{}
}
type PublishPublicKeyConfigEnabled struct {
    // Additionally list the previous version of the key if not compromised.
    ListPreviousVersion bool `json:"list_previous_version"`
}
func (x PublishPublicKeyConfig) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "PublishPublicKeyConfig", 
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
func (x *PublishPublicKeyConfig) UnmarshalJSON(data []byte) error {
    x.Enabled = nil
    x.Disabled = nil
    var h struct {
        Tag string `json:"state"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid PublishPublicKeyConfig")
    }
    switch h.Tag {
    case "enabled":
        var enabled PublishPublicKeyConfigEnabled
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

// Quorum approval policy.
type Quorum struct {
    N uint `json:"n"`
    Members []QuorumPolicy `json:"members"`
    Config ApprovalAuthConfig `json:"config"`
}
func (x Quorum) MarshalJSON() ([]byte, error) {
    m := make(map[string]interface{})
    { // x.Config is flattened
        b, err := json.Marshal(&x.Config)
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
    m["n"] = x.N
    if x.Members != nil {
        m["members"] = x.Members
    }
    return json.Marshal(&m)
}
func (x *Quorum) UnmarshalJSON(data []byte) error {
    if err := json.Unmarshal(data, &x.Config); err != nil {
        return err
    }
    var r struct {
    N uint `json:"n"`
    Members []QuorumPolicy `json:"members"`
    }
    if err := json.Unmarshal(data, &r); err != nil {
        return err
    }
    x.N = r.N
    x.Members = r.Members
    return nil
}

// Quorum Policy Configurations in clients
type QuorumApprovalConfig struct {
    WaitForQuorumApproval *ApprovalWaitConfig `json:"wait_for_quorum_approval,omitempty"`
}

// Approval policy.
type QuorumPolicy struct {
    Quorum *Quorum `json:"quorum,omitempty"`
    User *UUID `json:"user,omitempty"`
    App *UUID `json:"app,omitempty"`
}

// <https://www.w3.org/TR/webauthn-2/#enum-residentKeyRequirement>
//
// Tells Relying Party's requirement about client side discoverable
// creds (formely known as resident keys).
// If client side discoverable creds are there, it means that the
// authenticator is self-sufficient in identifying the user. If this
// isn't the case, the user needs to login first so that the server
// can identify the user and help send `allowCredentials` to authenticator.
//
// This is mostly meant for [username-less] authentication (which we don't
// support in DSM). We support 2FA where we already know about the logged
// in user.
//
// [username-less]: <https://groups.google.com/a/fidoalliance.org/g/fido-dev/c/ALQj3JXuyhs>
type ResidentKeyRequirement string

// List of supported ResidentKeyRequirement values
const (
    // Indicates that the relying party "prefers"
    // that client-side discoverable creds aren't
    // created.
    ResidentKeyRequirementDiscouraged ResidentKeyRequirement = "discouraged"
    // Indicates that relying party prefers resident
    // keys.
    ResidentKeyRequirementPreferred ResidentKeyRequirement = "preferred"
    // Indicates that relying party requires resident
    // keys.
    ResidentKeyRequirementRequired ResidentKeyRequirement = "required"
)

type RestrictedDuration struct {
    Min *TimeSpan `json:"min,omitempty"`
    Max *TimeSpan `json:"max,omitempty"`
}

// Reason for revoking a key.
type RevocationReason struct {
    Code RevocationReasonCode `json:"code"`
    // Message is used exclusively for audit trail/logging purposes and MAY contain additional
    // information about why the object was revoked.
    Message *string `json:"message,omitempty"`
    CompromiseOccuranceDate *Time `json:"compromise_occurance_date,omitempty"`
}

// Reasons to revoke a security object.
type RevocationReasonCode string

// List of supported RevocationReasonCode values
const (
    RevocationReasonCodeUnspecified RevocationReasonCode = "Unspecified"
    RevocationReasonCodeKeyCompromise RevocationReasonCode = "KeyCompromise"
    RevocationReasonCodeCACompromise RevocationReasonCode = "CACompromise"
    RevocationReasonCodeAffiliationChanged RevocationReasonCode = "AffiliationChanged"
    RevocationReasonCodeSuperseded RevocationReasonCode = "Superseded"
    RevocationReasonCodeCessationOfOperation RevocationReasonCode = "CessationOfOperation"
    RevocationReasonCodePrivilegeWithdrawn RevocationReasonCode = "PrivilegeWithdrawn"
)

type RotateCopiedKeys struct {
    AllExternal *struct{}
    Select *[]UUID
}
func (x RotateCopiedKeys) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "RotateCopiedKeys", 
                  []bool{ x.AllExternal != nil,
                  x.Select != nil });
                  err != nil {
        return nil, err
    }
    switch {
    case x.AllExternal != nil:
        return []byte(`"all_external"`), nil
    }
    var obj struct {
        Select *[]UUID `json:"select,omitempty"`
    }
    obj.Select = x.Select
    return json.Marshal(obj)
}
func (x *RotateCopiedKeys) UnmarshalJSON(data []byte) error {
    x.AllExternal = nil
    x.Select = nil
    var str string
    if err := json.Unmarshal(data, &str); err == nil {
        switch str {
        case "all_external":
            x.AllExternal = &struct{}{}
        default:
            return errors.Errorf("invalid value for RotateCopiedKeys: %v", str)
        }
        return nil
    }
    var obj struct {
        Select *[]UUID `json:"select,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.Select = obj.Select
    return nil
}

type RotationInterval struct {
    IntervalDays *uint32
    IntervalMonths *uint32
}
func (x RotationInterval) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "RotationInterval", 
                  []bool{ x.IntervalDays != nil,
                  x.IntervalMonths != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        IntervalDays *uint32 `json:"interval_days,omitempty"`
        IntervalMonths *uint32 `json:"interval_months,omitempty"`
    }
    obj.IntervalDays = x.IntervalDays
    obj.IntervalMonths = x.IntervalMonths
    return json.Marshal(obj)
}
func (x *RotationInterval) UnmarshalJSON(data []byte) error {
    x.IntervalDays = nil
    x.IntervalMonths = nil
    var obj struct {
        IntervalDays *uint32 `json:"interval_days,omitempty"`
        IntervalMonths *uint32 `json:"interval_months,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.IntervalDays = obj.IntervalDays
    x.IntervalMonths = obj.IntervalMonths
    return nil
}

type RotationPolicy struct {
    Interval *RotationInterval `json:"interval,omitempty"`
    EffectiveAt *Time `json:"effective_at,omitempty"`
    DeactivateRotatedKey *bool `json:"deactivate_rotated_key,omitempty"`
    RotateCopiedKeys *RotateCopiedKeys `json:"rotate_copied_keys,omitempty"`
}
func (x RotationPolicy) MarshalJSON() ([]byte, error) {
    m := make(map[string]interface{})
    { // x.Interval is flattened
        b, err := json.Marshal(&x.Interval)
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
    if x.EffectiveAt != nil {
        m["effective_at"] = x.EffectiveAt
    }
    if x.DeactivateRotatedKey != nil {
        m["deactivate_rotated_key"] = x.DeactivateRotatedKey
    }
    if x.RotateCopiedKeys != nil {
        m["rotate_copied_keys"] = x.RotateCopiedKeys
    }
    return json.Marshal(&m)
}
func (x *RotationPolicy) UnmarshalJSON(data []byte) error {
    if err := json.Unmarshal(data, &x.Interval); err != nil {
        return err
    }
    var r struct {
    EffectiveAt *Time `json:"effective_at,omitempty"`
    DeactivateRotatedKey *bool `json:"deactivate_rotated_key,omitempty"`
    RotateCopiedKeys *RotateCopiedKeys `json:"rotate_copied_keys,omitempty"`
    }
    if err := json.Unmarshal(data, &r); err != nil {
        return err
    }
    x.EffectiveAt = r.EffectiveAt
    x.DeactivateRotatedKey = r.DeactivateRotatedKey
    x.RotateCopiedKeys = r.RotateCopiedKeys
    return nil
}

// Type of padding to use for RSA encryption. The use of PKCS#1 v1.5 padding is strongly
// discouraged, because of its susceptibility to Bleichenbacher's attack. The padding specified
// must adhere to the key's encryption policy. If not specified, the default based on the key's
// policy will be used.
type RsaEncryptionPadding struct {
    // Optimal Asymmetric Encryption Padding (PKCS#1 v2.1).
    Oaep *RsaEncryptionPaddingOaep
    // PKCS#1 v1.5 padding. This is disallowed in FIPS builds.
    Pkcs1V15 *struct{}
    // RSA decryption without padding. (Raw RSA encryption is not supported)
    RawDecrypt *struct{}
}
// Optimal Asymmetric Encryption Padding (PKCS#1 v2.1).
type RsaEncryptionPaddingOaep struct {
    Mgf Mgf `json:"mgf"`
}
func (x RsaEncryptionPadding) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "RsaEncryptionPadding", 
                  []bool{ x.Oaep != nil,
                  x.Pkcs1V15 != nil,
                  x.RawDecrypt != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Oaep *RsaEncryptionPaddingOaep `json:"OAEP,omitempty"`
        Pkcs1V15 *struct{} `json:"PKCS1_V15,omitempty"`
        RawDecrypt *struct{} `json:"RAW_DECRYPT,omitempty"`
    }
    obj.Oaep = x.Oaep
    obj.Pkcs1V15 = x.Pkcs1V15
    obj.RawDecrypt = x.RawDecrypt
    return json.Marshal(obj)
}
func (x *RsaEncryptionPadding) UnmarshalJSON(data []byte) error {
    x.Oaep = nil
    x.Pkcs1V15 = nil
    x.RawDecrypt = nil
    var obj struct {
        Oaep *RsaEncryptionPaddingOaep `json:"OAEP,omitempty"`
        Pkcs1V15 *struct{} `json:"PKCS1_V15,omitempty"`
        RawDecrypt *struct{} `json:"RAW_DECRYPT,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.Oaep = obj.Oaep
    x.Pkcs1V15 = obj.Pkcs1V15
    x.RawDecrypt = obj.RawDecrypt
    return nil
}

// RSA encryption padding policy.
type RsaEncryptionPaddingPolicy struct {
    // The Optional Asymmetric Encryption Padding scheme, as defined
    // in RFC 8017 (PKCS #1 version 2.2)
    Oaep *RsaEncryptionPaddingPolicyOaep
    // PKCS #1 version 1.5 encryption padding. This is disallowed in
    // FIPS builds
    Pkcs1V15 *struct{}
    // Raw RSA decryption
    RawDecrypt *struct{}
}
// The Optional Asymmetric Encryption Padding scheme, as defined
// in RFC 8017 (PKCS #1 version 2.2)
type RsaEncryptionPaddingPolicyOaep struct {
    Mgf *MgfPolicy `json:"mgf,omitempty"`
}
func (x RsaEncryptionPaddingPolicy) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "RsaEncryptionPaddingPolicy", 
                  []bool{ x.Oaep != nil,
                  x.Pkcs1V15 != nil,
                  x.RawDecrypt != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Oaep *RsaEncryptionPaddingPolicyOaep `json:"OAEP,omitempty"`
        Pkcs1V15 *struct{} `json:"PKCS1_V15,omitempty"`
        RawDecrypt *struct{} `json:"RAW_DECRYPT,omitempty"`
    }
    obj.Oaep = x.Oaep
    obj.Pkcs1V15 = x.Pkcs1V15
    obj.RawDecrypt = x.RawDecrypt
    return json.Marshal(obj)
}
func (x *RsaEncryptionPaddingPolicy) UnmarshalJSON(data []byte) error {
    x.Oaep = nil
    x.Pkcs1V15 = nil
    x.RawDecrypt = nil
    var obj struct {
        Oaep *RsaEncryptionPaddingPolicyOaep `json:"OAEP,omitempty"`
        Pkcs1V15 *struct{} `json:"PKCS1_V15,omitempty"`
        RawDecrypt *struct{} `json:"RAW_DECRYPT,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.Oaep = obj.Oaep
    x.Pkcs1V15 = obj.Pkcs1V15
    x.RawDecrypt = obj.RawDecrypt
    return nil
}

// Constraints on RSA encryption parameters. In general, if a constraint is not specified, anything is allowed.
type RsaEncryptionPolicy struct {
    Padding *RsaEncryptionPaddingPolicy `json:"padding,omitempty"`
}

// RSA-specific options.
type RsaOptions struct {
    // Size in bits (not bytes) of the RSA key. Specify on Create only. Returned on Get.
    KeySize *uint32 `json:"key_size,omitempty"`
    // Public exponent to use for generating the RSA key. Specify on Create only.
    PublicExponent *uint32 `json:"public_exponent,omitempty"`
    // Encryption policy for an RSA key. When doing an encryption or key wrapping operation, the
    // policies are evaluated against the specified parameters one by one. If one matches, the
    // operation is allowed. If none match, including if the policy list is empty, the operation
    // is disallowed. Missing optional parameters will have their defaults specified according to
    // the matched policy. The default for new keys is `[{"padding":{"OAEP":{}}]`.
    // If (part of) a constraint is not specified, anything is allowed for that constraint.
    // To impose no constraints, specify `[{}]`.
    EncryptionPolicy *[]RsaEncryptionPolicy `json:"encryption_policy,omitempty"`
    // Signature policy for an RSA key. When doing a signature operation, the policies are
    // evaluated against the specified parameters one by one. If one matches, the operation is
    // allowed. If none match, including if the policy list is empty, the operation is disallowed.
    // Missing optional parameters will have their defaults specified according to the matched
    // policy. The default for new keys is `[{}]` (no constraints).
    // If (part of) a constraint is not specified, anything is allowed for that constraint.
    SignaturePolicy *[]RsaSignaturePolicy `json:"signature_policy,omitempty"`
    // The minimum allowed key length. This is only relevant for group or account cryptographic
    // policies (and hence has no effect in an RSA policy on a specific key).
    MinimumKeyLength *uint32 `json:"minimum_key_length,omitempty"`
}

type RsaOptionsPolicy struct {
    EncryptionPolicy *[]RsaEncryptionPolicy `json:"encryption_policy,omitempty"`
    // Signature policy for an RSA key. When doing a signature operation, the policies are
    // evaluated against the specified parameters one by one. If one matches, the operation is
    // allowed. If none match, including if the policy list is empty, the operation is disallowed.
    // Missing optional parameters will have their defaults specified according to the matched
    // policy. The default for new keys is `[{}]` (no constraints).
    // If (part of) a constraint is not specified, anything is allowed for that constraint.
    SignaturePolicy *[]RsaSignaturePolicy `json:"signature_policy,omitempty"`
    // The minimum allowed key length. This is only relevant for group or account cryptographic
    // policies (and hence has no effect in an RSA policy on a specific key).
    MinimumKeyLength *uint32 `json:"minimum_key_length,omitempty"`
}

// RSA signature padding policy.
type RsaSignaturePaddingPolicy struct {
    Pss *RsaSignaturePaddingPolicyPss
    Pkcs1V15 *struct{}
}
type RsaSignaturePaddingPolicyPss struct {
    Mgf *MgfPolicy `json:"mgf,omitempty"`
}
func (x RsaSignaturePaddingPolicy) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "RsaSignaturePaddingPolicy", 
                  []bool{ x.Pss != nil,
                  x.Pkcs1V15 != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Pss *RsaSignaturePaddingPolicyPss `json:"PSS,omitempty"`
        Pkcs1V15 *struct{} `json:"PKCS1_V15,omitempty"`
    }
    obj.Pss = x.Pss
    obj.Pkcs1V15 = x.Pkcs1V15
    return json.Marshal(obj)
}
func (x *RsaSignaturePaddingPolicy) UnmarshalJSON(data []byte) error {
    x.Pss = nil
    x.Pkcs1V15 = nil
    var obj struct {
        Pss *RsaSignaturePaddingPolicyPss `json:"PSS,omitempty"`
        Pkcs1V15 *struct{} `json:"PKCS1_V15,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.Pss = obj.Pss
    x.Pkcs1V15 = obj.Pkcs1V15
    return nil
}

// Constraints on RSA signature parameters. In general, if a constraint is not specified, anything is allowed.
type RsaSignaturePolicy struct {
    Padding *RsaSignaturePaddingPolicy `json:"padding,omitempty"`
}

type SecretOptionsPolicy struct {
}

type Secs = uint64

type SeedOptions struct {
    CipherMode *CipherMode `json:"cipher_mode,omitempty"`
    RandomIv *bool `json:"random_iv,omitempty"`
}

type SeedOptionsPolicy struct {
    RandomIv *bool `json:"random_iv,omitempty"`
}

// Signing keys used to validate JSON Web Signature objects including signed
// JSON Web Tokens.
type SigningKeys struct {
    Stored *SigningKeysStored
    Fetched *SigningKeysFetched
}
type SigningKeysStored struct {
    // Mapping key ids to DER-encoded public key.
    Keys map[string]ZeroizedBlob `json:"keys"`
}
type SigningKeysFetched struct {
    URL string `json:"url"`
    // Number of seconds that the service is allowed to cache the fetched keys.
    CacheDuration uint64 `json:"cache_duration"`
}
func (x SigningKeys) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "SigningKeys", 
                  []bool{ x.Stored != nil,
                  x.Fetched != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.Stored != nil:
        b, err := json.Marshal(x.Stored)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["kind"] = "stored"
    case x.Fetched != nil:
        b, err := json.Marshal(x.Fetched)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["kind"] = "fetched"
    }
    return json.Marshal(m)
}
func (x *SigningKeys) UnmarshalJSON(data []byte) error {
    x.Stored = nil
    x.Fetched = nil
    var h struct {
        Tag string `json:"kind"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid SigningKeys")
    }
    switch h.Tag {
    case "stored":
        var stored SigningKeysStored
        if err := json.Unmarshal(data, &stored); err != nil {
            return err
        }
        x.Stored = &stored
    case "fetched":
        var fetched SigningKeysFetched
        if err := json.Unmarshal(data, &fetched); err != nil {
            return err
        }
        x.Fetched = &fetched
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

type Sobject struct {
    // UUID of the account which the security object belongs to.
    AcctID UUID `json:"acct_id"`
    // Activation date of security object in seconds since EPOCH.
    ActivationDate *Time `json:"activation_date,omitempty"`
    // AES specific options.
    Aes *AesOptions `json:"aes,omitempty"`
    // Whether the sign operation response contains hash or data as output.
    AllowSignHash *bool `json:"allow_sign_hash,omitempty"`
    // ARIA specific options.
    Aria *AriaOptions `json:"aria,omitempty"`
    // BIP32 specific options.
    Bip32 *Bip32Options `json:"bip32,omitempty"`
    // BLS specific options.
    Bls *BlsOptions `json:"bls,omitempty"`
    // Whether this security object is compliant with cryptographic policies or not.
    CompliantWithPolicies *bool `json:"compliant_with_policies,omitempty"`
    // Compromise date of security object in seconds since EPOCH.
    CompromiseDate *Time `json:"compromise_date,omitempty"`
    // Timestamp at which the security object was created.
    CreatedAt Time `json:"created_at"`
    // DSM entity which created the security object.
    Creator Principal `json:"creator"`
    // User managed field for adding custom metadata to the security object.
    CustomMetadata *map[string]string `json:"custom_metadata,omitempty"`
    // Deactivation date of security object in seconds since EPOCH.
    DeactivationDate *Time `json:"deactivation_date,omitempty"`
    // Deletion date of security object in seconds since EPOCH.
    DeletionDate *Time `json:"deletion_date,omitempty"`
    // DES specific options.
    Des *DesOptions `json:"des,omitempty"`
    // DES3 specific options.
    Des3 *Des3Options `json:"des3,omitempty"`
    // Description of the security object.
    Description *string `json:"description,omitempty"`
    // Destruction date of security object in seconds since EPOCH.
    DestructionDate *Time `json:"destruction_date,omitempty"`
    // Optionally get deterministic signatures, if algorithm is EC or RSA.
    DeterministicSignatures *bool `json:"deterministic_signatures,omitempty"`
    // DSA specific options.
    Dsa *DsaOptions `json:"dsa,omitempty"`
    // ECKCDSA specific options.
    Eckcdsa *EcKcdsaOptions `json:"eckcdsa,omitempty"`
    // An aggregation of policies and permissions of the session creator for a security object.
    EffectiveKeyPolicy *EffectiveKeyPolicy `json:"effective_key_policy,omitempty"`
    // Identifies a standard elliptic curve.
    EllipticCurve *EllipticCurve `json:"elliptic_curve,omitempty"`
    // Whether this security object has cryptographic operations enabled.
    Enabled bool `json:"enabled"`
    // This export policy determines how exportable keys (ones with the `EXPORT` permission) may be exported.
    ExportPolicy *SobjectExportPolicy `json:"export_policy,omitempty"`
    // Information specific to an external KMS. Currently, it only has AWS related information.
    External *ExternalSobjectInfo `json:"external,omitempty"`
    // FPE specific options.
    Fpe *FpeOptions `json:"fpe,omitempty"`
    // Key Access Justifications for GCP EKM.
    // For more details: https://cloud.google.com/cloud-provider-access-management/key-access-justifications/docs/overview
    GoogleAccessReasonPolicy *GoogleAccessReasonPolicy `json:"google_access_reason_policy,omitempty"`
    // When a Key Undo Policy is in place, a list of (non-expired) history items is returned.
    // Each history item represents a past key state that can be reverted to.
    History *[]HistoryItem `json:"history,omitempty"`
    // KCDSA specific options.
    Kcdsa *KcdsaOptions `json:"kcdsa,omitempty"`
    // Key Checksum Value of the security object.
    Kcv *string `json:"kcv,omitempty"`
    // Cmac Key Checksum Value of the security object.
    KcvCmac *string `json:"kcv_cmac,omitempty"`
    // Operations allowed to be performed by a given key.
    KeyOps KeyOperations `json:"key_ops"`
    // Key size of the security object in bits.
    KeySize *uint32 `json:"key_size,omitempty"`
    // Unique identifier of the security object.
    Kid *UUID `json:"kid,omitempty"`
    // Linked security objects.
    Links *KeyLinks `json:"links,omitempty"`
    // LMS specific options.
    Lms *LmsOptions `json:"lms,omitempty"`
    // ML-DSA specific options (beta).
    MldsaBeta *MlDsaBetaOptions `json:"mldsa_beta,omitempty"`
    // ML-KEM specific options (beta).
    MlkemBeta *MlKemBetaOptions `json:"mlkem_beta,omitempty"`
    // Name of the security object.
    Name *string `json:"name,omitempty"`
    // Whether the security object was exportable at some point in its lifetime.
    NeverExportable *bool `json:"never_exportable,omitempty"`
    // Type of security object.
    ObjType ObjectType `json:"obj_type"`
    // The origin of the security object.
    Origin ObjectOrigin `json:"origin"`
    // Public key material of the security object, if it exists.
    PubKey *ZeroizedBlob `json:"pub_key,omitempty"`
    // Whether the security object only consists of public material.
    PublicOnly bool `json:"public_only"`
    // If enabled, the public key will be available publicly (without authentication)
    // through the GetPublicKey API.
    PublishPublicKey *PublishPublicKeyConfig `json:"publish_public_key,omitempty"`
    // Revocation reason for compromised security object.
    RevocationReason *RevocationReason `json:"revocation_reason,omitempty"`
    // Rotation policy of security objects.
    RotationPolicy *RotationPolicy `json:"rotation_policy,omitempty"`
    // RSA specific options.
    Rsa *RsaOptions `json:"rsa,omitempty"`
    // Timestamp at which security object will be rotated, if rotation policy exists.
    // This time will be clamped at 31 December 9999 11:59:59 pm UTC if the calculated
    // rotation time would exceed that date.
    ScheduledRotation *Time `json:"scheduled_rotation,omitempty"`
    // Seed options.
    Seed *SeedOptions `json:"seed,omitempty"`
    // Security object operational state.
    State *SobjectState `json:"state,omitempty"`
    // Transient key material.
    TransientKey *Blob `json:"transient_key,omitempty"`
    // Security object stored as byte array.
    Value *ZeroizedBlob `json:"value,omitempty"`
    // Metadata specific to the virtual key.
    VirtualKeyInfo *VirtualSobjectInfo `json:"virtual_key_info,omitempty"`
    // Group ids of groups that use this security object to encrypt the key material of their security objects
    WrappingKeyGroupIds *[]UUID `json:"wrapping_key_group_ids,omitempty"`
    // XMSS specific options.
    Xmss *XmssOptions `json:"xmss,omitempty"`
    // UUID of the group which the security object belongs to.
    GroupID *UUID `json:"group_id,omitempty"`
}

// Uniquely identifies a persisted or transient sobject.
type SobjectDescriptor struct {
    Kid *UUID
    Name *string
    TransientKey *Blob
    Inline *SobjectDescriptorInline
}
type SobjectDescriptorInline struct {
    Value ZeroizedBlob `json:"value"`
    ObjType ObjectType `json:"obj_type"`
}
func (x SobjectDescriptor) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "SobjectDescriptor", 
                  []bool{ x.Kid != nil,
                  x.Name != nil,
                  x.TransientKey != nil,
                  x.Inline != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Kid *UUID `json:"kid,omitempty"`
        Name *string `json:"name,omitempty"`
        TransientKey *Blob `json:"transient_key,omitempty"`
        Inline *SobjectDescriptorInline `json:"inline,omitempty"`
    }
    obj.Kid = x.Kid
    obj.Name = x.Name
    obj.TransientKey = x.TransientKey
    obj.Inline = x.Inline
    return json.Marshal(obj)
}
func (x *SobjectDescriptor) UnmarshalJSON(data []byte) error {
    x.Kid = nil
    x.Name = nil
    x.TransientKey = nil
    x.Inline = nil
    var obj struct {
        Kid *UUID `json:"kid,omitempty"`
        Name *string `json:"name,omitempty"`
        TransientKey *Blob `json:"transient_key,omitempty"`
        Inline *SobjectDescriptorInline `json:"inline,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.Kid = obj.Kid
    x.Name = obj.Name
    x.TransientKey = obj.TransientKey
    x.Inline = obj.Inline
    return nil
}

// Uniquely identifies a persisted sobject.
type SobjectDescriptorPersisted struct {
    Kid *UUID
    Name *string
}
func (x SobjectDescriptorPersisted) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "SobjectDescriptorPersisted", 
                  []bool{ x.Kid != nil,
                  x.Name != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Kid *UUID `json:"kid,omitempty"`
        Name *string `json:"name,omitempty"`
    }
    obj.Kid = x.Kid
    obj.Name = x.Name
    return json.Marshal(obj)
}
func (x *SobjectDescriptorPersisted) UnmarshalJSON(data []byte) error {
    x.Kid = nil
    x.Name = nil
    var obj struct {
        Kid *UUID `json:"kid,omitempty"`
        Name *string `json:"name,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.Kid = obj.Kid
    x.Name = obj.Name
    return nil
}

type SobjectExportPolicy struct {
    ExportPolicy ExportPolicy `json:"export_policy"`
    // When set to `false`, the `export_policy` for the sobject can never be relaxed,
    // it can only be made more strict.
    // This means that
    //  - If the export policy is set to `Wrapped`, it can never be set back to `Unrestricted`.
    //  - If the export policy is set to `Wrapped` with a limited set of keys specified,
    //    it can never bet set back to `Wrapped` with any key. Additionally, no new keys can
    //    be added to the set of wrapping keys. Also note that if all the wrapping keys (specified
    //    by key id) in the export policy have been deleted/destroyed/deactivated, the sobject
    //    becomes effectively unexportable.
    //
    // Note: these rules may change in the future.
    AllowWeakening bool `json:"allow_weakening"`
}
func (x SobjectExportPolicy) MarshalJSON() ([]byte, error) {
    m := make(map[string]interface{})
    { // x.ExportPolicy is flattened
        b, err := json.Marshal(&x.ExportPolicy)
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
    m["allow_weakening"] = x.AllowWeakening
    return json.Marshal(&m)
}
func (x *SobjectExportPolicy) UnmarshalJSON(data []byte) error {
    if err := json.Unmarshal(data, &x.ExportPolicy); err != nil {
        return err
    }
    var r struct {
    AllowWeakening bool `json:"allow_weakening"`
    }
    if err := json.Unmarshal(data, &r); err != nil {
        return err
    }
    x.AllowWeakening = r.AllowWeakening
    return nil
}

// Security object operational state.
type SobjectState string

// List of supported SobjectState values
const (
    // The security object exists but can not be used for any cryptographic purpose
    // until it's activated.
    SobjectStatePreActive SobjectState = "PreActive"
    // The security object can be used for any cryptographic purpose.
    SobjectStateActive SobjectState = "Active"
    // The security object can not be used for applying cryptographic protection,
    // but can be used for processing cryptographically protected information.
    // Key must be in the activated state in order to transition to the deactivated state.
    SobjectStateDeactivated SobjectState = "Deactivated"
    // The security object can not be used for applying cryptographic protection
    // but can be used for processing cryptographically protected information.
    SobjectStateCompromised SobjectState = "Compromised"
    // The security object can not perform any cryptographic operations, as the
    // key material gets deleted.
    SobjectStateDestroyed SobjectState = "Destroyed"
    // The security object does not exist in DSM. However, its compromised status
    // is retained for audit and security purposes.
    SobjectStateDeleted SobjectState = "Deleted"
)

type TepClientConfig struct {
    Schema TepSchema `json:"schema"`
    KeyMap TepKeyMapList `json:"key_map"`
}

type TepKeyContext string

// List of supported TepKeyContext values
const (
    TepKeyContextRequest TepKeyContext = "request"
    TepKeyContextResponse TepKeyContext = "response"
)

type TepKeyMap struct {
    Path ApiPath `json:"path"`
    Kid UUID `json:"kid"`
    Mode CipherMode `json:"mode"`
}

type TepKeyMapList = []TepKeyMap

type TepSchema struct {
    OpenAPI **string
}
func (x TepSchema) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "TepSchema", 
                  []bool{ x.OpenAPI != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.OpenAPI != nil:
        b, err := json.Marshal(x.OpenAPI)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["$type"] = "OpenAPI"
    }
    return json.Marshal(m)
}
func (x *TepSchema) UnmarshalJSON(data []byte) error {
    x.OpenAPI = nil
    var h struct {
        Tag string `json:"$type"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid TepSchema")
    }
    switch h.Tag {
    case "OpenAPI":
        var openAPI *string
        if err := json.Unmarshal(data, &openAPI); err != nil {
            return err
        }
        x.OpenAPI = &openAPI
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

type TimeSpan struct {
    Seconds *uint32
    Minutes *uint32
    Hours *uint32
    Days *uint32
}
func (x TimeSpan) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "TimeSpan", 
                  []bool{ x.Seconds != nil,
                  x.Minutes != nil,
                  x.Hours != nil,
                  x.Days != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Seconds *uint32 `json:"seconds,omitempty"`
        Minutes *uint32 `json:"minutes,omitempty"`
        Hours *uint32 `json:"hours,omitempty"`
        Days *uint32 `json:"days,omitempty"`
    }
    obj.Seconds = x.Seconds
    obj.Minutes = x.Minutes
    obj.Hours = x.Hours
    obj.Days = x.Days
    return json.Marshal(obj)
}
func (x *TimeSpan) UnmarshalJSON(data []byte) error {
    x.Seconds = nil
    x.Minutes = nil
    x.Hours = nil
    x.Days = nil
    var obj struct {
        Seconds *uint32 `json:"seconds,omitempty"`
        Minutes *uint32 `json:"minutes,omitempty"`
        Hours *uint32 `json:"hours,omitempty"`
        Days *uint32 `json:"days,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.Seconds = obj.Seconds
    x.Minutes = obj.Minutes
    x.Hours = obj.Hours
    x.Days = obj.Days
    return nil
}

// TLS client settings.
type TlsConfig struct {
    Disabled *struct{}
    Opportunistic *struct{}
    Required *TlsConfigRequired
}
type TlsConfigRequired struct {
    ValidateHostname bool `json:"validate_hostname"`
    Ca CaConfig `json:"ca"`
    ClientKey *ZeroizedBlob `json:"client_key,omitempty"`
    ClientCert *Blob `json:"client_cert,omitempty"`
}
func (x TlsConfig) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "TlsConfig", 
                  []bool{ x.Disabled != nil,
                  x.Opportunistic != nil,
                  x.Required != nil });
                  err != nil {
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

// Use of U2F is deprecated, use FIDO2 for second factor authentication.
type U2fAuthRequest struct {
    KeyHandle Blob `json:"keyHandle"`
    SignatureData Blob `json:"signatureData"`
    ClientData Blob `json:"clientData"`
}

// A challenge used for multi-factor authentication.
type U2fMfaChallengeResponse struct {
    U2fChallenge string `json:"u2f_challenge"`
    U2fKeys []U2fRegisteredKey `json:"u2f_keys"`
}

// Description of a registered U2F device.
type U2fRegisteredKey struct {
    KeyHandle string `json:"keyHandle"`
    Version string `json:"version"`
}

// User account flag
type UserAccountFlag string

// List of supported UserAccountFlag values
const (
    UserAccountFlagStateEnabled UserAccountFlag = "STATEENABLED"
    UserAccountFlagPendingInvite UserAccountFlag = "PENDINGINVITE"
)

// User account flag or legacy user account role name or custom role id
type UserAccountFlagOrRole struct {
    Flag *UserAccountFlag
    LegacyRole *LegacyUserAccountRole
    RoleID *UUID
}
func (x UserAccountFlagOrRole) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "UserAccountFlagOrRole", 
                  []bool{ x.Flag != nil,
                  x.LegacyRole != nil,
                  x.RoleID != nil });
                  err != nil {
        return nil, err
    }
    if x.Flag != nil {
        return json.Marshal(x.Flag)
    }
    if x.LegacyRole != nil {
        return json.Marshal(x.LegacyRole)
    }
    if x.RoleID != nil {
        return json.Marshal(x.RoleID)
    }
    panic("unreachable")
}
func (x *UserAccountFlagOrRole) UnmarshalJSON(data []byte) error {
    x.Flag = nil
    x.LegacyRole = nil
    x.RoleID = nil
    var flag UserAccountFlag
    if err := json.Unmarshal(data, &flag); err == nil {
        x.Flag = &flag
        return nil
    }
    var legacyRole LegacyUserAccountRole
    if err := json.Unmarshal(data, &legacyRole); err == nil {
        x.LegacyRole = &legacyRole
        return nil
    }
    var roleId UUID
    if err := json.Unmarshal(data, &roleId); err == nil {
        x.RoleID = &roleId
        return nil
    }
    return errors.Errorf("not a valid UserAccountFlagOrRole")
}

// User's role(s) and state in an account.
type UserAccountFlags = []UserAccountFlagOrRole

// User's role(s) in a group.
type UserGroupRole = []LegacyUserGroupRoleOrRoleId

// https://www.w3.org/TR/webauthn-2/#enum-userVerificationRequirement
// https://www.w3.org/TR/webauthn-2/#user-verification
type UserVerificationRequirement string

// List of supported UserVerificationRequirement values
const (
    // Indicates the requirement of UV by RP and op
    // fails if this wasn't satisfied.
    UserVerificationRequirementRequired UserVerificationRequirement = "required"
    // UV is preferred by the RP but op won't fail
    // if it isn't satisfied.
    UserVerificationRequirementPreferred UserVerificationRequirement = "preferred"
    // UV isn't "preferred" by RP.
    UserVerificationRequirementDiscouraged UserVerificationRequirement = "discouraged"
)

// Information specific to a virtual key. Currently, this is only relevant
// for virtual keys backed by DSM.
type VirtualSobjectInfo struct {
    // Whether or not the source key material is cached within the key.
    CachedKeyMaterial bool `json:"cached_key_material"`
}

type WrappingKeys struct {
    // Only keys in this list can be used to wrap the sobject
    Only *WrappingKeysOnly
    // Any key can be used to wrap the sobject
    Any *struct{}
}
// Only keys in this list can be used to wrap the sobject
type WrappingKeysOnly struct {
    Keys []SobjectDescriptorPersisted `json:"keys"`
}
func (x WrappingKeys) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "WrappingKeys", 
                  []bool{ x.Only != nil,
                  x.Any != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.Only != nil:
        b, err := json.Marshal(x.Only)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["$type"] = "Only"
    case x.Any != nil:
        m["$type"] = "Any"
    }
    return json.Marshal(m)
}
func (x *WrappingKeys) UnmarshalJSON(data []byte) error {
    x.Only = nil
    x.Any = nil
    var h struct {
        Tag string `json:"$type"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid WrappingKeys")
    }
    switch h.Tag {
    case "Only":
        var only WrappingKeysOnly
        if err := json.Unmarshal(data, &only); err != nil {
            return err
        }
        x.Only = &only
    case "Any":
        x.Any = &struct{}{}
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

// XMSS specific options
type XmssOptions struct {
    // The height of the Merkle tree (10, 16 or 20)
    Height *uint `json:"height,omitempty"`
    // The hash function to use
    Digest *DigestAlgorithm `json:"digest,omitempty"`
    // Amount of bytes associated to each node (24 or 32)
    NodeSize *uint `json:"node_size,omitempty"`
}

type XmssOptionsPolicy struct {
}

