/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package sdkms

import (
	"encoding/json"
	"fmt"

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
	//  Permission to create account-level approval policy. Note that
	//  updating/deleting the approval policy is protected by the approval
	//  policy itself.
	AccountPermissionsCreateAccountApprovalPolicy
	//  Permission to set approval request expiry for all approval requests
	//  created in the account.
	AccountPermissionsSetApprovalRequestExpiry
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
)

// MarshalJSON converts AccountPermissions to an array of strings
func (x AccountPermissions) MarshalJSON() ([]byte, error) {
	s := make([]string, 0)
	if x&AccountPermissionsManageLogging == AccountPermissionsManageLogging {
		s = append(s, "MANAGE_LOGGING")
	}
	if x&AccountPermissionsManageAuth == AccountPermissionsManageAuth {
		s = append(s, "MANAGE_AUTH")
	}
	if x&AccountPermissionsManageWorkspaceCse == AccountPermissionsManageWorkspaceCse {
		s = append(s, "MANAGE_WORKSPACE_CSE")
	}
	if x&AccountPermissionsUnwrapWorkspaceCsePrivileged == AccountPermissionsUnwrapWorkspaceCsePrivileged {
		s = append(s, "UNWRAP_WORKSPACE_CSE_PRIVILEGED")
	}
	if x&AccountPermissionsManageAccountClientConfigs == AccountPermissionsManageAccountClientConfigs {
		s = append(s, "MANAGE_ACCOUNT_CLIENT_CONFIGS")
	}
	if x&AccountPermissionsCreateAccountApprovalPolicy == AccountPermissionsCreateAccountApprovalPolicy {
		s = append(s, "CREATE_ACCOUNT_APPROVAL_POLICY")
	}
	if x&AccountPermissionsSetApprovalRequestExpiry == AccountPermissionsSetApprovalRequestExpiry {
		s = append(s, "SET_APPROVAL_REQUEST_EXPIRY")
	}
	if x&AccountPermissionsUpdateAccountCustomMetadataAttributes == AccountPermissionsUpdateAccountCustomMetadataAttributes {
		s = append(s, "UPDATE_ACCOUNT_CUSTOM_METADATA_ATTRIBUTES")
	}
	if x&AccountPermissionsManageAccountSubscription == AccountPermissionsManageAccountSubscription {
		s = append(s, "MANAGE_ACCOUNT_SUBSCRIPTION")
	}
	if x&AccountPermissionsManageAccountProfile == AccountPermissionsManageAccountProfile {
		s = append(s, "MANAGE_ACCOUNT_PROFILE")
	}
	if x&AccountPermissionsDeleteAccount == AccountPermissionsDeleteAccount {
		s = append(s, "DELETE_ACCOUNT")
	}
	if x&AccountPermissionsCreateAdminApps == AccountPermissionsCreateAdminApps {
		s = append(s, "CREATE_ADMIN_APPS")
	}
	if x&AccountPermissionsUpdateAdminApps == AccountPermissionsUpdateAdminApps {
		s = append(s, "UPDATE_ADMIN_APPS")
	}
	if x&AccountPermissionsDeleteAdminApps == AccountPermissionsDeleteAdminApps {
		s = append(s, "DELETE_ADMIN_APPS")
	}
	if x&AccountPermissionsRetrieveAdminAppSecrets == AccountPermissionsRetrieveAdminAppSecrets {
		s = append(s, "RETRIEVE_ADMIN_APP_SECRETS")
	}
	if x&AccountPermissionsManageAdminApps == AccountPermissionsManageAdminApps {
		s = append(s, "MANAGE_ADMIN_APPS")
	}
	if x&AccountPermissionsCreateCustomRoles == AccountPermissionsCreateCustomRoles {
		s = append(s, "CREATE_CUSTOM_ROLES")
	}
	if x&AccountPermissionsUpdateCustomRoles == AccountPermissionsUpdateCustomRoles {
		s = append(s, "UPDATE_CUSTOM_ROLES")
	}
	if x&AccountPermissionsDeleteCustomRoles == AccountPermissionsDeleteCustomRoles {
		s = append(s, "DELETE_CUSTOM_ROLES")
	}
	if x&AccountPermissionsManageCustomRoles == AccountPermissionsManageCustomRoles {
		s = append(s, "MANAGE_CUSTOM_ROLES")
	}
	if x&AccountPermissionsInviteUsersToAccount == AccountPermissionsInviteUsersToAccount {
		s = append(s, "INVITE_USERS_TO_ACCOUNT")
	}
	if x&AccountPermissionsDeleteUsersFromAccount == AccountPermissionsDeleteUsersFromAccount {
		s = append(s, "DELETE_USERS_FROM_ACCOUNT")
	}
	if x&AccountPermissionsUpdateUsersAccountRole == AccountPermissionsUpdateUsersAccountRole {
		s = append(s, "UPDATE_USERS_ACCOUNT_ROLE")
	}
	if x&AccountPermissionsUpdateUsersAccountEnabledState == AccountPermissionsUpdateUsersAccountEnabledState {
		s = append(s, "UPDATE_USERS_ACCOUNT_ENABLED_STATE")
	}
	if x&AccountPermissionsManageAccountUsers == AccountPermissionsManageAccountUsers {
		s = append(s, "MANAGE_ACCOUNT_USERS")
	}
	if x&AccountPermissionsCreateExternalRoles == AccountPermissionsCreateExternalRoles {
		s = append(s, "CREATE_EXTERNAL_ROLES")
	}
	if x&AccountPermissionsSyncExternalRoles == AccountPermissionsSyncExternalRoles {
		s = append(s, "SYNC_EXTERNAL_ROLES")
	}
	if x&AccountPermissionsDeleteExternalRoles == AccountPermissionsDeleteExternalRoles {
		s = append(s, "DELETE_EXTERNAL_ROLES")
	}
	if x&AccountPermissionsManageExternalRoles == AccountPermissionsManageExternalRoles {
		s = append(s, "MANAGE_EXTERNAL_ROLES")
	}
	if x&AccountPermissionsCreateAccountSobjectPolicies == AccountPermissionsCreateAccountSobjectPolicies {
		s = append(s, "CREATE_ACCOUNT_SOBJECT_POLICIES")
	}
	if x&AccountPermissionsUpdateAccountSobjectPolicies == AccountPermissionsUpdateAccountSobjectPolicies {
		s = append(s, "UPDATE_ACCOUNT_SOBJECT_POLICIES")
	}
	if x&AccountPermissionsDeleteAccountSobjectPolicies == AccountPermissionsDeleteAccountSobjectPolicies {
		s = append(s, "DELETE_ACCOUNT_SOBJECT_POLICIES")
	}
	if x&AccountPermissionsManageAccountSobjectPolicies == AccountPermissionsManageAccountSobjectPolicies {
		s = append(s, "MANAGE_ACCOUNT_SOBJECT_POLICIES")
	}
	if x&AccountPermissionsCreateChildAccounts == AccountPermissionsCreateChildAccounts {
		s = append(s, "CREATE_CHILD_ACCOUNTS")
	}
	if x&AccountPermissionsUpdateChildAccounts == AccountPermissionsUpdateChildAccounts {
		s = append(s, "UPDATE_CHILD_ACCOUNTS")
	}
	if x&AccountPermissionsDeleteChildAccounts == AccountPermissionsDeleteChildAccounts {
		s = append(s, "DELETE_CHILD_ACCOUNTS")
	}
	if x&AccountPermissionsCreateChildAccountUsers == AccountPermissionsCreateChildAccountUsers {
		s = append(s, "CREATE_CHILD_ACCOUNT_USERS")
	}
	if x&AccountPermissionsGetChildAccounts == AccountPermissionsGetChildAccounts {
		s = append(s, "GET_CHILD_ACCOUNTS")
	}
	if x&AccountPermissionsGetChildAccountUsers == AccountPermissionsGetChildAccountUsers {
		s = append(s, "GET_CHILD_ACCOUNT_USERS")
	}
	if x&AccountPermissionsManageChildAccounts == AccountPermissionsManageChildAccounts {
		s = append(s, "MANAGE_CHILD_ACCOUNTS")
	}
	if x&AccountPermissionsCreateLocalGroups == AccountPermissionsCreateLocalGroups {
		s = append(s, "CREATE_LOCAL_GROUPS")
	}
	if x&AccountPermissionsCreateExternalGroups == AccountPermissionsCreateExternalGroups {
		s = append(s, "CREATE_EXTERNAL_GROUPS")
	}
	if x&AccountPermissionsAllowQuorumReviewer == AccountPermissionsAllowQuorumReviewer {
		s = append(s, "ALLOW_QUORUM_REVIEWER")
	}
	if x&AccountPermissionsAllowKeyCustodian == AccountPermissionsAllowKeyCustodian {
		s = append(s, "ALLOW_KEY_CUSTODIAN")
	}
	if x&AccountPermissionsGetAllApprovalRequests == AccountPermissionsGetAllApprovalRequests {
		s = append(s, "GET_ALL_APPROVAL_REQUESTS")
	}
	if x&AccountPermissionsGetAdminApps == AccountPermissionsGetAdminApps {
		s = append(s, "GET_ADMIN_APPS")
	}
	if x&AccountPermissionsGetCustomRoles == AccountPermissionsGetCustomRoles {
		s = append(s, "GET_CUSTOM_ROLES")
	}
	if x&AccountPermissionsGetExternalRoles == AccountPermissionsGetExternalRoles {
		s = append(s, "GET_EXTERNAL_ROLES")
	}
	if x&AccountPermissionsGetAllUsers == AccountPermissionsGetAllUsers {
		s = append(s, "GET_ALL_USERS")
	}
	if x&AccountPermissionsGetAccountUsage == AccountPermissionsGetAccountUsage {
		s = append(s, "GET_ACCOUNT_USAGE")
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
		case "CREATE_ACCOUNT_APPROVAL_POLICY":
			*x = *x | AccountPermissionsCreateAccountApprovalPolicy
		case "SET_APPROVAL_REQUEST_EXPIRY":
			*x = *x | AccountPermissionsSetApprovalRequestExpiry
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
		}
	}
	return nil
}

type AesOptions struct {
	KeySizes   *[]uint32   `json:"key_sizes,omitempty"`
	Fpe        *FpeOptions `json:"fpe,omitempty"`
	TagLength  *int32      `json:"tag_length,omitempty"`
	CipherMode *CipherMode `json:"cipher_mode,omitempty"`
	RandomIv   *bool       `json:"random_iv,omitempty"`
	IvLength   *int32      `json:"iv_length,omitempty"`
}

// A cryptographic algorithm.
type Algorithm string

// List of supported Algorithm values
const (
	AlgorithmAes        Algorithm = "AES"
	AlgorithmAria       Algorithm = "ARIA"
	AlgorithmDes        Algorithm = "DES"
	AlgorithmDes3       Algorithm = "DES3"
	AlgorithmSeed       Algorithm = "SEED"
	AlgorithmRsa        Algorithm = "RSA"
	AlgorithmDsa        Algorithm = "DSA"
	AlgorithmKcdsa      Algorithm = "KCDSA"
	AlgorithmEc         Algorithm = "EC"
	AlgorithmEcKcdsa    Algorithm = "ECKCDSA"
	AlgorithmBip32      Algorithm = "BIP32"
	AlgorithmBls        Algorithm = "BLS"
	AlgorithmLms        Algorithm = "LMS"
	AlgorithmHmac       Algorithm = "HMAC"
	AlgorithmLedaBeta   Algorithm = "LEDABETA"
	AlgorithmRound5Beta Algorithm = "ROUND5BETA"
	AlgorithmPbe        Algorithm = "PBE"
)

// A helper enum with a single variant, All, which indicates that something should apply to an
// entire part. (This is here mainly to allow other untagged enums to work properly.)
type All string

// List of supported All values
const (
	AllAll All = "all"
)

type ApiPath struct {
	APIPath string          `json:"api_path"`
	Method  HyperHttpMethod `json:"method"`
	Context TepKeyContext   `json:"context"`
	KeyPath string          `json:"key_path"`
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
	if x&AppPermissionsAudit == AppPermissionsAudit {
		s = append(s, "AUDIT")
	}
	if x&AppPermissionsTransform == AppPermissionsTransform {
		s = append(s, "TRANSFORM")
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
		}
	}
	return nil
}

// Authentication requirements for approval request reviewers.
type ApprovalAuthConfig struct {
	RequirePassword *bool `json:"require_password,omitempty"`
	Require2fa      *bool `json:"require_2fa,omitempty"`
}

type AriaOptions struct {
	KeySizes   *[]uint32   `json:"key_sizes,omitempty"`
	TagLength  *uint8      `json:"tag_length,omitempty"`
	CipherMode *CipherMode `json:"cipher_mode,omitempty"`
	RandomIv   *bool       `json:"random_iv,omitempty"`
	IvLength   *uint8      `json:"iv_length,omitempty"`
}

// <https://www.w3.org/TR/webauthn-2/#enum-attestation-convey>
// <https://www.w3.org/TR/webauthn-2/#sctn-attestation>
//
// If you really want to understand attestation, read the following:
//
//	<https://fidoalliance.org/fido-technotes-the-truth-about-attestation/>
//	<https://medium.com/webauthnworks/webauthn-fido2-demystifying-attestation-and-mds-efc3b3cb3651>
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
		[]bool{x.Known != nil,
			x.Unknown != nil}); err != nil {
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

// Information and properties of AWS KMS resources. Currently,
// it only contains information specific to AWS multi region keys.
type AwsKmsInfo struct {
	MultiRegion *AwsMultiRegionInfo `json:"multi_region,omitempty"`
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
	DerivationPath *[]uint32     `json:"derivation_path,omitempty"`
	Network        *Bip32Network `json:"network,omitempty"`
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
	CaSet  *CaSet
	Pinned *[]Blob
}

func (x CaConfig) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"CaConfig",
		[]bool{x.CaSet != nil,
			x.Pinned != nil}); err != nil {
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

type CertificateOptions struct {
}

// Cipher mode used for symmetric key algorithms.
type CipherMode string

// List of supported CipherMode values
const (
	CipherModeEcb      CipherMode = "ECB"
	CipherModeCbc      CipherMode = "CBC"
	CipherModeCbcNoPad CipherMode = "CBCNOPAD"
	CipherModeCfb      CipherMode = "CFB"
	CipherModeOfb      CipherMode = "OFB"
	CipherModeCtr      CipherMode = "CTR"
	CipherModeGcm      CipherMode = "GCM"
	CipherModeCcm      CipherMode = "CCM"
	CipherModeKw       CipherMode = "KW"
	CipherModeKwp      CipherMode = "KWP"
	CipherModeFf1      CipherMode = "FF1"
)

type ClientConfigurations struct {
	// NOTE: not all clients use `common` configurations.
	Common *CommonClientConfig `json:"common,omitempty"`
	Pkcs11 *Pkcs11ClientConfig `json:"pkcs11,omitempty"`
	Kmip   *KmipClientConfig   `json:"kmip,omitempty"`
	Tep    *TepClientConfig    `json:"tep,omitempty"`
}

type ClientConfigurationsRequest struct {
	Common *Removable[CommonClientConfig] `json:"common,omitempty"`
	Pkcs11 *Removable[Pkcs11ClientConfig] `json:"pkcs11,omitempty"`
	Kmip   *Removable[KmipClientConfig]   `json:"kmip,omitempty"`
	Tep    *Removable[TepClientConfig]    `json:"tep,omitempty"`
}

type ClientFileLogging struct {
	Enabled  *ClientFileLoggingConfig
	Disabled *struct{}
}

func (x ClientFileLogging) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"ClientFileLogging",
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
	Path       *string `json:"path,omitempty"`
	FileSizeKb *uint64 `json:"file_size_kb,omitempty"`
	MaxFiles   *uint32 `json:"max_files,omitempty"`
}

type ClientLogConfig struct {
	System *bool              `json:"system,omitempty"`
	File   *ClientFileLogging `json:"file,omitempty"`
	Level  *string            `json:"level,omitempty"`
}

type CommonClientConfig struct {
	RetryTimeoutMillis *uint64          `json:"retry_timeout_millis,omitempty"`
	CacheTtl           *uint64          `json:"cache_ttl,omitempty"`
	Log                *ClientLogConfig `json:"log,omitempty"`
	H2NumConnections   *uint            `json:"h2_num_connections,omitempty"`
}

// `CipherMode` or `RsaEncryptionPadding`, depending on the encryption algorithm.
type CryptMode struct {
	// Block cipher mode of crypto operation
	Symmetric *CipherMode
	// RSA(with padding) mode of crypto operation
	Rsa *RsaEncryptionPadding
	// PKCS8 mode of crypto operation
	Pkcs8Mode *Pkcs8Mode
}

func (x CryptMode) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"CryptMode",
		[]bool{x.Symmetric != nil,
			x.Rsa != nil,
			x.Pkcs8Mode != nil}); err != nil {
		return nil, err
	}
	if x.Symmetric != nil {
		return json.Marshal(x.Symmetric)
	}
	if x.Rsa != nil {
		return json.Marshal(x.Rsa)
	}
	if x.Pkcs8Mode != nil {
		return json.Marshal(x.Pkcs8Mode)
	}
	panic("unreachable")
}
func (x *CryptMode) UnmarshalJSON(data []byte) error {
	x.Symmetric = nil
	x.Rsa = nil
	x.Pkcs8Mode = nil
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
	var pkcs8Mode Pkcs8Mode
	if err := json.Unmarshal(data, &pkcs8Mode); err == nil {
		x.Pkcs8Mode = &pkcs8Mode
		return nil
	}
	return errors.Errorf("not a valid CryptMode")
}

type CryptographicPolicy struct {
	Aes          *AesOptions         `json:"aes,omitempty"`
	Aria         *AriaOptions        `json:"aria,omitempty"`
	Des          *DesOptions         `json:"des,omitempty"`
	Des3         *Des3Options        `json:"des3,omitempty"`
	Seed         *SeedOptions        `json:"seed,omitempty"`
	Rsa          *RsaOptions         `json:"rsa,omitempty"`
	Dsa          *DsaOptions         `json:"dsa,omitempty"`
	Kcdsa        *KcdsaOptions       `json:"kcdsa,omitempty"`
	Ec           *EcOptions          `json:"ec,omitempty"`
	Eckcdsa      *EcKcdsaOptions     `json:"eckcdsa,omitempty"`
	Bip32        *Bip32Options       `json:"bip32,omitempty"`
	Bls          *BlsOptionsPolicy   `json:"bls,omitempty"`
	Opaque       *OpaqueOptions      `json:"opaque,omitempty"`
	Hmac         *HmacOptions        `json:"hmac,omitempty"`
	Secret       *SecretOptions      `json:"secret,omitempty"`
	Certificate  *CertificateOptions `json:"certificate,omitempty"`
	KeyOps       *KeyOperations      `json:"key_ops,omitempty"`
	LegacyPolicy *LegacyKeyPolicy    `json:"legacy_policy,omitempty"`
}

type Des3Options struct {
	KeySizes   *[]uint32   `json:"key_sizes,omitempty"`
	CipherMode *CipherMode `json:"cipher_mode,omitempty"`
	RandomIv   *bool       `json:"random_iv,omitempty"`
	IvLength   *int32      `json:"iv_length,omitempty"`
}

type DesOptions struct {
	CipherMode *CipherMode `json:"cipher_mode,omitempty"`
	RandomIv   *bool       `json:"random_iv,omitempty"`
}

// A hash algorithm.
type DigestAlgorithm string

// List of supported DigestAlgorithm values
const (
	DigestAlgorithmBlake2b256  DigestAlgorithm = "BLAKE2B256"
	DigestAlgorithmBlake2b384  DigestAlgorithm = "BLAKE2B384"
	DigestAlgorithmBlake2b512  DigestAlgorithm = "BLAKE2B512"
	DigestAlgorithmBlake2s256  DigestAlgorithm = "BLAKE2S256"
	DigestAlgorithmRipemd160   DigestAlgorithm = "RIPEMD160"
	DigestAlgorithmSsl3        DigestAlgorithm = "SSL3"
	DigestAlgorithmSha1        DigestAlgorithm = "SHA1"
	DigestAlgorithmSha224      DigestAlgorithm = "SHA224"
	DigestAlgorithmSha256      DigestAlgorithm = "SHA256"
	DigestAlgorithmSha384      DigestAlgorithm = "SHA384"
	DigestAlgorithmSha512      DigestAlgorithm = "SHA512"
	DigestAlgorithmStreebog256 DigestAlgorithm = "STREEBOG256"
	DigestAlgorithmStreebog512 DigestAlgorithm = "STREEBOG512"
	DigestAlgorithmSha3_224    DigestAlgorithm = "SHA3_224"
	DigestAlgorithmSha3_256    DigestAlgorithm = "SHA3_256"
	DigestAlgorithmSha3_384    DigestAlgorithm = "SHA3_384"
	DigestAlgorithmSha3_512    DigestAlgorithm = "SHA3_512"
)

type DsaOptions struct {
	SubgroupSize *uint32 `json:"subgroup_size,omitempty"`
}

type EcKcdsaOptions struct {
	HashAlg *DigestAlgorithm `json:"hash_alg,omitempty"`
}

type EcOptions struct {
	EllipticCurves *[]EllipticCurve `json:"elliptic_curves,omitempty"`
}

// An aggregation of policies and permissions of the session creator for
// a security object.
type EffectiveKeyPolicy struct {
	// Indicates allowed key operations for the security key.
	KeyOps KeyOperations `json:"key_ops"`
}

// Identifies a standardized elliptic curve.
type EllipticCurve string

// List of supported EllipticCurve values
const (
	EllipticCurveX25519    EllipticCurve = "X25519"
	EllipticCurveEd25519   EllipticCurve = "Ed25519"
	EllipticCurveX448      EllipticCurve = "X448"
	EllipticCurveSecP192K1 EllipticCurve = "SecP192K1"
	EllipticCurveSecP224K1 EllipticCurve = "SecP224K1"
	EllipticCurveSecP256K1 EllipticCurve = "SecP256K1"
	EllipticCurveNistP192  EllipticCurve = "NistP192"
	EllipticCurveNistP224  EllipticCurve = "NistP224"
	EllipticCurveNistP256  EllipticCurve = "NistP256"
	EllipticCurveNistP384  EllipticCurve = "NistP384"
	EllipticCurveNistP521  EllipticCurve = "NistP521"
	EllipticCurveGost256A  EllipticCurve = "Gost256A"
)

type ExternalKeyId struct {
	Pkcs11        *ExternalKeyIdPkcs11
	Fortanix      *ExternalKeyIdFortanix
	AwsKms        *ExternalKeyIdAwsKms
	AzureKeyVault *ExternalKeyIdAzureKeyVault
	GcpKeyRing    *ExternalKeyIdGcpKeyRing
	Wrapped       *struct{}
}
type ExternalKeyIdPkcs11 struct {
	ID    Blob `json:"id"`
	Label Blob `json:"label"`
}
type ExternalKeyIdFortanix struct {
	ID UUID `json:"id"`
}
type ExternalKeyIdAwsKms struct {
	KeyArn string `json:"key_arn"`
	KeyID  string `json:"key_id"`
}
type ExternalKeyIdAzureKeyVault struct {
	Version UUID   `json:"version"`
	Label   string `json:"label"`
}
type ExternalKeyIdGcpKeyRing struct {
	Version uint32 `json:"version"`
	Label   string `json:"label"`
}

func (x ExternalKeyId) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"ExternalKeyId",
		[]bool{x.Pkcs11 != nil,
			x.Fortanix != nil,
			x.AwsKms != nil,
			x.AzureKeyVault != nil,
			x.GcpKeyRing != nil,
			x.Wrapped != nil}); err != nil {
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
		[]bool{x.AWS != nil}); err != nil {
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
	HsmGroupID      UUID             `json:"hsm_group_id"`
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
		[]bool{x.Registration != nil,
			x.Authentication != nil}); err != nil {
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

// The character set to use for an encrypted portion of a complex tokenization data type.
// Characters should be specified as a list of pairs, where each pair [a, b] represents the
// range of characters from a to b, with both bounds being inclusive. A single character can
// be specified as [c, c].
//
// Normally, each character is assigned a numeric value for FF1. The first character is
// assigned a value of 0, and subsequent characters are assigned values of 1, 2, and so on,
// up to the size of the character set. Note that the order of the ranges matters; characters
// appearing in later ranges are assigned higher numerical values compared to earlier
// characters. For instance, in the character set [['a', 'z'], ['0', '9']], the digits '0' to
// '9' are assigned values from 26 to 35, since they are listed after the 'a' to 'z' range.
//
// In any case, ranges should not overlap with each other, and should not contain surrogate
// codepoints.
type FpeCharSet = [][2]Char

// Structure of a compound portion of a complex tokenization data type, itself composed of
// smaller parts.
type FpeCompoundPart struct {
	// Represents an OR of multiple structures.
	Or *FpeCompoundPartOr
	// Represents a concatenation of multiple structures (in a particular order).
	Concat *FpeCompoundPartConcat
	// Indicates a part that is possibly repeated multiple times.
	Multiple *FpeCompoundPartMultiple
}

// Represents an OR of multiple structures.
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
type FpeCompoundPartMultiple struct {
	// The subpart that may be repeated.
	Multiple *FpeDataPart `json:"multiple"`
	// The minimum number of times the subpart can be repeated.
	MinRepetitions *uint `json:"min_repetitions,omitempty"`
	// The maximum number of times the subpart can be repeated.
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
		[]bool{x.Or != nil,
			x.Concat != nil,
			x.Multiple != nil}); err != nil {
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
	// Whether the token part should satisfy the Luhn checksum. It is an error to apply this
	// constraint to non-numeric parts, or for an encrypted part to be under more than one
	// Luhn check constraint. Also, if an encrypted part has a Luhn check constraint applied
	// to it and may contain at least one digit that is not preserved, it must not specify
	// any other constraints.
	LuhnCheck *bool `json:"luhn_check,omitempty"`
	// Number that the token part should be greater than. This constraint can only be
	// specified on (non-compound) numeric encrypted parts guaranteed to preserve either
	// everything or nothing at all.
	NumGt *uint `json:"num_gt,omitempty"`
	// Number that the token part should be smaller than. This constraint can only be
	// specified on (non-compound) numeric encrypted parts guaranteed to preserve either
	// everything or nothing at all.
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
		[]bool{x.Simple != nil,
			x.BySubparts != nil}); err != nil {
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
	Encrypted *FpeEncryptedPart
	Literal   *FpeDataPartLiteral
	Compound  *FpeCompoundPart
}
type FpeDataPartLiteral struct {
	// The list of possible strings that make up this literal portion of the token.
	Literal []string `json:"literal"`
}

func (x FpeDataPart) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"FpeDataPart",
		[]bool{x.Encrypted != nil,
			x.Literal != nil,
			x.Compound != nil}); err != nil {
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
	After  *FpeDayMonthYearDate `json:"after,omitempty"`
}

// Represents a date that consists of a Month subpart and a Day subpart. It is an error to
// preserve only the Month part or the Day part.
type FpeDateMonthDay struct {
	Before *FpeDayMonthDate `json:"before,omitempty"`
	After  *FpeDayMonthDate `json:"after,omitempty"`
}

// Represents a date that consists of a Month subpart and a Year subpart. The Year part is
// allowed to be preserved; however, the Month part cannot be preserved by itself.
type FpeDateMonthYear struct {
	Before *FpeMonthYearDate `json:"before,omitempty"`
	After  *FpeMonthYearDate `json:"after,omitempty"`
}

func (x FpeDate) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"FpeDate",
		[]bool{x.DayMonthYear != nil,
			x.MonthDay != nil,
			x.MonthYear != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		DayMonthYear *FpeDateDayMonthYear `json:"dmy_date,omitempty"`
		MonthDay     *FpeDateMonthDay     `json:"month_day_date,omitempty"`
		MonthYear    *FpeDateMonthYear    `json:"month_year_date,omitempty"`
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
		MonthDay     *FpeDateMonthDay     `json:"month_day_date,omitempty"`
		MonthYear    *FpeDateMonthYear    `json:"month_year_date,omitempty"`
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
	// date, or independently). The part should be a numeric encrypted part that is guaranteed
	// to either preserve all of its digits or preserve none of them, and cannot be involved in
	// any Luhn-check constraints.
	DatePart *FpeDatePart
}

func (x FpeDateConstraint) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"FpeDateConstraint",
		[]bool{x.Date != nil,
			x.DatePart != nil}); err != nil {
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
	// Used to indicate that a token part represents a month. The part should be a number from 1
	// to 12, have its min_length field be at least 1, and have its max_length field be 2. Any
	// leading zero should be removed (unless the part is always 2 digits long, in which case a
	// leading zero may be needed).
	FpeDatePartMonth FpeDatePart = "month"
	// Used to indicate that a token part represents a day. The part should be a number from 1 to
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
	// The month, which should be a number from 1 to 12.
	Month uint8 `json:"month"`
	// The day, which should be a number from 1 to either 29, 30, or 31, depending on the month
	// and year. Here, February is treated as having 29 days.
	Day uint8 `json:"day"`
}

// A structure for specifying a particular date consisting of a day, month, and year, for use in
// an FpeDate structure.
type FpeDayMonthYearDate struct {
	// The year, which should be a number less than 100000. Zero is treated as a leap year.
	Year uint32 `json:"year"`
	// The month, which should be a number from 1 to 12.
	Month uint8 `json:"month"`
	// The day, which should be a number from 1 to either 28, 29, 30, or 31, depending on the
	// month and year.
	Day uint8 `json:"day"`
}

// Structure of a tokenized portion of a complex tokenization data type.
type FpeEncryptedPart struct {
	// The minimum allowed length for this part (in chars).
	MinLength uint32 `json:"min_length"`
	// The maximum allowed length for this part (in chars).
	MaxLength uint32 `json:"max_length"`
	// The character set to use for this part.
	CharSet FpeCharSet `json:"char_set"`
	// The output character set to use for this part. Defaults to `char_set` if not specified.
	// When specified, the cardinality of `cipher_char_set` must be the same as `char_set`.
	CipherCharSet *FpeCharSet `json:"cipher_char_set,omitempty"`
	// Additional constraints that the token type must satisfy.
	Constraints *FpeConstraints `json:"constraints,omitempty"`
	// The characters to be preserved while encrypting or decrypting.
	Preserve *FpePreserveMask `json:"preserve,omitempty"`
	// The characters to be masked while performing masked decryption.
	Mask *FpePreserveMask `json:"mask,omitempty"`
}

// A structure for specifying a particular date consisting of a month and a year, for use in an
// FpeDate structure.
type FpeMonthYearDate struct {
	// The year, which should be a number less than 100000. Zero is treated as a leap year.
	Year uint32 `json:"year"`
	// The month, which should be a number from 1 to 12.
	Month uint8 `json:"month"`
}

// FPE-specific options.
type FpeOptions struct {
	// For specifying basic tokens
	Basic    *FpeOptionsBasic
	Advanced *FpeOptionsAdvanced
}
type FpeOptionsAdvanced struct {
	// The structure of the data type.
	Format FpeDataPart `json:"format"`
	// The user-friendly name for the data type that represents the input data.
	Description *string `json:"description,omitempty"`
}

func (x FpeOptions) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"FpeOptions",
		[]bool{x.Basic != nil,
			x.Advanced != nil}); err != nil {
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

// Basic FPE-specific options.
type FpeOptionsBasic struct {
	// The base for input data.
	Radix uint32 `json:"radix"`
	// The minimum allowed length for the input data.
	MinLength uint32 `json:"min_length"`
	// The maximum allowed length for the input data.
	MaxLength uint32 `json:"max_length"`
	// The list of indices of characters to be preserved while performing encryption/decryption.
	Preserve []int `json:"preserve"`
	// The list of indices of characters to be masked while performing masked decryption.
	Mask *[]int `json:"mask,omitempty"`
	// Whether encrypted/decrypted data should satisfy LUHN checksum formula.
	LuhnCheck *bool `json:"luhn_check,omitempty"`
	// The user-friendly name for the data type that represents the input data.
	Name *string `json:"name,omitempty"`
}

// A structure indicating which indices in an encrypted part to mask or preserve.
type FpePreserveMask struct {
	// Indicates that the entire encrypted part is to be preserved or masked.
	Entire *All
	// Indicates that only certain characters are to be preserved or masked. Indices are
	// Python-like; i.e., negative indices index from the back of the token portion, with
	// index -1 being the end of the array. (Indicating that nothing should be preserved
	// or masked can be done via an empty list, which is the default value for this enum.)
	ByChars *[]int
}

func (x FpePreserveMask) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"FpePreserveMask",
		[]bool{x.Entire != nil,
			x.ByChars != nil}); err != nil {
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

// An access reason provided by Google when making EKMS API calls.
type GoogleAccessReason string

// List of supported GoogleAccessReason values
const (
	// No reason is available for the access.
	GoogleAccessReasonReasonUnspecified GoogleAccessReason = "REASON_UNSPECIFIED"
	// Access Transparency Types, public documentation can be found at:
	// https://cloud.google.com/logging/docs/audit/reading-access-transparency-logs#justification-reason-codes
	GoogleAccessReasonCustomerInitiatedSupport GoogleAccessReason = "CUSTOMER_INITIATED_SUPPORT"
	GoogleAccessReasonGoogleInitiatedService   GoogleAccessReason = "GOOGLE_INITIATED_SERVICE"
	GoogleAccessReasonThirdPartyDataRequest    GoogleAccessReason = "THIRD_PARTY_DATA_REQUEST"
	GoogleAccessReasonGoogleInitiatedReview    GoogleAccessReason = "GOOGLE_INITIATED_REVIEW"
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
	//  `CREATE_SOBJECTS`, `EXPORT_SOBJECTS`, `COPY_SOBJECTS`, `WRAP_SOBJECTS`, `UNWRAP_SOBJECTS`,
	//  `DERIVE_SOBJECTS`, `TRANSFORM_SOBJECTS`, `UPDATE_SOBJECTS_ENABLED_STATE`, `ROTATE_SOBJECTS`,
	//  `DELETE_SOBJECTS`, `REVOKE_SOBJECTS`, `ACTIVATE_SOBJECTS`, `MOVE_SOBJECTS`, `UPDATE_KEY_OPS`,
	//  `UPDATE_SOBJECT_POLICIES`, `UPDATE_SOBJECTS_PROFILE`, `GET_GROUP`, `GET_SOBJECTS`, `GET_APPS`,
	//  `GET_PLUGINS`, `GET_AUDIT_LOGS`
	//  Following account permissions are required as well:
	//  `GET_ALL_USERS`
	GroupPermissionsCreatePlugins
	//  Permission to update plugins. Implies `GET_PLUGINS`.
	//  For updating a plugin, following group permissions are also required
	//  in each group plugin is being added, to prevent privilege escalation:
	//  `CREATE_SOBJECTS`, `EXPORT_SOBJECTS`, `COPY_SOBJECTS`, `WRAP_SOBJECTS`, `UNWRAP_SOBJECTS`,
	//  `UPDATE_SOBJECTS_ENABLED_STATE`, `ROTATE_SOBJECTS`, `DELETE_SOBJECTS`, `REVOKE_SOBJECTS`,
	//  `ACTIVATE_SOBJECTS`, `MOVE_SOBJECTS`, `UPDATE_KEY_OPS`, `UPDATE_SOBJECT_POLICIES`,
	//  `UPDATE_SOBJECTS_PROFILE`, `GET_GROUP`, `GET_SOBJECTS`, `GET_APPS`, `GET_PLUGINS`,
	//  `GET_AUDIT_LOGS`
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
)

// MarshalJSON converts GroupPermissions to an array of strings
func (x GroupPermissions) MarshalJSON() ([]byte, error) {
	s := make([]string, 0)
	if x&GroupPermissionsCreateGroupApprovalPolicy == GroupPermissionsCreateGroupApprovalPolicy {
		s = append(s, "CREATE_GROUP_APPROVAL_POLICY")
	}
	if x&GroupPermissionsUpdateGroupExternalLinks == GroupPermissionsUpdateGroupExternalLinks {
		s = append(s, "UPDATE_GROUP_EXTERNAL_LINKS")
	}
	if x&GroupPermissionsManageGroupClientConfigs == GroupPermissionsManageGroupClientConfigs {
		s = append(s, "MANAGE_GROUP_CLIENT_CONFIGS")
	}
	if x&GroupPermissionsUpdateGroupProfile == GroupPermissionsUpdateGroupProfile {
		s = append(s, "UPDATE_GROUP_PROFILE")
	}
	if x&GroupPermissionsDeleteGroup == GroupPermissionsDeleteGroup {
		s = append(s, "DELETE_GROUP")
	}
	if x&GroupPermissionsMapExternalRolesForApps == GroupPermissionsMapExternalRolesForApps {
		s = append(s, "MAP_EXTERNAL_ROLES_FOR_APPS")
	}
	if x&GroupPermissionsMapExternalRolesForUsers == GroupPermissionsMapExternalRolesForUsers {
		s = append(s, "MAP_EXTERNAL_ROLES_FOR_USERS")
	}
	if x&GroupPermissionsMapExternalRoles == GroupPermissionsMapExternalRoles {
		s = append(s, "MAP_EXTERNAL_ROLES")
	}
	if x&GroupPermissionsAddUsersToGroup == GroupPermissionsAddUsersToGroup {
		s = append(s, "ADD_USERS_TO_GROUP")
	}
	if x&GroupPermissionsDeleteUsersFromGroup == GroupPermissionsDeleteUsersFromGroup {
		s = append(s, "DELETE_USERS_FROM_GROUP")
	}
	if x&GroupPermissionsUpdateUsersGroupRole == GroupPermissionsUpdateUsersGroupRole {
		s = append(s, "UPDATE_USERS_GROUP_ROLE")
	}
	if x&GroupPermissionsManageGroupUsers == GroupPermissionsManageGroupUsers {
		s = append(s, "MANAGE_GROUP_USERS")
	}
	if x&GroupPermissionsCreateGroupSobjectPolicies == GroupPermissionsCreateGroupSobjectPolicies {
		s = append(s, "CREATE_GROUP_SOBJECT_POLICIES")
	}
	if x&GroupPermissionsUpdateGroupSobjectPolicies == GroupPermissionsUpdateGroupSobjectPolicies {
		s = append(s, "UPDATE_GROUP_SOBJECT_POLICIES")
	}
	if x&GroupPermissionsDeleteGroupSobjectPolicies == GroupPermissionsDeleteGroupSobjectPolicies {
		s = append(s, "DELETE_GROUP_SOBJECT_POLICIES")
	}
	if x&GroupPermissionsManageGroupSobjectPolicies == GroupPermissionsManageGroupSobjectPolicies {
		s = append(s, "MANAGE_GROUP_SOBJECT_POLICIES")
	}
	if x&GroupPermissionsCreateGroupCustodianPolicy == GroupPermissionsCreateGroupCustodianPolicy {
		s = append(s, "CREATE_GROUP_CUSTODIAN_POLICY")
	}
	if x&GroupPermissionsUpdateGroupCustodianPolicy == GroupPermissionsUpdateGroupCustodianPolicy {
		s = append(s, "UPDATE_GROUP_CUSTODIAN_POLICY")
	}
	if x&GroupPermissionsDeleteGroupCustodianPolicy == GroupPermissionsDeleteGroupCustodianPolicy {
		s = append(s, "DELETE_GROUP_CUSTODIAN_POLICY")
	}
	if x&GroupPermissionsManageGroupCustodianPolicy == GroupPermissionsManageGroupCustodianPolicy {
		s = append(s, "MANAGE_GROUP_CUSTODIAN_POLICY")
	}
	if x&GroupPermissionsCreateApps == GroupPermissionsCreateApps {
		s = append(s, "CREATE_APPS")
	}
	if x&GroupPermissionsUpdateApps == GroupPermissionsUpdateApps {
		s = append(s, "UPDATE_APPS")
	}
	if x&GroupPermissionsRetrieveAppSecrets == GroupPermissionsRetrieveAppSecrets {
		s = append(s, "RETRIEVE_APP_SECRETS")
	}
	if x&GroupPermissionsDeleteApps == GroupPermissionsDeleteApps {
		s = append(s, "DELETE_APPS")
	}
	if x&GroupPermissionsManageApps == GroupPermissionsManageApps {
		s = append(s, "MANAGE_APPS")
	}
	if x&GroupPermissionsCreatePlugins == GroupPermissionsCreatePlugins {
		s = append(s, "CREATE_PLUGINS")
	}
	if x&GroupPermissionsUpdatePlugins == GroupPermissionsUpdatePlugins {
		s = append(s, "UPDATE_PLUGINS")
	}
	if x&GroupPermissionsInvokePlugins == GroupPermissionsInvokePlugins {
		s = append(s, "INVOKE_PLUGINS")
	}
	if x&GroupPermissionsDeletePlugins == GroupPermissionsDeletePlugins {
		s = append(s, "DELETE_PLUGINS")
	}
	if x&GroupPermissionsManagePlugins == GroupPermissionsManagePlugins {
		s = append(s, "MANAGE_PLUGINS")
	}
	if x&GroupPermissionsCreateSobjects == GroupPermissionsCreateSobjects {
		s = append(s, "CREATE_SOBJECTS")
	}
	if x&GroupPermissionsExportSobjects == GroupPermissionsExportSobjects {
		s = append(s, "EXPORT_SOBJECTS")
	}
	if x&GroupPermissionsCopySobjects == GroupPermissionsCopySobjects {
		s = append(s, "COPY_SOBJECTS")
	}
	if x&GroupPermissionsWrapSobjects == GroupPermissionsWrapSobjects {
		s = append(s, "WRAP_SOBJECTS")
	}
	if x&GroupPermissionsUnwrapSobjects == GroupPermissionsUnwrapSobjects {
		s = append(s, "UNWRAP_SOBJECTS")
	}
	if x&GroupPermissionsDeriveSobjects == GroupPermissionsDeriveSobjects {
		s = append(s, "DERIVE_SOBJECTS")
	}
	if x&GroupPermissionsTransformSobjects == GroupPermissionsTransformSobjects {
		s = append(s, "TRANSFORM_SOBJECTS")
	}
	if x&GroupPermissionsUpdateSobjectsEnabledState == GroupPermissionsUpdateSobjectsEnabledState {
		s = append(s, "UPDATE_SOBJECTS_ENABLED_STATE")
	}
	if x&GroupPermissionsRotateSobjects == GroupPermissionsRotateSobjects {
		s = append(s, "ROTATE_SOBJECTS")
	}
	if x&GroupPermissionsDeleteSobjects == GroupPermissionsDeleteSobjects {
		s = append(s, "DELETE_SOBJECTS")
	}
	if x&GroupPermissionsDestroySobjects == GroupPermissionsDestroySobjects {
		s = append(s, "DESTROY_SOBJECTS")
	}
	if x&GroupPermissionsRevokeSobjects == GroupPermissionsRevokeSobjects {
		s = append(s, "REVOKE_SOBJECTS")
	}
	if x&GroupPermissionsActivateSobjects == GroupPermissionsActivateSobjects {
		s = append(s, "ACTIVATE_SOBJECTS")
	}
	if x&GroupPermissionsRevertSobjects == GroupPermissionsRevertSobjects {
		s = append(s, "REVERT_SOBJECTS")
	}
	if x&GroupPermissionsDeleteKeyMaterial == GroupPermissionsDeleteKeyMaterial {
		s = append(s, "DELETE_KEY_MATERIAL")
	}
	if x&GroupPermissionsMoveSobjects == GroupPermissionsMoveSobjects {
		s = append(s, "MOVE_SOBJECTS")
	}
	if x&GroupPermissionsUpdateKeyOps == GroupPermissionsUpdateKeyOps {
		s = append(s, "UPDATE_KEY_OPS")
	}
	if x&GroupPermissionsUpdateSobjectPolicies == GroupPermissionsUpdateSobjectPolicies {
		s = append(s, "UPDATE_SOBJECT_POLICIES")
	}
	if x&GroupPermissionsUpdateSobjectsProfile == GroupPermissionsUpdateSobjectsProfile {
		s = append(s, "UPDATE_SOBJECTS_PROFILE")
	}
	if x&GroupPermissionsScanExternalSobjects == GroupPermissionsScanExternalSobjects {
		s = append(s, "SCAN_EXTERNAL_SOBJECTS")
	}
	if x&GroupPermissionsRestoreExternalSobjects == GroupPermissionsRestoreExternalSobjects {
		s = append(s, "RESTORE_EXTERNAL_SOBJECTS")
	}
	if x&GroupPermissionsWrapWorkspaceCse == GroupPermissionsWrapWorkspaceCse {
		s = append(s, "WRAP_WORKSPACE_CSE")
	}
	if x&GroupPermissionsUnwrapWorkspaceCse == GroupPermissionsUnwrapWorkspaceCse {
		s = append(s, "UNWRAP_WORKSPACE_CSE")
	}
	if x&GroupPermissionsWorkspaceCse == GroupPermissionsWorkspaceCse {
		s = append(s, "WORKSPACE_CSE")
	}
	if x&GroupPermissionsGetGroup == GroupPermissionsGetGroup {
		s = append(s, "GET_GROUP")
	}
	if x&GroupPermissionsGetSobjects == GroupPermissionsGetSobjects {
		s = append(s, "GET_SOBJECTS")
	}
	if x&GroupPermissionsGetApps == GroupPermissionsGetApps {
		s = append(s, "GET_APPS")
	}
	if x&GroupPermissionsGetPlugins == GroupPermissionsGetPlugins {
		s = append(s, "GET_PLUGINS")
	}
	if x&GroupPermissionsGetGroupApprovalRequests == GroupPermissionsGetGroupApprovalRequests {
		s = append(s, "GET_GROUP_APPROVAL_REQUESTS")
	}
	if x&GroupPermissionsGetAuditLogs == GroupPermissionsGetAuditLogs {
		s = append(s, "GET_AUDIT_LOGS")
	}
	if x&GroupPermissionsManageGroupWrappingKey == GroupPermissionsManageGroupWrappingKey {
		s = append(s, "MANAGE_GROUP_WRAPPING_KEY")
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
		}
	}
	return nil
}

type HistoryItem struct {
	ID        UUID             `json:"id"`
	State     HistoryItemState `json:"state"`
	CreatedAt Time             `json:"created_at"`
	Expiry    Time             `json:"expiry"`
}

type HistoryItemState struct {
	ActivationDate         *Time             `json:"activation_date,omitempty"`
	ActivationUndoWindow   *Secs             `json:"activation_undo_window,omitempty"`
	RevocationReason       *RevocationReason `json:"revocation_reason,omitempty"`
	CompromiseDate         *Time             `json:"compromise_date,omitempty"`
	DeactivationDate       *Time             `json:"deactivation_date,omitempty"`
	DeactivationUndoWindow *Secs             `json:"deactivation_undo_window,omitempty"`
	DestructionDate        *Time             `json:"destruction_date,omitempty"`
	DeletionDate           *Time             `json:"deletion_date,omitempty"`
	State                  SobjectState      `json:"state"`
	KeyOps                 KeyOperations     `json:"key_ops"`
	PublicOnly             bool              `json:"public_only"`
	HasKey                 bool              `json:"has_key"`
	RotationPolicy         *RotationPolicy   `json:"rotation_policy,omitempty"`
	GroupID                *UUID             `json:"group_id,omitempty"`
}

type HmacOptions struct {
	MinimumKeyLength *uint32 `json:"minimum_key_length,omitempty"`
}

// Signing keys used to validate signed JWT tokens.
type JwtSigningKeys struct {
	Stored  *JwtSigningKeysStored
	Fetched *JwtSigningKeysFetched
}
type JwtSigningKeysStored struct {
	// Mapping key ids to DER-encoded public key.
	Keys map[string]Blob `json:"keys"`
}
type JwtSigningKeysFetched struct {
	URL string `json:"url"`
	// Number of seconds that the service is allowed to cache the fetched keys.
	CacheDuration uint64 `json:"cache_duration"`
}

func (x JwtSigningKeys) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"JwtSigningKeys",
		[]bool{x.Stored != nil,
			x.Fetched != nil}); err != nil {
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
func (x *JwtSigningKeys) UnmarshalJSON(data []byte) error {
	x.Stored = nil
	x.Fetched = nil
	var h struct {
		Tag string `json:"kind"`
	}
	if err := json.Unmarshal(data, &h); err != nil {
		return errors.Errorf("not a valid JwtSigningKeys")
	}
	switch h.Tag {
	case "stored":
		var stored JwtSigningKeysStored
		if err := json.Unmarshal(data, &stored); err != nil {
			return err
		}
		x.Stored = &stored
	case "fetched":
		var fetched JwtSigningKeysFetched
		if err := json.Unmarshal(data, &fetched); err != nil {
			return err
		}
		x.Fetched = &fetched
	default:
		return errors.Errorf("invalid tag value: %v", h.Tag)
	}
	return nil
}

type KcdsaOptions struct {
	SubgroupSize *uint32          `json:"subgroup_size,omitempty"`
	HashAlg      *DigestAlgorithm `json:"hash_alg,omitempty"`
}

type KeyHistoryPolicy struct {
	UndoTimeWindow Secs `json:"undo_time_window"`
}

// Linked security objects.
type KeyLinks struct {
	Replacement *UUID   `json:"replacement,omitempty"`
	Replaced    *UUID   `json:"replaced,omitempty"`
	CopiedFrom  *UUID   `json:"copiedFrom,omitempty"`
	CopiedTo    *[]UUID `json:"copiedTo,omitempty"`
	Subkeys     *[]UUID `json:"subkeys,omitempty"`
	Parent      *UUID   `json:"parent,omitempty"`
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
)

// MarshalJSON converts KeyOperations to an array of strings
func (x KeyOperations) MarshalJSON() ([]byte, error) {
	s := make([]string, 0)
	if x&KeyOperationsSign == KeyOperationsSign {
		s = append(s, "SIGN")
	}
	if x&KeyOperationsVerify == KeyOperationsVerify {
		s = append(s, "VERIFY")
	}
	if x&KeyOperationsEncrypt == KeyOperationsEncrypt {
		s = append(s, "ENCRYPT")
	}
	if x&KeyOperationsDecrypt == KeyOperationsDecrypt {
		s = append(s, "DECRYPT")
	}
	if x&KeyOperationsWrapkey == KeyOperationsWrapkey {
		s = append(s, "WRAPKEY")
	}
	if x&KeyOperationsUnwrapkey == KeyOperationsUnwrapkey {
		s = append(s, "UNWRAPKEY")
	}
	if x&KeyOperationsDerivekey == KeyOperationsDerivekey {
		s = append(s, "DERIVEKEY")
	}
	if x&KeyOperationsTransform == KeyOperationsTransform {
		s = append(s, "TRANSFORM")
	}
	if x&KeyOperationsMacgenerate == KeyOperationsMacgenerate {
		s = append(s, "MACGENERATE")
	}
	if x&KeyOperationsMacverify == KeyOperationsMacverify {
		s = append(s, "MACVERIFY")
	}
	if x&KeyOperationsExport == KeyOperationsExport {
		s = append(s, "EXPORT")
	}
	if x&KeyOperationsAppmanageable == KeyOperationsAppmanageable {
		s = append(s, "APPMANAGEABLE")
	}
	if x&KeyOperationsHighvolume == KeyOperationsHighvolume {
		s = append(s, "HIGHVOLUME")
	}
	if x&KeyOperationsAgreekey == KeyOperationsAgreekey {
		s = append(s, "AGREEKEY")
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
		}
	}
	return nil
}

type KmipClientConfig struct {
	IgnoreUnknownKeyOpsForSecrets *bool `json:"ignore_unknown_key_ops_for_secrets,omitempty"`
}

// Role of a user or app in an account for the purpose of LDAP configurations.
type LdapAccountRole struct {
	Legacy *LegacyLdapAccountRole
	Custom *UUID
}

func (x LdapAccountRole) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"LdapAccountRole",
		[]bool{x.Legacy != nil,
			x.Custom != nil}); err != nil {
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
		[]bool{x.Construct != nil,
			x.SearchByMail != nil,
			x.UserPrincipalName != nil}); err != nil {
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
// Then which role should be assigned to this user in G1?
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
	// A user that belongs to LDAP groups A, B and C will become a member of
	// DSM group G1 with role R1 + R3.
	LdapRoleConflictResolutionDisregardExclusiveRoles LdapRoleConflictResolution = "disregard_exclusive_roles"
)

// Credentials used by the service to authenticate itself to an LDAP server.
type LdapServiceAccount struct {
	Dn       string `json:"dn"`
	Password string `json:"password"`
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
		[]bool{x.Fixed != nil}); err != nil {
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
	LegacyLdapAccountRoleAdminUser   LegacyLdapAccountRole = "ADMIN_USER"
	LegacyLdapAccountRoleMemberUser  LegacyLdapAccountRole = "MEMBER_USER"
	LegacyLdapAccountRoleAuditorUser LegacyLdapAccountRole = "AUDITOR_USER"
	LegacyLdapAccountRoleAdminApp    LegacyLdapAccountRole = "ADMIN_APP"
	LegacyLdapAccountRoleCryptoApp   LegacyLdapAccountRole = "CRYPTO_APP"
)

// Legacy user account role
type LegacyUserAccountRole string

// List of supported LegacyUserAccountRole values
const (
	LegacyUserAccountRoleAccountAdministrator LegacyUserAccountRole = "ACCOUNTADMINISTRATOR"
	LegacyUserAccountRoleAccountMember        LegacyUserAccountRole = "ACCOUNTMEMBER"
	LegacyUserAccountRoleAccountAuditor       LegacyUserAccountRole = "ACCOUNTAUDITOR"
)

// Legacy user group role
type LegacyUserGroupRole string

// List of supported LegacyUserGroupRole values
const (
	LegacyUserGroupRoleGroupAuditor       LegacyUserGroupRole = "GROUPAUDITOR"
	LegacyUserGroupRoleGroupAdministrator LegacyUserGroupRole = "GROUPADMINISTRATOR"
)

// Legacy user group role name or custom role id
type LegacyUserGroupRoleOrRoleId struct {
	LegacyRole *LegacyUserGroupRole
	RoleID     *UUID
}

func (x LegacyUserGroupRoleOrRoleId) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"LegacyUserGroupRoleOrRoleId",
		[]bool{x.LegacyRole != nil,
			x.RoleID != nil}); err != nil {
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
	// The height of the top level tree
	L1Height uint32 `json:"l1_height"`
	// The height of the secondary tree
	L2Height uint32 `json:"l2_height"`
	// The hash function to use
	Digest *DigestAlgorithm `json:"digest,omitempty"`
}

type Metadata struct {
	TotalCount    *uint `json:"total_count,omitempty"`
	FilteredCount *uint `json:"filtered_count,omitempty"`
}

type MetadataDurationConstraint struct {
	Forbidden *struct{}
	Required  *MetadataDurationConstraintRequired
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
		[]bool{x.Forbidden != nil,
			x.Required != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Forbidden *struct{}                           `json:"forbidden,omitempty"`
		Required  *MetadataDurationConstraintRequired `json:"required,omitempty"`
	}
	obj.Forbidden = x.Forbidden
	obj.Required = x.Required
	return json.Marshal(obj)
}
func (x *MetadataDurationConstraint) UnmarshalJSON(data []byte) error {
	x.Forbidden = nil
	x.Required = nil
	var obj struct {
		Forbidden *struct{}                           `json:"forbidden,omitempty"`
		Required  *MetadataDurationConstraintRequired `json:"required,omitempty"`
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
	Description    *MetadataStringConstraint           `json:"description,omitempty"`
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
	Required  *MetadataStringConstraintRequired
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
		[]bool{x.Forbidden != nil,
			x.Required != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Forbidden *struct{}                         `json:"forbidden,omitempty"`
		Required  *MetadataStringConstraintRequired `json:"required,omitempty"`
	}
	obj.Forbidden = x.Forbidden
	obj.Required = x.Required
	return json.Marshal(obj)
}
func (x *MetadataStringConstraint) UnmarshalJSON(data []byte) error {
	x.Forbidden = nil
	x.Required = nil
	var obj struct {
		Forbidden *struct{}                         `json:"forbidden,omitempty"`
		Required  *MetadataStringConstraintRequired `json:"required,omitempty"`
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
	Fido2     *Fido2MfaChallengeResponse
}

func (x MfaChallengeResponse) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"MfaChallengeResponse",
		[]bool{x.LegacyU2f != nil,
			x.Fido2 != nil}); err != nil {
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
		[]bool{x.Mgf1 != nil}); err != nil {
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
		[]bool{x.Mgf1 != nil}); err != nil {
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

// OAuth scope.
type OauthScope string

// List of supported OauthScope values
const (
	OauthScopeApp     OauthScope = "app"
	OauthScopeOpenID  OauthScope = "openid"
	OauthScopeEmail   OauthScope = "email"
	OauthScopeProfile OauthScope = "profile"
)

// The origin of a security object - where it was created / generated.
type ObjectOrigin string

// List of supported ObjectOrigin values
const (
	ObjectOriginFortanixHSM ObjectOrigin = "FortanixHSM"
	ObjectOriginTransient   ObjectOrigin = "Transient"
	ObjectOriginExternal    ObjectOrigin = "External"
)

// Type of security object.
type ObjectType string

// List of supported ObjectType values
const (
	ObjectTypeAes         ObjectType = "AES"
	ObjectTypeAria        ObjectType = "ARIA"
	ObjectTypeDes         ObjectType = "DES"
	ObjectTypeDes3        ObjectType = "DES3"
	ObjectTypeSeed        ObjectType = "SEED"
	ObjectTypeRsa         ObjectType = "RSA"
	ObjectTypeDsa         ObjectType = "DSA"
	ObjectTypeEc          ObjectType = "EC"
	ObjectTypeKcdsa       ObjectType = "KCDSA"
	ObjectTypeEcKcdsa     ObjectType = "ECKCDSA"
	ObjectTypeBip32       ObjectType = "BIP32"
	ObjectTypeBls         ObjectType = "BLS"
	ObjectTypeOpaque      ObjectType = "OPAQUE"
	ObjectTypeHmac        ObjectType = "HMAC"
	ObjectTypeLedaBeta    ObjectType = "LEDABETA"
	ObjectTypeRound5Beta  ObjectType = "ROUND5BETA"
	ObjectTypeSecret      ObjectType = "SECRET"
	ObjectTypeLms         ObjectType = "LMS"
	ObjectTypeCertificate ObjectType = "CERTIFICATE"
	ObjectTypePbe         ObjectType = "PBE"
)

type OpaqueOptions struct {
}

type Pkcs11ClientConfig struct {
	FakeRsaX931KeygenSupport        *bool `json:"fake_rsa_x9_31_keygen_support,omitempty"`
	SigningAesKeyAsHmac             *bool `json:"signing_aes_key_as_hmac,omitempty"`
	ExactKeyOps                     *bool `json:"exact_key_ops,omitempty"`
	PreventDuplicateOpaqueObjects   *bool `json:"prevent_duplicate_opaque_objects,omitempty"`
	OpaqueObjectsAreNotCertificates *bool `json:"opaque_objects_are_not_certificates,omitempty"`
	MaxConcurrentRequestsPerSlot    *uint `json:"max_concurrent_requests_per_slot,omitempty"`
}

type Pkcs8Mode string

// List of supported Pkcs8Mode values
const (
	Pkcs8ModePbeWithSHAAnd128BitRC4         Pkcs8Mode = "PBEWITHSHAAND128BITRC4"
	Pkcs8ModePbeWithSHAAnd3KeyTripleDesCbc  Pkcs8Mode = "PBEWITHSHAAND3KEYTRIPLEDESCBC"
	Pkcs8ModePbeWithSHAAnd2KeyTripleDesCbc  Pkcs8Mode = "PBEWITHSHAAND2KEYTRIPLEDESCBC"
	Pkcs8ModePbes2WithPBKDF2AndKeyDes       Pkcs8Mode = "PBES2WITHPBKDF2ANDKEYDES"
	Pkcs8ModePbes2WithPBKDF2AndKeyTripleDes Pkcs8Mode = "PBES2WITHPBKDF2ANDKEYTRIPLEDES"
)

// A security principal.
type Principal struct {
	App    *UUID
	User   *UUID
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
	UserID UUID         `json:"user_id"`
	Scopes []OauthScope `json:"scopes"`
}

func (x Principal) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"Principal",
		[]bool{x.App != nil,
			x.User != nil,
			x.Plugin != nil,
			x.UserViaApp != nil,
			x.System != nil,
			x.UnregisteredUser != nil}); err != nil {
		return nil, err
	}
	switch {
	case x.System != nil:
		return []byte(`"system"`), nil
	case x.UnregisteredUser != nil:
		return []byte(`"unregistereduser"`), nil
	}
	var obj struct {
		App        *UUID                `json:"app,omitempty"`
		User       *UUID                `json:"user,omitempty"`
		Plugin     *UUID                `json:"plugin,omitempty"`
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
		App        *UUID                `json:"app,omitempty"`
		User       *UUID                `json:"user,omitempty"`
		Plugin     *UUID                `json:"plugin,omitempty"`
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
	Enabled  *PublishPublicKeyConfigEnabled
	Disabled *struct{}
}
type PublishPublicKeyConfigEnabled struct {
	// Additionally list the previous version of the key if not compromised.
	ListPreviousVersion bool `json:"list_previous_version"`
}

func (x PublishPublicKeyConfig) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"PublishPublicKeyConfig",
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
	N       uint               `json:"n"`
	Members []QuorumPolicy     `json:"members"`
	Config  ApprovalAuthConfig `json:"config"`
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
		N       uint           `json:"n"`
		Members []QuorumPolicy `json:"members"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	x.N = r.N
	x.Members = r.Members
	return nil
}

// Approval policy.
type QuorumPolicy struct {
	Quorum *Quorum `json:"quorum,omitempty"`
	User   *UUID   `json:"user,omitempty"`
	App    *UUID   `json:"app,omitempty"`
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
	Message                 *string `json:"message,omitempty"`
	CompromiseOccuranceDate *Time   `json:"compromise_occurance_date,omitempty"`
}

// Reasons to revoke a security object.
type RevocationReasonCode string

// List of supported RevocationReasonCode values
const (
	RevocationReasonCodeUnspecified          RevocationReasonCode = "Unspecified"
	RevocationReasonCodeKeyCompromise        RevocationReasonCode = "KeyCompromise"
	RevocationReasonCodeCACompromise         RevocationReasonCode = "CACompromise"
	RevocationReasonCodeAffiliationChanged   RevocationReasonCode = "AffiliationChanged"
	RevocationReasonCodeSuperseded           RevocationReasonCode = "Superseded"
	RevocationReasonCodeCessationOfOperation RevocationReasonCode = "CessationOfOperation"
	RevocationReasonCodePrivilegeWithdrawn   RevocationReasonCode = "PrivilegeWithdrawn"
)

type RotateCopiedKeys struct {
	AllExternal *struct{}
	Select      *[]UUID
}

func (x RotateCopiedKeys) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"RotateCopiedKeys",
		[]bool{x.AllExternal != nil,
			x.Select != nil}); err != nil {
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
	IntervalDays   *uint32
	IntervalMonths *uint32
}

func (x RotationInterval) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"RotationInterval",
		[]bool{x.IntervalDays != nil,
			x.IntervalMonths != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		IntervalDays   *uint32 `json:"interval_days,omitempty"`
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
		IntervalDays   *uint32 `json:"interval_days,omitempty"`
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
	Interval             *RotationInterval `json:"interval,omitempty"`
	EffectiveAt          *Time             `json:"effective_at,omitempty"`
	DeactivateRotatedKey *bool             `json:"deactivate_rotated_key,omitempty"`
	RotateCopiedKeys     *RotateCopiedKeys `json:"rotate_copied_keys,omitempty"`
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
		EffectiveAt          *Time             `json:"effective_at,omitempty"`
		DeactivateRotatedKey *bool             `json:"deactivate_rotated_key,omitempty"`
		RotateCopiedKeys     *RotateCopiedKeys `json:"rotate_copied_keys,omitempty"`
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
	// PKCS#1 v1.5 padding.
	Pkcs1V15 *struct{}
	// RSA encryption without padding
	RawDecrypt *struct{}
}

// Optimal Asymmetric Encryption Padding (PKCS#1 v2.1).
type RsaEncryptionPaddingOaep struct {
	Mgf Mgf `json:"mgf"`
}

func (x RsaEncryptionPadding) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"RsaEncryptionPadding",
		[]bool{x.Oaep != nil,
			x.Pkcs1V15 != nil,
			x.RawDecrypt != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Oaep       *RsaEncryptionPaddingOaep `json:"OAEP,omitempty"`
		Pkcs1V15   *struct{}                 `json:"PKCS1_V15,omitempty"`
		RawDecrypt *struct{}                 `json:"RAW_DECRYPT,omitempty"`
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
		Oaep       *RsaEncryptionPaddingOaep `json:"OAEP,omitempty"`
		Pkcs1V15   *struct{}                 `json:"PKCS1_V15,omitempty"`
		RawDecrypt *struct{}                 `json:"RAW_DECRYPT,omitempty"`
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
	Oaep       *RsaEncryptionPaddingPolicyOaep
	Pkcs1V15   *struct{}
	RawDecrypt *struct{}
}
type RsaEncryptionPaddingPolicyOaep struct {
	Mgf *MgfPolicy `json:"mgf,omitempty"`
}

func (x RsaEncryptionPaddingPolicy) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"RsaEncryptionPaddingPolicy",
		[]bool{x.Oaep != nil,
			x.Pkcs1V15 != nil,
			x.RawDecrypt != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Oaep       *RsaEncryptionPaddingPolicyOaep `json:"OAEP,omitempty"`
		Pkcs1V15   *struct{}                       `json:"PKCS1_V15,omitempty"`
		RawDecrypt *struct{}                       `json:"RAW_DECRYPT,omitempty"`
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
		Oaep       *RsaEncryptionPaddingPolicyOaep `json:"OAEP,omitempty"`
		Pkcs1V15   *struct{}                       `json:"PKCS1_V15,omitempty"`
		RawDecrypt *struct{}                       `json:"RAW_DECRYPT,omitempty"`
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
	SignaturePolicy  *[]RsaSignaturePolicy `json:"signature_policy,omitempty"`
	MinimumKeyLength *uint32               `json:"minimum_key_length,omitempty"`
}

// Type of padding to use for RSA signatures. The padding specified must adhere to the key's
// signature policy. If not specified, the default based on the key's policy will be used.
type RsaSignaturePadding struct {
	// Probabilistic Signature Scheme (PKCS#1 v2.1).
	Pss *RsaSignaturePaddingPss
	// PKCS#1 v1.5 padding.
	Pkcs1V15 *struct{}
}

// Probabilistic Signature Scheme (PKCS#1 v2.1).
type RsaSignaturePaddingPss struct {
	Mgf Mgf `json:"mgf"`
}

func (x RsaSignaturePadding) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"RsaSignaturePadding",
		[]bool{x.Pss != nil,
			x.Pkcs1V15 != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Pss      *RsaSignaturePaddingPss `json:"PSS,omitempty"`
		Pkcs1V15 *struct{}               `json:"PKCS1_V15,omitempty"`
	}
	obj.Pss = x.Pss
	obj.Pkcs1V15 = x.Pkcs1V15
	return json.Marshal(obj)
}
func (x *RsaSignaturePadding) UnmarshalJSON(data []byte) error {
	x.Pss = nil
	x.Pkcs1V15 = nil
	var obj struct {
		Pss      *RsaSignaturePaddingPss `json:"PSS,omitempty"`
		Pkcs1V15 *struct{}               `json:"PKCS1_V15,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.Pss = obj.Pss
	x.Pkcs1V15 = obj.Pkcs1V15
	return nil
}

// RSA signature padding policy.
type RsaSignaturePaddingPolicy struct {
	Pss      *RsaSignaturePaddingPolicyPss
	Pkcs1V15 *struct{}
}
type RsaSignaturePaddingPolicyPss struct {
	Mgf *MgfPolicy `json:"mgf,omitempty"`
}

func (x RsaSignaturePaddingPolicy) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"RsaSignaturePaddingPolicy",
		[]bool{x.Pss != nil,
			x.Pkcs1V15 != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Pss      *RsaSignaturePaddingPolicyPss `json:"PSS,omitempty"`
		Pkcs1V15 *struct{}                     `json:"PKCS1_V15,omitempty"`
	}
	obj.Pss = x.Pss
	obj.Pkcs1V15 = x.Pkcs1V15
	return json.Marshal(obj)
}
func (x *RsaSignaturePaddingPolicy) UnmarshalJSON(data []byte) error {
	x.Pss = nil
	x.Pkcs1V15 = nil
	var obj struct {
		Pss      *RsaSignaturePaddingPolicyPss `json:"PSS,omitempty"`
		Pkcs1V15 *struct{}                     `json:"PKCS1_V15,omitempty"`
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

type SecretOptions struct {
}

type Secs = uint64

type SeedOptions struct {
	CipherMode *CipherMode `json:"cipher_mode,omitempty"`
	RandomIv   *bool       `json:"random_iv,omitempty"`
}

// Request body to sign data (or hash value) using an asymmetric key.
type SignRequest struct {
	// Identifier of the sobject used for signing
	Key *SobjectDescriptor `json:"key,omitempty"`
	// Hashing algorithm used for signing
	HashAlg DigestAlgorithm `json:"hash_alg"`
	// Hash value to be signed. Exactly one of `hash` and `data` is required.
	Hash *Blob `json:"hash,omitempty"`
	// Data to be signed. Exactly one of `hash` and `data` is required.
	// To reduce request size and avoid reaching the request size limit, prefer `hash`.
	Data *Blob `json:"data,omitempty"`
	// Signature mechanism
	Mode *SignatureMode `json:"mode,omitempty"`
	// Boolean value to choose deterministic signature
	DeterministicSignature *bool `json:"deterministic_signature,omitempty"`
}

// Response body of sign operation.
type SignResponse struct {
	// UUID of the Key. Key id is returned for non-transient keys.
	Kid *UUID `json:"kid,omitempty"`
	// Signed data
	Signature Blob `json:"signature"`
}

// Signature mechanism
type SignatureMode struct {
	// RSA Signature mechanism with padding
	Rsa *RsaSignaturePadding
}

func (x SignatureMode) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"SignatureMode",
		[]bool{x.Rsa != nil}); err != nil {
		return nil, err
	}
	if x.Rsa != nil {
		return json.Marshal(x.Rsa)
	}
	panic("unreachable")
}
func (x *SignatureMode) UnmarshalJSON(data []byte) error {
	x.Rsa = nil
	var rsa RsaSignaturePadding
	if err := json.Unmarshal(data, &rsa); err == nil {
		x.Rsa = &rsa
		return nil
	}
	return errors.Errorf("not a valid SignatureMode")
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
	// Name of the security object.
	Name *string `json:"name,omitempty"`
	// Whether the security object was exportable at some point in its lifetime.
	NeverExportable *bool `json:"never_exportable,omitempty"`
	// Type of security object.
	ObjType ObjectType `json:"obj_type"`
	// The origin of the security object.
	Origin ObjectOrigin `json:"origin"`
	// Public key material of the security object, if it exists.
	PubKey *Blob `json:"pub_key,omitempty"`
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
	ScheduledRotation *Time `json:"scheduled_rotation,omitempty"`
	// Seed options.
	Seed *SeedOptions `json:"seed,omitempty"`
	// Security object operational state.
	State *SobjectState `json:"state,omitempty"`
	// Transient key material.
	TransientKey *Blob `json:"transient_key,omitempty"`
	// Security object stored as byte array.
	Value *Blob `json:"value,omitempty"`
	// Metadata specific to the virtual key.
	VirtualKeyInfo *VirtualSobjectInfo `json:"virtual_key_info,omitempty"`
	// Group ids of groups that use this security object to encrypt the key material of their security objects
	WrappingKeyGroupIds *[]UUID `json:"wrapping_key_group_ids,omitempty"`
	// UUID of the group which the security object belongs to.
	GroupID *UUID `json:"group_id,omitempty"`
}

// Uniquely identifies a persisted or transient sobject.
type SobjectDescriptor struct {
	Kid          *UUID
	Name         *string
	TransientKey *Blob
	Inline       *SobjectDescriptorInline
}
type SobjectDescriptorInline struct {
	Value   Blob       `json:"value"`
	ObjType ObjectType `json:"obj_type"`
}

func (x SobjectDescriptor) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"SobjectDescriptor",
		[]bool{x.Kid != nil,
			x.Name != nil,
			x.TransientKey != nil,
			x.Inline != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Kid          *UUID                    `json:"kid,omitempty"`
		Name         *string                  `json:"name,omitempty"`
		TransientKey *Blob                    `json:"transient_key,omitempty"`
		Inline       *SobjectDescriptorInline `json:"inline,omitempty"`
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
		Kid          *UUID                    `json:"kid,omitempty"`
		Name         *string                  `json:"name,omitempty"`
		TransientKey *Blob                    `json:"transient_key,omitempty"`
		Inline       *SobjectDescriptorInline `json:"inline,omitempty"`
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
	Schema TepSchema     `json:"schema"`
	KeyMap TepKeyMapList `json:"key_map"`
}

type TepKeyContext string

// List of supported TepKeyContext values
const (
	TepKeyContextRequest  TepKeyContext = "request"
	TepKeyContextResponse TepKeyContext = "response"
)

type TepKeyMap struct {
	Path ApiPath    `json:"path"`
	Kid  UUID       `json:"kid"`
	Mode CipherMode `json:"mode"`
}

type TepKeyMapList = []TepKeyMap

type TepSchema struct {
	OpenAPI **string
}

func (x TepSchema) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"TepSchema",
		[]bool{x.OpenAPI != nil}); err != nil {
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
	Hours   *uint32
	Days    *uint32
}

func (x TimeSpan) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"TimeSpan",
		[]bool{x.Seconds != nil,
			x.Minutes != nil,
			x.Hours != nil,
			x.Days != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Seconds *uint32 `json:"seconds,omitempty"`
		Minutes *uint32 `json:"minutes,omitempty"`
		Hours   *uint32 `json:"hours,omitempty"`
		Days    *uint32 `json:"days,omitempty"`
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
		Hours   *uint32 `json:"hours,omitempty"`
		Days    *uint32 `json:"days,omitempty"`
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

// TLS settings.
type TlsConfig struct {
	Disabled      *struct{}
	Opportunistic *struct{}
	Required      *TlsConfigRequired
}
type TlsConfigRequired struct {
	ValidateHostname bool     `json:"validate_hostname"`
	Ca               CaConfig `json:"ca"`
	ClientKey        *Blob    `json:"client_key,omitempty"`
	ClientCert       *Blob    `json:"client_cert,omitempty"`
}

func (x TlsConfig) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"TlsConfig",
		[]bool{x.Disabled != nil,
			x.Opportunistic != nil,
			x.Required != nil}); err != nil {
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

// Request for second factor authentication with a U2f device.
type U2fAuthRequest struct {
	KeyHandle     Blob `json:"keyHandle"`
	SignatureData Blob `json:"signatureData"`
	ClientData    Blob `json:"clientData"`
}

// A challenge used for multi-factor authentication.
type U2fMfaChallengeResponse struct {
	U2fChallenge string             `json:"u2f_challenge"`
	U2fKeys      []U2fRegisteredKey `json:"u2f_keys"`
}

// Description of a registered U2F device.
type U2fRegisteredKey struct {
	KeyHandle string `json:"keyHandle"`
	Version   string `json:"version"`
}

// User account flag
type UserAccountFlag string

// List of supported UserAccountFlag values
const (
	UserAccountFlagStateEnabled  UserAccountFlag = "STATEENABLED"
	UserAccountFlagPendingInvite UserAccountFlag = "PENDINGINVITE"
)

// User account flag or legacy user account role name or custom role id
type UserAccountFlagOrRole struct {
	Flag       *UserAccountFlag
	LegacyRole *LegacyUserAccountRole
	RoleID     *UUID
}

func (x UserAccountFlagOrRole) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"UserAccountFlagOrRole",
		[]bool{x.Flag != nil,
			x.LegacyRole != nil,
			x.RoleID != nil}); err != nil {
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

// Request to verify a signature using an asymmetric key.
type VerifyRequest struct {
	// Identifier of the sobject used for verification
	Key *SobjectDescriptor `json:"key,omitempty"`
	// Hash algorithm used for verifying signature
	HashAlg DigestAlgorithm `json:"hash_alg"`
	// The hash of the data on which the signature is being verified.
	// Exactly one of `hash` and `data` is required.
	Hash *Blob `json:"hash,omitempty"`
	// The data on which the signature is being verified.
	// Exactly one of `hash` and `data` is required.
	// To reduce request size and avoid reaching the request size limit, prefer `hash`.
	Data *Blob `json:"data,omitempty"`
	// Signature mechanism used for verification
	Mode *SignatureMode `json:"mode,omitempty"`
	// The signature to verify.
	Signature Blob `json:"signature"`
}

// Result of verifying a signature or MAC.
type VerifyResponse struct {
	// Key id is returned for non-transient keys.
	Kid *UUID `json:"kid,omitempty"`
	// True if the signature verified and false if it did not.
	Result bool `json:"result"`
}

// Information specific to a virtual key. Currently, this is only relevant
// for virtual keys backed by DSM.
type VirtualSobjectInfo struct {
	// Whether or not the source key material is cached within the key.
	CachedKeyMaterial bool `json:"cached_key_material"`
}
