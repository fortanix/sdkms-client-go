/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package sdkms

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// This represents the authenticator's response to a client’s request
// for the creation of a new public key credential. It contains
// information about the new credential that can be used to identify
// it for later use, and metadata that can be used by the WebAuthn
// Relying Party to assess the characteristics of the credential during
// registration.
//
// <https://www.w3.org/TR/webauthn-2/#iface-authenticatorattestationresponse>
type AuthenticatorAttestationResponse struct {
	// Base64url of [crate::fido2::models::CollectedClientData] in JSON form.
	ClientDataJson Base64UrlSafe `json:"clientDataJSON"`
	// Values obtained from `AuthenticatorAttestationResponse.getTransports()`.
	// Webauthn spec recommends RP to store it and user them along with
	// `allowCredentials` while authentication ceremony.
	GetTransports *[]AuthenticatorTransport `json:"getTransports,omitempty"`
	// Base64url of the attestation object.
	//
	// See in order:
	// <https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-attestationobject>
	// <https://www.w3.org/TR/webauthn-2/#sctn-attestation>
	// <https://www.w3.org/TR/webauthn-2/#sctn-defined-attestation-formats>
	//
	// Currently, only U2F is supported, others will be rejected.
	AttestationObject Base64UrlSafe `json:"attestationObject"`
}

type ConfirmEmailRequest struct {
	ConfirmToken string `json:"confirm_token"`
}

type ConfirmEmailResponse struct {
	UserEmail string `json:"user_email"`
}

// This contains the request for adding a FIDO device
// to user's data.
// Initially, `POST /sys/v1/session/config_2fa/new_challenge` needs
// to be called with protocol set to `fido2` and using that data,
// `navigator.credentials.create()` is called in the frontend.
// The data returned by `create` is sent in this request. The data
// sent back here creates a new FIDO2 device for the user after
// the payload is verified as per the rules stated in webauthn doc.
type FidoAddDeviceRequest struct {
	// A user friendly name for the device.
	Name string `json:"name"`
	// Result of calling `navigator.credentials.create()` with the
	// data obtained from `new_challenge` API.
	AttestationResult PublicKeyCredentialAuthenticatorAttestationResponse `json:"attestationResult"`
}

// Initiate password reset sequence.
type ForgotPasswordRequest struct {
	UserEmail string `json:"user_email"`
}

type GetUserPermissionsParams struct {
	// If `true`, implied permissions are added in the output. For example, if
	// permission A implies permission B, and the user has permission A, the
	// output will include both A and B if this is set to `true`. If this is
	// set to `false`, B will only be returned if it was assigned to the user
	// directly.
	WithImplied *bool `json:"with_implied,omitempty"`
}

func (x GetUserPermissionsParams) urlEncode(v map[string][]string) error {
	if x.WithImplied != nil {
		v["with_implied"] = []string{fmt.Sprintf("%v", *x.WithImplied)}
	}
	return nil
}

type GetUserPermissionsResponse struct {
	// User's permissions in the account.
	Account AccountPermissions `json:"account"`
	// User's permissions in all groups. Note that this will only be returned
	// if the user has one or more all-groups roles.
	AllGroups *GroupPermissions `json:"all_groups,omitempty"`
	// User's permissions in groups.
	Groups map[UUID]GroupPermissions `json:"groups"`
}

type ListUsersParams struct {
	GroupID *UUID    `json:"group_id,omitempty"`
	AcctID  *UUID    `json:"acct_id,omitempty"`
	Limit   *uint    `json:"limit,omitempty"`
	Offset  *uint    `json:"offset,omitempty"`
	Sort    UserSort `json:"sort"`
}

func (x ListUsersParams) urlEncode(v map[string][]string) error {
	if x.GroupID != nil {
		v["group_id"] = []string{fmt.Sprintf("%v", *x.GroupID)}
	}
	if x.AcctID != nil {
		v["acct_id"] = []string{fmt.Sprintf("%v", *x.AcctID)}
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
	return nil
}

// Request to delete a FIDO device.
type MfaDelDeviceRequest struct {
	// Name of the FIDO device to delete.
	Name string `json:"name"`
}

// A FIDO device that may be used for second factor authentication.
type MfaDevice struct {
	// Name given to the FIDO device.
	Name string `json:"name"`
	// Origin of the FIDO device.
	Origin *string `json:"origin,omitempty"`
}

// Request to rename a FIDO device.
type MfaRenameDeviceRequest struct {
	// Old name of FIDO device.
	OldName string `json:"old_name"`
	// New name of FIDO device.
	NewName string `json:"new_name"`
}

// Request to change user's password.
type PasswordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// Request to perform a password reset.
type PasswordResetRequest struct {
	ResetToken  string `json:"reset_token"`
	NewPassword string `json:"new_password"`
}

// Accept/reject invitations to join account.
type ProcessInviteRequest struct {
	// Optional list of account IDs to accept.
	Accepts *[]UUID `json:"accepts,omitempty"`
	// Optional list of account IDs to reject.
	Rejects *[]UUID `json:"rejects,omitempty"`
}

// U2F recovery codes.
type RecoveryCodes struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

// Request to signup a new user.
type SignupRequest struct {
	UserEmail         string  `json:"user_email"`
	UserPassword      string  `json:"user_password"`
	RecaptchaResponse *string `json:"recaptcha_response,omitempty"`
	FirstName         *string `json:"first_name,omitempty"`
	LastName          *string `json:"last_name,omitempty"`
}

// Description of a U2F device to add for two factor authentication.
type U2fAddDeviceRequest struct {
	Name             string `json:"name"`
	RegistrationData Blob   `json:"registrationData"`
	ClientData       Blob   `json:"clientData"`
	Version          string `json:"version"`
}

type User struct {
	AccountRole   UserAccountFlags `json:"account_role"`
	CreatedAt     *Time            `json:"created_at,omitempty"`
	Description   *string          `json:"description,omitempty"`
	EmailVerified *bool            `json:"email_verified,omitempty"`
	// Explicit group assignments.
	//
	// This is similar to `groups` field except that it does not include groups due to
	// all-groups roles. Use this field to find out which group assignments can be
	// changed using `mod_groups` and `del_groups` fields in user update API.
	ExplicitGroups map[UUID]UserGroupRole `json:"explicit_groups"`
	FirstName      *string                `json:"first_name,omitempty"`
	Groups         map[UUID]UserGroupRole `json:"groups"`
	HasAccount     *bool                  `json:"has_account,omitempty"`
	HasPassword    *bool                  `json:"has_password,omitempty"`
	LastLoggedInAt *Time                  `json:"last_logged_in_at,omitempty"`
	LastName       *string                `json:"last_name,omitempty"`
	// Mfa devices registered with the user
	MfaDevices      []MfaDevice `json:"mfa_devices"`
	NewEmail        *string     `json:"new_email,omitempty"`
	SelfProvisioned *bool       `json:"self_provisioned,omitempty"`
	U2fDevices      []MfaDevice `json:"u2f_devices"`
	UserEmail       *string     `json:"user_email,omitempty"`
	UserID          UUID        `json:"user_id"`
}

type UserRequest struct {
	AccountRole *UserAccountFlags       `json:"account_role,omitempty"`
	AddGroups   *map[UUID]UserGroupRole `json:"add_groups,omitempty"`
	// FIDO devices to add. Only one device can be added at present.
	AddMfaDevices *[]FidoAddDeviceRequest `json:"add_mfa_devices,omitempty"`
	AddU2fDevices *[]U2fAddDeviceRequest  `json:"add_u2f_devices,omitempty"`
	DelGroups     *map[UUID]UserGroupRole `json:"del_groups,omitempty"`
	// Mfa devices to delete
	DelMfaDevices *[]MfaDelDeviceRequest  `json:"del_mfa_devices,omitempty"`
	DelU2fDevices *[]MfaDelDeviceRequest  `json:"del_u2f_devices,omitempty"`
	Description   *string                 `json:"description,omitempty"`
	Enable        *bool                   `json:"enable,omitempty"`
	FirstName     *string                 `json:"first_name,omitempty"`
	LastName      *string                 `json:"last_name,omitempty"`
	ModGroups     *map[UUID]UserGroupRole `json:"mod_groups,omitempty"`
	// Mfa devices to rename
	RenameMfaDevices *[]MfaRenameDeviceRequest `json:"rename_mfa_devices,omitempty"`
	RenameU2fDevices *[]MfaRenameDeviceRequest `json:"rename_u2f_devices,omitempty"`
	UserEmail        *string                   `json:"user_email,omitempty"`
	UserPassword     *string                   `json:"user_password,omitempty"`
}

type UserSort struct {
	ByUserID *UserSortByUserId
}
type UserSortByUserId struct {
	Order Order `json:"order"`
	Start *UUID `json:"start,omitempty"`
}

func (x UserSort) urlEncode(v map[string][]string) error {
	if x.ByUserID != nil {
		v["sort"] = []string{"user_id" + string(x.ByUserID.Order)}
		if x.ByUserID.Start != nil {
			v["start"] = []string{fmt.Sprintf("%v", *x.ByUserID.Start)}
		}
	}
	return nil
}

type ValidateTokenRequest struct {
	ResetToken string `json:"reset_token"`
}

type ValidateTokenResponse struct {
	UserEmail string `json:"user_email"`
}

// Change user's password.
func (c *Client) ChangePassword(ctx context.Context, body PasswordChangeRequest) error {
	u := "/sys/v1/users/change_password"
	if err := c.fetch(ctx, http.MethodPost, u, &body, nil); err != nil {
		return err
	}
	return nil
}

// Confirms user's email address.
func (c *Client) ConfirmEmail(ctx context.Context, id string, body ConfirmEmailRequest) (*ConfirmEmailResponse, error) {
	u := "/sys/v1/users/:id/confirm_email"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r ConfirmEmailResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Delete a stale user (for sysadmins).
func (c *Client) DeleteStale(ctx context.Context, id string) error {
	u := "/sys/v1/users/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
		return err
	}
	return nil
}

// Delete the currently logged-in user.
func (c *Client) DeleteUser(ctx context.Context) error {
	u := "/sys/v1/users"
	if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
		return err
	}
	return nil
}

// Remove user's association with an account.
func (c *Client) DeleteUserAccount(ctx context.Context, id string) error {
	u := "/sys/v1/users/:id/accounts"
	u = strings.NewReplacer(":id", id).Replace(u)
	if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
		return err
	}
	return nil
}

// Initiate password reset sequence for a user.
func (c *Client) ForgotPassword(ctx context.Context, body ForgotPasswordRequest) error {
	u := "/sys/v1/users/forgot_password"
	if err := c.fetch(ctx, http.MethodPost, u, &body, nil); err != nil {
		return err
	}
	return nil
}

// Generate recovery codes for two factor authentication.
//
// Generate backup recovery codes that may be used to complete two
// factor authentication. Two factor configuration must be unlocked
// to use this API.
func (c *Client) GenerateRecoveryCodes(ctx context.Context) (*RecoveryCodes, error) {
	u := "/sys/v1/users/generate_recovery_codes"
	var r RecoveryCodes
	if err := c.fetch(ctx, http.MethodPost, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Lookup a user.
func (c *Client) GetUser(ctx context.Context, id string) (*User, error) {
	u := "/sys/v1/users/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r User
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Get user's accounts.
func (c *Client) GetUserAccounts(ctx context.Context) (map[UUID]UserAccountFlags, error) {
	u := "/sys/v1/users/accounts"
	var r map[UUID]UserAccountFlags
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return r, nil
}

// Returns the caller's permissions
func (c *Client) GetUserPermissions(ctx context.Context, queryParameters *GetUserPermissionsParams) (*GetUserPermissionsResponse, error) {
	u := "/sys/v1/users/permissions"
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	var r GetUserPermissionsResponse
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Invite an existing user or new user to join an existing account.
func (c *Client) InviteUser(ctx context.Context, body UserRequest) (*User, error) {
	u := "/sys/v1/users/invite"
	var r User
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Get all users accessible to the requester.
func (c *Client) ListUsers(ctx context.Context, queryParameters *ListUsersParams) ([]User, error) {
	u := "/sys/v1/users"
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	var r []User
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return r, nil
}

// Accept or reject pending account invitations.
func (c *Client) ProcessInvite(ctx context.Context, body ProcessInviteRequest) error {
	u := "/sys/v1/users/process_invite"
	if err := c.fetch(ctx, http.MethodPost, u, &body, nil); err != nil {
		return err
	}
	return nil
}

// Resend email with link to confirm user's email address.
func (c *Client) ResendConfirmEmail(ctx context.Context) error {
	u := "/sys/v1/users/resend_confirm_email"
	if err := c.fetch(ctx, http.MethodPost, u, nil, nil); err != nil {
		return err
	}
	return nil
}

// Resend invite to the user to join a specific account.
func (c *Client) ResendInvite(ctx context.Context, id string) error {
	u := "/sys/v1/users/:id/resend_invite"
	u = strings.NewReplacer(":id", id).Replace(u)
	if err := c.fetch(ctx, http.MethodPost, u, nil, nil); err != nil {
		return err
	}
	return nil
}

// Reset a user's password. Requires a valid password reset token.
func (c *Client) ResetPassword(ctx context.Context, id string, body PasswordResetRequest) error {
	u := "/sys/v1/users/:id/reset_password"
	u = strings.NewReplacer(":id", id).Replace(u)
	if err := c.fetch(ctx, http.MethodPost, u, &body, nil); err != nil {
		return err
	}
	return nil
}

// Create a new user with the given properties.
func (c *Client) SignupUser(ctx context.Context, body SignupRequest) (*User, error) {
	u := "/sys/v1/users"
	var r User
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Change a user's properties like first_name, last_name,
// description, etc.
func (c *Client) UpdateUser(ctx context.Context, id string, body UserRequest) (*User, error) {
	u := "/sys/v1/users/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r User
	if err := c.fetch(ctx, http.MethodPatch, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Validates password reset token for the user.
func (c *Client) ValidateToken(ctx context.Context, id string, body ValidateTokenRequest) (*ValidateTokenResponse, error) {
	u := "/sys/v1/users/:id/validate_token"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r ValidateTokenResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
