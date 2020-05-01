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

// U2F recovery codes.
type RecoveryCodes struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

// User's role and state in an account.
type UserAccountFlags uint64

// List of supported UserAccountFlags values
const (
	UserAccountFlagsAccountadministrator UserAccountFlags = 1 << iota
	UserAccountFlagsAccountmember
	UserAccountFlagsAccountauditor
	UserAccountFlagsStateenabled
	UserAccountFlagsPendinginvite
)

// MarshalJSON converts UserAccountFlags to an array of strings
func (x UserAccountFlags) MarshalJSON() ([]byte, error) {
	s := make([]string, 0)
	if x&UserAccountFlagsAccountadministrator == UserAccountFlagsAccountadministrator {
		s = append(s, "ACCOUNTADMINISTRATOR")
	}
	if x&UserAccountFlagsAccountmember == UserAccountFlagsAccountmember {
		s = append(s, "ACCOUNTMEMBER")
	}
	if x&UserAccountFlagsAccountauditor == UserAccountFlagsAccountauditor {
		s = append(s, "ACCOUNTAUDITOR")
	}
	if x&UserAccountFlagsStateenabled == UserAccountFlagsStateenabled {
		s = append(s, "STATEENABLED")
	}
	if x&UserAccountFlagsPendinginvite == UserAccountFlagsPendinginvite {
		s = append(s, "PENDINGINVITE")
	}
	return json.Marshal(s)
}

// UnmarshalJSON converts array of strings to UserAccountFlags
func (x *UserAccountFlags) UnmarshalJSON(data []byte) error {
	*x = 0
	var s []string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	for _, v := range s {
		switch v {
		case "ACCOUNTADMINISTRATOR":
			*x = *x | UserAccountFlagsAccountadministrator
		case "ACCOUNTMEMBER":
			*x = *x | UserAccountFlagsAccountmember
		case "ACCOUNTAUDITOR":
			*x = *x | UserAccountFlagsAccountauditor
		case "STATEENABLED":
			*x = *x | UserAccountFlagsStateenabled
		case "PENDINGINVITE":
			*x = *x | UserAccountFlagsPendinginvite
		}
	}
	return nil
}

type User struct {
	AccountRole    UserAccountFlags       `json:"account_role"`
	CreatedAt      *Time                  `json:"created_at,omitempty"`
	Description    *string                `json:"description,omitempty"`
	EmailVerified  *bool                  `json:"email_verified,omitempty"`
	FirstName      *string                `json:"first_name,omitempty"`
	Groups         map[UUID]UserGroupRole `json:"groups"`
	HasPassword    *bool                  `json:"has_password,omitempty"`
	LastLoggedInAt *Time                  `json:"last_logged_in_at,omitempty"`
	LastName       *string                `json:"last_name,omitempty"`
	NewEmail       *string                `json:"new_email,omitempty"`
	U2fDevices     []U2fDevice            `json:"u2f_devices"`
	UserEmail      *string                `json:"user_email,omitempty"`
	UserID         UUID                   `json:"user_id"`
}

type UserRequest struct {
	AccountRole      *UserAccountFlags         `json:"account_role,omitempty"`
	AddGroups        *map[UUID]UserGroupRole   `json:"add_groups,omitempty"`
	AddU2fDevices    *[]U2fAddDeviceRequest    `json:"add_u2f_devices,omitempty"`
	DelGroups        *map[UUID]UserGroupRole   `json:"del_groups,omitempty"`
	DelU2fDevices    *[]U2fDelDeviceRequest    `json:"del_u2f_devices,omitempty"`
	Description      *string                   `json:"description,omitempty"`
	Enable           *bool                     `json:"enable,omitempty"`
	FirstName        *string                   `json:"first_name,omitempty"`
	LastName         *string                   `json:"last_name,omitempty"`
	ModGroups        *map[UUID]UserGroupRole   `json:"mod_groups,omitempty"`
	RenameU2fDevices *[]U2fRenameDeviceRequest `json:"rename_u2f_devices,omitempty"`
	UserEmail        *string                   `json:"user_email,omitempty"`
	UserPassword     *string                   `json:"user_password,omitempty"`
}

// Description of a U2F device to add for two factor authentication.
type U2fAddDeviceRequest struct {
	Name             string `json:"name"`
	RegistrationData Blob   `json:"registrationData"`
	ClientData       Blob   `json:"clientData"`
	Version          string `json:"version"`
}

// Request to rename a U2F device.
type U2fRenameDeviceRequest struct {
	OldName string `json:"old_name"`
	NewName string `json:"new_name"`
}

// Request to delete a U2F device.
type U2fDelDeviceRequest struct {
	Name string `json:"name"`
}

// A U2f device that may be used for second factor authentication.
type U2fDevice struct {
	Name string `json:"name"`
}

// Request to change user's password.
type PasswordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// Accept/reject invitations to join account.
type ProcessInviteRequest struct {
	// Optional list of account IDs to accept.
	Accepts *[]UUID `json:"accepts,omitempty"`
	// Optional list of account IDs to reject.
	Rejects *[]UUID `json:"rejects,omitempty"`
}

// Initiate password reset sequence.
type ForgotPasswordRequest struct {
	UserEmail string `json:"user_email"`
}

// Request to perform a password reset.
type PasswordResetRequest struct {
	ResetToken  string `json:"reset_token"`
	NewPassword string `json:"new_password"`
}

// Request to signup a new user.
type SignupRequest struct {
	UserEmail         string  `json:"user_email"`
	UserPassword      string  `json:"user_password"`
	RecaptchaResponse *string `json:"recaptcha_response,omitempty"`
	FirstName         *string `json:"first_name,omitempty"`
	LastName          *string `json:"last_name,omitempty"`
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

// Create a new user.
func (c *Client) SignupUser(ctx context.Context, body SignupRequest) (*User, error) {
	u := "/sys/v1/users"
	var r User
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Get all users.
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

// Lookup a user by its ID.
func (c *Client) GetUser(ctx context.Context, id string) (*User, error) {
	u := "/sys/v1/users/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r User
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Update a user.
func (c *Client) UpdateUser(ctx context.Context, id string, body UserRequest) (*User, error) {
	u := "/sys/v1/users/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r User
	if err := c.fetch(ctx, http.MethodPatch, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
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

// Initiate password reset sequence for a user.
func (c *Client) ForgotPassword(ctx context.Context, body ForgotPasswordRequest) error {
	u := "/sys/v1/users/forgot_password"
	if err := c.fetch(ctx, http.MethodPost, u, &body, nil); err != nil {
		return err
	}
	return nil
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

// Accept or reject pending account invitations.
func (c *Client) ProcessInvite(ctx context.Context, body ProcessInviteRequest) error {
	u := "/sys/v1/users/process_invite"
	if err := c.fetch(ctx, http.MethodPost, u, &body, nil); err != nil {
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

// Delete a user.
func (c *Client) DeleteUser(ctx context.Context) error {
	u := "/sys/v1/users"
	if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
		return err
	}
	return nil
}

// Change user's password.
func (c *Client) ChangePassword(ctx context.Context, body PasswordChangeRequest) error {
	u := "/sys/v1/users/change_password"
	if err := c.fetch(ctx, http.MethodPost, u, &body, nil); err != nil {
		return err
	}
	return nil
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

// Remove user's association with an account.
func (c *Client) DeleteUserAccount(ctx context.Context, id string) error {
	u := "/sys/v1/users/:id/accounts"
	u = strings.NewReplacer(":id", id).Replace(u)
	if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
		return err
	}
	return nil
}

// Generate recovery codes for two factor authentication.
func (c *Client) GenerateRecoveryCodes(ctx context.Context) (*RecoveryCodes, error) {
	u := "/sys/v1/users/generate_recovery_codes"
	var r RecoveryCodes
	if err := c.fetch(ctx, http.MethodPost, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
