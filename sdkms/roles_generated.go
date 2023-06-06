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

type AccountRole struct {
	Permissions AccountPermissions `json:"permissions"`
	Exclusive   *bool              `json:"exclusive,omitempty"`
	// If specified, users with this account role will have the specified role
	// in all groups. The uuid should refer to an existing `Role` of kind
	// `RoleKind::Group`.
	AllGroupsRole *UUID `json:"all_groups_role,omitempty"`
}

type GroupRole struct {
	Permissions GroupPermissions `json:"permissions"`
	Exclusive   *bool            `json:"exclusive,omitempty"`
}

type ListRolesParams struct {
	Filter *string  `json:"filter,omitempty"`
	Limit  *uint    `json:"limit,omitempty"`
	Sort   RoleSort `json:"sort"`
}

func (x ListRolesParams) urlEncode(v map[string][]string) error {
	if x.Filter != nil {
		v["filter"] = []string{fmt.Sprintf("%v", *x.Filter)}
	}
	if x.Limit != nil {
		v["limit"] = []string{fmt.Sprintf("%v", *x.Limit)}
	}
	if err := x.Sort.urlEncode(v); err != nil {
		return err
	}
	return nil
}

type ListRolesResponse struct {
	Metadata Metadata `json:"metadata"`
	Items    []Role   `json:"items"`
}

type Role struct {
	CreatedAt     Time        `json:"created_at"`
	Creator       Principal   `json:"creator"`
	Description   string      `json:"description"`
	Details       RoleDetails `json:"details"`
	Kind          *RoleKind   `json:"kind,omitempty"`
	LastUpdatedAt Time        `json:"last_updated_at"`
	Name          string      `json:"name"`
	RoleID        UUID        `json:"role_id"`
	AcctID        UUID        `json:"acct_id"`
}

type RoleDetails struct {
	Account *AccountRole
	Group   *GroupRole
}

func (x RoleDetails) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"RoleDetails",
		[]bool{x.Account != nil,
			x.Group != nil}); err != nil {
		return nil, err
	}
	m := make(map[string]interface{})
	switch {
	case x.Account != nil:
		b, err := json.Marshal(x.Account)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		m["kind"] = "account"
	case x.Group != nil:
		b, err := json.Marshal(x.Group)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		m["kind"] = "group"
	}
	return json.Marshal(m)
}
func (x *RoleDetails) UnmarshalJSON(data []byte) error {
	x.Account = nil
	x.Group = nil
	var h struct {
		Tag string `json:"kind"`
	}
	if err := json.Unmarshal(data, &h); err != nil {
		return errors.Errorf("not a valid RoleDetails")
	}
	switch h.Tag {
	case "account":
		var account AccountRole
		if err := json.Unmarshal(data, &account); err != nil {
			return err
		}
		x.Account = &account
	case "group":
		var group GroupRole
		if err := json.Unmarshal(data, &group); err != nil {
			return err
		}
		x.Group = &group
	default:
		return errors.Errorf("invalid tag value: %v", h.Tag)
	}
	return nil
}

type RoleKind string

// List of supported RoleKind values
const (
	RoleKindAccount RoleKind = "account"
	RoleKindGroup   RoleKind = "group"
)

type RoleRequest struct {
	Description *string      `json:"description,omitempty"`
	Details     *RoleDetails `json:"details,omitempty"`
	Name        *string      `json:"name,omitempty"`
}

type RoleSort struct {
	ByRoleID *RoleSortByRoleId
}
type RoleSortByRoleId struct {
	Order Order `json:"order"`
	Start *UUID `json:"start,omitempty"`
}

func (x RoleSort) urlEncode(v map[string][]string) error {
	if x.ByRoleID != nil {
		v["sort"] = []string{"role_id" + string(x.ByRoleID.Order)}
		if x.ByRoleID.Start != nil {
			v["start"] = []string{fmt.Sprintf("%v", *x.ByRoleID.Start)}
		}
	}
	return nil
}

// Create a new role.
func (c *Client) CreateRole(ctx context.Context, body RoleRequest) (*Role, error) {
	u := "/sys/v1/roles"
	var r Role
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Delete a role.
func (c *Client) DeleteRole(ctx context.Context, id string) error {
	u := "/sys/v1/roles/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
		return err
	}
	return nil
}

// Lookup a role.
func (c *Client) GetRole(ctx context.Context, id string) (*Role, error) {
	u := "/sys/v1/roles/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r Role
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Get all roles.
func (c *Client) ListRoles(ctx context.Context, queryParameters *ListRolesParams) (*ListRolesResponse, error) {
	u := "/sys/v1/roles"
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	var r ListRolesResponse
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Update a role given by the input ID.
func (c *Client) UpdateRole(ctx context.Context, id string, body RoleRequest) (*Role, error) {
	u := "/sys/v1/roles/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r Role
	if err := c.fetch(ctx, http.MethodPatch, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToUpdateRole(
	ctx context.Context,
	id string,
	body RoleRequest,
	description *string) (*ApprovalRequest, error) {
	u := "/sys/v1/roles/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPatch),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}
