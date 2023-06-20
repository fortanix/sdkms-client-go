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

type ExternalRole struct {
	ExternalRoleID UUID                         `json:"external_role_id"`
	Groups         map[UUID]ExternalRoleMapping `json:"groups"`
	Kind           ExternalRoleKind             `json:"kind"`
	LastSynced     Time                         `json:"last_synced"`
	Name           string                       `json:"name"`
	SourceID       UUID                         `json:"source_id"`
	AcctID         UUID                         `json:"acct_id"`
}

// Type of an external role.
type ExternalRoleKind string

// List of supported ExternalRoleKind values
const (
	ExternalRoleKindLdapGroup ExternalRoleKind = "ldap-group"
)

type ExternalRoleMapping struct {
	Users *UserGroupRole  `json:"users,omitempty"`
	Apps  *AppPermissions `json:"apps,omitempty"`
}

type ExternalRoleRequest struct {
	AddGroups *map[UUID]ExternalRoleMapping `json:"add_groups,omitempty"`
	DelGroups *[]UUID                       `json:"del_groups,omitempty"`
	Kind      *ExternalRoleKind             `json:"kind,omitempty"`
	ModGroups *map[UUID]ExternalRoleMapping `json:"mod_groups,omitempty"`
	Name      *string                       `json:"name,omitempty"`
	SourceID  *UUID                         `json:"source_id,omitempty"`
}

type ListExternalRolesParams struct {
	GroupID *UUID `json:"group_id,omitempty"`
}

func (x ListExternalRolesParams) urlEncode(v map[string][]string) error {
	if x.GroupID != nil {
		v["group_id"] = []string{fmt.Sprintf("%v", *x.GroupID)}
	}
	return nil
}

// Create a new external role.
func (c *Client) CreateExternalRole(ctx context.Context, body ExternalRoleRequest) (*ExternalRole, error) {
	u := "/sys/v1/external_roles"
	var r ExternalRole
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Delete an external role.
func (c *Client) DeleteExternalRole(ctx context.Context, id string) error {
	u := "/sys/v1/external_roles/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
		return err
	}
	return nil
}

// Lookup a particular external role by its ID.
func (c *Client) GetExternalRole(ctx context.Context, id string) (*ExternalRole, error) {
	u := "/sys/v1/external_roles/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r ExternalRole
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Get all external roles.
func (c *Client) ListExternalRoles(ctx context.Context, queryParameters *ListExternalRolesParams) ([]ExternalRole, error) {
	u := "/sys/v1/external_roles"
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	var r []ExternalRole
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return r, nil
}

// Synchronize information about the external role by retrieving it from external source.
func (c *Client) SyncExternalRole(ctx context.Context, id string) (*ExternalRole, error) {
	u := "/sys/v1/external_roles/:id/sync"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r ExternalRole
	if err := c.fetch(ctx, http.MethodPost, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Update an external role.
func (c *Client) UpdateExternalRole(ctx context.Context, id string, body ExternalRoleRequest) (*ExternalRole, error) {
	u := "/sys/v1/external_roles/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r ExternalRole
	if err := c.fetch(ctx, http.MethodPatch, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
