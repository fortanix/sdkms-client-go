/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package sdkms

import (
	"context"
	"net/http"
	"strings"
)

type Group struct {
	AcctID         UUID            `json:"acct_id"`
	ApprovalPolicy *ApprovalPolicy `json:"approval_policy,omitempty"`
	CreatedAt      Time            `json:"created_at"`
	Creator        Principal       `json:"creator"`
	Description    *string         `json:"description,omitempty"`
	GroupID        UUID            `json:"group_id"`
	Name           string          `json:"name"`
}

type GroupRequest struct {
	ApprovalPolicy *ApprovalPolicy `json:"approval_policy,omitempty"`
	Description    *string         `json:"description,omitempty"`
	Name           *string         `json:"name,omitempty"`
}

// Get all groups accessible to the current user.
func (c *Client) ListGroups(ctx context.Context) ([]Group, error) {
	u := "/sys/v1/groups"
	var r []Group
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return r, nil
}

// Lookup a specific group by its ID.
func (c *Client) GetGroup(ctx context.Context, id string) (*Group, error) {
	u := "/sys/v1/groups/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r Group
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Create a new group.
func (c *Client) CreateGroup(ctx context.Context, body GroupRequest) (*Group, error) {
	u := "/sys/v1/groups"
	var r Group
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Update an account.
func (c *Client) UpdateGroup(ctx context.Context, id string, body GroupRequest) (*Group, error) {
	u := "/sys/v1/groups/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r Group
	if err := c.fetch(ctx, http.MethodPatch, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToUpdateGroup(ctx context.Context, id string, body GroupRequest, description *string) (*ApprovalRequest, error) {
	u := "/sys/v1/groups/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPatch),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Delete a group.
func (c *Client) DeleteGroup(ctx context.Context, id string) error {
	u := "/sys/v1/groups/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
		return err
	}
	return nil
}
