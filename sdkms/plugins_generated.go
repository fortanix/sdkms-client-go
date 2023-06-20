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

// Language of plugin code.
type Language string

// List of supported Language values
const (
	LanguageLua Language = "LUA"
)

// Query parameters to get Plugins.
type ListPluginsParams struct {
	// Group for which the associated plugins should be retrived.
	GroupID *UUID `json:"group_id,omitempty"`
	// Maximum number of entries to return.
	Limit *uint `json:"limit,omitempty"`
	// Starting offset.
	Offset *uint `json:"offset,omitempty"`
	// Sort plugins in ascending or descending order by Plugin Id.
	Sort PluginSort `json:"sort"`
}

func (x ListPluginsParams) urlEncode(v map[string][]string) error {
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
	return nil
}

type Plugin struct {
	// The id of the Account that the plugin belongs to.
	AcctID UUID `json:"acct_id"`
	// Timestamp when the plugin was created.
	CreatedAt Time `json:"created_at"`
	// Creator of the plugin.
	Creator Principal `json:"creator"`
	// The default group a plugin belongs to.
	DefaultGroup UUID `json:"default_group"`
	// Description of the plugin.
	Description *string `json:"description,omitempty"`
	// Is plugin enabled.
	Enabled bool `json:"enabled"`
	// Timestamp when the plugin was most recently used.
	LastrunAt *Time `json:"lastrun_at,omitempty"`
	// Timestamp when the plugin was most recently updated.
	LastupdatedAt Time `json:"lastupdated_at"`
	// If a requester is updating/using a Plugin they must have the relevant
	// permissions in all Groups that Plugin has access to. But for legacy Plugins,
	// the requester is required to have relevant permissions in any one of the groups
	// that Plugin has access to.
	LegacyAccess bool `json:"legacy_access"`
	// Name of the plugin, which must be unique within an account.
	Name string `json:"name"`
	// Unique id to identify a plugin.
	PluginID UUID `json:"plugin_id"`
	// Type of plugin.
	PluginType PluginType `json:"plugin_type"`
	// Source of plugin. It contains language & source code of plugin. In case of marketplace plugin repo_url & version as well
	Source PluginSource `json:"source"`
	// Set of all the groups that plugin is part of.
	Groups []UUID `json:"groups"`
}

type PluginRequest struct {
	// The default group a plugin belongs to.
	DefaultGroup *UUID `json:"default_group,omitempty"`
	// Description of the plugin.
	Description *string `json:"description,omitempty"`
	// Is plugin enabled.
	Enabled *bool `json:"enabled,omitempty"`
	// Name of the plugin, which must be unique within an account.
	Name *string `json:"name,omitempty"`
	// Type of plugin.
	PluginType *PluginType `json:"plugin_type,omitempty"`
	// Request to get source of plugin.
	SourceReq *PluginSourceRequest `json:"source,omitempty"`
	// Set of all the groups that plugin is part of.
	AddGroups *[]UUID `json:"add_groups,omitempty"`
	// Set of all the groups that plugin is part of.
	DelGroups *[]UUID `json:"del_groups,omitempty"`
	// Set of all the groups that plugin is part of.
	ModGroups *[]UUID `json:"mod_groups,omitempty"`
}

// Sorting order on listed Plugins.
type PluginSort struct {
	// Sort plugins by Plugin Id.
	ByPluginID *PluginSortByPluginId
}

// Sort plugins by Plugin Id.
type PluginSortByPluginId struct {
	// Order of sorting(Ascending/Descending).
	Order Order `json:"order"`
	// Starting offset(UUID of plugin).
	Start *UUID `json:"start,omitempty"`
}

func (x PluginSort) urlEncode(v map[string][]string) error {
	if x.ByPluginID != nil {
		v["sort"] = []string{"plugin_id" + string(x.ByPluginID.Order)}
		if x.ByPluginID.Start != nil {
			v["start"] = []string{fmt.Sprintf("%v", *x.ByPluginID.Start)}
		}
	}
	return nil
}

// Plugin code that will be executed inside SGX enclave.
type PluginSource struct {
	FromRepo *PluginSourceFromRepo
	Inline   *PluginSourceInline
}
type PluginSourceFromRepo struct {
	RepoURL  string        `json:"repo_url"`
	Name     string        `json:"name"`
	Version  PluginVersion `json:"version"`
	Language Language      `json:"language"`
	Code     string        `json:"code"`
}
type PluginSourceInline struct {
	Language Language `json:"language"`
	Code     string   `json:"code"`
}

func (x PluginSource) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"PluginSource",
		[]bool{x.FromRepo != nil,
			x.Inline != nil}); err != nil {
		return nil, err
	}
	if x.FromRepo != nil {
		return json.Marshal(x.FromRepo)
	}
	if x.Inline != nil {
		return json.Marshal(x.Inline)
	}
	panic("unreachable")
}
func (x *PluginSource) UnmarshalJSON(data []byte) error {
	x.FromRepo = nil
	x.Inline = nil
	var fromRepo PluginSourceFromRepo
	if err := json.Unmarshal(data, &fromRepo); err == nil {
		x.FromRepo = &fromRepo
		return nil
	}
	var inline PluginSourceInline
	if err := json.Unmarshal(data, &inline); err == nil {
		x.Inline = &inline
		return nil
	}
	return errors.Errorf("not a valid PluginSource")
}

type PluginSourceRequest struct {
	FromRepo *PluginSourceRequestFromRepo
	Inline   *PluginSourceRequestInline
}
type PluginSourceRequestFromRepo struct {
	RepoURL    string        `json:"repo_url"`
	PluginName string        `json:"plugin_name"`
	Version    PluginVersion `json:"version"`
}
type PluginSourceRequestInline struct {
	Language Language `json:"language"`
	Code     string   `json:"code"`
}

func (x PluginSourceRequest) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"PluginSourceRequest",
		[]bool{x.FromRepo != nil,
			x.Inline != nil}); err != nil {
		return nil, err
	}
	if x.FromRepo != nil {
		return json.Marshal(x.FromRepo)
	}
	if x.Inline != nil {
		return json.Marshal(x.Inline)
	}
	panic("unreachable")
}
func (x *PluginSourceRequest) UnmarshalJSON(data []byte) error {
	x.FromRepo = nil
	x.Inline = nil
	var fromRepo PluginSourceRequestFromRepo
	if err := json.Unmarshal(data, &fromRepo); err == nil {
		x.FromRepo = &fromRepo
		return nil
	}
	var inline PluginSourceRequestInline
	if err := json.Unmarshal(data, &inline); err == nil {
		x.Inline = &inline
		return nil
	}
	return errors.Errorf("not a valid PluginSourceRequest")
}

// Type of a plugin.
type PluginType string

// List of supported PluginType values
const (
	PluginTypeStandard        PluginType = "STANDARD"
	PluginTypeImpersonating   PluginType = "IMPERSONATING"
	PluginTypeCustomAlgorithm PluginType = "CUSTOMALGORITHM"
)

// Create a new plugin.
func (c *Client) CreatePlugin(ctx context.Context, body PluginRequest) (*Plugin, error) {
	u := "/sys/v1/plugins"
	var r Plugin
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToCreatePlugin(
	ctx context.Context,
	body PluginRequest,
	description *string) (*ApprovalRequest, error) {
	u := "/sys/v1/plugins"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Delete a plugin.
func (c *Client) DeletePlugin(ctx context.Context, id string) error {
	u := "/sys/v1/plugins/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
		return err
	}
	return nil
}

// Lookup a plugin.
func (c *Client) GetPlugin(ctx context.Context, id string) (*Plugin, error) {
	u := "/sys/v1/plugins/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r Plugin
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Invokes a plugin execution with the provided request body
// as input to the plugin.
func (c *Client) InvokePlugin(ctx context.Context, id string, body interface{}) (*PluginOutput, error) {
	u := "/sys/v1/plugins/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r PluginOutput
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToInvokePlugin(
	ctx context.Context,
	id string,
	body interface{},
	description *string) (*ApprovalRequest, error) {
	u := "/sys/v1/plugins/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Get details of all plugins accessible to the requester.
func (c *Client) ListPlugins(ctx context.Context, queryParameters *ListPluginsParams) ([]Plugin, error) {
	u := "/sys/v1/plugins"
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	var r []Plugin
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return r, nil
}

// Change a plugin's properties, such as name, description,
// code, group membership, etc.
func (c *Client) UpdatePlugin(ctx context.Context, id string, body PluginRequest) (*Plugin, error) {
	u := "/sys/v1/plugins/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r Plugin
	if err := c.fetch(ctx, http.MethodPatch, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToUpdatePlugin(
	ctx context.Context,
	id string,
	body PluginRequest,
	description *string) (*ApprovalRequest, error) {
	u := "/sys/v1/plugins/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPatch),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}
