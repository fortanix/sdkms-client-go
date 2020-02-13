package sdkms

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

// Type of a plugin.
type PluginType string

// List of supported PluginType values
const (
	PluginTypeStandard        PluginType = "STANDARD"
	PluginTypeImpersonating   PluginType = "IMPERSONATING"
	PluginTypeCustomAlgorithm PluginType = "CUSTOMALGORITHM"
)

// Language of plugin code.
type Language string

// List of supported Language values
const (
	LanguageLua Language = "LUA"
)

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
	if err := checkEnumPointers("PluginSourceRequest", []bool{x.FromRepo != nil, x.Inline != nil}); err != nil {
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
	if err := checkEnumPointers("PluginSource", []bool{x.FromRepo != nil, x.Inline != nil}); err != nil {
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

type PluginVersion struct {
	Major uint32 `json:"major"`
	Minor uint32 `json:"minor"`
}

type Plugin struct {
	AcctID        UUID         `json:"acct_id"`
	CreatedAt     Time         `json:"created_at"`
	Creator       Principal    `json:"creator"`
	DefaultGroup  UUID         `json:"default_group"`
	Description   *string      `json:"description,omitempty"`
	Enabled       bool         `json:"enabled"`
	LastrunAt     *Time        `json:"lastrun_at,omitempty"`
	LastupdatedAt Time         `json:"lastupdated_at"`
	Name          string       `json:"name"`
	PluginID      UUID         `json:"plugin_id"`
	PluginType    PluginType   `json:"plugin_type"`
	Source        PluginSource `json:"source"`
	Groups        []UUID       `json:"groups"`
}

type PluginRequest struct {
	DefaultGroup *UUID                `json:"default_group,omitempty"`
	Description  *string              `json:"description,omitempty"`
	Enabled      *bool                `json:"enabled,omitempty"`
	Name         *string              `json:"name,omitempty"`
	PluginType   *PluginType          `json:"plugin_type,omitempty"`
	SourceReq    *PluginSourceRequest `json:"source,omitempty"`
	AddGroups    *[]UUID              `json:"add_groups,omitempty"`
	DelGroups    *[]UUID              `json:"del_groups,omitempty"`
	ModGroups    *[]UUID              `json:"mod_groups,omitempty"`
}

type ListPluginsParams struct {
	GroupID *UUID      `json:"group_id,omitempty"`
	Limit   *uint      `json:"limit,omitempty"`
	Offset  *uint      `json:"offset,omitempty"`
	Sort    PluginSort `json:"sort"`
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

type PluginSort struct {
	ByPluginID *PluginSortByPluginId
}
type PluginSortByPluginId struct {
	Order Order `json:"order"`
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

// Get all plugins.
func (c *Client) ListPlugins(ctx context.Context, queryParameters ListPluginsParams) ([]Plugin, error) {
	u := "/sys/v1/plugins"
	q, err := encodeURLParams(&queryParameters)
	if err != nil {
		return nil, err
	}
	u = fmt.Sprintf("%v?%v", u, q)
	var r []Plugin
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return r, nil
}

// Lookup a plugin by its ID.
func (c *Client) GetPlugin(ctx context.Context, id string) (*Plugin, error) {
	u := "/sys/v1/plugins/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r Plugin
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Create a plugin.
func (c *Client) CreatePlugin(ctx context.Context, body PluginRequest) (*Plugin, error) {
	u := "/sys/v1/plugins"
	var r Plugin
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToCreatePlugin(ctx context.Context, body PluginRequest, description *string) (*ApprovalRequest, error) {
	u := "/sys/v1/plugins"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Update a plugin.
func (c *Client) UpdatePlugin(ctx context.Context, id string, body PluginRequest) (*Plugin, error) {
	u := "/sys/v1/plugins/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r Plugin
	if err := c.fetch(ctx, http.MethodPatch, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToUpdatePlugin(ctx context.Context, id string, body PluginRequest, description *string) (*ApprovalRequest, error) {
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

// Delete a plugin.
func (c *Client) DeletePlugin(ctx context.Context, id string) error {
	u := "/sys/v1/plugins/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
		return err
	}
	return nil
}

// Invoke a plugin.
func (c *Client) InvokePlugin(ctx context.Context, id string, body interface{}) (*PluginOutput, error) {
	u := "/sys/v1/plugins/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r PluginOutput
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToInvokePlugin(ctx context.Context, id string, body interface{}, description *string) (*ApprovalRequest, error) {
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
