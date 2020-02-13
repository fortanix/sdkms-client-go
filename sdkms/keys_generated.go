package sdkms

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

type SobjectRequest struct {
	ActivationDate          *Time                   `json:"activation_date,omitempty"`
	CustomMetadata          *map[string]string      `json:"custom_metadata,omitempty"`
	DeactivationDate        *Time                   `json:"deactivation_date,omitempty"`
	Description             *string                 `json:"description,omitempty"`
	DeterministicSignatures *bool                   `json:"deterministic_signatures,omitempty"`
	EllipticCurve           *EllipticCurve          `json:"elliptic_curve,omitempty"`
	Enabled                 *bool                   `json:"enabled,omitempty"`
	Fpe                     *FpeOptions             `json:"fpe,omitempty"`
	KeyOps                  *KeyOperations          `json:"key_ops,omitempty"`
	KeySize                 *uint32                 `json:"key_size,omitempty"`
	Name                    *string                 `json:"name,omitempty"`
	ObjType                 *ObjectType             `json:"obj_type,omitempty"`
	PubExponent             *uint32                 `json:"pub_exponent,omitempty"`
	PublishPublicKey        *PublishPublicKeyConfig `json:"publish_public_key,omitempty"`
	Rsa                     *RsaOptions             `json:"rsa,omitempty"`
	State                   *SobjectState           `json:"state,omitempty"`
	Transient               *bool                   `json:"transient,omitempty"`
	Value                   *Blob                   `json:"value,omitempty"`
	GroupID                 *UUID                   `json:"group_id,omitempty"`
}

// Request to compute digest of a key.
type ObjectDigestRequest struct {
	Key SobjectDescriptor `json:"key"`
	Alg DigestAlgorithm   `json:"alg"`
}

// Digest of a key.
type ObjectDigestResponse struct {
	Kid    *UUID `json:"kid,omitempty"`
	Digest Blob  `json:"digest"`
}

// Request to persist a transient key.
type PersistTransientKeyRequest struct {
	ActivationDate   *Time `json:"activation_date,omitempty"`
	DeactivationDate *Time `json:"deactivation_date,omitempty"`
	// Name of the persisted security object. Security object names must be unique within an account.
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	// User-defined metadata for the persisted key stored as key-value pairs.
	CustomMetadata *map[string]string `json:"custom_metadata,omitempty"`
	// Whether the new security object should be enabled. Disabled security objects may not perform cryptographic operations.
	Enabled *bool `json:"enabled,omitempty"`
	// Group ID of the security group that the persisted key should belong to. The user or
	// application creating this security object must be a member of this group. If no group is
	// specified, the default group for the requesting application will be used.
	GroupID *UUID         `json:"group_id,omitempty"`
	State   *SobjectState `json:"state,omitempty"`
	// Transient key to persist.
	TransientKey Blob `json:"transient_key"`
}

type ListSobjectsParams struct {
	GroupID *UUID       `json:"group_id,omitempty"`
	Creator *UUID       `json:"creator,omitempty"`
	Name    *string     `json:"name,omitempty"`
	Limit   *uint       `json:"limit,omitempty"`
	Offset  *uint       `json:"offset,omitempty"`
	Sort    SobjectSort `json:"sort"`
}

func (x ListSobjectsParams) urlEncode(v map[string][]string) error {
	if x.GroupID != nil {
		v["group_id"] = []string{fmt.Sprintf("%v", *x.GroupID)}
	}
	if x.Creator != nil {
		v["creator"] = []string{fmt.Sprintf("%v", *x.Creator)}
	}
	if x.Name != nil {
		v["name"] = []string{fmt.Sprintf("%v", *x.Name)}
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

type GetSobjectParams struct {
	View SobjectEncoding `json:"view"`
}

func (x GetSobjectParams) urlEncode(v map[string][]string) error {
	v["view"] = []string{fmt.Sprintf("%v", x.View)}
	return nil
}

type SobjectEncoding string

// List of supported SobjectEncoding values
const (
	SobjectEncodingJson  SobjectEncoding = "json"
	SobjectEncodingValue SobjectEncoding = "value"
)

type SobjectSort struct {
	ByKid  *SobjectSortByKid
	ByName *SobjectSortByName
}
type SobjectSortByKid struct {
	Order Order `json:"order"`
	Start *UUID `json:"start,omitempty"`
}
type SobjectSortByName struct {
	Order Order   `json:"order"`
	Start *string `json:"start,omitempty"`
}

func (x SobjectSort) urlEncode(v map[string][]string) error {
	if x.ByKid != nil && x.ByName != nil {
		return errors.New("SobjectSort can be either ByKid or ByName")
	}
	if x.ByKid != nil {
		v["sort"] = []string{"kid" + string(x.ByKid.Order)}
		if x.ByKid.Start != nil {
			v["start"] = []string{fmt.Sprintf("%v", *x.ByKid.Start)}
		}
	}
	if x.ByName != nil {
		v["sort"] = []string{"name" + string(x.ByName.Order)}
		if x.ByName.Start != nil {
			v["start"] = []string{fmt.Sprintf("%v", *x.ByName.Start)}
		}
	}
	return nil
}

// Generate a new security object.
func (c *Client) CreateSobject(ctx context.Context, body SobjectRequest) (*Sobject, error) {
	u := "/crypto/v1/keys"
	var r Sobject
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Import a security object.
func (c *Client) ImportSobject(ctx context.Context, body SobjectRequest) (*Sobject, error) {
	u := "/crypto/v1/keys"
	var r Sobject
	if err := c.fetch(ctx, http.MethodPut, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Update a security object.
func (c *Client) UpdateSobject(ctx context.Context, id string, body SobjectRequest) (*Sobject, error) {
	u := "/crypto/v1/keys/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r Sobject
	if err := c.fetch(ctx, http.MethodPatch, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToUpdateSobject(ctx context.Context, id string, body SobjectRequest, description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/keys/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPatch),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Delete a security object.
func (c *Client) DeleteSobject(ctx context.Context, id string) error {
	u := "/crypto/v1/keys/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
		return err
	}
	return nil
}

func (c *Client) RequestApprovalToDeleteSobject(ctx context.Context, id string, description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/keys/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodDelete),
		Operation:   &u,
		Body:        nil,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Get all security objects accessible to the currently authenticated entity (user or app).
func (c *Client) ListSobjects(ctx context.Context, queryParameters ListSobjectsParams) ([]Sobject, error) {
	u := "/crypto/v1/keys"
	q, err := encodeURLParams(&queryParameters)
	if err != nil {
		return nil, err
	}
	u = fmt.Sprintf("%v?%v", u, q)
	var r []Sobject
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return r, nil
}

// Lookup a security object by its ID or name.
func (c *Client) GetSobject(ctx context.Context, queryParameters GetSobjectParams, body SobjectDescriptor) (*Sobject, error) {
	u := "/crypto/v1/keys/info"
	q, err := encodeURLParams(&queryParameters)
	if err != nil {
		return nil, err
	}
	u = fmt.Sprintf("%v?%v", u, q)
	var r Sobject
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Destroy private half of an asymmetric key.
func (c *Client) RemovePrivate(ctx context.Context, id string) error {
	u := "/crypto/v1/keys/:id/private"
	u = strings.NewReplacer(":id", id).Replace(u)
	if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
		return err
	}
	return nil
}

// Retrieve the value of an exportable security object.
func (c *Client) ExportSobject(ctx context.Context, body SobjectDescriptor) (*Sobject, error) {
	u := "/crypto/v1/keys/export"
	var r Sobject
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToExportSobject(ctx context.Context, body SobjectDescriptor, description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/keys/export"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Retrieve the digest (hash) of the value of an exportable security object.
func (c *Client) DigestSobject(ctx context.Context, body ObjectDigestRequest) (*ObjectDigestResponse, error) {
	u := "/crypto/v1/keys/digest"
	var r ObjectDigestResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Persist a transient key.
func (c *Client) PersistTransientKey(ctx context.Context, body PersistTransientKeyRequest) (*Sobject, error) {
	u := "/crypto/v1/keys/persist"
	var r Sobject
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Rotate a security object.
func (c *Client) RotateSobject(ctx context.Context, body SobjectRequest) (*Sobject, error) {
	u := "/crypto/v1/keys/rekey"
	var r Sobject
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Transition a security object to Active state.
func (c *Client) ActivateSobject(ctx context.Context, id string) error {
	u := "/crypto/v1/keys/:id/activate"
	u = strings.NewReplacer(":id", id).Replace(u)
	if err := c.fetch(ctx, http.MethodPost, u, nil, nil); err != nil {
		return err
	}
	return nil
}

// Transition a security object to Deactivated or Compromised state.
func (c *Client) RevokeSobject(ctx context.Context, id string, body RevocationReason) error {
	u := "/crypto/v1/keys/:id/revoke"
	u = strings.NewReplacer(":id", id).Replace(u)
	if err := c.fetch(ctx, http.MethodPost, u, &body, nil); err != nil {
		return err
	}
	return nil
}

// Batch sign with one or more private keys.
func (c *Client) BatchSign(ctx context.Context, body []SignRequest) ([]BatchSignResponseItem, error) {
	u := "/crypto/v1/keys/batch/sign"
	var r []BatchSignResponseItem
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return r, nil
}

func (c *Client) RequestApprovalToBatchSign(ctx context.Context, body []SignRequest, description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/keys/batch/sign"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Batch verify with one or more public keys.
func (c *Client) BatchVerify(ctx context.Context, body []VerifyRequest) ([]BatchVerifyResponseItem, error) {
	u := "/crypto/v1/keys/batch/verify"
	var r []BatchVerifyResponseItem
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return r, nil
}
