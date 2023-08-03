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

// Request to copy a security object.
type CopySobjectRequest struct {
	// Unique identifier of the security object to be copied.
	Key SobjectDescriptor `json:"key"`
	// Properties for the new security object.
	Dest SobjectRequest `json:"dest"`
}

func (x CopySobjectRequest) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	{ // x.Dest is flattened
		b, err := json.Marshal(&x.Dest)
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
	m["key"] = x.Key
	return json.Marshal(&m)
}
func (x *CopySobjectRequest) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &x.Dest); err != nil {
		return err
	}
	var r struct {
		Key SobjectDescriptor `json:"key"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	x.Key = r.Key
	return nil
}

// Export security object by components response.
type ExportComponentsResponse struct {
	// Key components
	Components []SobjectComponent `json:"components"`
	// Initialization vector
	Iv *Blob `json:"iv,omitempty"`
	// Tag, if required by the encryption mode.
	Tag *Blob `json:"tag,omitempty"`
	// KCV for the exported key
	KeyKcv *string `json:"key_kcv,omitempty"`
	// Description of the exported key
	Description *string `json:"description,omitempty"`
}

// Request to Export a security object by components
type ExportSobjectComponentsRequest struct {
	// Unique identifier of the security object
	Key SobjectDescriptor `json:"key"`
	// Details of wrapping key
	WrapKeyParams *WrapKeyParams `json:"wrap_key_params,omitempty"`
	// Key holder identifier
	Custodians []Principal `json:"custodians"`
	// Splitting method
	Method *SplittingMethod `json:"method,omitempty"`
	// Description of the exported security object
	Description *string `json:"description,omitempty"`
}

// Parameters to show sobject details.
type GetSobjectParams struct {
	// Response data encoding
	View *SobjectEncoding `json:"view,omitempty"`
	// Show destroyed security object(s).
	ShowDestroyed *bool `json:"show_destroyed,omitempty"`
	// Show deleted security object(s).
	ShowDeleted *bool `json:"show_deleted,omitempty"`
	// Show value of security object(s).
	ShowValue *bool `json:"show_value,omitempty"`
	// Show public key of security objects(s) if present.
	ShowPubKey *bool `json:"show_pub_key,omitempty"`
}

func (x GetSobjectParams) urlEncode(v map[string][]string) error {
	if x.View != nil {
		v["view"] = []string{fmt.Sprintf("%v", *x.View)}
	}
	if x.ShowDestroyed != nil {
		v["show_destroyed"] = []string{fmt.Sprintf("%v", *x.ShowDestroyed)}
	}
	if x.ShowDeleted != nil {
		v["show_deleted"] = []string{fmt.Sprintf("%v", *x.ShowDeleted)}
	}
	if x.ShowValue != nil {
		v["show_value"] = []string{fmt.Sprintf("%v", *x.ShowValue)}
	}
	if x.ShowPubKey != nil {
		v["show_pub_key"] = []string{fmt.Sprintf("%v", *x.ShowPubKey)}
	}
	return nil
}

// Request to import a security object by components.
type ImportSobjectComponentsRequest struct {
	// Properties of the imported security object
	Key SobjectRequest `json:"key"`
	// Details of unwrapping key, if components are wrapped.
	UnwrapKeyParams *UnwrapKeyParams `json:"unwrap_key_params,omitempty"`
	// Key holder identifier
	Custodians []Principal `json:"custodians"`
	// Key material by parts
	Components *[]SobjectComponent `json:"components,omitempty"`
	// Description of the imported security object
	Description *string `json:"description,omitempty"`
	// Splitting method used to join the key components
	Method *SplittingMethod `json:"method,omitempty"`
	// Authentication requirements for approval requests
	AuthConfig *ApprovalAuthConfig `json:"auth_config,omitempty"`
}

// KCV of a key
type KeyCheckValueResponse struct {
	// UUID, only for persistent keys.
	Kid *UUID `json:"kid,omitempty"`
	// Key Checksum Value
	Kcv string `json:"kcv"`
}

// Request parameters for filtering and listing security objects.
type ListSobjectsParams struct {
	// Filter security object(s) by group ID.
	GroupID *UUID `json:"group_id,omitempty"`
	// Filter security object(s) by a particular creator.
	Creator *UUID `json:"creator,omitempty"`
	// Filter security object(s) by name.
	Name *string `json:"name,omitempty"`
	// Filter security object(s) by PKCS11 label.
	Pkcs11Label *string `json:"pkcs11_label,omitempty"`
	// Filter security object(s) by PKCS11 unique identifier.
	Pkcs11ID *Blob `json:"pkcs11_id,omitempty"`
	// Filter security object(s) by object type.
	ObjType *ObjectType `json:"obj_type,omitempty"`
	// Set max security objects in returned in response (default: 1000).
	Limit *uint `json:"limit,omitempty"`
	// Skip first n (offset) matches.
	Offset *uint `json:"offset,omitempty"`
	// Sorting method for listed security objects.
	Sort *SobjectSort `json:"sort,omitempty"`
	// Only show security objects complying with group and account policies.
	CompliantWithPolicies *bool `json:"compliant_with_policies,omitempty"`
	// Filter security object(s) by custom_metadata fields.
	CustomMetadata *CustomMetadata `json:"custom_metadata,omitempty"`
	// Display query metadata in response, containing information on total objects
	// and number of objects skipped.
	WithMetadata *bool `json:"with_metadata,omitempty"`
	// Show destroyed security object(s).
	ShowDestroyed *bool `json:"show_destroyed,omitempty"`
	// Show deleted security object(s).
	ShowDeleted *bool `json:"show_deleted,omitempty"`
	// Show non-sensitive key material of security object(s).
	ShowValue *bool `json:"show_value,omitempty"`
	// Show public key of security objects(s) if present.
	ShowPubKey *bool `json:"show_pub_key,omitempty"`
	// Show key check value for security object(s).
	ShowKcv *bool `json:"show_kcv,omitempty"`
	// Provide custom filtering query.
	Filter *string `json:"filter,omitempty"`
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
	if x.Pkcs11Label != nil {
		v["pkcs11_label"] = []string{fmt.Sprintf("%v", *x.Pkcs11Label)}
	}
	if x.Pkcs11ID != nil {
		v["pkcs11_id"] = []string{fmt.Sprintf("%v", *x.Pkcs11ID)}
	}
	if x.ObjType != nil {
		v["obj_type"] = []string{fmt.Sprintf("%v", *x.ObjType)}
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
	if x.CompliantWithPolicies != nil {
		v["compliant_with_policies"] = []string{fmt.Sprintf("%v", *x.CompliantWithPolicies)}
	}
	if err := x.CustomMetadata.urlEncode(v); err != nil {
		return err
	}
	if x.WithMetadata != nil {
		v["with_metadata"] = []string{fmt.Sprintf("%v", *x.WithMetadata)}
	}
	if x.ShowDestroyed != nil {
		v["show_destroyed"] = []string{fmt.Sprintf("%v", *x.ShowDestroyed)}
	}
	if x.ShowDeleted != nil {
		v["show_deleted"] = []string{fmt.Sprintf("%v", *x.ShowDeleted)}
	}
	if x.ShowValue != nil {
		v["show_value"] = []string{fmt.Sprintf("%v", *x.ShowValue)}
	}
	if x.ShowPubKey != nil {
		v["show_pub_key"] = []string{fmt.Sprintf("%v", *x.ShowPubKey)}
	}
	if x.ShowKcv != nil {
		v["show_kcv"] = []string{fmt.Sprintf("%v", *x.ShowKcv)}
	}
	if x.Filter != nil {
		v["filter"] = []string{fmt.Sprintf("%v", *x.Filter)}
	}
	return nil
}

// Request to compute digest of a key.
type ObjectDigestRequest struct {
	// Uniquely identifies a security object.
	Key SobjectDescriptor `json:"key"`
	// Digest algorithm
	Alg DigestAlgorithm `json:"alg"`
}

// Digest of a key.
type ObjectDigestResponse struct {
	// UUID, only displayed for persistent keys.
	Kid *UUID `json:"kid,omitempty"`
	// Digest value
	Digest Blob `json:"digest"`
}

// Request to persist a transient key.
type PersistTransientKeyRequest struct {
	// Intended activation date of the security object.
	ActivationDate *Time `json:"activation_date,omitempty"`
	// Intended deactivation date of the security object.
	DeactivationDate *Time `json:"deactivation_date,omitempty"`
	// Name of the persisted security object. Security object names must be unique within an account.
	Name string `json:"name"`
	// User-defined readable description
	Description *string `json:"description,omitempty"`
	// User-defined metadata for the persisted key stored as key-value pairs.
	CustomMetadata *map[string]string `json:"custom_metadata,omitempty"`
	// Whether the new security object should be enabled. Disabled security objects may not perform cryptographic operations.
	Enabled *bool `json:"enabled,omitempty"`
	// Group ID of the security group that the persisted key should belong to. The user or
	// application creating this security object must be a member of this group. If no group is
	// specified, the default group for the requesting application will be used.
	GroupID *UUID `json:"group_id,omitempty"`
	// Intended initial state of the key
	State *SobjectState `json:"state,omitempty"`
	// Transient key to persist
	TransientKey Blob `json:"transient_key"`
}

type RevertRequest struct {
	Ids []UUID `json:"ids"`
}

// Component of security object, held by a custodian.
type SobjectComponent struct {
	// Key component
	Component Blob `json:"component"`
	// Key component KCV
	ComponentKcv *string `json:"component_kcv,omitempty"`
	// Component custodian
	Custodian Principal `json:"custodian"`
}

// Uniquely identifies a persisted sobject.
type SobjectDescriptorPersisted struct {
	Kid  *UUID
	Name *string
}

func (x SobjectDescriptorPersisted) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"SobjectDescriptorPersisted",
		[]bool{x.Kid != nil,
			x.Name != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Kid  *UUID   `json:"kid,omitempty"`
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
		Kid  *UUID   `json:"kid,omitempty"`
		Name *string `json:"name,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.Kid = obj.Kid
	x.Name = obj.Name
	return nil
}

// Response data encoding.
type SobjectEncoding string

// List of supported SobjectEncoding values
const (
	// JSON format
	SobjectEncodingJson SobjectEncoding = "json"
	// Value format
	SobjectEncodingValue SobjectEncoding = "value"
)

// Request to rekey a security object.
type SobjectRekeyRequest struct {
	// If set to true, the old key is deactivated on rekey.
	DeactivateRotatedKey *bool `json:"deactivate_rotated_key,omitempty"`
	// Parameters for the new security object.
	Dest SobjectRequest `json:"dest"`
}

func (x SobjectRekeyRequest) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	{ // x.Dest is flattened
		b, err := json.Marshal(&x.Dest)
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
	if x.DeactivateRotatedKey != nil {
		m["deactivate_rotated_key"] = x.DeactivateRotatedKey
	}
	return json.Marshal(&m)
}
func (x *SobjectRekeyRequest) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &x.Dest); err != nil {
		return err
	}
	var r struct {
		DeactivateRotatedKey *bool `json:"deactivate_rotated_key,omitempty"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	x.DeactivateRotatedKey = r.DeactivateRotatedKey
	return nil
}

// Request to rotate a security object to an existing security object.
type SobjectReplaceRequest struct {
	// Security object that will be replaced as part of this operation.
	Replaced SobjectDescriptorPersisted `json:"replaced"`
	// New name for the replaced security object.
	ReplacedNewName string `json:"replaced_new_name"`
	// Security object that will become the replacement of the security object
	// that has to be replaced.
	Replacement SobjectDescriptorPersisted `json:"replacement"`
}

type SobjectRequest struct {
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
	// User managed field for adding custom metadata to the security object.
	CustomMetadata *map[string]string `json:"custom_metadata,omitempty"`
	// Deactivation date of security object in seconds since EPOCH.
	DeactivationDate *Time `json:"deactivation_date,omitempty"`
	// DES specific options.
	Des *DesOptions `json:"des,omitempty"`
	// DES3 specific options.
	Des3 *Des3Options `json:"des3,omitempty"`
	// Description of the security object.
	Description *string `json:"description,omitempty"`
	// Optionally get deterministic signatures, if algorithm is EC or RSA.
	DeterministicSignatures *bool `json:"deterministic_signatures,omitempty"`
	// DSA specific options.
	Dsa *DsaOptions `json:"dsa,omitempty"`
	// ECKCDSA specific options.
	Eckcdsa *EcKcdsaOptions `json:"eckcdsa,omitempty"`
	// Identifies a standard elliptic curve.
	EllipticCurve *EllipticCurve `json:"elliptic_curve,omitempty"`
	// Whether this security object has cryptographic operations enabled.
	Enabled *bool `json:"enabled,omitempty"`
	// Information specific to an external KMS. Currently, it only has AWS related information.
	External *ExternalKmsInfo `json:"external,omitempty"`
	// FPE specific options.
	Fpe *FpeOptions `json:"fpe,omitempty"`
	// Key Access Justifications for GCP EKM.
	// For more details: https://cloud.google.com/cloud-provider-access-management/key-access-justifications/docs/overview
	GoogleAccessReasonPolicy *Removable[GoogleAccessReasonPolicy] `json:"google_access_reason_policy,omitempty"`
	// KCDSA specific options.
	Kcdsa *KcdsaOptions `json:"kcdsa,omitempty"`
	// Key Checksum Value of the security object.
	Kcv *string `json:"kcv,omitempty"`
	// Operations allowed to be performed by a given key.
	KeyOps *KeyOperations `json:"key_ops,omitempty"`
	// Key size of the security object in bits.
	KeySize *uint32 `json:"key_size,omitempty"`
	// Linked security objects.
	Links *KeyLinks `json:"links,omitempty"`
	// LMS specific options.
	Lms *LmsOptions `json:"lms,omitempty"`
	// Name of the security object.
	Name *string `json:"name,omitempty"`
	// Type of security object.
	ObjType *ObjectType `json:"obj_type,omitempty"`
	// Public exponent
	PubExponent *uint32 `json:"pub_exponent,omitempty"`
	// If enabled, the public key will be available publicly (without authentication)
	// through the GetPublicKey API.
	PublishPublicKey *PublishPublicKeyConfig `json:"publish_public_key,omitempty"`
	// Rotation policy of security objects.
	RotationPolicy *RotationPolicy `json:"rotation_policy,omitempty"`
	// RSA specific options.
	Rsa *RsaOptions `json:"rsa,omitempty"`
	// Seed options.
	Seed *SeedOptions `json:"seed,omitempty"`
	// Security object operational state.
	State *SobjectState `json:"state,omitempty"`
	// If set to true, the security object will cease to exist after session ends.
	Transient *bool `json:"transient,omitempty"`
	// Security object stored as byte array.
	Value *Blob `json:"value,omitempty"`
	// UUID of the group which the security object belongs to.
	GroupID *UUID `json:"group_id,omitempty"`
}

// Sorting order on listed security objects.
type SobjectSort struct {
	// Security object UUID
	ByKid *SobjectSortByKid
	// Security object name
	ByName *SobjectSortByName
}

// Security object UUID
type SobjectSortByKid struct {
	// Order of listing
	Order Order `json:"order"`
	// Initial security object UUID
	Start *UUID `json:"start,omitempty"`
}

// Security object name
type SobjectSortByName struct {
	// Order of listing
	Order Order `json:"order"`
	// Initial security object Name
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

// Method used to split the key into multiple components.
type SplittingMethod string

// List of supported SplittingMethod values
const (
	// Logical XOR operation
	SplittingMethodXOR SplittingMethod = "XOR"
)

// Request to unwrap a security object
type UnwrapKeyParams struct {
	// Unique identifier of the security object.
	Key SobjectDescriptor `json:"key"`
	// Cryptographic algorithm used for unwrapping.
	Alg Algorithm `json:"alg"`
	// Block cipher mode of operation, required for symmetric algorithms.
	Mode *CryptMode `json:"mode,omitempty"`
	// Initialization vector is required for symmetric algorithms.
	Iv *Blob `json:"iv,omitempty"`
	// Authenticated data is only applicable if mode is GCM.
	Ad *Blob `json:"ad,omitempty"`
	// Tag is required if mode is GCM.
	Tag *Blob `json:"tag,omitempty"`
}

// Verify KCV of a key
type VerifyKcvRequest struct {
	// Key Checksum Value
	Kcv string `json:"kcv"`
	// Key material
	Value Blob `json:"value"`
	// Type of Security object
	ObjType ObjectType `json:"obj_type"`
}

// Key Checksum Value verification status.
type VerifyKcvResponse struct {
	// Verification status
	Verified bool `json:"verified"`
}

// Wrapping key parameters
type WrapKeyParams struct {
	// Wrapping key
	Key SobjectDescriptor `json:"key"`
	// Cryptographic algorithm of security object
	Alg Algorithm `json:"alg"`
	// Block cipher mode of operation, required for symmetric algorithms.
	Mode *CryptMode `json:"mode,omitempty"`
	// Initialization vector is required for symmetric algorithms.
	Iv *Blob `json:"iv,omitempty"`
	// Authenticated data is only applicable if mode is GCM.
	Ad *Blob `json:"ad,omitempty"`
	// Tag length is required when mode is GCM.
	TagLen *uint `json:"tag_len,omitempty"`
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

// Batch sign with one or more private keys.
//
// The order of batch items in the response matches that of the request.
// An individual status code is returned for each batch item.
func (c *Client) BatchSign(ctx context.Context, body []SignRequest) ([]BatchSignResponseItem, error) {
	u := "/crypto/v1/keys/batch/sign"
	var r []BatchSignResponseItem
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return r, nil
}

func (c *Client) RequestApprovalToBatchSign(
	ctx context.Context,
	body []SignRequest,
	description *string) (*ApprovalRequest, error) {
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
//
// The order of batch items in the response matches that of the request.
// An individual status code is returned for each batch item.
func (c *Client) BatchVerify(ctx context.Context, body []VerifyRequest) ([]BatchVerifyResponseItem, error) {
	u := "/crypto/v1/keys/batch/verify"
	var r []BatchVerifyResponseItem
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return r, nil
}

// Make a copy of a security object.
//
// A new key will be created in the target group and will have the
// same key material as the original key. Links will be maintained
// between all copied keys and the source key.
// If the key is being copied to an externally linked group, it needs
// to be exportable.
//
// This can also be used to rotate an external key by copying the
// key material from a native DSM key. This key material will then
// finally be imported into the external KMS.
// For AWS KMS keys, after the rotation, the new key will have the
// original aliases and the old key's aliases will have
// (rotated at <timestamp>) appended in front of it.
func (c *Client) CopySobject(ctx context.Context, body CopySobjectRequest) (*Sobject, error) {
	u := "/crypto/v1/keys/copy"
	var r Sobject
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToCopySobject(
	ctx context.Context,
	body CopySobjectRequest,
	description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/keys/copy"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Generate a new security object.
//
// Generate a new security object (such as an RSA key pair or an AES key)
// of the requested size, elliptic curve, etc.
//
// By default, all key operations except for EXPORT that are implemented
// for that type of key will be enabled. These may be overridden by
// requesting specific operations in the key creation request.
//
// Objects of type Secret/Opaque may not be generated with this API.
// They must be imported via the import API.
//
// For AWS KMS keys, this generates the key material in AWS and a corresponding
// virtual key is created in DSM. Only 256-bit AES keys are supported.
func (c *Client) CreateSobject(ctx context.Context, body SobjectRequest) (*Sobject, error) {
	u := "/crypto/v1/keys"
	var r Sobject
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Delete the specified security object.
func (c *Client) DeleteSobject(ctx context.Context, id string) error {
	u := "/crypto/v1/keys/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
		return err
	}
	return nil
}

func (c *Client) RequestApprovalToDeleteSobject(
	ctx context.Context,
	id string,
	description *string) (*ApprovalRequest, error) {
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

// Transition a security object to Destroyed state. Objects in the
// `Destroyed` state cannot be used in any cryptographic operation.
// Their metadata however, remains accessible.
func (c *Client) DestroySobject(ctx context.Context, id string) error {
	u := "/crypto/v1/keys/:id/destroy"
	u = strings.NewReplacer(":id", id).Replace(u)
	if err := c.fetch(ctx, http.MethodPost, u, nil, nil); err != nil {
		return err
	}
	return nil
}

func (c *Client) RequestApprovalToDestroySobject(
	ctx context.Context,
	id string,
	description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/keys/:id/destroy"
	u = strings.NewReplacer(":id", id).Replace(u)
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        nil,
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

// Get the details and value of a particular exportable security object.
func (c *Client) ExportSobject(ctx context.Context, body SobjectDescriptor) (*Sobject, error) {
	u := "/crypto/v1/keys/export"
	var r Sobject
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToExportSobject(
	ctx context.Context,
	body SobjectDescriptor,
	description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/keys/export"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Exports the security object as components.
//
// Exports the security object as components. This API can only be called
// through an approval request and won't work if called directly. This
// requires a key custodian policy and quorum approval policy to be set at
// the group level. A new approval request needs to be created (see
// `POST /sys/v1/approval_requests`), then after getting the required approvals,
// the key custodians can fetch the result of this approval request
// (See `POST /sys/v1/approval_requests/:id/result`).
// Each key custodian will be able to get only their component.
//
// Only AES, DES, DES3 & HMAC objects are exportable by components.
//
// This is described in detail in the following article:
// https://support.fortanix.com/hc/en-us/articles/360043559332-User-s-Guide-Key-Components
func (c *Client) ExportSobjectComponents(ctx context.Context, body ExportSobjectComponentsRequest) (*ExportComponentsResponse, error) {
	u := "/crypto/v1/keys/components/export"
	var r ExportComponentsResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToExportSobjectComponents(
	ctx context.Context,
	body ExportSobjectComponentsRequest,
	description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/keys/components/export"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Computes the KCV of the input and returns. This is
// only valid for AES, DES & DES3 keys.
func (c *Client) GetKcv(ctx context.Context, body SobjectDescriptor) (*KeyCheckValueResponse, error) {
	u := "/crypto/v1/keys/kcv"
	var r KeyCheckValueResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Get public part of an asymmetric key.
//
// Returns the public part of an asymmetric key. This needs
// account id and key name as input. No auth is required for this.
// This works with RSA, EC and Certificate objects.
func (c *Client) GetPubkey(ctx context.Context, id string, name string) (map[string]Blob, error) {
	u := "/crypto/v1/pubkey/:id/:name"
	u = strings.NewReplacer(":id", id, ":name", name).Replace(u)
	var r map[string]Blob
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return r, nil
}

// Lookup a security object.
func (c *Client) GetSobject(ctx context.Context, queryParameters *GetSobjectParams, body SobjectDescriptor) (*Sobject, error) {
	u := "/crypto/v1/keys/info"
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	var r Sobject
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Import a security object.
//
// By default, all key operations that are implemented for that type of
// key will be enabled. These may be overridden by requesting specific
// operations in the key import request.
//
// For symmetric and asymmetric keys, value is base64-encoding of the
// key material in DER format.
//
// For AWS KMS keys, this imports the key material provided into the
// external KMS and a corresponding virtual key is created in DSM.
// Only AES 256 is supported for now.
func (c *Client) ImportSobject(ctx context.Context, body SobjectRequest) (*Sobject, error) {
	u := "/crypto/v1/keys"
	var r Sobject
	if err := c.fetch(ctx, http.MethodPut, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Import a security object by components.
//
// Import a security object by components. This API can only be called
// through an approval request and won't work if called directly. A key
// custodian and quorum policy needs to be set at the group level. After
// an import by components request has been made, key custodians will
// need to add their respective component via
// `POST /sys/v1/approval_requests/:id/approve`.
//
// Only AES, DES, DES3 & HMAC objects are importable by components.
//
// This is described in detail in the following article:
// https://support.fortanix.com/hc/en-us/articles/360043559332-User-s-Guide-Key-Components
func (c *Client) ImportSobjectByComponents(ctx context.Context, body ImportSobjectComponentsRequest) (*Sobject, error) {
	u := "/crypto/v1/keys/components/import"
	var r Sobject
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToImportSobjectByComponents(
	ctx context.Context,
	body ImportSobjectComponentsRequest,
	description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/keys/components/import"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Get all security objects accessible to the requester.
func (c *Client) ListSobjects(ctx context.Context, queryParameters *ListSobjectsParams) (*ListSobjectsResponse, error) {
	u := "/crypto/v1/keys"
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	var r ListSobjectsResponse
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Persist a transient key.
//
// This API copies a transient key as a persisted security
// object. If the transient key's origin is "FortanixHSM",
// the origin of the persisted key will be "Transient". If the
// transient key's origin is "External", the origin of the persisted
// key will be "External".
func (c *Client) PersistTransientKey(ctx context.Context, body PersistTransientKeyRequest) (*Sobject, error) {
	u := "/crypto/v1/keys/persist"
	var r Sobject
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Destroy private half of an asymmetric key.
//
// Removes the private portion of an asymmetric key. After this
// operation is performed, operations that require the private key, such
// as encryption and generating signatures, can no longer be performed.
func (c *Client) RemovePrivate(ctx context.Context, id string) error {
	u := "/crypto/v1/keys/:id/private"
	u = strings.NewReplacer(":id", id).Replace(u)
	if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
		return err
	}
	return nil
}

func (c *Client) RequestApprovalToRemovePrivate(
	ctx context.Context,
	id string,
	description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/keys/:id/private"
	u = strings.NewReplacer(":id", id).Replace(u)
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodDelete),
		Operation:   &u,
		Body:        nil,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Rotate a security object to an existing security object.
//
// For two keys R and S, where R is the key to be replaced,
// and S is the intended replacement, this operation will
//   - Rename R to the name provided in the request
//   - Establish an replaced-replacement between R and S
//   - Assign R's old name to S
//
// The metadata of S should be mostly same as that of R, and
// it is not possible to update any fields of S while
// performing this operation. If S does not have any custom
// metadata or a rotation policy, any corresponding values
// from R will be copied over to S.
// For now, this operation is not supported if R, S, or both
// are externally-backed keys.
func (c *Client) ReplaceSobject(ctx context.Context, body SobjectReplaceRequest) error {
	u := "/crypto/v1/keys/replace"
	if err := c.fetch(ctx, http.MethodPost, u, &body, nil); err != nil {
		return err
	}
	return nil
}

func (c *Client) RequestApprovalToReplaceSobject(
	ctx context.Context,
	body SobjectReplaceRequest,
	description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/keys/replace"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Reverts a security object to a previous state.
//
// When a Key Undo Policy is in place, security objects maintain a list
// of history states. Using this API endpoint, clients may revert the
// security object to a previous (non-expired) history state.
func (c *Client) RevertPrevKeyOp(ctx context.Context, id string, body RevertRequest) error {
	u := "/crypto/v1/keys/:id/revert"
	u = strings.NewReplacer(":id", id).Replace(u)
	if err := c.fetch(ctx, http.MethodPut, u, &body, nil); err != nil {
		return err
	}
	return nil
}

func (c *Client) RequestApprovalToRevertPrevKeyOp(
	ctx context.Context,
	id string,
	body RevertRequest,
	description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/keys/:id/revert"
	u = strings.NewReplacer(":id", id).Replace(u)
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPut),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
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

func (c *Client) RequestApprovalToRevokeSobject(
	ctx context.Context,
	id string,
	body RevocationReason,
	description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/keys/:id/revoke"
	u = strings.NewReplacer(":id", id).Replace(u)
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Rotate a security object.
//
// Renames current key to "<current_name> (rotated at <timestamp>)"
// and generates a new key with the original name of the source key.
// The metadata of the newly generated key is mostly same as original
// key and it is possible to update the following fields while performing
// rotation: `activation_date`, `deactivation_date`, `state`, `rsa`,
// `aes`, `aria`, `des`, `des3`, `seed`, `dsa`, `kcdsa`, `eckcdsa`,
// `pub_exponent`, `elliptic_curve`, `key_size`, `key_ops`, `description`,
// `enabled`, `custom_metadata`, `publish_public_key`, `rotation_policy`.
//
// If the key is an external key, additional changes
// might happen (like changes to aws-alias custom_metadata, etc).
// (yet to be documented)
//
// For AWS KMS keys, a new key is generated in the external KMS and
// after the rotation, the new key will have the original aliases and the old
// key's aliases will have (rotated at <timestamp>) appended in front of it.
func (c *Client) RotateSobject(ctx context.Context, body SobjectRekeyRequest) (*Sobject, error) {
	u := "/crypto/v1/keys/rekey"
	var r Sobject
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToRotateSobject(
	ctx context.Context,
	body SobjectRekeyRequest,
	description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/keys/rekey"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Update the properties of a security object like
// name, description, etc.
func (c *Client) UpdateSobject(ctx context.Context, id string, body SobjectRequest) (*Sobject, error) {
	u := "/crypto/v1/keys/:id"
	u = strings.NewReplacer(":id", id).Replace(u)
	var r Sobject
	if err := c.fetch(ctx, http.MethodPatch, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToUpdateSobject(
	ctx context.Context,
	id string,
	body SobjectRequest,
	description *string) (*ApprovalRequest, error) {
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

// Computes the KCV of the input blob and checks if
// it matches the input KCV.
func (c *Client) VerifyKcv(ctx context.Context, body VerifyKcvRequest) (*VerifyKcvResponse, error) {
	u := "/crypto/v1/keys/kcv/verify"
	var r VerifyKcvResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
