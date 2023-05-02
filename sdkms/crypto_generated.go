/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package sdkms

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/pkg/errors"
)

// A cryptographic algorithm.
type Algorithm string

// List of supported Algorithm values
const (
	AlgorithmAes  Algorithm = "AES"
	AlgorithmDes  Algorithm = "DES"
	AlgorithmDes3 Algorithm = "DES3"
	AlgorithmRsa  Algorithm = "RSA"
	AlgorithmEc   Algorithm = "EC"
	AlgorithmHmac Algorithm = "HMAC"
)

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

// A request to encrypt data using a symmetric or asymmetric key.
type EncryptRequest struct {
	Key   *SobjectDescriptor `json:"key,omitempty"`
	Alg   Algorithm          `json:"alg"`
	Plain Blob               `json:"plain"`
	// Mode is required for symmetric algorithms.
	Mode *CryptMode `json:"mode,omitempty"`
	// Initialization vector is optional and will be randomly generated if not specified.
	Iv *Blob `json:"iv,omitempty"`
	// Authenticated data is only applicable when using GCM mode.
	Ad *Blob `json:"ad,omitempty"`
	// Tag length is only applicable when using GCM mode.
	TagLen *uint `json:"tag_len,omitempty"`
}

// Result of an encryption.
type EncryptResponse struct {
	// Key id is returned for non-transient keys.
	Kid    *UUID `json:"kid,omitempty"`
	Cipher Blob  `json:"cipher"`
	// Initialization vector is only returned for symmetric encryption.
	Iv *Blob `json:"iv,omitempty"`
	// Tag is only returned for symmetric encryption with GCM mode.
	Tag *Blob `json:"tag,omitempty"`
}

// Initialize multi-part encryption. AEAD ciphers are not currently supported in this mode.
type EncryptInitRequest struct {
	Key *SobjectDescriptor `json:"key,omitempty"`
	Alg Algorithm          `json:"alg"`
	// Mode is required for symmetric encryption.
	Mode *CipherMode `json:"mode,omitempty"`
	Iv   *Blob       `json:"iv,omitempty"`
}

// Result of initializing multi-part encryption.
type EncryptInitResponse struct {
	// Key id is returned for non-transient keys.
	Kid *UUID `json:"kid,omitempty"`
	// Initialization vector is only returned for symmetric encryption.
	Iv *Blob `json:"iv,omitempty"`
	// Opaque data, not to be interpreted or modified by the client and must be provided with next request.
	State Blob `json:"state"`
}

// Multi-part encryption request.
type EncryptUpdateRequest struct {
	Key   *SobjectDescriptor `json:"key,omitempty"`
	Plain Blob               `json:"plain"`
	State Blob               `json:"state"`
}

// Result of multi-part encryption.
type EncryptUpdateResponse struct {
	Cipher Blob `json:"cipher"`
	// Opaque data, not to be interpreted or modified by the client and must be provided with next request.
	State Blob `json:"state"`
}

// Finalize a multi-part encryption.
type EncryptFinalRequest struct {
	Key   *SobjectDescriptor `json:"key,omitempty"`
	State Blob               `json:"state"`
}

// Final result of a multi-part encryption.
type EncryptFinalResponse struct {
	Cipher Blob `json:"cipher"`
}

// A request to decrypt data using a symmetric or asymmetric key.
type DecryptRequest struct {
	Key    *SobjectDescriptor `json:"key,omitempty"`
	Alg    *Algorithm         `json:"alg,omitempty"`
	Cipher Blob               `json:"cipher"`
	// Mode is required for symmetric algorithms.
	Mode *CryptMode `json:"mode,omitempty"`
	// Initialization vector is required for symmetric algorithms.
	Iv *Blob `json:"iv,omitempty"`
	// Authenticated data is only applicable when using GCM mode.
	Ad *Blob `json:"ad,omitempty"`
	// Tag is only applicable when using GCM mode.
	Tag *Blob `json:"tag,omitempty"`
}

// Result of a decryption.
type DecryptResponse struct {
	// The key id of the key used to decrypt. Returned for non-transient keys.
	Kid   *UUID `json:"kid,omitempty"`
	Plain Blob  `json:"plain"`
}

// Initialize multi-part decryption. AEAD ciphers are not currently supported in this mode.
type DecryptInitRequest struct {
	Key *SobjectDescriptor `json:"key,omitempty"`
	Alg *Algorithm         `json:"alg,omitempty"`
	// Mode is required for symmetric algorithms.
	Mode *CipherMode `json:"mode,omitempty"`
	// Initialization vector is required for symmetric algorithms.
	Iv *Blob `json:"iv,omitempty"`
}

// Result of initializing multi-part decryption.
type DecryptInitResponse struct {
	// The key id is returned for non-transient keys.
	Kid *UUID `json:"kid,omitempty"`
	// Opaque data, not to be interpreted or modified by the client and must be provided with next request.
	State Blob `json:"state"`
}

// Multi-part decryption request.
type DecryptUpdateRequest struct {
	Key    *SobjectDescriptor `json:"key,omitempty"`
	Cipher Blob               `json:"cipher"`
	State  Blob               `json:"state"`
}

// Result of multi-part decryption.
type DecryptUpdateResponse struct {
	Plain Blob `json:"plain"`
	// Opaque data, not to be interpreted or modified by the client and must be provided with next request.
	State Blob `json:"state"`
}

// Finalize a multi-part decryption.
type DecryptFinalRequest struct {
	Key   *SobjectDescriptor `json:"key,omitempty"`
	State Blob               `json:"state"`
}

// Final result of a multi-part decryption.
type DecryptFinalResponse struct {
	Plain Blob `json:"plain"`
}

// Request to compute the hash of arbitrary data.
type DigestRequest struct {
	Alg  DigestAlgorithm `json:"alg"`
	Data Blob            `json:"data"`
}

// Result of a hash operation.
type DigestResponse struct {
	Digest Blob `json:"digest"`
}

// Request for HMAC or CMAC operation.
type MacRequest struct {
	Key  *SobjectDescriptor `json:"key,omitempty"`
	Alg  *DigestAlgorithm   `json:"alg,omitempty"`
	Data Blob               `json:"data"`
}

// Result of HMAC or CMAC operation.
type MacResponse struct {
	Kid *UUID `json:"kid,omitempty"`
	// This field is retained for backward compatibility in API for HMAC.
	Digest *Blob `json:"digest,omitempty"`
	// The MAC generated for the input data.
	Mac Blob `json:"mac"`
}

// Rquest to verify a MAC value.
type VerifyMacRequest struct {
	Key *SobjectDescriptor `json:"key,omitempty"`
	// Algorithm is required for HMAC.
	Alg  *DigestAlgorithm `json:"alg,omitempty"`
	Data Blob             `json:"data"`
	// This field is deprecated. Instead you should use the `mac` field.
	Digest *Blob `json:"digest,omitempty"`
	// Either `digest` or `mac` should be specified.
	Mac *Blob `json:"mac,omitempty"`
}

type DeriveKeyMechanismHkdf struct {
	HashAlg DigestAlgorithm `json:"hash_alg"`

	Info string `json:"info,omitempty"`

	Salt string `json:"salt,omitempty"`
}

// Encodes the mechanism to be used when deriving a new key from an existing key.
// Currently, the only supported mechanism is encrypting data to derive the new key.
// Other mechanisms may be added in the future.
type DeriveKeyMechanism struct {
	EncryptData *EncryptRequest `json:"encrypt_data,omitempty"`
	Hkdf        *DeriveKeyMechanismHkdf `json:"hkdf,omitempty"`
}

func (x DeriveKeyMechanism) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers("DeriveKeyMechanism", []bool{x.EncryptData != nil, x.Hkdf != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		EncryptData *EncryptRequest `json:"encrypt_data,omitempty"`
		Hkdf  *DeriveKeyMechanismHkdf `json:"hkdf,omitempty"`
	}
	if x.EncryptData != nil {
		obj.EncryptData = x.EncryptData
	}
	if x.Hkdf != nil {
		obj.Hkdf = x.Hkdf
	}
	return json.Marshal(obj)

}
func (x *DeriveKeyMechanism) UnmarshalJSON(data []byte) error {
	x.EncryptData = nil
	x.Hkdf = nil
	var hkdf DeriveKeyMechanismHkdf
	if err := json.Unmarshal(data, &hkdf); err == nil {
		x.Hkdf = &hkdf
		return nil
	}
	var encryptdata EncryptRequest
	if err := json.Unmarshal(data, &encryptdata); err == nil {
		x.EncryptData = &encryptdata
		return nil
	}
	return errors.Errorf("Not a valid Key Derivation mode")
}

// Request to derive a key.
type DeriveKeyRequest struct {
	ActivationDate   *Time              `json:"activation_date,omitempty"`
	DeactivationDate *Time              `json:"deactivation_date,omitempty"`
	Key              *SobjectDescriptor `json:"key,omitempty"`
	// Name of the derived key. Key names must be unique within an account.
	Name *string `json:"name,omitempty"`
	// Group ID of the security group that this security object should belong to. The user or
	// application creating this security object must be a member of this group. If no group is
	// specified, the default group for the requesting application will be used.
	GroupID *UUID `json:"group_id,omitempty"`
	// Type of key to be derived.
	KeyType ObjectType `json:"key_type"`
	// Key size of the derived key in bits.
	KeySize uint32 `json:"key_size"`
	// Mechanism to use for key derivation.
	Mechanism DeriveKeyMechanism `json:"mechanism"`
	// Whether the derived key should have cryptographic operations enabled.
	Enabled     *bool   `json:"enabled,omitempty"`
	Description *string `json:"description,omitempty"`
	// User-defined metadata for this key stored as key-value pairs.
	CustomMetadata *map[string]string `json:"custom_metadata,omitempty"`
	// Optional array of key operations to be enabled for this security object. If not
	// provided the service will provide a default set of key operations. Note that if you
	// provide an empty array, all key operations will be disabled.
	KeyOps *KeyOperations `json:"key_ops,omitempty"`
	State  *SobjectState  `json:"state,omitempty"`
	// If set to true, the derived key will be transient.
	Transient *bool `json:"transient,omitempty"`
}

// Mechanism to use for key agreement.
type AgreeKeyMechanism string

// List of supported AgreeKeyMechanism values
const (
	AgreeKeyMechanismDiffieHellman AgreeKeyMechanism = "diffie_hellman"
)

// Request to perform key agreement.
type AgreeKeyRequest struct {
	ActivationDate   *Time             `json:"activation_date,omitempty"`
	DeactivationDate *Time             `json:"deactivation_date,omitempty"`
	PrivateKey       SobjectDescriptor `json:"private_key"`
	PublicKey        SobjectDescriptor `json:"public_key"`
	// Mechanism to use for key derivation.
	Mechanism AgreeKeyMechanism `json:"mechanism"`
	// Name of the agreed-upon key. Key names must be unique within an account.
	// The name is ignored for transient keys.
	Name *string `json:"name,omitempty"`
	// Group ID of the security group that this security object should belong to. The user or
	// application creating this security object must be a member of this group. If no group is
	// specified, the default group for the requesting application will be used.
	GroupID *UUID `json:"group_id,omitempty"`
	// Type of key to be derived. NB. for security reasons, you shouldn't specify anything but HMAC or Secret.
	KeyType ObjectType `json:"key_type"`
	// Key size in bits. If less than the output size of the algorithm, the secret's most-significant bits will be truncated.
	KeySize     uint32  `json:"key_size"`
	Enabled     bool    `json:"enabled"`
	Description *string `json:"description,omitempty"`
	// User-defined metadata for this key stored as key-value pairs.
	CustomMetadata *map[string]string `json:"custom_metadata,omitempty"`
	// Optional array of key operations to be enabled for this security object. If not
	// provided the service will provide a default set of key operations. Note that if you
	// provide an empty array, all key operations will be disabled.
	KeyOps *KeyOperations `json:"key_ops,omitempty"`
	State  *SobjectState  `json:"state,omitempty"`
	// If set to true, the resulting key will be transient.
	Transient bool `json:"transient"`
}

// `CipherMode` or `RsaEncryptionPadding`, depending on the encryption algorithm.
type CryptMode struct {
	Symmetric *CipherMode
	Rsa       *RsaEncryptionPadding
}

func (x CryptMode) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers("CryptMode", []bool{x.Symmetric != nil, x.Rsa != nil}); err != nil {
		return nil, err
	}
	if x.Symmetric != nil {
		return json.Marshal(x.Symmetric)
	}
	if x.Rsa != nil {
		return json.Marshal(x.Rsa)
	}
	panic("unreachable")
}
func (x *CryptMode) UnmarshalJSON(data []byte) error {
	x.Symmetric = nil
	x.Rsa = nil
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
	return errors.Errorf("not a valid CryptMode")
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
}

// Optimal Asymmetric Encryption Padding (PKCS#1 v2.1).
type RsaEncryptionPaddingOaep struct {
	Mgf Mgf `json:"mgf"`
}

func (x RsaEncryptionPadding) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers("RsaEncryptionPadding", []bool{x.Oaep != nil, x.Pkcs1V15 != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Oaep     *RsaEncryptionPaddingOaep `json:"OAEP,omitempty"`
		Pkcs1V15 *struct{}                 `json:"PKCS1_V15,omitempty"`
	}
	obj.Oaep = x.Oaep
	obj.Pkcs1V15 = x.Pkcs1V15
	return json.Marshal(obj)
}
func (x *RsaEncryptionPadding) UnmarshalJSON(data []byte) error {
	x.Oaep = nil
	x.Pkcs1V15 = nil
	var obj struct {
		Oaep     *RsaEncryptionPaddingOaep `json:"OAEP,omitempty"`
		Pkcs1V15 *struct{}                 `json:"PKCS1_V15,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.Oaep = obj.Oaep
	x.Pkcs1V15 = obj.Pkcs1V15
	return nil
}

// Request to perform key wrapping.
type WrapKeyRequest struct {
	// The wrapping key.
	Key *SobjectDescriptor `json:"key,omitempty"`
	// The key to be wrapped.
	Subject *SobjectDescriptor `json:"subject,omitempty"`
	// Id of the key to be wrapped (legacy, mutually exclusive with `subject`).
	Kid *UUID     `json:"kid,omitempty"`
	Alg Algorithm `json:"alg"`
	// Mode is required for symmetric algorithms.
	Mode *CryptMode `json:"mode,omitempty"`
	Iv   *Blob      `json:"iv,omitempty"`
	// Authenticated data is only applicable if mode is GCM.
	Ad *Blob `json:"ad,omitempty"`
	// Tag length is required when mode is GCM.
	TagLen *uint `json:"tag_len,omitempty"`
}

// Result of key wrapping operation.
type WrapKeyResponse struct {
	WrappedKey Blob `json:"wrapped_key"`
	// Initialization vector is only returned for symmetric algorithms.
	Iv *Blob `json:"iv,omitempty"`
	// Tag is only returned for symmetric algorithm with GCM mode.
	Tag *Blob `json:"tag,omitempty"`
}

// Request to perform key unwrapping.
type UnwrapKeyRequest struct {
	Key *SobjectDescriptor `json:"key,omitempty"`
	Alg Algorithm          `json:"alg"`
	// Object type of the key being unwrapped.
	ObjType ObjectType  `json:"obj_type"`
	Rsa     *RsaOptions `json:"rsa,omitempty"`
	// A Security Object previously wrapped with another key.
	WrappedKey Blob `json:"wrapped_key"`
	// Mode is required for symmetric algorithms.
	Mode *CryptMode `json:"mode,omitempty"`
	// Initialization vector is required for symmetric algorithms.
	Iv *Blob `json:"iv,omitempty"`
	// Authenticated data is only applicable if mode is GCM.
	Ad *Blob `json:"ad,omitempty"`
	// Tag is required if mode is GCM.
	Tag *Blob `json:"tag,omitempty"`
	// Name to be given to the resulting security object if persisted.
	Name *string `json:"name,omitempty"`
	// Group ID of the security group that the resulting security object should belong to. The user or
	// application creating this security object must be a member of this group. If no group is
	// specified, the default group for the requesting application will be used.
	GroupID     *UUID   `json:"group_id,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
	Description *string `json:"description,omitempty"`
	// User-defined metadata for the resulting key stored as key-value pairs.
	CustomMetadata *map[string]string `json:"custom_metadata,omitempty"`
	// Optional array of key operations to be enabled for the resulting security object. If not
	// provided the service will provide a default set of key operations. Note that if you provide
	// an empty array, all key operations will be disabled.
	KeyOps    *KeyOperations `json:"key_ops,omitempty"`
	Transient *bool          `json:"transient,omitempty"`
}

// Encrypt data using a symmetric or asymmetric key.
//
// For symmetric ciphers, `mode` (the block cipher mode) is a required field.
// For GCM and CCM modes, `tag_len` is a required field.
// `iv` is optional for symmetric ciphers and unused for asymmetric ciphers. If
// provided, it will be used as the cipher initialization value. Length of `iv`
// must match the initialization value size for the cipher and mode. If not
// provided, SDKMS will create a random iv of the correct length for the cipher
// and mode and return this value in the response.
// Objects of type Opaque, EC, or HMAC may not be used with this API.
func (c *Client) Encrypt(ctx context.Context, body EncryptRequest) (*EncryptResponse, error) {
	u := "/crypto/v1/encrypt"
	var r EncryptResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToEncrypt(ctx context.Context, body EncryptRequest, description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/encrypt"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Begin multi-part encryption.
//
// This API is used when encrypting more data than the client wishes to submit in
// a single request. It supports only symmetric ciphers and only conventional (not
// AEAD) modes of operation. To perform multi-part encryption, the client makes
// one `init` request, zero or more `update` requests, followed by one `final`
// request. The response to init and update requests includes a `state` field. The
// `state` is an opaque data blob that must be supplied unmodified by the client
// with each subsequent request.
func (c *Client) EncryptInit(ctx context.Context, body EncryptInitRequest) (*EncryptInitResponse, error) {
	u := "/crypto/v1/encrypt/init"
	var r EncryptInitResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Continue multi-part encryption.
func (c *Client) EncryptUpdate(ctx context.Context, body EncryptUpdateRequest) (*EncryptUpdateResponse, error) {
	u := "/crypto/v1/encrypt/update"
	var r EncryptUpdateResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Conclude multi-part encryption.
func (c *Client) EncryptFinal(ctx context.Context, body EncryptFinalRequest) (*EncryptFinalResponse, error) {
	u := "/crypto/v1/encrypt/final"
	var r EncryptFinalResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Decrypt data using a symmetric or asymmetric key.
//
// For symmetric ciphers, `mode` (the block cipher mode) is a required field.
// For GCM and CCM modes, `tag_len` is a required field.
// `iv` is required for symmetric ciphers and unused for asymmetric ciphers.
// It must contain the initialization value used when the data was encrypted.
// Objects of type Opaque, EC, or HMAC may not be used with this API.
func (c *Client) Decrypt(ctx context.Context, body DecryptRequest) (*DecryptResponse, error) {
	u := "/crypto/v1/decrypt"
	var r DecryptResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToDecrypt(ctx context.Context, body DecryptRequest, description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/decrypt"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Begin multi-part decryption.
//
// This API is used when decrypting more data than the client wishes to submit in
// a single request. It supports only symmetric ciphers and only conventional (not
// AEAD) modes of operation. To perform multi-part decryption, the client makes
// one `init` request, zero or more `update` requests, followed by one `final`
// request. The response to init and update requests includes a `state` field. The
// `state` is an opaque data blob that must be supplied unmodified by the client
// with each subsequent request.
func (c *Client) DecryptInit(ctx context.Context, body DecryptInitRequest) (*DecryptInitResponse, error) {
	u := "/crypto/v1/decrypt/init"
	var r DecryptInitResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Continue multi-part decryption.
func (c *Client) DecryptUpdate(ctx context.Context, body DecryptUpdateRequest) (*DecryptUpdateResponse, error) {
	u := "/crypto/v1/decrypt/update"
	var r DecryptUpdateResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Conclude multi-part decryption.
func (c *Client) DecryptFinal(ctx context.Context, body DecryptFinalRequest) (*DecryptFinalResponse, error) {
	u := "/crypto/v1/decrypt/final"
	var r DecryptFinalResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Sign with a private key.
func (c *Client) Sign(ctx context.Context, body SignRequest) (*SignResponse, error) {
	u := "/crypto/v1/sign"
	var r SignResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToSign(ctx context.Context, body SignRequest, description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/sign"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Verify a signature with a public key.
func (c *Client) Verify(ctx context.Context, body VerifyRequest) (*VerifyResponse, error) {
	u := "/crypto/v1/verify"
	var r VerifyResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Wrap a security object with another security object.
//
// Wrap (encrypt) an existing security object with a key. This allows keys to be
// securely exported from SDKMS so they can be later imported into SDKMS or
// another key management system.
// The key being wrapped must have the export operation enabled. The wrapping key
// must have the wrapkey operation enabled.
//
// The following wrapping operations are supported:
//   - Symmetric keys, HMAC keys, opaque objects, and secret objects may be wrapped
//     with symmetric or asymmetric keys.
//   - Asymmetric keys may be wrapped with symmetric keys. Wrapping an asymmetric
//     key with an asymmetric key is not supported.
//
// When wrapping with an asymmetric key, the wrapped object size must fit as
// plaintext for the wrapping key size and algorithm.
func (c *Client) Wrap(ctx context.Context, body WrapKeyRequest) (*WrapKeyResponse, error) {
	u := "/crypto/v1/wrapkey"
	var r WrapKeyResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToWrap(ctx context.Context, body WrapKeyRequest, description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/wrapkey"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Unwrap a security object with another security object.
//
// Unwrap (decrypt) a wrapped key and import it into SDKMS. This allows one to
// securely import security objects into SDKMS that were previously wrapped by
// SDKMS or another key management system. A new security object will be created
// in SDKMS with the unwrapped data.
// The wrapping key must have the unwrapkey operation enabled.
// The `obj_type` parameter specifies the object type of the security object being
// unwrapped.
func (c *Client) Unwrap(ctx context.Context, body UnwrapKeyRequest) (*Sobject, error) {
	u := "/crypto/v1/unwrapkey"
	var r Sobject
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToUnwrap(ctx context.Context, body UnwrapKeyRequest, description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/unwrapkey"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Compute MAC using a key.
//
// Compute a cryptographic Message Authentication Code (MAC) on a message using a
// symmetric key. The key must have the MACGenerate operation enabled.
// Asymmetric keys may not be used with this API.
func (c *Client) Mac(ctx context.Context, body MacRequest) (*MacResponse, error) {
	u := "/crypto/v1/mac"
	var r MacResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToMac(ctx context.Context, body MacRequest, description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/mac"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Verify MAC.
func (c *Client) MacVerify(ctx context.Context, body VerifyMacRequest) (*VerifyResponse, error) {
	u := "/crypto/v1/macverify"
	var r VerifyResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Derive a new key from an existing key.
func (c *Client) Derive(ctx context.Context, body DeriveKeyRequest) (*Sobject, error) {
	u := "/crypto/v1/derive"
	var r Sobject
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToDerive(ctx context.Context, body DeriveKeyRequest, description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/derive"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Agree on a key from two other keys.
//
// Perform a cryptographic key agreement operation between a public key and a
// private key. Both keys must have been generated from the same parameters (e.g.
// the same elliptic curve). Both keys must allow the AGREEKEY operation. The
// request body contains the requested properties for the new key as well as the
// mechanism (e.g. Diffie-Hellman) to be used to produce the key material for the
// new key. The output of this API should not be used directly as a cryptographic
// key. The target object type should be HMAC or Secret, and a key derivation
// procedure should be used to derive the actual key material.
func (c *Client) Agree(ctx context.Context, body AgreeKeyRequest) (*Sobject, error) {
	u := "/crypto/v1/agree"
	var r Sobject
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToAgree(ctx context.Context, body AgreeKeyRequest, description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/agree"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Compute digest (hash) of data.
func (c *Client) CreateDigest(ctx context.Context, body DigestRequest) (*DigestResponse, error) {
	u := "/crypto/v1/digest"
	var r DigestResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
