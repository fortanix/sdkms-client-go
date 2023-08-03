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
)

// Options to use for key agreement mechanism.
type AgreeKeyMechanism string

// List of supported AgreeKeyMechanism values
const (
	// Diffie-Hellman key exchange mechanism
	AgreeKeyMechanismDiffieHellman AgreeKeyMechanism = "diffie_hellman"
)

// Request body to perform key agreement.
type AgreeKeyRequest struct {
	// Activation date of the agreed key
	ActivationDate *Time `json:"activation_date,omitempty"`
	// Deactivation date of the agreed key
	DeactivationDate *Time `json:"deactivation_date,omitempty"`
	// Identifier of the private key used for agreement
	PrivateKey SobjectDescriptor `json:"private_key"`
	// Identifier of the public key used for agreement
	PublicKey SobjectDescriptor `json:"public_key"`
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
	KeySize uint32 `json:"key_size"`
	// Whether the agreed key should have cryptographic operations enabled
	Enabled *bool `json:"enabled,omitempty"`
	// Description of the agreed key
	Description *string `json:"description,omitempty"`
	// User-defined metadata for this key stored as key-value pairs.
	CustomMetadata *map[string]string `json:"custom_metadata,omitempty"`
	// Optional array of key operations to be enabled for this security object. If not
	// provided the service will provide a default set of key operations. Note that if you
	// provide an empty array, all key operations will be disabled.
	KeyOps *KeyOperations `json:"key_ops,omitempty"`
	// State of the agreed key
	State *SobjectState `json:"state,omitempty"`
	// If set to true, the resulting key will be transient.
	Transient *bool `json:"transient,omitempty"`
}

// Request body to finalise a multi-part decryption.
type DecryptFinalRequest struct {
	// Identifier of the sobject used for finalizing multi-part decryption
	Key *SobjectDescriptor `json:"key,omitempty"`
	// Current state of the encrypted cipher
	State Blob `json:"state"`
	// Tag value of the encrypted cipher. Only applicable when using GCM mode.
	Tag *Blob `json:"tag,omitempty"`
}

// Final response body of a multi-part decryption.
type DecryptFinalResponse struct {
	// Decrypted bytes
	Plain Blob `json:"plain"`
}

// Request body to initialize multi-part decryption.
type DecryptInitRequest struct {
	// Identifier of the sobject used for initializing multi-part decryption
	Key *SobjectDescriptor `json:"key,omitempty"`
	// Algorithm used for multi-part decryption
	Alg *Algorithm `json:"alg,omitempty"`
	// Mode of multi-part decryption. Required for symmetric algorithms.
	Mode *CipherMode `json:"mode,omitempty"`
	// Initialization vector. Required for symmetric algorithms.
	Iv *Blob `json:"iv,omitempty"`
	// Authenticated data. Only applicable when using GCM mode.
	Ad *Blob `json:"ad,omitempty"`
}

// Response body for initializing multi-part decryption.
type DecryptInitResponse struct {
	// The key id is returned for non-transient keys.
	Kid *UUID `json:"kid,omitempty"`
	// Opaque data, not to be interpreted or modified by the client and must be provided with next request.
	State Blob `json:"state"`
}

// Request to decrypt data.
type DecryptRequest struct {
	// Reference to the sobject to use for decryption. This can be a key
	// ID, key name, or a transient key blob.
	Key *SobjectDescriptor `json:"key,omitempty"`
	// Decryption algorithm to use. If specified, this must be compatible
	// with the key type; for example, an RSA key cannot be used with AES.
	Alg *Algorithm `json:"alg,omitempty"`
	// Ciphertext bytes to be decrypted.
	//
	// Note that when performing format-preserving decryption (i.e.,
	// detokenization), the ciphertext should be encoded as UTF-8 bytes.
	Cipher Blob `json:"cipher"`
	// Decryption mode to use. This is required for symmetric decryption.
	// For RSA decryption, the mode can be used to optionally specify the
	// padding to use. For all other algorithms, this field should not be
	// specified.
	Mode *CryptMode `json:"mode,omitempty"`
	// The initialization vector to use, required for modes that take IVs
	// (and irrelevant otherwise).
	Iv *Blob `json:"iv,omitempty"`
	// The authenticated data to use. This is only applicable when using
	// authenticated decryption modes (like GCM or CCM).
	Ad *Blob `json:"ad,omitempty"`
	// The authentication tag, relevant for authenticated encryption modes
	// (i.e., GCM or CCM), and otherwise irrelevant.
	Tag *Blob `json:"tag,omitempty"`
	// Whether to returned a masked result when detokenizing (i.e., when
	// decrypting using the FF1/FPE mode). Defaults to false.
	//
	// This field is only useful if the app has the `DECRYPT` permission.
	// In such situations, when this field is `true`, decryption returns
	// masked output. However, with the `MASKDECRYPT` permission, this field
	// is ignored and detokenization will always return the masked output.
	Masked *bool `json:"masked,omitempty"`
}

// Response of a decryption request.
type DecryptResponse struct {
	// The ID of the key used for decryption. Returned for non-transient keys.
	Kid *UUID `json:"kid,omitempty"`
	// Decrypted plaintext bytes.
	//
	// Note that when performing format-preserving decryption (i.e.,
	// detokenization), the plaintext is encoded as UTF-8 bytes.
	Plain Blob `json:"plain"`
}

// Request body for multi-part decryption.
type DecryptUpdateRequest struct {
	// Identifier of the sobject used for multi-part decryption
	Key *SobjectDescriptor `json:"key,omitempty"`
	// Encrypted bytes
	Cipher Blob `json:"cipher"`
	// Currrent state of the encrypted cipher
	State Blob `json:"state"`
}

// Reponse body of multi-part decryption.
type DecryptUpdateResponse struct {
	// Decrypted bytes
	Plain Blob `json:"plain"`
	// Current state of the multi part decrypted object.
	// Opaque data, not to be interpreted or modified by the client and must be provided with next request.
	State Blob `json:"state"`
}

// Mechanism to be used when deriving a new key from an existing key.
type DeriveKeyMechanism struct {
	EncryptData        *EncryptRequest
	Bip32MasterKey     *DeriveKeyMechanismBip32MasterKey
	Bip32HardenedChild *DeriveKeyMechanismBip32HardenedChild
	Hkdf               *DeriveKeyMechanismHkdf
}
type DeriveKeyMechanismBip32MasterKey struct {
	Network Bip32Network `json:"network"`
}
type DeriveKeyMechanismBip32HardenedChild struct {
	Index uint32 `json:"index"`
}
type DeriveKeyMechanismHkdf struct {
	HashAlg DigestAlgorithm `json:"hash_alg"`
	Info    *Blob           `json:"info,omitempty"`
	Salt    *Blob           `json:"salt,omitempty"`
}

func (x DeriveKeyMechanism) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"DeriveKeyMechanism",
		[]bool{x.EncryptData != nil,
			x.Bip32MasterKey != nil,
			x.Bip32HardenedChild != nil,
			x.Hkdf != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		EncryptData        *EncryptRequest                       `json:"encrypt_data,omitempty"`
		Bip32MasterKey     *DeriveKeyMechanismBip32MasterKey     `json:"bip32_master_key,omitempty"`
		Bip32HardenedChild *DeriveKeyMechanismBip32HardenedChild `json:"bip32_hardened_child,omitempty"`
		Hkdf               *DeriveKeyMechanismHkdf               `json:"hkdf,omitempty"`
	}
	obj.EncryptData = x.EncryptData
	obj.Bip32MasterKey = x.Bip32MasterKey
	obj.Bip32HardenedChild = x.Bip32HardenedChild
	obj.Hkdf = x.Hkdf
	return json.Marshal(obj)
}
func (x *DeriveKeyMechanism) UnmarshalJSON(data []byte) error {
	x.EncryptData = nil
	x.Bip32MasterKey = nil
	x.Bip32HardenedChild = nil
	x.Hkdf = nil
	var obj struct {
		EncryptData        *EncryptRequest                       `json:"encrypt_data,omitempty"`
		Bip32MasterKey     *DeriveKeyMechanismBip32MasterKey     `json:"bip32_master_key,omitempty"`
		Bip32HardenedChild *DeriveKeyMechanismBip32HardenedChild `json:"bip32_hardened_child,omitempty"`
		Hkdf               *DeriveKeyMechanismHkdf               `json:"hkdf,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.EncryptData = obj.EncryptData
	x.Bip32MasterKey = obj.Bip32MasterKey
	x.Bip32HardenedChild = obj.Bip32HardenedChild
	x.Hkdf = obj.Hkdf
	return nil
}

// Request body to derive a key.
type DeriveKeyRequest struct {
	// Activation date of the derived key
	ActivationDate *Time `json:"activation_date,omitempty"`
	// Deactivation date of the derived key
	DeactivationDate *Time `json:"deactivation_date,omitempty"`
	// Identifier of the sobject from which new key will be derived
	Key *SobjectDescriptor `json:"key,omitempty"`
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
	Enabled *bool `json:"enabled,omitempty"`
	// Description for derived key
	Description *string `json:"description,omitempty"`
	// User-defined metadata for this key stored as key-value pairs.
	CustomMetadata *map[string]string `json:"custom_metadata,omitempty"`
	// Optional array of key operations to be enabled for this security object. If not
	// provided the service will provide a default set of key operations. Note that if you
	// provide an empty array, all key operations will be disabled.
	KeyOps *KeyOperations `json:"key_ops,omitempty"`
	// State of the derived key
	State *SobjectState `json:"state,omitempty"`
	// If set to true, the derived key will be transient.
	Transient *bool `json:"transient,omitempty"`
}

// Request to compute the hash of arbitrary data.
type DigestRequest struct {
	// Hash Algorithm to compute digest
	Alg DigestAlgorithm `json:"alg"`
	// Raw binary data
	Data Blob `json:"data"`
}

// Response body of a hash operation.
type DigestResponse struct {
	// Hashed binary output
	Digest Blob `json:"digest"`
}

// Request body to finalize a multi-part encryption.
type EncryptFinalRequest struct {
	// Reference to the sobject used for finalizing multi-part encryption
	Key *SobjectDescriptor `json:"key,omitempty"`
	// Last state of the encrypted cipher
	State Blob `json:"state"`
	// Size of authentication tag.
	// Tag length is only applicable when using GCM mode.
	TagLen *uint `json:"tag_len,omitempty"`
}

// Final response body of a multi-part encryption.
type EncryptFinalResponse struct {
	// Final encrypted bytes
	Cipher Blob `json:"cipher"`
	// Tag is only returned for symmetric encryption with GCM mode.
	Tag *Blob `json:"tag,omitempty"`
}

// Request body to initialize multi-part encryption.
type EncryptInitRequest struct {
	// Reference to the sobject used for initializing multi-part encryption
	Key *SobjectDescriptor `json:"key,omitempty"`
	// Algorithm to be used for multipart encryption
	Alg Algorithm `json:"alg"`
	// Cipher mode of operation for symmetric multi-part encryption
	Mode *CipherMode `json:"mode,omitempty"`
	// Initialization vector
	Iv *Blob `json:"iv,omitempty"`
	// Authenticated data, required for AEAD algorithms
	Ad *Blob `json:"ad,omitempty"`
}

// Response body of initializing multi-part encryption.
type EncryptInitResponse struct {
	// Key id is returned for non-transient keys.
	Kid *UUID `json:"kid,omitempty"`
	// Initialization vector. Only returned for symmetric encryption.
	Iv *Blob `json:"iv,omitempty"`
	// Current state of the encrypted cipher.
	// Opaque data, not to be interpreted or modified by the client and must be provided with next request.
	State Blob `json:"state"`
}

// Request to encrypt data.
type EncryptRequest struct {
	// Reference to the sobject to use for encryption. This can be a key
	// ID, key name, or a transient key blob.
	Key *SobjectDescriptor `json:"key,omitempty"`
	// Encryption algorithm to use. The algorithm must be compatible with
	// the key type; for example, an RSA key cannot be used with AES.
	Alg Algorithm `json:"alg"`
	// Plaintext bytes to be encrypted.
	//
	// Note that when performing format-preserving encryption (i.e.,
	// tokenization), the plaintext should be encoded as UTF-8 bytes.
	Plain Blob `json:"plain"`
	// Encryption mode to use. This is required for symmetric encryption.
	// For RSA encryption, the mode can be used to optionally specify the
	// padding to use. For all other algorithms, this field should not be
	// specified.
	Mode *CryptMode `json:"mode,omitempty"`
	// The initialization vector to use. This is only applicable to modes
	// that take IVs, and will be randomly generated if not specified.
	Iv *Blob `json:"iv,omitempty"`
	// The authenticated data to use. This is only applicable when using
	// authenticated encryption modes (like GCM or CCM).
	Ad *Blob `json:"ad,omitempty"`
	// The length of the authentication tag, in bits, for authenticated
	// encryption modes (i.e., GCM or CCM). For other modes, this field
	// is irrelevant.
	TagLen *uint `json:"tag_len,omitempty"`
}

// Response of an encryption request.
type EncryptResponse struct {
	// The ID of the key used for encryption. Returned for non-transient keys.
	Kid *UUID `json:"kid,omitempty"`
	// Encrypted ciphertext bytes.
	//
	// Note that when performing format-preserving encryption (i.e.,
	// tokenization), the ciphertext is encoded as UTF-8 bytes.
	Cipher Blob `json:"cipher"`
	// The intialization vector used during encryption. This is only
	// applicable for certain symmetric encryption modes.
	Iv *Blob `json:"iv,omitempty"`
	// When using the GCM or CCM modes, the tag is returned from
	// authenticated encryption.
	Tag *Blob `json:"tag,omitempty"`
}

// Request body for continuing multi part encryption
type EncryptUpdateRequest struct {
	// Reference to the sobject used for continuing multi part encryption
	Key *SobjectDescriptor `json:"key,omitempty"`
	// Data bytes to be encrypted
	Plain Blob `json:"plain"`
	// Last state of the encrypted cipher
	State Blob `json:"state"`
}

// Response body of multi-part encryption.
type EncryptUpdateResponse struct {
	// Encrypted bytes object from multi-part flow
	Cipher Blob `json:"cipher"`
	// Current state of the encrypted cipher
	// Opaque data, not to be interpreted or modified by the client and must be provided with next request.
	State Blob `json:"state"`
}

// Key Format
type KeyFormat string

// List of supported KeyFormat values
const (
	KeyFormatDefault KeyFormat = "Default"
	KeyFormatPkcs8   KeyFormat = "Pkcs8"
)

// Request to compute a MAC.
type MacRequest struct {
	// Reference to the sobject with which to compute a MAC.
	// This can be a key ID, key name, or a transient key blob.
	Key *SobjectDescriptor `json:"key,omitempty"`
	// The hash algorithm to use when computing an HMAC. Irrelevant
	// if computing a CMAC.
	Alg *DigestAlgorithm `json:"alg,omitempty"`
	// The data for which to generate a MAC
	Data Blob `json:"data"`
}

// Response of an MAC verification request.
type MacResponse struct {
	// The ID of the key used to compute the MAC. Returned for
	// non-transient keys
	Kid *UUID `json:"kid,omitempty"`
	// MAC generated for the input data
	Mac Blob `json:"mac"`
}

// Options for mechanism to be used when transforming a key
type TransformKeyMechanism struct {
	Bip32WeakChild *TransformKeyMechanismBip32WeakChild
}
type TransformKeyMechanismBip32WeakChild struct {
	// The index of a weak child is an integer between 0 and 2**31 - 1.
	Index uint32 `json:"index"`
}

func (x TransformKeyMechanism) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers(
		"TransformKeyMechanism",
		[]bool{x.Bip32WeakChild != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Bip32WeakChild *TransformKeyMechanismBip32WeakChild `json:"bip32_weak_child,omitempty"`
	}
	obj.Bip32WeakChild = x.Bip32WeakChild
	return json.Marshal(obj)
}
func (x *TransformKeyMechanism) UnmarshalJSON(data []byte) error {
	x.Bip32WeakChild = nil
	var obj struct {
		Bip32WeakChild *TransformKeyMechanismBip32WeakChild `json:"bip32_weak_child,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.Bip32WeakChild = obj.Bip32WeakChild
	return nil
}

// Request body to transform a key.
type TransformKeyRequest struct {
	// Activation date of the transformed key
	ActivationDate *Time `json:"activation_date,omitempty"`
	// Deactivation date of the transformed key
	DeactivationDate *Time `json:"deactivation_date,omitempty"`
	// Identifier of the sobject which will be transformed
	Key *SobjectDescriptor `json:"key,omitempty"`
	// Name of the transformed key. Key names must be unique within an account.
	Name *string `json:"name,omitempty"`
	// Group ID of the group that this security object should belong to. The user or
	// application creating this security object must be a member of this group. If no group is
	// specified, the default group for the requesting application will be used.
	GroupID *UUID `json:"group_id,omitempty"`
	// Type of the transformed key.
	KeyType ObjectType `json:"key_type"`
	// Mechanism to use for key transformation.
	Mechanism TransformKeyMechanism `json:"mechanism"`
	// Whether the transformed key should have cryptographic operations enabled.
	Enabled *bool `json:"enabled,omitempty"`
	// Description of the transformed key
	Description *string `json:"description,omitempty"`
	// User-defined metadata for this key stored as key-value pairs.
	CustomMetadata *map[string]string `json:"custom_metadata,omitempty"`
	// Optional array of key operations to be enabled for this security object. If not
	// provided the service will provide a default set of key operations. Note that if you
	// provide an empty array, all key operations will be disabled.
	KeyOps *KeyOperations `json:"key_ops,omitempty"`
	// State of the transformed key
	State *SobjectState `json:"state,omitempty"`
	// If set to true, the transformed key will be transient.
	Transient *bool `json:"transient,omitempty"`
}

// Request to unwrap an sobject with another sobject.
type UnwrapKeyRequest struct {
	// Reference to the unwrapping key. This can be a key ID, key name,
	// or a transient key blob. It may also be a password (if unwrapping
	// PKCS #8 blobs).
	Key *SobjectDescriptor `json:"key,omitempty"`
	// Algorithm to use for key unwrapping. The algorithm must be
	// compatible with the key type; for example, an RSA key cannot
	// be used with AES.
	Alg Algorithm `json:"alg"`
	// Object type of the key being unwrapped
	ObjType ObjectType `json:"obj_type"`
	// RSA-specific options for the key being unwrapped
	Rsa *RsaOptions `json:"rsa,omitempty"`
	// A security object previously wrapped with another key
	WrappedKey Blob `json:"wrapped_key"`
	// Decryption mode to use. This is required for unwrapping via
	// symmetric decryption. For RSA-based wrapping, the mode can be used
	// to optionally specify the padding to use. For all other algorithms,
	// this field should not be specified.
	Mode *CryptMode `json:"mode,omitempty"`
	// The initialization vector to use, required for modes that take IVs
	// (and irrelevant otherwise).
	Iv *Blob `json:"iv,omitempty"`
	// The authenticated data to use. This is only applicable when using
	// authenticated decryption modes (i.e., GCM or CCM).
	Ad *Blob `json:"ad,omitempty"`
	// The authentication tag, relevant for authenticated encryption modes
	// (i.e., GCM or CCM), and otherwise irrelevant.
	Tag *Blob `json:"tag,omitempty"`
	// Name to be given to the resulting security object, if persisted
	Name *string `json:"name,omitempty"`
	// ID of the group that the unwrapped security object should belong to
	// (if persisted). The user or application creating this security object
	// must be a member of this group. If no group is specified, and the
	// requester is an app, the app's default group will be used.
	GroupID *UUID `json:"group_id,omitempty"`
	// Whether the unwrapped key should have cryptographic operations enabled.
	// Defaults to true.
	Enabled *bool `json:"enabled,omitempty"`
	// User-defined description of the unwrapped key
	Description *string `json:"description,omitempty"`
	// User-defined metadata for the resulting key, stored as key-value pairs.
	CustomMetadata *map[string]string `json:"custom_metadata,omitempty"`
	// Optional array of key operations to be enabled for the resulting security
	// object. If not provided, DSM will provide a default set of key operations.
	// Note that an empty array will result in all key operations being disabled.
	KeyOps *KeyOperations `json:"key_ops,omitempty"`
	// Whether the unwrapped key should be a transient key
	Transient *bool `json:"transient,omitempty"`
	// Checksum value of the wrapped key
	Kcv *string `json:"kcv,omitempty"`
}

// Request to verify a MAC.
type VerifyMacRequest struct {
	// Reference to the sobject with which to verify a MAC.
	// This can be a key ID, key name, or a transient key blob.
	Key *SobjectDescriptor `json:"key,omitempty"`
	// The hash algorithm used when computing the HMAC. Irrelevant
	// if verifying a CMAC.
	Alg *DigestAlgorithm `json:"alg,omitempty"`
	// The data over which the MAC needs to be verified
	Data Blob `json:"data"`
	// The MAC to verify. Note that the previously available
	// field `digest` is deprecated; this field should be used
	// instead.
	Mac *Blob `json:"mac,omitempty"`
}

// Request to wrap an sobject with another sobject.
type WrapKeyRequest struct {
	// Reference to the wrapping key. This can be a key ID, key name,
	// or a transient key blob.
	Key *SobjectDescriptor `json:"key,omitempty"`
	// Reference to the sobject being wrapped. This can be an sobject
	// ID, sobject name, or a transient sobject blob.
	//
	// If specified, the `kid` field should not be present.
	Subject *SobjectDescriptor `json:"subject,omitempty"`
	// ID of the sobject to be wrapped. (This is a legacy field,
	// mutually exclusive with `subject`).
	Kid *UUID `json:"kid,omitempty"`
	// Algorithm to use for key wrapping. The algorithm must be
	// compatible with the key type; for example, an RSA key cannot
	// be used with AES.
	Alg Algorithm `json:"alg"`
	// Encryption mode to use. This is required for wrapping via symmetric
	// encryption. For RSA-based wrapping, the mode can be used to
	// optionally specify the padding to use. For all other algorithms,
	// this field should not be specified.
	Mode *CryptMode `json:"mode,omitempty"`
	// The initialization vector to use. This is only applicable to modes
	// that take IVs, and will be randomly generated if not specified.
	Iv *Blob `json:"iv,omitempty"`
	// The authenticated data to use. This is only applicable when using
	// authenticated encryption modes (i.e., GCM or CCM).
	Ad *Blob `json:"ad,omitempty"`
	// The length of the authentication tag, in bits, for authenticated
	// encryption modes (i.e., GCM or CCM). For other modes, this field
	// is irrelevant.
	TagLen *uint `json:"tag_len,omitempty"`
	// Format of the wrapped key
	KeyFormat *KeyFormat `json:"key_format,omitempty"`
}

// Result of a key wrapping request.
type WrapKeyResponse struct {
	// The wrapped key blob
	WrappedKey Blob `json:"wrapped_key"`
	// The intialization vector used during encryption. This is only
	// applicable for certain symmetric encryption modes.
	Iv *Blob `json:"iv,omitempty"`
	// The authenticated tag returned from authenticated encryption
	// (i.e., using GCM or CCM mode). For other modes, this field is
	// not applicable.
	Tag *Blob `json:"tag,omitempty"`
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

func (c *Client) RequestApprovalToAgree(
	ctx context.Context,
	body AgreeKeyRequest,
	description *string) (*ApprovalRequest, error) {
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

// Decrypt data using a symmetric or asymmetric key.
//
// For symmetric ciphers, `mode` (the block cipher mode) is a required field.
// For GCM and CCM modes, `tag_len` is a required field.
// `iv` is required for symmetric ciphers and unused for asymmetric ciphers.
// If the mode requires one, the request must contain the initialization vector
// used when the data was encrypted.
// Objects of type Opaque, EC, or HMAC may not be used with this API.
func (c *Client) Decrypt(ctx context.Context, body DecryptRequest) (*DecryptResponse, error) {
	u := "/crypto/v1/decrypt"
	var r DecryptResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToDecrypt(
	ctx context.Context,
	body DecryptRequest,
	description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/decrypt"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Conclude multi-part decryption. See `/crypto/v1/decrypt/init` for
// more details.
func (c *Client) DecryptFinal(ctx context.Context, body DecryptFinalRequest) (*DecryptFinalResponse, error) {
	u := "/crypto/v1/decrypt/final"
	var r DecryptFinalResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Begin multi-part decryption.
//
// This API is used when decrypting more data than the client wishes
// to submit in a single request. It supports only symmetric ciphers
// and CBC, CBCNOPAD, CTR, and GCM modes of operation. To perform
// multi-part decryption, the client makes one request to the `init`
// resource, zero or more requests to the `update` resource, followed
// by one request to the `final` resource. The response to init and
// update requests includes a `state` field. The `state` is an opaque
// data blob that must be supplied unmodified by the client with each
// subsequent request.
func (c *Client) DecryptInit(ctx context.Context, body DecryptInitRequest) (*DecryptInitResponse, error) {
	u := "/crypto/v1/decrypt/init"
	var r DecryptInitResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Continue multi-part decryption. See `/crypto/v1/decrypt/init` for
// more details.
func (c *Client) DecryptUpdate(ctx context.Context, body DecryptUpdateRequest) (*DecryptUpdateResponse, error) {
	u := "/crypto/v1/decrypt/update"
	var r DecryptUpdateResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Derive a new key from an existing key.
//
// The request body contains the requested properties for the new key
// as well as the mechanism to be used to produce the key material for
// the new key.
func (c *Client) Derive(ctx context.Context, body DeriveKeyRequest) (*Sobject, error) {
	u := "/crypto/v1/derive"
	var r Sobject
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToDerive(
	ctx context.Context,
	body DeriveKeyRequest,
	description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/derive"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Encrypt data using a symmetric or asymmetric key.
//
// For symmetric ciphers, `mode` (the block cipher mode) is a required field.
// For GCM and CCM modes, `tag_len` is a required field.
// `iv` is optional for symmetric ciphers and unused for asymmetric ciphers. If
// provided, it will be used as the cipher initialization vector. The length of
// `iv` must match the initialization vector size for the cipher and mode. If not
// provided, a random iv of the correct length is created and returned in the
// response.
// Objects of type Opaque, EC, or HMAC may not be used with this API.
func (c *Client) Encrypt(ctx context.Context, body EncryptRequest) (*EncryptResponse, error) {
	u := "/crypto/v1/encrypt"
	var r EncryptResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToEncrypt(
	ctx context.Context,
	body EncryptRequest,
	description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/encrypt"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Conclude multi-part encryption. See `/crypto/v1/encrypt/init`
// for more details.
func (c *Client) EncryptFinal(ctx context.Context, body EncryptFinalRequest) (*EncryptFinalResponse, error) {
	u := "/crypto/v1/encrypt/final"
	var r EncryptFinalResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Begin multi-part encryption.
//
// This API is used when encrypting more data than the client wishes
// to submit in a single request. It supports only symmetric ciphers
// and CBC, CBCNOPAD, CTR, and GCM modes of operation. To perform
// multi-part encryption, the client makes one request to the `init`
// resource, zero or more requests to the `update` resource, followed
// by one request to the `final` resource. The response to init and
// update requests includes a `state` field. The `state` is an opaque
// data blob that must be supplied unmodified by the client with each
// subsequent request.
func (c *Client) EncryptInit(ctx context.Context, body EncryptInitRequest) (*EncryptInitResponse, error) {
	u := "/crypto/v1/encrypt/init"
	var r EncryptInitResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Continue multi-part encryption. See `/crypto/v1/encrypt/init`
// for more details.
func (c *Client) EncryptUpdate(ctx context.Context, body EncryptUpdateRequest) (*EncryptUpdateResponse, error) {
	u := "/crypto/v1/encrypt/update"
	var r EncryptUpdateResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Compute a message authentication code (HMAC or CMAC). The key being used
// should have the `MACGENERATE` key operation.
//
// A key of type `HMAC` needs to be used for computing an HMAC, and the hash
// algorithm should be present in the request.
//
// AES, ARIA, DES3, and SEED keys can be used for computing a CMAC. No hash
// algorithm should be specified for CMAC computation.
// The digest algorithm shouldn't be specified in case of CMAC.
func (c *Client) Mac(ctx context.Context, body MacRequest) (*MacResponse, error) {
	u := "/crypto/v1/mac"
	var r MacResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToMac(
	ctx context.Context,
	body MacRequest,
	description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/mac"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Verify the input MAC. The key used must have the `MACVERIFY`
// key operation.
func (c *Client) MacVerify(ctx context.Context, body VerifyMacRequest) (*VerifyResponse, error) {
	u := "/crypto/v1/macverify"
	var r VerifyResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Sign with a private key. The key must be asymmetric
// and have the `SIGN` key operation enabled.
func (c *Client) Sign(ctx context.Context, body SignRequest) (*SignResponse, error) {
	u := "/crypto/v1/sign"
	var r SignResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToSign(
	ctx context.Context,
	body SignRequest,
	description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/sign"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Transform an existing key into a new one.
//
// Some protocols (such as BIP32) require weak forms of key derivation,
// where the resulting key can be used to recompute the original key.
func (c *Client) Transform(ctx context.Context, body TransformKeyRequest) (*Sobject, error) {
	u := "/crypto/v1/transform"
	var r Sobject
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) RequestApprovalToTransform(
	ctx context.Context,
	body TransformKeyRequest,
	description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/transform"
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
// Unwrap (decrypt) a wrapped key and import it into DSM. This allows one to
// securely import security objects into DSM that were previously wrapped by
// DSM or another key management system. A new security object will be created
// in DSM with the unwrapped data.
// The wrapping key must have the `UNWRAPKEY` operation enabled.
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

func (c *Client) RequestApprovalToUnwrap(
	ctx context.Context,
	body UnwrapKeyRequest,
	description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/unwrapkey"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Verify a signature with a public key. The verifying key must
// be an asymmetric key with the `VERIFY` key operation enabled.
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
// securely exported from DSM so they can be later imported into DSM or
// another key management system.
// The key being wrapped must have the `EXPORT` operation enabled. The wrapping key
// must have the `WRAPKEY` operation enabled.
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

func (c *Client) RequestApprovalToWrap(
	ctx context.Context,
	body WrapKeyRequest,
	description *string) (*ApprovalRequest, error) {
	u := "/crypto/v1/wrapkey"
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   &u,
		Body:        &body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}
