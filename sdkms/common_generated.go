/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package sdkms

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
)

// Operations allowed to be performed on a given key.
type KeyOperations uint64

// List of supported KeyOperations values
const (
	KeyOperationsSign KeyOperations = 1 << iota
	KeyOperationsVerify
	KeyOperationsEncrypt
	KeyOperationsDecrypt
	KeyOperationsWrapkey
	KeyOperationsUnwrapkey
	KeyOperationsDerivekey
	KeyOperationsMacgenerate
	KeyOperationsMacverify
	KeyOperationsExport
	KeyOperationsAppmanageable
	KeyOperationsHighvolume
	KeyOperationsAgreekey
)

// MarshalJSON converts KeyOperations to an array of strings
func (x KeyOperations) MarshalJSON() ([]byte, error) {
	s := make([]string, 0)
	if x&KeyOperationsSign == KeyOperationsSign {
		s = append(s, "SIGN")
	}
	if x&KeyOperationsVerify == KeyOperationsVerify {
		s = append(s, "VERIFY")
	}
	if x&KeyOperationsEncrypt == KeyOperationsEncrypt {
		s = append(s, "ENCRYPT")
	}
	if x&KeyOperationsDecrypt == KeyOperationsDecrypt {
		s = append(s, "DECRYPT")
	}
	if x&KeyOperationsWrapkey == KeyOperationsWrapkey {
		s = append(s, "WRAPKEY")
	}
	if x&KeyOperationsUnwrapkey == KeyOperationsUnwrapkey {
		s = append(s, "UNWRAPKEY")
	}
	if x&KeyOperationsDerivekey == KeyOperationsDerivekey {
		s = append(s, "DERIVEKEY")
	}
	if x&KeyOperationsMacgenerate == KeyOperationsMacgenerate {
		s = append(s, "MACGENERATE")
	}
	if x&KeyOperationsMacverify == KeyOperationsMacverify {
		s = append(s, "MACVERIFY")
	}
	if x&KeyOperationsExport == KeyOperationsExport {
		s = append(s, "EXPORT")
	}
	if x&KeyOperationsAppmanageable == KeyOperationsAppmanageable {
		s = append(s, "APPMANAGEABLE")
	}
	if x&KeyOperationsHighvolume == KeyOperationsHighvolume {
		s = append(s, "HIGHVOLUME")
	}
	if x&KeyOperationsAgreekey == KeyOperationsAgreekey {
		s = append(s, "AGREEKEY")
	}
	return json.Marshal(s)
}

// UnmarshalJSON converts array of strings to KeyOperations
func (x *KeyOperations) UnmarshalJSON(data []byte) error {
	*x = 0
	var s []string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	for _, v := range s {
		switch v {
		case "SIGN":
			*x = *x | KeyOperationsSign
		case "VERIFY":
			*x = *x | KeyOperationsVerify
		case "ENCRYPT":
			*x = *x | KeyOperationsEncrypt
		case "DECRYPT":
			*x = *x | KeyOperationsDecrypt
		case "WRAPKEY":
			*x = *x | KeyOperationsWrapkey
		case "UNWRAPKEY":
			*x = *x | KeyOperationsUnwrapkey
		case "DERIVEKEY":
			*x = *x | KeyOperationsDerivekey
		case "MACGENERATE":
			*x = *x | KeyOperationsMacgenerate
		case "MACVERIFY":
			*x = *x | KeyOperationsMacverify
		case "EXPORT":
			*x = *x | KeyOperationsExport
		case "APPMANAGEABLE":
			*x = *x | KeyOperationsAppmanageable
		case "HIGHVOLUME":
			*x = *x | KeyOperationsHighvolume
		case "AGREEKEY":
			*x = *x | KeyOperationsAgreekey
		}
	}
	return nil
}

// Type of security object.
type ObjectType string

// List of supported ObjectType values
const (
	ObjectTypeAes         ObjectType = "AES"
	ObjectTypeDes         ObjectType = "DES"
	ObjectTypeDes3        ObjectType = "DES3"
	ObjectTypeRsa         ObjectType = "RSA"
	ObjectTypeEc          ObjectType = "EC"
	ObjectTypeOpaque      ObjectType = "OPAQUE"
	ObjectTypeHmac        ObjectType = "HMAC"
	ObjectTypeSecret      ObjectType = "SECRET"
	ObjectTypeCertificate ObjectType = "CERTIFICATE"
)

// The origin of a security object - where it was created / generated.
type ObjectOrigin string

// List of supported ObjectOrigin values
const (
	ObjectOriginFortanixHSM ObjectOrigin = "FortanixHSM"
	ObjectOriginTransient   ObjectOrigin = "Transient"
	ObjectOriginExternal    ObjectOrigin = "External"
)

// Identifies a standardized elliptic curve.
type EllipticCurve string

// List of supported EllipticCurve values
const (
	EllipticCurveX25519    EllipticCurve = "X25519"
	EllipticCurveEd25519   EllipticCurve = "Ed25519"
	EllipticCurveX448      EllipticCurve = "X448"
	EllipticCurveSecP192K1 EllipticCurve = "SecP192K1"
	EllipticCurveSecP224K1 EllipticCurve = "SecP224K1"
	EllipticCurveSecP256K1 EllipticCurve = "SecP256K1"
	EllipticCurveNistP192  EllipticCurve = "NistP192"
	EllipticCurveNistP224  EllipticCurve = "NistP224"
	EllipticCurveNistP256  EllipticCurve = "NistP256"
	EllipticCurveNistP384  EllipticCurve = "NistP384"
	EllipticCurveNistP521  EllipticCurve = "NistP521"
	EllipticCurveGost256A  EllipticCurve = "Gost256A"
)

// Linked security objects.
type KeyLinks struct {
	Replacement *UUID `json:"replacement,omitempty"`
	Replaced    *UUID `json:"replaced,omitempty"`
}

// A security principal.
type Principal struct {
	App    *UUID
	User   *UUID
	Plugin *UUID
	// UserViaApp signifies a user authorizing some app to act on its behalf through OAuth.
	UserViaApp *PrincipalUserViaApp
}

// UserViaApp signifies a user authorizing some app to act on its behalf through OAuth.
type PrincipalUserViaApp struct {
	UserID UUID         `json:"user_id"`
	Scopes []OauthScope `json:"scopes"`
}

func (x Principal) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers("Principal", []bool{x.App != nil, x.User != nil, x.Plugin != nil, x.UserViaApp != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		App        *UUID                `json:"app,omitempty"`
		User       *UUID                `json:"user,omitempty"`
		Plugin     *UUID                `json:"plugin,omitempty"`
		UserViaApp *PrincipalUserViaApp `json:"userviaapp,omitempty"`
	}
	obj.App = x.App
	obj.User = x.User
	obj.Plugin = x.Plugin
	obj.UserViaApp = x.UserViaApp
	return json.Marshal(obj)
}
func (x *Principal) UnmarshalJSON(data []byte) error {
	x.App = nil
	x.User = nil
	x.Plugin = nil
	x.UserViaApp = nil
	var obj struct {
		App        *UUID                `json:"app,omitempty"`
		User       *UUID                `json:"user,omitempty"`
		Plugin     *UUID                `json:"plugin,omitempty"`
		UserViaApp *PrincipalUserViaApp `json:"userviaapp,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.App = obj.App
	x.User = obj.User
	x.Plugin = obj.Plugin
	x.UserViaApp = obj.UserViaApp
	return nil
}

// A hash algorithm.
type DigestAlgorithm string

// List of supported DigestAlgorithm values
const (
	DigestAlgorithmBlake2b256  DigestAlgorithm = "BLAKE2B256"
	DigestAlgorithmBlake2b384  DigestAlgorithm = "BLAKE2B384"
	DigestAlgorithmBlake2b512  DigestAlgorithm = "BLAKE2B512"
	DigestAlgorithmBlake2s256  DigestAlgorithm = "BLAKE2S256"
	DigestAlgorithmRipemd160   DigestAlgorithm = "RIPEMD160"
	DigestAlgorithmSsl3        DigestAlgorithm = "SSL3"
	DigestAlgorithmSha1        DigestAlgorithm = "SHA1"
	DigestAlgorithmSha256      DigestAlgorithm = "SHA256"
	DigestAlgorithmSha384      DigestAlgorithm = "SHA384"
	DigestAlgorithmSha512      DigestAlgorithm = "SHA512"
	DigestAlgorithmStreebog256 DigestAlgorithm = "STREEBOG256"
	DigestAlgorithmStreebog512 DigestAlgorithm = "STREEBOG512"
	DigestAlgorithmSha3_224    DigestAlgorithm = "SHA3_224"
	DigestAlgorithmSha3_256    DigestAlgorithm = "SHA3_256"
	DigestAlgorithmSha3_384    DigestAlgorithm = "SHA3_384"
	DigestAlgorithmSha3_512    DigestAlgorithm = "SHA3_512"
)

// OAuth scope.
type OauthScope string

// List of supported OauthScope values
const (
	OauthScopeApp OauthScope = "app"
)

// User's role in a group.
type UserGroupRole string

// List of supported UserGroupRole values
const (
	UserGroupRoleGroupAuditor       UserGroupRole = "GROUPAUDITOR"
	UserGroupRoleGroupAdministrator UserGroupRole = "GROUPADMINISTRATOR"
)

func (x UserGroupRole) MarshalJSON() ([]byte, error) {
	var s []string
	s = append(s, string(x))
	return json.Marshal(s)
}

func (x *UserGroupRole) UnmarshalJSON(data []byte) error {
	var s []string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if len(s) != 1 {
		return fmt.Errorf("invalid JSON value, expected array with 1 element, found %v elements", len(s))
	}
	*x = UserGroupRole(s[0])
	return nil
}

// Signing keys used to validate signed JWT tokens.
type JwtSigningKeys struct {
	Stored  *JwtSigningKeysStored
	Fetched *JwtSigningKeysFetched
}
type JwtSigningKeysStored struct {
	// Mapping key ids to DER-encoded public key.
	Keys map[string]Blob `json:"keys"`
}
type JwtSigningKeysFetched struct {
	URL string `json:"url"`
	// Number of seconds that the service is allowed to cache the fetched keys.
	CacheDuration uint64 `json:"cache_duration"`
}

func (x JwtSigningKeys) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers("JwtSigningKeys", []bool{x.Stored != nil, x.Fetched != nil}); err != nil {
		return nil, err
	}
	m := make(map[string]interface{})
	switch {
	case x.Stored != nil:
		b, err := json.Marshal(x.Stored)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		m["kind"] = "stored"
	case x.Fetched != nil:
		b, err := json.Marshal(x.Fetched)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		m["kind"] = "fetched"
	}
	return json.Marshal(m)
}
func (x *JwtSigningKeys) UnmarshalJSON(data []byte) error {
	x.Stored = nil
	x.Fetched = nil
	var h struct {
		Tag string `json:"kind"`
	}
	if err := json.Unmarshal(data, &h); err != nil {
		return errors.Errorf("not a valid JwtSigningKeys")
	}
	switch h.Tag {
	case "stored":
		var stored JwtSigningKeysStored
		if err := json.Unmarshal(data, &stored); err != nil {
			return err
		}
		x.Stored = &stored
	case "fetched":
		var fetched JwtSigningKeysFetched
		if err := json.Unmarshal(data, &fetched); err != nil {
			return err
		}
		x.Fetched = &fetched
	default:
		return errors.Errorf("invalid tag value: %v", h.Tag)
	}
	return nil
}

// Constraints on RSA encryption parameters. In general, if a constraint is not specified, anything is allowed.
type RsaEncryptionPolicy struct {
	Padding *RsaEncryptionPaddingPolicy `json:"padding,omitempty"`
}

// RSA encryption padding policy.
type RsaEncryptionPaddingPolicy struct {
	Oaep     *RsaEncryptionPaddingPolicyOaep
	Pkcs1V15 *struct{}
}
type RsaEncryptionPaddingPolicyOaep struct {
	Mgf *MgfPolicy `json:"mgf,omitempty"`
}

func (x RsaEncryptionPaddingPolicy) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers("RsaEncryptionPaddingPolicy", []bool{x.Oaep != nil, x.Pkcs1V15 != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Oaep     *RsaEncryptionPaddingPolicyOaep `json:"OAEP,omitempty"`
		Pkcs1V15 *struct{}                       `json:"PKCS1_V15,omitempty"`
	}
	obj.Oaep = x.Oaep
	obj.Pkcs1V15 = x.Pkcs1V15
	return json.Marshal(obj)
}
func (x *RsaEncryptionPaddingPolicy) UnmarshalJSON(data []byte) error {
	x.Oaep = nil
	x.Pkcs1V15 = nil
	var obj struct {
		Oaep     *RsaEncryptionPaddingPolicyOaep `json:"OAEP,omitempty"`
		Pkcs1V15 *struct{}                       `json:"PKCS1_V15,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.Oaep = obj.Oaep
	x.Pkcs1V15 = obj.Pkcs1V15
	return nil
}

// Constraints on RSA signature parameters. In general, if a constraint is not specified, anything is allowed.
type RsaSignaturePolicy struct {
	Padding *RsaSignaturePaddingPolicy `json:"padding,omitempty"`
}

// RSA signature padding policy.
type RsaSignaturePaddingPolicy struct {
	Pss      *RsaSignaturePaddingPolicyPss
	Pkcs1V15 *struct{}
}
type RsaSignaturePaddingPolicyPss struct {
	Mgf *MgfPolicy `json:"mgf,omitempty"`
}

func (x RsaSignaturePaddingPolicy) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers("RsaSignaturePaddingPolicy", []bool{x.Pss != nil, x.Pkcs1V15 != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Pss      *RsaSignaturePaddingPolicyPss `json:"PSS,omitempty"`
		Pkcs1V15 *struct{}                     `json:"PKCS1_V15,omitempty"`
	}
	obj.Pss = x.Pss
	obj.Pkcs1V15 = x.Pkcs1V15
	return json.Marshal(obj)
}
func (x *RsaSignaturePaddingPolicy) UnmarshalJSON(data []byte) error {
	x.Pss = nil
	x.Pkcs1V15 = nil
	var obj struct {
		Pss      *RsaSignaturePaddingPolicyPss `json:"PSS,omitempty"`
		Pkcs1V15 *struct{}                     `json:"PKCS1_V15,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.Pss = obj.Pss
	x.Pkcs1V15 = obj.Pkcs1V15
	return nil
}

// MGF policy.
type MgfPolicy struct {
	Mgf1 *MgfPolicyMgf1
}
type MgfPolicyMgf1 struct {
	Hash *DigestAlgorithm `json:"hash,omitempty"`
}

func (x MgfPolicy) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers("MgfPolicy", []bool{x.Mgf1 != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Mgf1 *MgfPolicyMgf1 `json:"mgf1,omitempty"`
	}
	obj.Mgf1 = x.Mgf1
	return json.Marshal(obj)
}
func (x *MgfPolicy) UnmarshalJSON(data []byte) error {
	x.Mgf1 = nil
	var obj struct {
		Mgf1 *MgfPolicyMgf1 `json:"mgf1,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.Mgf1 = obj.Mgf1
	return nil
}

// RSA-specific options.
type RsaOptions struct {
	// Size in bits (not bytes) of the RSA key. Specify on Create only. Returned on Get.
	KeySize *uint32 `json:"key_size,omitempty"`
	// Public exponent to use for generating the RSA key. Specify on Create only.
	PublicExponent *uint32 `json:"public_exponent,omitempty"`
	// Encryption policy for an RSA key. When doing an encryption or key wrapping operation, the
	// policies are evaluated against the specified parameters one by one. If one matches, the
	// operation is allowed. If none match, including if the policy list is empty, the operation
	// is disallowed. Missing optional parameters will have their defaults specified according to
	// the matched policy. The default for new keys is `[{"padding":{"OAEP":{}}]`.
	// If (part of) a constraint is not specified, anything is allowed for that constraint.
	// To impose no constraints, specify `[{}]`.
	EncryptionPolicy []RsaEncryptionPolicy `json:"encryption_policy"`
	// Signature policy for an RSA key. When doing a signature operation, the policies are
	// evaluated against the specified parameters one by one. If one matches, the operation is
	// allowed. If none match, including if the policy list is empty, the operation is disallowed.
	// Missing optional parameters will have their defaults specified according to the matched
	// policy. The default for new keys is `[{}]` (no constraints).
	// If (part of) a constraint is not specified, anything is allowed for that constraint.
	SignaturePolicy []RsaSignaturePolicy `json:"signature_policy"`
}

// FPE-specific options.
type FpeOptions struct {
	// The base for input data.
	Radix uint32 `json:"radix"`
	// The minimum allowed length for the input data.
	MinLength uint32 `json:"min_length"`
	// The maximum allowed length for the input data.
	MaxLength uint32 `json:"max_length"`
	// The list of indices of characters to be preserved while performing encryption/decryption.
	Preserve []int `json:"preserve"`
	// The list of indices of characters to be masked while performing masked decryption.
	Mask *[]int `json:"mask,omitempty"`
	// Whether encrypted/decrypted data should satisfy LUHN checksum formula.
	LuhnCheck *bool `json:"luhn_check,omitempty"`
	// The user-friendly name for the data type that represents the input data.
	Name *string `json:"name,omitempty"`
}

// Approval policy.
type ApprovalPolicy struct {
	Quorum *ApprovalPolicyQuorum `json:"quorum,omitempty"`
	User   *UUID                 `json:"user,omitempty"`
	App    *UUID                 `json:"app,omitempty"`
}

// Quorum approval policy.
type ApprovalPolicyQuorum struct {
	N       uint               `json:"n"`
	Members []ApprovalPolicy   `json:"members"`
	Config  ApprovalAuthConfig `json:"config"`
}

func (x ApprovalPolicyQuorum) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	{ // Config
		b, err := json.Marshal(&x.Config)
		if err != nil {
			return nil, err
		}
		f := make(map[string]interface{})
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, err
		}
		for k, v := range f {
			m[k] = &v
		}
	}
	m["n"] = &x.N
	m["members"] = &x.Members
	return json.Marshal(&m)
}
func (x *ApprovalPolicyQuorum) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &x.Config); err != nil {
		return err
	}
	var r struct {
		N       uint             `json:"n"`
		Members []ApprovalPolicy `json:"members"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	x.N = r.N
	x.Members = r.Members
	return nil
}

// Authentication requirements for approval request reviewers.
type ApprovalAuthConfig struct {
	RequirePassword bool `json:"require_password"`
	Require2fa      bool `json:"require_2fa"`
}

// Reason for revoking a key.
type RevocationReason struct {
	Code RevocationReasonCode `json:"code"`
	// Message is used exclusively for audit trail/logging purposes and MAY contain additional
	// information about why the object was revoked.
	Message                 *string `json:"message,omitempty"`
	CompromiseOccuranceDate *Time   `json:"compromise_occurance_date,omitempty"`
}

// Reasons to revoke a security object.
type RevocationReasonCode string

// List of supported RevocationReasonCode values
const (
	RevocationReasonCodeUnspecified          RevocationReasonCode = "Unspecified"
	RevocationReasonCodeKeyCompromise        RevocationReasonCode = "KeyCompromise"
	RevocationReasonCodeCACompromise         RevocationReasonCode = "CACompromise"
	RevocationReasonCodeAffiliationChanged   RevocationReasonCode = "AffiliationChanged"
	RevocationReasonCodeSuperseded           RevocationReasonCode = "Superseded"
	RevocationReasonCodeCessationOfOperation RevocationReasonCode = "CessationOfOperation"
	RevocationReasonCodePrivilegeWithdrawn   RevocationReasonCode = "PrivilegeWithdrawn"
)

// If enabled, the public key will be available publicly (without authentication) through the GetPublicKey API.
type PublishPublicKeyConfig struct {
	Enabled  *PublishPublicKeyConfigEnabled
	Disabled *struct{}
}
type PublishPublicKeyConfigEnabled struct {
	// Additionally list the previous version of the key if not compromised.
	ListPreviousVersion bool `json:"list_previous_version"`
}

func (x PublishPublicKeyConfig) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers("PublishPublicKeyConfig", []bool{x.Enabled != nil, x.Disabled != nil}); err != nil {
		return nil, err
	}
	m := make(map[string]interface{})
	switch {
	case x.Enabled != nil:
		b, err := json.Marshal(x.Enabled)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		m["state"] = "enabled"
	case x.Disabled != nil:
		m["state"] = "disabled"
	}
	return json.Marshal(m)
}
func (x *PublishPublicKeyConfig) UnmarshalJSON(data []byte) error {
	x.Enabled = nil
	x.Disabled = nil
	var h struct {
		Tag string `json:"state"`
	}
	if err := json.Unmarshal(data, &h); err != nil {
		return errors.Errorf("not a valid PublishPublicKeyConfig")
	}
	switch h.Tag {
	case "enabled":
		var enabled PublishPublicKeyConfigEnabled
		if err := json.Unmarshal(data, &enabled); err != nil {
			return err
		}
		x.Enabled = &enabled
	case "disabled":
		x.Disabled = &struct{}{}
	default:
		return errors.Errorf("invalid tag value: %v", h.Tag)
	}
	return nil
}

type Sobject struct {
	AcctID                  UUID                    `json:"acct_id"`
	ActivationDate          *Time                   `json:"activation_date,omitempty"`
	CompromiseDate          *Time                   `json:"compromise_date,omitempty"`
	CreatedAt               Time                    `json:"created_at"`
	Creator                 Principal               `json:"creator"`
	CustomMetadata          *map[string]string      `json:"custom_metadata,omitempty"`
	DeactivationDate        *Time                   `json:"deactivation_date,omitempty"`
	Description             *string                 `json:"description,omitempty"`
	DeterministicSignatures *bool                   `json:"deterministic_signatures,omitempty"`
	EllipticCurve           *EllipticCurve          `json:"elliptic_curve,omitempty"`
	Enabled                 bool                    `json:"enabled"`
	Fpe                     *FpeOptions             `json:"fpe,omitempty"`
	KeyOps                  KeyOperations           `json:"key_ops"`
	KeySize                 *uint32                 `json:"key_size,omitempty"`
	Kid                     *UUID                   `json:"kid,omitempty"`
	LastusedAt              Time                    `json:"lastused_at"`
	Links                   *KeyLinks               `json:"links,omitempty"`
	Name                    *string                 `json:"name,omitempty"`
	NeverExportable         *bool                   `json:"never_exportable,omitempty"`
	ObjType                 ObjectType              `json:"obj_type"`
	Origin                  ObjectOrigin            `json:"origin"`
	PubKey                  *Blob                   `json:"pub_key,omitempty"`
	PublicOnly              bool                    `json:"public_only"`
	PublishPublicKey        *PublishPublicKeyConfig `json:"publish_public_key,omitempty"`
	RevocationReason        *RevocationReason       `json:"revocation_reason,omitempty"`
	Rsa                     *RsaOptions             `json:"rsa,omitempty"`
	State                   *SobjectState           `json:"state,omitempty"`
	TransientKey            *Blob                   `json:"transient_key,omitempty"`
	Value                   *Blob                   `json:"value,omitempty"`
	GroupID                 *UUID                   `json:"group_id,omitempty"`
}

// A request to sign data (or hash value) using an asymmetric key.
type SignRequest struct {
	Key     *SobjectDescriptor `json:"key,omitempty"`
	HashAlg DigestAlgorithm    `json:"hash_alg"`
	// Hash value to be signed. Exactly one of `hash` and `data` is required.
	Hash *Blob `json:"hash,omitempty"`
	// Data to be signed. Exactly one of `hash` and `data` is required.
	// To reduce request size and avoid reaching the request size limit, prefer `hash`.
	Data                   *Blob          `json:"data,omitempty"`
	Mode                   *SignatureMode `json:"mode,omitempty"`
	DeterministicSignature *bool          `json:"deterministic_signature,omitempty"`
}

// Result of sign operation.
type SignResponse struct {
	// Key id is returned for non-transient keys.
	Kid       *UUID `json:"kid,omitempty"`
	Signature Blob  `json:"signature"`
}

// Request to verify a signature using an asymmetric key.
type VerifyRequest struct {
	Key     *SobjectDescriptor `json:"key,omitempty"`
	HashAlg DigestAlgorithm    `json:"hash_alg"`
	// The hash of the data on which the signature is being verified.
	// Exactly one of `hash` and `data` is required.
	Hash *Blob `json:"hash,omitempty"`
	// The data on which the signature is being verified.
	// Exactly one of `hash` and `data` is required.
	// To reduce request size and avoid reaching the request size limit, prefer `hash`.
	Data *Blob          `json:"data,omitempty"`
	Mode *SignatureMode `json:"mode,omitempty"`
	// The signature to verify.
	Signature Blob `json:"signature"`
}

// Result of verifying a signature or MAC.
type VerifyResponse struct {
	// Key id is returned for non-transient keys.
	Kid *UUID `json:"kid,omitempty"`
	// True if the signature verified and false if it did not.
	Result bool `json:"result"`
}

// Specifies the Mask Generating Function (MGF) to use.
type Mgf struct {
	Mgf1 *Mgf1
}
type Mgf1 struct {
	Hash DigestAlgorithm `json:"hash"`
}

func (x Mgf) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers("Mgf", []bool{x.Mgf1 != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Mgf1 *Mgf1 `json:"mgf1,omitempty"`
	}
	obj.Mgf1 = x.Mgf1
	return json.Marshal(obj)
}
func (x *Mgf) UnmarshalJSON(data []byte) error {
	x.Mgf1 = nil
	var obj struct {
		Mgf1 *Mgf1 `json:"mgf1,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.Mgf1 = obj.Mgf1
	return nil
}

// Signature mode.
type SignatureMode struct {
	Rsa *RsaSignaturePadding
}

func (x SignatureMode) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers("SignatureMode", []bool{x.Rsa != nil}); err != nil {
		return nil, err
	}
	if x.Rsa != nil {
		return json.Marshal(x.Rsa)
	}
	panic("unreachable")
}
func (x *SignatureMode) UnmarshalJSON(data []byte) error {
	x.Rsa = nil
	var rsa RsaSignaturePadding
	if err := json.Unmarshal(data, &rsa); err == nil {
		x.Rsa = &rsa
		return nil
	}
	return errors.Errorf("not a valid SignatureMode")
}

// Type of padding to use for RSA signatures. The padding specified must adhere to the key's
// signature policy. If not specified, the default based on the key's policy will be used.
type RsaSignaturePadding struct {
	// Probabilistic Signature Scheme (PKCS#1 v2.1).
	Pss *RsaSignaturePaddingPss
	// PKCS#1 v1.5 padding.
	Pkcs1V15 *struct{}
}

// Probabilistic Signature Scheme (PKCS#1 v2.1).
type RsaSignaturePaddingPss struct {
	Mgf Mgf `json:"mgf"`
}

func (x RsaSignaturePadding) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers("RsaSignaturePadding", []bool{x.Pss != nil, x.Pkcs1V15 != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Pss      *RsaSignaturePaddingPss `json:"PSS,omitempty"`
		Pkcs1V15 *struct{}               `json:"PKCS1_V15,omitempty"`
	}
	obj.Pss = x.Pss
	obj.Pkcs1V15 = x.Pkcs1V15
	return json.Marshal(obj)
}
func (x *RsaSignaturePadding) UnmarshalJSON(data []byte) error {
	x.Pss = nil
	x.Pkcs1V15 = nil
	var obj struct {
		Pss      *RsaSignaturePaddingPss `json:"PSS,omitempty"`
		Pkcs1V15 *struct{}               `json:"PKCS1_V15,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.Pss = obj.Pss
	x.Pkcs1V15 = obj.Pkcs1V15
	return nil
}

// Uniquely identifies a persisted or transient sobject.
type SobjectDescriptor struct {
	Kid          *UUID
	Name         *string
	TransientKey *Blob
}

func (x SobjectDescriptor) MarshalJSON() ([]byte, error) {
	if err := checkEnumPointers("SobjectDescriptor", []bool{x.Kid != nil, x.Name != nil, x.TransientKey != nil}); err != nil {
		return nil, err
	}
	var obj struct {
		Kid          *UUID   `json:"kid,omitempty"`
		Name         *string `json:"name,omitempty"`
		TransientKey *Blob   `json:"transient_key,omitempty"`
	}
	obj.Kid = x.Kid
	obj.Name = x.Name
	obj.TransientKey = x.TransientKey
	return json.Marshal(obj)
}
func (x *SobjectDescriptor) UnmarshalJSON(data []byte) error {
	x.Kid = nil
	x.Name = nil
	x.TransientKey = nil
	var obj struct {
		Kid          *UUID   `json:"kid,omitempty"`
		Name         *string `json:"name,omitempty"`
		TransientKey *Blob   `json:"transient_key,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	x.Kid = obj.Kid
	x.Name = obj.Name
	x.TransientKey = obj.TransientKey
	return nil
}

// Request for second factor authentication with a U2f device.
type U2fAuthRequest struct {
	KeyHandle     Blob `json:"keyHandle"`
	SignatureData Blob `json:"signatureData"`
	ClientData    Blob `json:"clientData"`
}

type SobjectState string

// List of supported SobjectState values
const (
	SobjectStatePreActive   SobjectState = "PreActive"
	SobjectStateActive      SobjectState = "Active"
	SobjectStateDeactivated SobjectState = "Deactivated"
	SobjectStateCompromised SobjectState = "Compromised"
)
