package sdkms

import (
	"encoding/json"

	"github.com/pkg/errors"
)

// Blob represents binary data
type Blob = []byte

// Algorithm specifies a cryptographic algorithm
type Algorithm string

// List of supported Algorithm values
const (
	AlgorithmAES  Algorithm = "AES"
	AlgorithmDES  Algorithm = "DES"
	AlgorithmDES3 Algorithm = "DES3"
	AlgorithmRSA  Algorithm = "RSA"
	AlgorithmEC   Algorithm = "EC"
	AlgorithmHMAC Algorithm = "HMAC"
)

// CipherMode is used for symmetric encryption
type CipherMode string

// List of supported CipherMode values
const (
	CipherModeECB      CipherMode = "ECB"
	CipherModeCBC      CipherMode = "CBC"
	CipherModeCBCNOPAD CipherMode = "CBCNOPAD"
	CipherModeCFB      CipherMode = "CFB"
	CipherModeCTR      CipherMode = "CTR"
	CipherModeGCM      CipherMode = "GCM"
	CipherModeCCM      CipherMode = "CCM"
)

// RsaEncryptionPaddingOaep is OAEP parameters for RSA encryption padding
type RsaEncryptionPaddingOaep struct {
	Mgf Mgf `json:"mgf"`
}

// RsaEncryptionPadding can be either PKCS#1 V1.5 or OAEP
type RsaEncryptionPadding struct {
	Pkcs1V15 *struct{}                 `json:"PKCS1_V15,omitempty"`
	Oaep     *RsaEncryptionPaddingOaep `json:"OAEP,omitempty"`
}

// RsaEncryptionPaddingPKCS1V15 returns RSA encryption padding set to PKCS#1 V1.5
func RsaEncryptionPaddingPKCS1V15() RsaEncryptionPadding {
	return RsaEncryptionPadding{
		Pkcs1V15: &struct{}{},
	}
}

// RsaEncryptionPaddingOAEPMGF1 returns RSA encryption padding set to OAEP with MGF1 using the specified hash algorithm
func RsaEncryptionPaddingOAEPMGF1(hash DigestAlgorithm) RsaEncryptionPadding {
	return RsaEncryptionPadding{
		Oaep: &RsaEncryptionPaddingOaep{Mgf: Mgf{Mgf1: &Mgf1{Hash: hash}}},
	}
}

// CryptMode can be either a symmetric cipher mode or RSA encryption padding
type CryptMode struct {
	Symmetric *CipherMode
	Rsa       *RsaEncryptionPadding
}

// CryptModeSymmetric returns CryptMode set to the specified symmetric cipher mode
func CryptModeSymmetric(mode CipherMode) *CryptMode {
	return &CryptMode{
		Symmetric: &mode,
	}
}

// CryptModeRSA returns CryptMode set to the specified RSA encryption padding
func CryptModeRSA(mode RsaEncryptionPadding) *CryptMode {
	return &CryptMode{
		Rsa: &mode,
	}
}

// MarshalJSON implements untagged JSON serialization for CryptMode
func (cm *CryptMode) MarshalJSON() ([]byte, error) {
	if cm.Symmetric != nil {
		return json.Marshal(cm.Symmetric)
	}
	return json.Marshal(cm.Rsa)
}

// UnmarshalJSON implements untagged JSON deserialization for CryptMode
func (cm *CryptMode) UnmarshalJSON(data []byte) error {
	var symmetric CipherMode
	if err := json.Unmarshal(data, &symmetric); err == nil {
		cm.Symmetric = &symmetric
		cm.Rsa = nil
		return nil
	}
	var rsa RsaEncryptionPadding
	if err := json.Unmarshal(data, &rsa); err == nil {
		cm.Symmetric = nil
		cm.Rsa = &rsa
		return nil
	}
	return errors.Errorf("not a valid CryptMode")
}

// DigestAlgorithm represents a hash algorithm
type DigestAlgorithm string

// List of supported DigestAlgorithm values
const (
	DigestAlgorithmSHA1       DigestAlgorithm = "SHA1"
	DigestAlgorithmSHA256     DigestAlgorithm = "SHA256"
	DigestAlgorithmSHA384     DigestAlgorithm = "SHA384"
	DigestAlgorithmSHA512     DigestAlgorithm = "SHA512"
	DigestAlgorithmSSL3       DigestAlgorithm = "Ssl3"
	DigestAlgorithmBLAKE2B256 DigestAlgorithm = "Blake2b256"
	DigestAlgorithmBLAKE2B384 DigestAlgorithm = "Blake2b384"
	DigestAlgorithmBLAKE2B512 DigestAlgorithm = "Blake2b512"
	DigestAlgorithmBLAKE2S256 DigestAlgorithm = "Blake2s256"
	DigestAlgorithmRIPEMD160  DigestAlgorithm = "RIPEMD160"
)

// Mgf1 stores MGF1 parameters
type Mgf1 struct {
	Hash DigestAlgorithm `json:"hash"`
}

// Mgf specifies the Mask Generating Function (MGF) to use.
type Mgf struct {
	Mgf1 *Mgf1 `json:"mgf1,omitempty"`
}

// RsaSignaturePaddingPss is Probabilistic Signature Scheme (PKCS#1 v2.1) for RSA
type RsaSignaturePaddingPss struct {
	Mgf Mgf `json:"mgf"`
}

// RsaSignaturePadding can be either PKCS#1 V1.5 or PSS
type RsaSignaturePadding struct {
	Pkcs1V15 *struct{}               `json:"PKCS1_V15,omitempty"`
	Pss      *RsaSignaturePaddingPss `json:"PSS,omitempty"`
}

// RsaSignaturePaddingPKCS1V15 returns RSA signature padding set to PKCS#1 V1.5
func RsaSignaturePaddingPKCS1V15() RsaSignaturePadding {
	return RsaSignaturePadding{
		Pkcs1V15: &struct{}{},
	}
}

// RsaSignaturePaddingPSSMGF1 returns RSA signature padding set to PSS with MGF1 using the specified hash algorithm
func RsaSignaturePaddingPSSMGF1(hash DigestAlgorithm) RsaSignaturePadding {
	return RsaSignaturePadding{
		Pss: &RsaSignaturePaddingPss{Mgf: Mgf{Mgf1: &Mgf1{Hash: hash}}},
	}
}

// SignatureMode can be RSA signature padding (may be extended in the future)
type SignatureMode struct {
	Rsa *RsaSignaturePadding
}

// SignatureModeRSA returns SignatureMode set to the specified RSA signature padding
func SignatureModeRSA(mode RsaSignaturePadding) *SignatureMode {
	return &SignatureMode{
		Rsa: &mode,
	}
}

// MarshalJSON implements untagged JSON serialization for SignatureMode
func (cm *SignatureMode) MarshalJSON() ([]byte, error) {
	return json.Marshal(cm.Rsa)
}

// UnmarshalJSON implements untagged JSON deserialization for SignatureMode
func (cm *SignatureMode) UnmarshalJSON(data []byte) error {
	var rsa RsaSignaturePadding
	if err := json.Unmarshal(data, &rsa); err == nil {
		cm.Rsa = &rsa
		return nil
	}
	return errors.Errorf("not a valid SignatureMode")
}

// SobjectDescriptor is used to identify a security object by key id, by name or transient key
type SobjectDescriptor struct {
	Kid          *string `json:"kid,omitempty"`
	Name         *string `json:"name,omitempty"`
	TransientKey *Blob   `json:"transient_key,omitempty"`
}

// SobjectByID returns a SobjectDescriptor that identifies a security object by id
func SobjectByID(id string) SobjectDescriptor {
	return SobjectDescriptor{
		Kid: &id,
	}
}

// SobjectByName returns a SobjectDescriptor that identifies a security object by name
func SobjectByName(name string) SobjectDescriptor {
	return SobjectDescriptor{
		Name: &name,
	}
}

// TransientKey returns a SobjectDescriptor that identifies a transient key
func TransientKey(key Blob) SobjectDescriptor {
	return SobjectDescriptor{
		TransientKey: &key,
	}
}

// Principal can be app, user, or plugin
type Principal struct {
	AppID    *string `json:"app,omitempty"`
	UserID   *string `json:"user,omitempty"`
	PluginID *string `json:"plugin,omitempty"`
}

// ApprovalStatus shows approval request status
type ApprovalStatus string

// List of supported ApprovalStatus values
const (
	ApprovalStatusPending  ApprovalStatus = "PENDING"
	ApprovalStatusApproved ApprovalStatus = "APPROVED"
	ApprovalStatusDenied   ApprovalStatus = "DENIED"
	ApprovalStatusFailed   ApprovalStatus = "FAILED"
)

// ApprovalSubject identifies an object acted upon by an approval request
type ApprovalSubject struct {
	GroupID   *string `json:"group,omitempty"`
	SobjectID *string `json:"sobject,omitempty"`
	AppID     *string `json:"app,omitempty"`
	PluginID  *string `json:"plugin,omitempty"`
}
