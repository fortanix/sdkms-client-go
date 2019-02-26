package sdkms

import (
	"context"
	"net/http"
)

// EncryptRequest is a request to encrypt data
type EncryptRequest struct {
	Plain Blob              `json:"plain"`
	Alg   Algorithm         `json:"alg"`
	Key   SobjectDescriptor `json:"key"`
	Mode  *CryptMode        `json:"mode,omitempty"`
	// For symmetric ciphers, this value will be used for the cipher initialization value. If not provided, SDKMS will
	// generate a random iv and return it in the response. If provided, iv length must match the length required by the
	// cipher and mode.
	Iv *Blob `json:"iv,omitempty"`
	// For symmetric ciphers with cipher mode GCM or CCM, this optionally specifies the authenticated data used by the
	// cipher. This field must not be provided with other cipher modes.
	Ad *Blob `json:"ad,omitempty"`
	// For symmetric ciphers with cipher mode GCM or CCM, this field specifies the length of the authentication tag to be
	// produced. This field is specified in bits (not bytes). This field is required for symmetric ciphers with cipher
	// mode GCM or CCM. It must not be specified for asymmetric ciphers and symmetric ciphers with other cipher modes.
	TagLen *uint32 `json:"tag_len,omitempty"`
}

// EncryptResponse is the result of encryption
type EncryptResponse struct {
	Cipher Blob `json:"cipher"`
	// Returned for non-transient keys
	Kid *string `json:"kid,omitempty"`
	// The initialiation value used for symmetric encryption. Not returned for asymmetric ciphers.
	Iv *Blob `json:"iv,omitempty"`
	// For symmetric ciphers with cipher mode GCM or CCM, the authentication tag produced by the cipher. Its length
	// will match the tag length specified by the encryption request.
	Tag *Blob `json:"tag,omitempty"`
}

// DecryptRequest is a request to decrypt data
type DecryptRequest struct {
	Cipher Blob              `json:"cipher"`
	Key    SobjectDescriptor `json:"key"`
	Alg    *Algorithm        `json:"alg,omitempty"`
	Mode   *CryptMode        `json:"mode,omitempty"`
	// The initialization value used to encrypt this ciphertext. This field is required for symmetric ciphers, and
	// ignored for asymmetric ciphers.
	Iv *Blob `json:"iv,omitempty"`
	// The authenticated data used with this ciphertext and authentication tag. This field is required for symmetric
	// ciphers using cipher mode GCM or CCM, and must not be specified for all other ciphers.
	Ad *Blob `json:"ad,omitempty"`
	// The authentication tag used with this ciphertext and authenticated data. This field is required for symmetric
	// ciphers using cipher mode GCM or CCM, and must not be specified for all other ciphers.
	Tag *Blob `json:"tag,omitempty"`
}

// DecryptResponse is the result of decryption
type DecryptResponse struct {
	Plain Blob `json:"plain"`
	// The key ID of the key used to decrypt
	Kid *string `json:"kid,omitempty"`
}

// SignRequest is a request to sign data or hash
type SignRequest struct {
	Key     SobjectDescriptor `json:"key"`
	HashAlg DigestAlgorithm   `json:"hash_alg"`
	Mode    *SignatureMode    `json:"mode,omitempty"`
	// Hash of the data to be signed. Exactly one of `hash` and `data` is required.
	Hash *Blob `json:"hash,omitempty"`
	// Data to be signed. Exactly one of `hash` and `data` is required. To reduce request size and avoid reaching the
	// request size limit, prefer `hash`.
	Data *Blob `json:"data,omitempty"`
}

// SignResponse is the result of signing
type SignResponse struct {
	Signature Blob `json:"signature"`
	// Key ID of the key used to sign this data
	Kid *string `json:"kid,omitempty"`
}

// VerifyRequest is a request to verify signatures
type VerifyRequest struct {
	Signature Blob              `json:"signature"`
	Key       SobjectDescriptor `json:"key"`
	HashAlg   DigestAlgorithm   `json:"hash_alg"`
	Mode      *SignatureMode    `json:"mode,omitempty"`
	// The hash of the data on which the signature is being verified. Exactly one of `hash` and `data` is required.
	Hash *Blob `json:"hash,omitempty"`
	// The data on which the signature is being verified. Exactly one of `hash` and `data` is required. To reduce
	// request size and avoid reaching the request size limit, prefer `hash`.
	Data *Blob `json:"data,omitempty"`
}

// VerifyResponse is the result of signature verification
type VerifyResponse struct {
	// True if the signature verified and False if it did not
	Result bool `json:"result"`
	// The Key ID of the key used to verify this data
	Kid *string `json:"kid,omitempty"`
}

// Encrypt encrypts data
func (c *Client) Encrypt(ctx context.Context, body EncryptRequest) (*EncryptResponse, error) {
	var response EncryptResponse
	if err := c.fetch(ctx, http.MethodPost, "/crypto/v1/encrypt", body, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// RequestApprovalToEncrypt requests approval to encrypt
func (c *Client) RequestApprovalToEncrypt(ctx context.Context, body EncryptRequest, description *string) (*ApprovalRequest, error) {
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   "/crypto/v1/encrypt",
		Body:        body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Decrypt decrypts data
func (c *Client) Decrypt(ctx context.Context, body DecryptRequest) (*DecryptResponse, error) {
	var response DecryptResponse
	if err := c.fetch(ctx, http.MethodPost, "/crypto/v1/decrypt", body, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// RequestApprovalToDecrypt requests approval to decrypt
func (c *Client) RequestApprovalToDecrypt(ctx context.Context, body DecryptRequest, description *string) (*ApprovalRequest, error) {
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   "/crypto/v1/decrypt",
		Body:        body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Sign signs data
func (c *Client) Sign(ctx context.Context, body SignRequest) (*SignResponse, error) {
	var response SignResponse
	if err := c.fetch(ctx, http.MethodPost, "/crypto/v1/sign", body, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// RequestApprovalToSign requests approval to sign
func (c *Client) RequestApprovalToSign(ctx context.Context, body SignRequest, description *string) (*ApprovalRequest, error) {
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   "/crypto/v1/sign",
		Body:        body,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}

// Verify verifies a signature
func (c *Client) Verify(ctx context.Context, body VerifyRequest) (*VerifyResponse, error) {
	var response VerifyResponse
	if err := c.fetch(ctx, http.MethodPost, "/crypto/v1/verify", body, &response); err != nil {
		return nil, err
	}
	return &response, nil
}
