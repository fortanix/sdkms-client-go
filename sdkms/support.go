/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package sdkms

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pkg/errors"
)

// Blob represents binary data
type Blob = []byte

// UUID is a universally-unique identifier in hyphenated format
type UUID = string

// Time in ISO 8601 format
type Time string

// Std returns a time.Time value representing t
func (t Time) Std() (time.Time, error) {
	return time.Parse("20060102T150405Z0700", string(t))
}

// Char represents a single `rune` encoded as a JSON string
type Char rune

func (c Char) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("%c", c))
}

func (c *Char) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}
	count := utf8.RuneCountInString(s)
	if count > 1 {
		return fmt.Errorf("expected a single character, found %v", count)
	}
	r, _ := utf8.DecodeRuneInString(s)
	*c = Char(r)
	return nil
}

// AppGroups contains a list of groups and optionally permissions granted to an app in each group.
// In order to get information about the app permissions in each group, you should set
// `GroupPermissions` to true in GetAppParams/ListAppsParams when making app-related requests.
// When creating a new app, you should always specify desired permissions for each group.
type AppGroups map[UUID]*AppPermissions

// UnmarshalJSON implements JSON unmarshalling for AppGroups
func (a *AppGroups) UnmarshalJSON(data []byte) error {
	var s []UUID
	if err := json.Unmarshal(data, &s); err == nil {
		*a = make(map[UUID]*AppPermissions)
		for _, id := range s {
			(*a)[id] = nil
		}
		return nil
	}
	var m map[UUID]*AppPermissions
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*a = m
	return nil
}

// MarshalJSON implements JSON marshalling for AppGroups
func (a AppGroups) MarshalJSON() ([]byte, error) {
	b := make(map[UUID]AppPermissions)
	var empty AppPermissions
	for k, v := range a {
		if v == nil {
			v = &empty
		}
		b[k] = *v
	}
	return json.Marshal(b)
}

type approvableResult struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

// ApprovableResult is the result of an operation performed through approval requests
type ApprovableResult struct {
	inner approvableResult
}

// UnmarshalJSON implements JSON unmarshalling for ApprovableResult
func (a *ApprovableResult) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &a.inner)
}

// Parse the operation result
func (a *ApprovableResult) Parse(successResult interface{}) error {
	if a.inner.Status >= 300 {
		var errorMessage string
		_ = json.Unmarshal(a.inner.Body, &errorMessage)
		return newBackendError(a.inner.Status, errorMessage)
	}
	return json.Unmarshal(a.inner.Body, successResult)
}

type batchResponseItem struct {
	Status uint16          `json:"status"`
	Error  *string         `json:"error"`
	Body   json.RawMessage `json:"body"`
}

// BatchSignResponseItem is returned by BatchSign operation
type BatchSignResponseItem struct {
	inner batchResponseItem
}

// UnmarshalJSON implements JSON unmarshalling for BatchSignResponseItem
func (b *BatchSignResponseItem) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &b.inner)
}

// Result returns the Sign operation result
func (b *BatchSignResponseItem) Result() (*SignResponse, error) {
	if b.inner.Error == nil {
		var response SignResponse
		if err := json.Unmarshal(b.inner.Body, &response); err != nil {
			return nil, err
		}
		return &response, nil
	}
	return nil, newBackendError(int(b.inner.Status), *b.inner.Error)
}

// BatchVerifyResponseItem is returned by BatchVerify operation
type BatchVerifyResponseItem struct {
	inner batchResponseItem
}

// UnmarshalJSON implements JSON unmarshalling for BatchVerifyResponseItem
func (b *BatchVerifyResponseItem) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &b.inner)
}

// Result returns the Verify operation result
func (b *BatchVerifyResponseItem) Result() (*VerifyResponse, error) {
	if b.inner.Error == nil {
		var response VerifyResponse
		if err := json.Unmarshal(b.inner.Body, &response); err != nil {
			return nil, err
		}
		return &response, nil
	}
	return nil, newBackendError(int(b.inner.Status), *b.inner.Error)
}

// PluginOutput is returned by the InvokePlugin operation
type PluginOutput []byte

// HasValue returns true if plugin returned any value
func (po PluginOutput) HasValue() bool {
	return len(po) > 0
}

// Parse the plugin output as the desired type
func (po PluginOutput) Parse(output interface{}) error {
	if len(po) == 0 {
		return errors.Errorf("Plugin did not output anything")
	}
	return json.Unmarshal(po, output)
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

// SignatureModeRSA returns SignatureMode set to the specified RSA signature padding
func SignatureModeRSA(mode RsaSignaturePadding) *SignatureMode {
	return &SignatureMode{
		Rsa: &mode,
	}
}

// SobjectByID returns a SobjectDescriptor that identifies a security object by id
func SobjectByID(id string) *SobjectDescriptor {
	return &SobjectDescriptor{
		Kid: &id,
	}
}

// SobjectByName returns a SobjectDescriptor that identifies a security object by name
func SobjectByName(name string) *SobjectDescriptor {
	return &SobjectDescriptor{
		Name: &name,
	}
}

// TransientKey returns a SobjectDescriptor that identifies a transient key
func TransientKey(key Blob) *SobjectDescriptor {
	return &SobjectDescriptor{
		TransientKey: &key,
	}
}

// TLSConfigGlobalRootCAs returns a TlsConfig set to global root CAs
func TLSConfigGlobalRootCAs(validateHostname bool) TlsConfig {
	set := CaSetGlobalRoots
	return TlsConfig{
		Required: &TlsConfigRequired{
			ValidateHostname: validateHostname,
			Ca: CaConfig{
				CaSet: &set,
			},
		},
	}
}

// TLSConfigPinned returns a TlsConfig set to the given CA certificates
func TLSConfigPinned(certs []Blob, validateHostname bool) TlsConfig {
	return TlsConfig{
		Required: &TlsConfigRequired{
			ValidateHostname: validateHostname,
			Ca: CaConfig{
				Pinned: &certs,
			},
		},
	}
}

func checkEnumPointers(typeName string, nonNilPtrs []bool) error {
	count := 0
	for _, p := range nonNilPtrs {
		if p {
			count++
		}
	}
	if count != 1 {
		return errors.Errorf("%s: exactly one pointer should be non-nil, found %v", typeName, count)
	}
	return nil
}

type urlEncode interface {
	urlEncode(v map[string][]string) error
}

func encodeURLParams(x urlEncode) (string, error) {
	v := make(url.Values)
	if err := x.urlEncode(v); err != nil {
		return "", err
	}
	return v.Encode(), nil
}

// Order specifies sort order of objects returned
type Order string

// List of values for Order
const (
	OrderAscending  Order = ":asc"
	OrderDescending Order = ":desc"
)

type HyperHttpMethod string

// Common HTTP methods.
//
// Unless otherwise noted, these are defined in RFC 7231 section 4.3.
const (
	MethodGet     HyperHttpMethod = "GET"
	MethodHead    HyperHttpMethod = "HEAD"
	MethodPost    HyperHttpMethod = "POST"
	MethodPut     HyperHttpMethod = "PUT"
	MethodPatch   HyperHttpMethod = "PATCH" // RFC 5789
	MethodDelete  HyperHttpMethod = "DELETE"
	MethodConnect HyperHttpMethod = "CONNECT"
	MethodOptions HyperHttpMethod = "OPTIONS"
	MethodTrace   HyperHttpMethod = "TRACE"
)

type COSEAlgorithmIdentifier int16

const (
	Es256 COSEAlgorithmIdentifier = -7
)

type PublicKeyCredentialEntityForRp struct {
	// Name of the entity
	Name string `json:"name"`
	// <https://www.w3.org/TR/webauthn-2/#dictionary-rp-credential-params>
	Entity *PublicKeyCredentialRpEntity `json:"entity"`
}

type PublicKeyCredentialAuthenticatorAssertionResponse struct {
	// Identifier of Credential
	Id string `json:"id"`
	// Type of credential
	Type     *PublicKeyCredentialType        `json:"type"`
	Response *AuthenticatorAssertionResponse `json:"response"`
	// This field contains client extension output entries produced by the extension’s client extension processing.
	ExtensionResults *AuthenticationExtensionsClientOutputs `json:"get_client_extension_results"`
}

type PublicKeyCredentialEntityForUser struct {
	//
	Name string `json:"name"`
	//
	Entity PublicKeyCredentialUserEntity `json:"entity"`
}

type Removable[T any] struct {
	value *T
}

func (r *Removable[T]) RemoveVal() Removable[T] {
	return Removable[T]{value: nil}
}

func (r *Removable[T]) BuildStruct(value T) Removable[T] {
	return Removable[T]{value: &value}
}

func (r Removable[T]) Get() *T {
	return r.value
}

func (r *Removable[T]) MarshalJSON() ([]byte, error) {
	if r.value == nil {
		return json.Marshal("remove")
	}
	return json.Marshal(r.value)
}

func (r *Removable[T]) UnmarshalJSON(data []byte) error {
	var maybeRemove string
	if err := json.Unmarshal(data, &maybeRemove); err == nil {
		if maybeRemove == "remove" {
			r.value = nil
			return nil
		} else {
			t := *new(T)
			return errors.Errorf("invalid value for Removable[%T]: expected \"remove\" or %T", t, t)
		}
	}
	return json.Unmarshal(data, &r.value)
}

type Base64UrlSafe []byte

func (x Base64UrlSafe) MarshalJSON() ([]byte, error) {

	enc := make([]byte, len(x))
	b64.URLEncoding.Encode(enc, x)
	return json.Marshal(&enc)
}

func (x Base64UrlSafe) UnmarshalJSON(data []byte) error {
	var raw string
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}
	var sDec []byte
	var decErr error
	if decErr != nil {
		return decErr
	}
	sDec, decErr = b64.URLEncoding.DecodeString(raw)
	x = sDec
	return nil
}

type IpAddr struct {
	Address net.IP
}

func (x *IpAddr) MarshalJSON() ([]byte, error) {
	return x.Address.MarshalText()
}

func (x *IpAddr) UnmarshalJSON(data []byte) error {
	err := x.Address.UnmarshalText(data)
	return err
}

type Duration struct {
	Secs  uint64 `json:"secs,omitempty"`
	Nanos uint32 `json:"nanos,omitempty"` // Always 0 <= nanos < NANOS_PER_SEC
}

type PluginVersion struct {
	Major uint64
	Minor uint64
}

func (x *PluginVersion) MarshalJSON() ([]byte, error) {
	var ver string
	ver = fmt.Sprintf("%v.%v", x.Major, x.Minor)
	return json.Marshal(&ver)
}

func (x *PluginVersion) UnmarshalJSON(data []byte) error {
	var obj string
	err := json.Unmarshal(data, &obj)
	if err != nil {
		return err
	}
	ver := strings.Split(obj, ".")
	var convErr error
	maj, convErr := strconv.ParseUint(ver[0], 10, 32)
	if convErr != nil {
		return convErr
	}
	min, convErr := strconv.ParseUint(ver[1], 10, 32)
	if convErr != nil {
		return convErr
	}
	x.Major = maj
	x.Minor = min
	return nil
}

type PublicKeyCredentialAuthenticatorAttestationResponse struct {
	Id               Base64UrlSafe                         `json:"id,omitempty"`
	Type             PublicKeyCredentialType               `json:"type,omitempty"`
	Response         AuthenticatorAssertionResponse        `json:"response,omitempty"`
	ExtensionResults AuthenticationExtensionsClientOutputs `json:"get_client_extension_results,omitempty"`
}

type AuditLogTime time.Time

func (t AuditLogTime) MarshalJSON() ([]byte, error) {
	strDate := time.Time(t).Format(time.RFC3339)
	return json.Marshal(strDate)
}

func (t *AuditLogTime) UnmarshalJSON(data []byte) (err error) {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	q, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return fmt.Errorf("Unable to parse the AuditLogTime: %v", err)
	}
	*t = AuditLogTime(q)
	return nil
}

func (r *ListSobjectsResponse) UnmarshalJSON(data []byte) error {
	// Define an intermediate struct to decode the items array.
	type response struct {
		Md    Metadata  `json:"metadata,omitempty"`
		Items []Sobject `json:"items,omitempty"`
	}

	// Decode the JSON into the intermediate struct.
	var resp1 response
	var resp2 []Sobject
	err1 := json.Unmarshal(data, &resp1)
	err2 := json.Unmarshal(data, &resp2)

	if err1 == nil {
		r.Items = resp1.Items
		r.Md = resp1.Md
		return nil
	}

	if err2 == nil {
		r.Items = resp2
		return nil
	}
	if err1 != nil && err2 != nil {
		return fmt.Errorf("Error in decoding ListSobjectResponse: %v, %v", err1, err2)
	}
	return nil
}

type CustomMetadata map[string]string

func (x *CustomMetadata) urlEncode(v map[string][]string) error {
	if x == nil {
		return nil
	}
	for k, val := range *x {
		v[fmt.Sprintf("custom_metadata.%s", k)] = []string{val}
	}
	return nil
}

// Turns a value into a non-nil pointer. This is a convenience function since
// it's not possible to take the address of a literal in Go.
func Some[T any](x T) *T {
	return &x
}

// TODO: remove these in favor of the generic Some. Note that these are used in
// generated code, so we should change the codegen to use the generic version.

func someString(val string) *string { return &val }
func someBlob(val []byte) *[]byte   { return &val }
