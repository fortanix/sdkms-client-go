/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package sdkms

import (
	"encoding/json"
	"fmt"
	"testing"
)

func Test_AppGroups1(t *testing.T) {
	p1 := AppPermissionsEncrypt | AppPermissionsDecrypt
	p2 := AppPermissionsAgreekey | AppPermissionsDecrypt | AppPermissionsDerivekey | AppPermissionsEncrypt |
		AppPermissionsExport | AppPermissionsMacgenerate | AppPermissionsMacverify | AppPermissionsManage |
		AppPermissionsSign | AppPermissionsUnwrapkey | AppPermissionsVerify | AppPermissionsWrapkey
	var p3 AppPermissions // empty list
	tt := []struct {
		input AppGroups
		want  string
	}{
		{
			input: AppGroups{"1": &p1},
			want:  `{"1":["ENCRYPT","DECRYPT"]}`,
		},
		{
			input: AppGroups{"1": &p1, "2": &p2},
			want:  `{"1":["ENCRYPT","DECRYPT"],"2":["SIGN","VERIFY","ENCRYPT","DECRYPT","WRAPKEY","UNWRAPKEY","DERIVEKEY","MACGENERATE","MACVERIFY","EXPORT","MANAGE","AGREEKEY"]}`,
		},
		{
			input: AppGroups{"3": &p3},
			want:  `{"3":[]}`,
		},
		{
			input: AppGroups{"4": nil},
			want:  `{"4":[]}`,
		},
	}
	for i, tc := range tt {
		t.Run(fmt.Sprintf("Marshal-%v", i), func(t *testing.T) {
			b, err := json.Marshal(tc.input)
			if err != nil {
				t.Fatalf("Failed to marshal: %v", err)
			}
			got := string(b)
			if got != tc.want {
				t.Errorf("Expected JSON value %#v, got %#v", tc.want, got)
			}
		})
		t.Run(fmt.Sprintf("Unmarshal-%v", i), func(t *testing.T) {
			var v AppGroups
			if err := json.Unmarshal([]byte(tc.want), &v); err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}
			if !v.equals(&tc.input) {
				t.Errorf("Unmarshalled value differs from expected value")
			}
		})
	}
}

func Test_AppGroups2(t *testing.T) {
	p1 := AppPermissionsEncrypt | AppPermissionsDecrypt
	tt := []struct {
		input string
		want  AppGroups
	}{
		// modern form
		{
			input: `{"1":["ENCRYPT","DECRYPT"]}`,
			want:  AppGroups{"1": &p1},
		},
		{
			input: `{}`,
			want:  AppGroups{},
		},
		// backcompat form
		{
			input: `["1","2"]`,
			want:  AppGroups{"1": nil, "2": nil},
		},
		{
			input: `[]`,
			want:  AppGroups{},
		},
	}
	for i, tc := range tt {
		t.Run(fmt.Sprintf("Unmarshal-%v", i), func(t *testing.T) {
			var v AppGroups
			if err := json.Unmarshal([]byte(tc.input), &v); err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}
			if !v.equals(&tc.want) {
				t.Errorf("Unmarshalled value differs from expected value")
			}
		})
	}
}

func Test_CryptMode(t *testing.T) {
	tt := []struct {
		input CryptMode
		want  string
	}{
		{
			input: *CryptModeRSA(RsaEncryptionPaddingPKCS1V15()),
			want:  `{"PKCS1_V15":{}}`,
		},
		{
			input: *CryptModeRSA(RsaEncryptionPaddingOAEPMGF1(DigestAlgorithmSha256)),
			want:  `{"OAEP":{"mgf":{"mgf1":{"hash":"SHA256"}}}}`,
		},
		{
			input: *CryptModeSymmetric(CipherModeGcm),
			want:  `"GCM"`,
		},
	}
	for i, tc := range tt {
		t.Run(fmt.Sprintf("Marshal-%v", i), func(t *testing.T) {
			b, err := json.Marshal(tc.input)
			if err != nil {
				t.Fatalf("Failed to marshal: %v", err)
			}
			got := string(b)
			if got != tc.want {
				t.Errorf("Expected JSON value %#v, got %#v", tc.want, got)
			}
		})
		t.Run(fmt.Sprintf("Unmarshal-%v", i), func(t *testing.T) {
			var v CryptMode
			if err := json.Unmarshal([]byte(tc.want), &v); err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}
			if !v.equals(&tc.input) {
				t.Errorf("Unmarshalled value differs from expected value")
			}
		})
	}
}

func Test_Principal(t *testing.T) {
	tt := []struct {
		input Principal
		want  string
	}{
		{
			input: Principal{User: someString("b0814e50-41b9-4913-be93-6184294a55ea")},
			want:  `{"user":"b0814e50-41b9-4913-be93-6184294a55ea"}`,
		},
		{
			input: Principal{Plugin: someString("8ecb8bd8-5da6-469e-b114-aed52519f03e")},
			want:  `{"plugin":"8ecb8bd8-5da6-469e-b114-aed52519f03e"}`,
		},
		{
			input: Principal{App: someString("7dcb8bd0-3db4-349f-b114-4174284a355e1")},
			want:  `{"app":"7dcb8bd0-3db4-349f-b114-4174284a355e1"}`,
		},
		{
			input: Principal{UserViaApp: &PrincipalUserViaApp{
				UserID: "b0814e50-41b9-4913-be93-6184294a55ea",
				Scopes: []OauthScope{OauthScopeApp},
			}},
			want: `{"userviaapp":{"user_id":"b0814e50-41b9-4913-be93-6184294a55ea","scopes":["app"]}}`,
		},
	}
	for i, tc := range tt {
		t.Run(fmt.Sprintf("Marshal-%v", i), func(t *testing.T) {
			b, err := json.Marshal(tc.input)
			if err != nil {
				t.Fatalf("Failed to marshal: %v", err)
			}
			got := string(b)
			if got != tc.want {
				t.Errorf("Expected JSON value %#v, got %#v", tc.want, got)
			}
		})
		t.Run(fmt.Sprintf("Unmarshal-%v", i), func(t *testing.T) {
			var v Principal
			if err := json.Unmarshal([]byte(tc.want), &v); err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}
			if !v.equals(&tc.input) {
				t.Errorf("Unmarshalled value differs from expected value")
			}
		})
	}
}

func Test_TlsConfig(t *testing.T) {
	tt := []struct {
		input TlsConfig
		want  string
	}{
		{input: TlsConfig{Disabled: &struct{}{}}, want: `{"mode":"disabled"}`},
		{input: TlsConfig{Opportunistic: &struct{}{}}, want: `{"mode":"opportunistic"}`},
		{
			input: TLSConfigGlobalRootCAs(true),
			want:  `{"ca":{"ca_set":"global_roots"},"mode":"required","validate_hostname":true}`,
		},
		{
			input: TLSConfigPinned([]Blob{{104, 101, 108, 108, 111}}, true),
			want:  `{"ca":{"pinned":["aGVsbG8="]},"mode":"required","validate_hostname":true}`,
		},
		{
			input: TLSConfigPinned([]Blob{{104, 101, 108, 108, 111}, {119, 111, 114, 108, 100}}, false),
			want:  `{"ca":{"pinned":["aGVsbG8=","d29ybGQ="]},"mode":"required","validate_hostname":false}`,
		},
	}
	for i, tc := range tt {
		t.Run(fmt.Sprintf("Marshal-%v", i), func(t *testing.T) {
			b, err := json.Marshal(tc.input)
			if err != nil {
				t.Fatalf("Failed to marshal: %v", err)
			}
			got := string(b)
			if got != tc.want {
				t.Errorf("Expected JSON value %#v, got %#v", tc.want, got)
			}
		})
		t.Run(fmt.Sprintf("Unmarshal-%v", i), func(t *testing.T) {
			var v TlsConfig
			if err := json.Unmarshal([]byte(tc.want), &v); err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}
			if !v.equals(&tc.input) {
				t.Errorf("Unmarshalled value differs from expected value")
			}
		})
	}
}

type optionalEnums struct {
	CryptMode *CryptMode `json:"cm,omitempty"`
	TlsConfig *TlsConfig `json:"tc,omitempty"`
	Principal *Principal `json:"pr,omitempty"`
}

func (p1 *optionalEnums) equals(p2 *optionalEnums) bool {
	if xor(p1.CryptMode == nil, p2.CryptMode == nil) {
		return false
	}
	if xor(p1.TlsConfig == nil, p2.TlsConfig == nil) {
		return false
	}
	if xor(p1.Principal == nil, p2.Principal == nil) {
		return false
	}
	return (p1.CryptMode == p2.CryptMode || p1.CryptMode.equals(p2.CryptMode)) &&
		(p1.TlsConfig == p2.TlsConfig || p1.TlsConfig.equals(p2.TlsConfig)) &&
		(p1.Principal == p2.Principal || p1.Principal.equals(p2.Principal))
}

func Test_OptionalEnums(t *testing.T) {
	tt := []struct {
		input optionalEnums
		want  string
	}{
		{input: optionalEnums{}, want: `{}`},
		{
			input: optionalEnums{
				CryptMode: CryptModeSymmetric(CipherModeCtr),
			},
			want: `{"cm":"CTR"}`,
		},
		{
			input: optionalEnums{
				TlsConfig: &TlsConfig{Opportunistic: &struct{}{}},
			},
			want: `{"tc":{"mode":"opportunistic"}}`,
		},
		{
			input: optionalEnums{
				Principal: &Principal{App: someString("7dcb8bd0-3db4-349f-b114-4174284a355e1")},
			},
			want: `{"pr":{"app":"7dcb8bd0-3db4-349f-b114-4174284a355e1"}}`,
		},
		{
			input: optionalEnums{
				CryptMode: CryptModeSymmetric(CipherModeCtr),
				TlsConfig: &TlsConfig{Opportunistic: &struct{}{}},
				Principal: &Principal{App: someString("7dcb8bd0-3db4-349f-b114-4174284a355e1")},
			},
			want: `{"cm":"CTR","tc":{"mode":"opportunistic"},"pr":{"app":"7dcb8bd0-3db4-349f-b114-4174284a355e1"}}`,
		},
	}
	for i, tc := range tt {
		t.Run(fmt.Sprintf("Marshal-%v", i), func(t *testing.T) {
			b, err := json.Marshal(tc.input)
			if err != nil {
				t.Fatalf("Failed to marshal: %v", err)
			}
			got := string(b)
			if got != tc.want {
				t.Errorf("Expected JSON value %#v, got %#v", tc.want, got)
			}
		})
		t.Run(fmt.Sprintf("Unmarshal-%v", i), func(t *testing.T) {
			var v optionalEnums
			if err := json.Unmarshal([]byte(tc.want), &v); err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}
			if !v.equals(&tc.input) {
				t.Errorf("Unmarshalled value differs from expected value")
			}
		})
	}
}

func (p1 *TlsConfig) equals(p2 *TlsConfig) bool {
	if xor(p1.Disabled == nil, p2.Disabled == nil) {
		return false
	}
	if xor(p1.Opportunistic == nil, p2.Opportunistic == nil) {
		return false
	}
	if xor(p1.Required == nil, p2.Required == nil) {
		return false
	}
	return (p1.Disabled == p2.Disabled || *p1.Disabled == *p2.Disabled) &&
		(p1.Opportunistic == p2.Opportunistic || *p1.Opportunistic == *p2.Opportunistic) &&
		(p1.Required == p2.Required || p1.Required.equals(p2.Required))
}

func (p1 *TlsConfigRequired) equals(p2 *TlsConfigRequired) bool {
	return p1.ValidateHostname == p2.ValidateHostname && p1.Ca.equals(&p2.Ca)
}

func (p1 *CaConfig) equals(p2 *CaConfig) bool {
	if xor(p1.CaSet == nil, p2.CaSet == nil) {
		return false
	}
	if xor(p1.Pinned == nil, p2.Pinned == nil) {
		return false
	}
	if p1.Pinned != nil {
		for i := range *p1.Pinned {
			if len((*p1.Pinned)[i]) != len((*p2.Pinned)[i]) {
				return false
			}
			for j := range (*p1.Pinned)[i] {
				if (*p1.Pinned)[i][j] != (*p2.Pinned)[i][j] {
					return false
				}
			}
		}
	}
	return p1.CaSet == p2.CaSet || *p1.CaSet == *p2.CaSet
}

func (p1 *Principal) equals(p2 *Principal) bool {
	if xor(p1.App == nil, p2.App == nil) {
		return false
	}
	if xor(p1.Plugin == nil, p2.Plugin == nil) {
		return false
	}
	if xor(p1.User == nil, p2.User == nil) {
		return false
	}
	if xor(p1.UserViaApp == nil, p2.UserViaApp == nil) {
		return false
	}
	return (p1.App == p2.App || *p1.App == *p2.App) &&
		(p1.Plugin == p2.Plugin || *p1.Plugin == *p2.Plugin) &&
		(p1.User == p2.User || *p1.User == *p2.User) &&
		(p1.UserViaApp == p2.UserViaApp || p1.UserViaApp.equals(p2.UserViaApp))
}

func (p1 *PrincipalUserViaApp) equals(p2 *PrincipalUserViaApp) bool {
	if p1.UserID != p2.UserID {
		return false
	}
	if len(p1.Scopes) != len(p2.Scopes) {
		return false
	}
	for i := range p1.Scopes {
		if p1.Scopes[i] != p2.Scopes[i] {
			return false
		}
	}
	return true
}

func (p1 *CryptMode) equals(p2 *CryptMode) bool {
	if xor(p1.Rsa == nil, p2.Rsa == nil) {
		return false
	}
	if xor(p1.Symmetric == nil, p2.Symmetric == nil) {
		return false
	}
	return (p1.Rsa == p2.Rsa || p1.Rsa.equals(p2.Rsa)) &&
		(p1.Symmetric == p2.Symmetric || p1.Symmetric.equals(p2.Symmetric))
}

func (p1 *RsaEncryptionPadding) equals(p2 *RsaEncryptionPadding) bool {
	if xor(p1.Oaep == nil, p2.Oaep == nil) {
		return false
	}
	if xor(p1.Pkcs1V15 == nil, p2.Pkcs1V15 == nil) {
		return false
	}
	return (p1.Oaep == p2.Oaep || p1.Oaep.equals(p2.Oaep)) &&
		(p1.Pkcs1V15 == p2.Pkcs1V15 || *p1.Pkcs1V15 == *p2.Pkcs1V15)
}

func (p1 *RsaEncryptionPaddingOaep) equals(p2 *RsaEncryptionPaddingOaep) bool {
	return p1.Mgf.equals(&p2.Mgf)
}

func (p1 *Mgf) equals(p2 *Mgf) bool {
	if xor(p1.Mgf1 == nil, p2.Mgf1 == nil) {
		return false
	}
	return p1.Mgf1 == p2.Mgf1 || *p1.Mgf1 == *p2.Mgf1
}

func (p1 *CipherMode) equals(p2 *CipherMode) bool {
	if xor(p1 == nil, p2 == nil) {
		return false
	}
	return p1 == p2 || *p1 == *p2
}

func (p1 *AppGroups) equals(p2 *AppGroups) bool {
	if xor(p1 == nil, p2 == nil) {
		return false
	}
	if p1 == nil && p2 == nil {
		return true
	}
	if len(*p1) != len(*p2) {
		return false
	}
	for k, v1 := range *p1 {
		v2, ok := (*p2)[k]
		if !ok || !v1.equals(v2) {
			return false
		}
	}
	return true
}

func (p1 *AppPermissions) equals(p2 *AppPermissions) bool {
	var empty AppPermissions
	if p1 == nil && p2 != nil && *p2 == empty {
		return true
	}
	if p2 == nil && p1 != nil && *p1 == empty {
		return true
	}
	if xor(p1 == nil, p2 == nil) {
		return false
	}
	return p1 == p2 || *p1 == *p2
}

func xor(a, b bool) bool {
	return a && !b || !a && b
}
