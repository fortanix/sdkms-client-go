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
    "github.com/pkg/errors"
)

type AuthDiscoverParams struct {
    // The account for which the user wishes to discover authentication mechanisms.
    // Note that if specified, the user_email field in an AuthDiscoverRequest will
    // be ignored.
    AcctID *UUID `json:"acct_id,omitempty"`
}
func (x AuthDiscoverParams) urlEncode(v map[string][]string) error {
    if x.AcctID != nil {
        v["acct_id"] = []string{fmt.Sprintf("%v", *x.AcctID)}
    }
    return nil
}

type AuthDiscoverRequest struct {
    // The email of the user wishing to log in. If the auth discovery
    // request also includes an acct_id query parameter, this field
    // will be effectively ignored.
    UserEmail *string `json:"user_email,omitempty"`
}

type AuthMethod struct {
    Password *struct{}
    SamlPost *AuthMethodSamlPost
    OauthAuthCodeGrant *AuthMethodOauthAuthCodeGrant
    LdapPassword *AuthMethodLdapPassword
    Vcd *AuthMethodVcd
}
type AuthMethodSamlPost struct {
    Name string `json:"name"`
    IconURL string `json:"icon_url"`
    ID string `json:"id"`
    BindingURL string `json:"binding_url"`
    AuthnRequest string `json:"authn_request"`
    IdpID Blob `json:"idp_id"`
}
type AuthMethodOauthAuthCodeGrant struct {
    Name string `json:"name"`
    IconURL string `json:"icon_url"`
    AuthorizationURL string `json:"authorization_url"`
    ClientID string `json:"client_id"`
    RedirectURI string `json:"redirect_uri"`
    State string `json:"state"`
    IdpID Blob `json:"idp_id"`
    AuthParams OauthAuthenticationParameters `json:"auth_params"`
}
type AuthMethodLdapPassword struct {
    Name string `json:"name"`
    IconURL string `json:"icon_url"`
    IdpID Blob `json:"idp_id"`
}
type AuthMethodVcd struct {
    Name string `json:"name"`
    AuthorizationURL string `json:"authorization_url"`
    IdpID Blob `json:"idp_id"`
}
func (x AuthMethod) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "AuthMethod", 
                  []bool{ x.Password != nil,
                  x.SamlPost != nil,
                  x.OauthAuthCodeGrant != nil,
                  x.LdapPassword != nil,
                  x.Vcd != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.Password != nil:
        m["method"] = "password"
    case x.SamlPost != nil:
        b, err := json.Marshal(x.SamlPost)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["method"] = "saml-post"
    case x.OauthAuthCodeGrant != nil:
        b, err := json.Marshal(x.OauthAuthCodeGrant)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["method"] = "oauth-auth-code-grant"
    case x.LdapPassword != nil:
        b, err := json.Marshal(x.LdapPassword)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["method"] = "ldap-password"
    case x.Vcd != nil:
        b, err := json.Marshal(x.Vcd)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["method"] = "vcd"
    }
    return json.Marshal(m)
}
func (x *AuthMethod) UnmarshalJSON(data []byte) error {
    x.Password = nil
    x.SamlPost = nil
    x.OauthAuthCodeGrant = nil
    x.LdapPassword = nil
    x.Vcd = nil
    var h struct {
        Tag string `json:"method"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid AuthMethod")
    }
    switch h.Tag {
    case "password":
        x.Password = &struct{}{}
    case "saml-post":
        var samlPost AuthMethodSamlPost
        if err := json.Unmarshal(data, &samlPost); err != nil {
            return err
        }
        x.SamlPost = &samlPost
    case "oauth-auth-code-grant":
        var oauthAuthCodeGrant AuthMethodOauthAuthCodeGrant
        if err := json.Unmarshal(data, &oauthAuthCodeGrant); err != nil {
            return err
        }
        x.OauthAuthCodeGrant = &oauthAuthCodeGrant
    case "ldap-password":
        var ldapPassword AuthMethodLdapPassword
        if err := json.Unmarshal(data, &ldapPassword); err != nil {
            return err
        }
        x.LdapPassword = &ldapPassword
    case "vcd":
        var vcd AuthMethodVcd
        if err := json.Unmarshal(data, &vcd); err != nil {
            return err
        }
        x.Vcd = &vcd
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

type AuthRequest struct {
    TokenType *TokenType `json:"token_type,omitempty"`
    Method AuthRequestMethod `json:"method"`
}
func (x AuthRequest) MarshalJSON() ([]byte, error) {
    m := make(map[string]interface{})
    { // x.Method is flattened
        b, err := json.Marshal(&x.Method)
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
    if x.TokenType != nil {
        m["token_type"] = x.TokenType
    }
    return json.Marshal(&m)
}
func (x *AuthRequest) UnmarshalJSON(data []byte) error {
    if err := json.Unmarshal(data, &x.Method); err != nil {
        return err
    }
    var r struct {
    TokenType *TokenType `json:"token_type,omitempty"`
    }
    if err := json.Unmarshal(data, &r); err != nil {
        return err
    }
    x.TokenType = r.TokenType
    return nil
}

type AuthRequestMethod struct {
    SamlResponse *AuthRequestMethodSamlResponse
    OauthAuthCode *OauthCodeData
    LdapBasicAuth *AuthRequestMethodLdapBasicAuth
    AuthByAppName *AuthRequestMethodAuthByAppName
    AwsIam *AuthRequestMethodAwsIam
    // Login using a DSM user password and, optionally, a captcha. This is useful
    // for situations where a user is locked out of their DSM account, and wants to
    // become unlocked.
    Password *AuthRequestMethodPassword
}
type AuthRequestMethodSamlResponse struct {
    ID *string `json:"id,omitempty"`
    Response string `json:"response"`
}
type AuthRequestMethodLdapBasicAuth struct {
    IdpID Blob `json:"idp_id"`
    Email string `json:"email"`
    Password ZeroizedString `json:"password"`
    // The account where the IdP is configured. This should
    // only be used if attempting to self-provision into the
    // account. (Self-provisioning may not be possible for
    // existing users; they may need to be manually invited
    // into the account.)
    AcctID *UUID `json:"acct_id,omitempty"`
}
type AuthRequestMethodAuthByAppName struct {
    AcctID UUID `json:"acct_id"`
    Name string `json:"name"`
    Password ZeroizedString `json:"password"`
}
type AuthRequestMethodAwsIam struct {
    AcctID UUID `json:"acct_id"`
    Region string `json:"region"`
    Headers map[string]string `json:"headers"`
}
// Login using a DSM user password and, optionally, a captcha. This is useful
// for situations where a user is locked out of their DSM account, and wants to
// become unlocked.
type AuthRequestMethodPassword struct {
    // The user's email.
    Email string `json:"email"`
    // The user's password.
    Password ZeroizedString `json:"password"`
    // The response token after solving a reCAPTCHA successfully.
    RecaptchaResponse *string `json:"recaptcha_response,omitempty"`
}
func (x AuthRequestMethod) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "AuthRequestMethod", 
                  []bool{ x.SamlResponse != nil,
                  x.OauthAuthCode != nil,
                  x.LdapBasicAuth != nil,
                  x.AuthByAppName != nil,
                  x.AwsIam != nil,
                  x.Password != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.SamlResponse != nil:
        b, err := json.Marshal(x.SamlResponse)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["method"] = "saml-response"
    case x.OauthAuthCode != nil:
        b, err := json.Marshal(x.OauthAuthCode)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["method"] = "oauth-auth-code"
    case x.LdapBasicAuth != nil:
        b, err := json.Marshal(x.LdapBasicAuth)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["method"] = "ldap-basic-auth"
    case x.AuthByAppName != nil:
        b, err := json.Marshal(x.AuthByAppName)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["method"] = "auth-by-app-name"
    case x.AwsIam != nil:
        b, err := json.Marshal(x.AwsIam)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["method"] = "aws-iam"
    case x.Password != nil:
        b, err := json.Marshal(x.Password)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["method"] = "password"
    }
    return json.Marshal(m)
}
func (x *AuthRequestMethod) UnmarshalJSON(data []byte) error {
    x.SamlResponse = nil
    x.OauthAuthCode = nil
    x.LdapBasicAuth = nil
    x.AuthByAppName = nil
    x.AwsIam = nil
    x.Password = nil
    var h struct {
        Tag string `json:"method"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid AuthRequestMethod")
    }
    switch h.Tag {
    case "saml-response":
        var samlResponse AuthRequestMethodSamlResponse
        if err := json.Unmarshal(data, &samlResponse); err != nil {
            return err
        }
        x.SamlResponse = &samlResponse
    case "oauth-auth-code":
        var oauthAuthCode OauthCodeData
        if err := json.Unmarshal(data, &oauthAuthCode); err != nil {
            return err
        }
        x.OauthAuthCode = &oauthAuthCode
    case "ldap-basic-auth":
        var ldapBasicAuth AuthRequestMethodLdapBasicAuth
        if err := json.Unmarshal(data, &ldapBasicAuth); err != nil {
            return err
        }
        x.LdapBasicAuth = &ldapBasicAuth
    case "auth-by-app-name":
        var authByAppName AuthRequestMethodAuthByAppName
        if err := json.Unmarshal(data, &authByAppName); err != nil {
            return err
        }
        x.AuthByAppName = &authByAppName
    case "aws-iam":
        var awsIam AuthRequestMethodAwsIam
        if err := json.Unmarshal(data, &awsIam); err != nil {
            return err
        }
        x.AwsIam = &awsIam
    case "password":
        var password AuthRequestMethodPassword
        if err := json.Unmarshal(data, &password); err != nil {
            return err
        }
        x.Password = &password
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

type AuthResponse struct {
    TokenType TokenType `json:"token_type"`
    ExpiresIn uint32 `json:"expires_in"`
    // Token value that the client should subsequently pass in Authorization header.
    AccessToken *ZeroizedString `json:"access_token,omitempty"`
    EntityID UUID `json:"entity_id"`
    Challenge *U2fMfaChallengeResponse `json:"challenge,omitempty"`
    // Its presence indicates that 2FA is required for this
    // session and contains response that should be used with
    // `navigator.credentials.get()`
    Fido2AssertionOptions *PublicKeyCredentialRequestOptions `json:"fido2_assertion_options,omitempty"`
    AllowedMfaMethods *[]MfaAuthMethod `json:"allowed_mfa_methods,omitempty"`
}

// Temporary credentials to be used for AWS KMS.
type AwsTemporaryCredentials struct {
    AccessKey string `json:"access_key"`
    SecretKey ZeroizedString `json:"secret_key"`
    SessionToken ZeroizedString `json:"session_token"`
}

// Request to start configuring U2F.
type Config2faAuthRequest struct {
    Password ZeroizedString `json:"password"`
}

type Config2faAuthResponse struct {
}

type MfaAuthMethod struct {
    Fido2 *MfaAuthMethodFido2
}
type MfaAuthMethodFido2 struct {
    Challenge PublicKeyCredentialRequestOptions `json:"challenge"`
    ChallengeToken Blob `json:"challenge_token"`
    MfaDevices []MfaDevice `json:"mfa_devices"`
}
func (x MfaAuthMethod) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "MfaAuthMethod", 
                  []bool{ x.Fido2 != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Fido2 *MfaAuthMethodFido2 `json:"Fido2,omitempty"`
    }
    obj.Fido2 = x.Fido2
    return json.Marshal(obj)
}
func (x *MfaAuthMethod) UnmarshalJSON(data []byte) error {
    x.Fido2 = nil
    var obj struct {
        Fido2 *MfaAuthMethodFido2 `json:"Fido2,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.Fido2 = obj.Fido2
    return nil
}

type OauthCodeData struct {
    IdpID Blob `json:"idp_id"`
    Code string `json:"code"`
    Email string `json:"email"`
}

// Request to authenticate using U2F recovery code.
type RecoveryCodeAuthRequest struct {
    RecoveryCode ZeroizedString `json:"recovery_code"`
}

// Request to select an account.
type SelectAccountRequest struct {
    AcctID UUID `json:"acct_id"`
}

// Response to select account request.
type SelectAccountResponse struct {
    Cookie *string `json:"cookie,omitempty"`
}

type TokenType string

// List of supported TokenType values
const (
    TokenTypeBearer TokenType = "Bearer"
    TokenTypeCookie TokenType = "Cookie"
)

// Returns the available auth methods for the given user email.
// Example: password, ldap, oauth, etc.
func (c *Client) AuthDiscover(ctx context.Context, queryParameters *AuthDiscoverParams, body AuthDiscoverRequest) ([]AuthMethod, error) {
    u := "/sys/v1/session/auth/discover"
    if queryParameters != nil {
        q, err := encodeURLParams(queryParameters)
        if err != nil {
            return nil, err
        }
        u = fmt.Sprintf("%v?%v", u, q)
    }
    var r []AuthMethod
    if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
        return nil, err
    }
    return r, nil
}

// Create a session for a user or an app.
//
// Authenticate a user or an app to begin a session.
// The caller needs to provide a basic authentication token or
// an appropriate request body (see input type).
// The response body contains a bearer authentication token
// which needs to be provided by subsequent calls for the
// duration of the session.
//
// If this is basic auth and the user has MFA devices configured,
// the response also contains challenge for the device to sign.
// Until the signed assertion is passed to `POST /sys/v1/session/auth/2fa/fido2`
// to complete 2FA, the bearer token can't be used for anything else.
func (c *Client) Authenticate(ctx context.Context, body AuthRequest) (*AuthResponse, error) {
    u := "/sys/v1/session/auth"
    var r AuthResponse
    if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Unlock two factor configuration.
//
// Re-authenticate to unlock two factor configuration.
// Two factor configuration must be unlocked to enable or disable two
// factor authentication, add or remove two factor devices, or
// regenerate recovery codes.
func (c *Client) Config2faAuth(ctx context.Context, body Config2faAuthRequest) (*Config2faAuthResponse, error) {
    u := "/sys/v1/session/config_2fa/auth"
    var r Config2faAuthResponse
    if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Lock two factor configuration.
//
// Lock two factor configuration after completing two factor
// reconfiguration. If this API is not called, two factor
// configuration will be locked automatically after ten minutes.
// Locking this back is necessary if the 2FA device needs to be used
// for other things like approval requests. It is not possible use
// 2FA for other purposes when configuration mode is unlocked.
func (c *Client) Config2faTerminate(ctx context.Context) error {
    u := "/sys/v1/session/config_2fa/terminate"
    if err := c.fetch(ctx, http.MethodPost, u, nil, nil); err != nil {
        return err
    }
    return nil
}

// Create a new session for an App using an existing
// session bearer token.
func (c *Client) Reauthenticate(ctx context.Context) (*AuthResponse, error) {
    u := "/sys/v1/session/reauth"
    var r AuthResponse
    if err := c.fetch(ctx, http.MethodPost, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Use a backup recovery code to complete authentication.
//
// Complete two factor authentication with a backup recovery code.
// Each recovery code may only be used once, so users should update
// their two factor configuration after using this API.
func (c *Client) RecoveryCodeAuth(ctx context.Context, body RecoveryCodeAuthRequest) error {
    u := "/sys/v1/session/auth/2fa/recovery_code"
    if err := c.fetch(ctx, http.MethodPost, u, &body, nil); err != nil {
        return err
    }
    return nil
}

// Perform a no-op to keep session from expiring.
func (c *Client) Refresh(ctx context.Context) error {
    u := "/sys/v1/session/refresh"
    if err := c.fetch(ctx, http.MethodPost, u, nil, nil); err != nil {
        return err
    }
    return nil
}

// Select one of user's account to proceed. Even if the user has only
// one account, this needs to be called.
func (c *Client) SelectAccount(ctx context.Context, body SelectAccountRequest) (*SelectAccountResponse, error) {
    u := "/sys/v1/session/select_account"
    var r SelectAccountResponse
    if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// This sets AWS temporary credentials in the session so that calls to
// AWS backed groups use these credentials.
// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html
func (c *Client) SetAwsTemporaryCredentials(ctx context.Context, body AwsTemporaryCredentials) error {
    u := "/sys/v1/session/aws_temporary_credentials"
    if err := c.fetch(ctx, http.MethodPost, u, &body, nil); err != nil {
        return err
    }
    return nil
}

// Terminate the current session.
//
// Terminate an authenticated session. After this call, the provided
// bearer authentication token will be invalidated and cannot be used
// to make any further API calls.
func (c *Client) Terminate(ctx context.Context) error {
    u := "/sys/v1/session/terminate"
    if err := c.fetch(ctx, http.MethodPost, u, nil, nil); err != nil {
        return err
    }
    return nil
}

// Use of U2F is deprecated, this endpoint will return BadRequest.
func (c *Client) U2fAuth(ctx context.Context, body U2fAuthRequest) error {
    u := "/sys/v1/session/auth/2fa/u2f"
    if err := c.fetch(ctx, http.MethodPost, u, &body, nil); err != nil {
        return err
    }
    return nil
}

