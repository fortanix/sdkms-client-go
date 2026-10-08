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
    "net/url"
    "strings"
    "github.com/pkg/errors"
)

// Authentication configuration for Azure integrations that use Credential Objects.
type AzureCredentialAuth struct {
    // OAuth2 client credentials with a client secret value.
    // The `tenant_id` and `client_id` is here as well as we
    // need these to get a token from the client credentials flow.
    ClientSecret *AzureCredentialAuthClientSecret
    // OAuth2 client credentials with a certificate.
    // Azure AD verifies the JWT using the uploaded certificate's public key
    Certificate *AzureCredentialAuthCertificate
}
// OAuth2 client credentials with a client secret value.
// The `tenant_id` and `client_id` is here as well as we
// need these to get a token from the client credentials flow.
type AzureCredentialAuthClientSecret struct {
    // Directory (tenant) ID of the Azure application
    TenantID string `json:"tenant_id"`
    // Application (client) ID of the Azure application
    ClientID string `json:"client_id"`
    // Reference to a `Secret` sobject containing the Azure app's client secret value
    ClientSecret SobjectId `json:"client_secret"`
}
// OAuth2 client credentials with a certificate.
// Azure AD verifies the JWT using the uploaded certificate's public key
type AzureCredentialAuthCertificate struct {
    // Directory (tenant) ID of the Azure application
    TenantID string `json:"tenant_id"`
    // Application (client) ID of the Azure application
    ClientID string `json:"client_id"`
    // Reference to a `Certificate` sobject used to compute
    // the SHA-1 thumbprint (`x5t` header) in the JWT assertion.
    ClientCert SobjectId `json:"client_cert"`
    // Reference to an `RSA` sobject where the private key is used to sign the JWT assertion
    ClientKey SobjectId `json:"client_key"`
}
func (x AzureCredentialAuth) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "AzureCredentialAuth", 
                  []bool{ x.ClientSecret != nil,
                  x.Certificate != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.ClientSecret != nil:
        b, err := json.Marshal(x.ClientSecret)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["$type"] = "ClientSecret"
    case x.Certificate != nil:
        b, err := json.Marshal(x.Certificate)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["$type"] = "Certificate"
    }
    return json.Marshal(m)
}
func (x *AzureCredentialAuth) UnmarshalJSON(data []byte) error {
    x.ClientSecret = nil
    x.Certificate = nil
    var h struct {
        Tag string `json:"$type"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid AzureCredentialAuth")
    }
    switch h.Tag {
    case "ClientSecret":
        var clientSecret AzureCredentialAuthClientSecret
        if err := json.Unmarshal(data, &clientSecret); err != nil {
            return err
        }
        x.ClientSecret = &clientSecret
    case "Certificate":
        var certificate AzureCredentialAuthCertificate
        if err := json.Unmarshal(data, &certificate); err != nil {
            return err
        }
        x.Certificate = &certificate
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

// Describes the authentication type for a given integration.
// 
// This type is the "backbone" to the credential objects in DSM as it's what
// contains the relevant information and references to the sobject(s) needed to authenticate
// to external systems/services.
type CredentialDetails struct {
    // Credential details for an OCI Key Vault Integration.
    Oci *OciCredentialAuth
    // Credential details for Azure Monitor Logs integrations.
    Azure *AzureCredentialAuth
    // Credential details for LDAP integrations.
    Ldap *LdapCredentialAuth
}
func (x CredentialDetails) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "CredentialDetails", 
                  []bool{ x.Oci != nil,
                  x.Azure != nil,
                  x.Ldap != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Tag string `json:"$type"`
        Value any `json:"body,omitempty"`
    }
    if x.Oci != nil {
        obj.Tag = "Oci"
        obj.Value = x.Oci
    } else if x.Azure != nil {
        obj.Tag = "Azure"
        obj.Value = x.Azure
    } else if x.Ldap != nil {
        obj.Tag = "Ldap"
        obj.Value = x.Ldap
    }
    return json.Marshal(obj)
}

func (x *CredentialDetails) UnmarshalJSON(data []byte) error {
    x.Oci = nil
    x.Azure = nil
    x.Ldap = nil

    var metadata struct {
        Tag string `json:"$type"`
        Value json.RawMessage `json:"body"`
    }

    if err := json.Unmarshal(data, &metadata); err != nil {
        return errors.Errorf("not a valid CredentialDetails")
    }

    switch metadata.Tag {
    case "Oci":
        var oci OciCredentialAuth
        if err := json.Unmarshal(metadata.Value, &oci); err != nil {
            return err
        }
        x.Oci = &oci
    case "Azure":
        var azure AzureCredentialAuth
        if err := json.Unmarshal(metadata.Value, &azure); err != nil {
            return err
        }
        x.Azure = &azure
    case "Ldap":
        var ldap LdapCredentialAuth
        if err := json.Unmarshal(metadata.Value, &ldap); err != nil {
            return err
        }
        x.Ldap = &ldap
    default:
         return errors.Errorf("invalid tag value: %v", metadata.Tag)
    }
    return nil
}

type CredentialSort struct {
    // Sort the credentials on the basis of the credential_id
    ByCredentialID *CredentialSortByCredentialId
    // Sort credentials on the basis of the credential name
    ByCredentialName *CredentialSortByCredentialName
}
// Sort the credentials on the basis of the credential_id
type CredentialSortByCredentialId struct {
    Order Order `json:"order"`
}
// Sort credentials on the basis of the credential name
type CredentialSortByCredentialName struct {
    Order Order `json:"order"`
}
func (x CredentialSort) urlEncode(v map[string][]string) error {
    if x.ByCredentialId != nil && x.ByCredentialName != nil {
        return errors.New("CredentialSort can be either ByCredentialId or ByCredentialName")
    }
    if x.ByCredentialID != nil {
        v["sort_by"] = []string{"credential_id" + string(x.ByCredentialID.Order)}
    }
    if x.ByCredentialName != nil {
        v["sort_by"] = []string{"credential_name" + string(x.ByCredentialName.Order)}
    }
    return nil
}

type IntegrationCredential struct {
    // The time the credential was created
    CreatedAt Time `json:"created_at"`
    // The principal that created the credential
    Creator Principal `json:"creator"`
    // The information for a credential to a specific integration for DSM
    CredentialDetails CredentialDetails `json:"credential_details"`
    CredentialID UUID `json:"credential_id"`
    Description *string `json:"description,omitempty"`
    // The ID of the group that this credential is associated with
    GroupID UUID `json:"group_id"`
    // The human readable name of the credential
    Name string `json:"name"`
}

type IntegrationCredentialCreateRequest struct {
    // The information for a credential to a specific integration for DSM
    CredentialDetails CredentialDetails `json:"credential_details"`
    Description *string `json:"description,omitempty"`
    // The ID of the group that this credential is associated with
    GroupID UUID `json:"group_id"`
    // The human readable name of the credential
    Name string `json:"name"`
}

type IntegrationCredentialRotationRequest struct {
    // The kind of rotation that the credential will undergo. 
    Method RotationMethod `json:"method"`
}

type IntegrationCredentialUpdateRequest struct {
    // The information for a credential to a specific integration for DSM
    CredentialDetails *CredentialDetails `json:"credential_details,omitempty"`
    Description *string `json:"description,omitempty"`
    // The human readable name of the credential
    Name *string `json:"name,omitempty"`
}

// Credential details for an LDAP auth configuration.
type LdapCredentialAuth struct {
    // Details for an LDAP service account and its password.
    ServiceAccountWithPassword *LdapCredentialAuthServiceAccountWithPassword
}
// Details for an LDAP service account and its password.
type LdapCredentialAuthServiceAccountWithPassword struct {
    // Distinguished name of the service account.
    Dn string `json:"dn"`
    // Information about the service account password.
    Password LdapCredentialPassword `json:"password"`
}
func (x LdapCredentialAuth) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "LdapCredentialAuth", 
                  []bool{ x.ServiceAccountWithPassword != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.ServiceAccountWithPassword != nil:
        b, err := json.Marshal(x.ServiceAccountWithPassword)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["$type"] = "service_account_with_password"
    }
    return json.Marshal(m)
}
func (x *LdapCredentialAuth) UnmarshalJSON(data []byte) error {
    x.ServiceAccountWithPassword = nil
    var h struct {
        Tag string `json:"$type"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid LdapCredentialAuth")
    }
    switch h.Tag {
    case "service_account_with_password":
        var serviceAccountWithPassword LdapCredentialAuthServiceAccountWithPassword
        if err := json.Unmarshal(data, &serviceAccountWithPassword); err != nil {
            return err
        }
        x.ServiceAccountWithPassword = &serviceAccountWithPassword
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

// Information about a password used in an [`LdapCredentialAuth`] object.
type LdapCredentialPassword struct {
    Sobject *LdapCredentialPasswordSobject
}
type LdapCredentialPasswordSobject struct {
    // The ID of the security object containing the password. This must point
    // to a security object of type Secret, consisting of valid UTF-8 bytes.
    SobjectID SobjectId `json:"sobject_id"`
}
func (x LdapCredentialPassword) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "LdapCredentialPassword", 
                  []bool{ x.Sobject != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.Sobject != nil:
        b, err := json.Marshal(x.Sobject)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["source"] = "sobject"
    }
    return json.Marshal(m)
}
func (x *LdapCredentialPassword) UnmarshalJSON(data []byte) error {
    x.Sobject = nil
    var h struct {
        Tag string `json:"source"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid LdapCredentialPassword")
    }
    switch h.Tag {
    case "sobject":
        var sobject LdapCredentialPasswordSobject
        if err := json.Unmarshal(data, &sobject); err != nil {
            return err
        }
        x.Sobject = &sobject
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

type ListCredentialsMetadata struct {
    TotalCount uint `json:"total_count"`
    FilteredCount uint `json:"filtered_count"`
}

type ListCredentialsParams struct {
    // Specify how to sort the credentials returned in the response
    Sort *CredentialSort `json:"sort,omitempty"`
    // Set the max number of credentials to be returned in the response (default: 1000).
    Limit *uint `json:"limit,omitempty"`
    // Skip first n (offset) matches
    Offset *uint `json:"offset,omitempty"`
    // Allows for more specific filters on the credential.
    Filter *string `json:"filter,omitempty"`
}
func (x ListCredentialsParams) urlEncode(v map[string][]string) error {
    if err := x.Sort.urlEncode(v); err != nil {
        return err
    }
    if x.Limit != nil {
        v["limit"] = []string{fmt.Sprintf("%v", *x.Limit)}
    }
    if x.Offset != nil {
        v["offset"] = []string{fmt.Sprintf("%v", *x.Offset)}
    }
    if x.Filter != nil {
        v["filter"] = []string{fmt.Sprintf("%v", *x.Filter)}
    }
    return nil
}

type ListCredentialsResponse struct {
    Items []IntegrationCredential `json:"items"`
    Metadata ListCredentialsMetadata `json:"metadata"`
}

type OciCredentialAuth struct {
    // **NOTE**: This is not to be confused with a static long-lived token.
    APIKey *OciCredentialAuthApiKey
}
// **NOTE**: This is not to be confused with a static long-lived token.
type OciCredentialAuthApiKey struct {
    // The user's OCID from Oracle who will have the public key
    // configured as an "API Key" on Oracle servers. That public
    // key is part of the key-pair represented by `signing_key`.
    UserOcid string `json:"user_ocid"`
    // The tenant OCID from Oracle
    TenantOcid string `json:"tenant_ocid"`
    // A reference to the security object which will be used
    // to sign requests to OCI.
    SigningKey SobjectId `json:"signing_key"`
}
func (x OciCredentialAuth) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "OciCredentialAuth", 
                  []bool{ x.APIKey != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.APIKey != nil:
        b, err := json.Marshal(x.APIKey)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["$type"] = "ApiKey"
    }
    return json.Marshal(m)
}
func (x *OciCredentialAuth) UnmarshalJSON(data []byte) error {
    x.APIKey = nil
    var h struct {
        Tag string `json:"$type"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid OciCredentialAuth")
    }
    switch h.Tag {
    case "ApiKey":
        var apiKey OciCredentialAuthApiKey
        if err := json.Unmarshal(data, &apiKey); err != nil {
            return err
        }
        x.APIKey = &apiKey
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

// Describes the how to rotate the credential and any additional information
// that is required for that to happen successfully.
type RotationMethod struct {
    // The [`IntegrationCredential`] being rotated will have the
    // underlying security objects generated by DSM based on the
    // current parameters.
    Generate *struct{}
}
func (x RotationMethod) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "RotationMethod", 
                  []bool{ x.Generate != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.Generate != nil:
        m["$type"] = "Generate"
    }
    return json.Marshal(m)
}
func (x *RotationMethod) UnmarshalJSON(data []byte) error {
    x.Generate = nil
    var h struct {
        Tag string `json:"$type"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid RotationMethod")
    }
    switch h.Tag {
    case "Generate":
        x.Generate = &struct{}{}
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

// A wrapper type to provide better clarity that the id referenced
// is a security object.
type SobjectId = UUID

// Create a new integration credential
func (c *Client) CreateCredential(ctx context.Context, body IntegrationCredentialCreateRequest) (*IntegrationCredential, error) {
    u := "/sys/v1/credentials"
    var r IntegrationCredential
    if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Delete a credential by id
func (c *Client) DeleteCredential(ctx context.Context, cred_id string) error {
    u := "/sys/v1/credentials/:cred_id"
    u = strings.NewReplacer(":cred_id", cred_id).Replace(u)
    if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
        return err
    }
    return nil
}

// Get all credentials accessible to the requester
func (c *Client) GetAllCredentials(ctx context.Context, queryParameters *ListCredentialsParams) (*ListCredentialsResponse, error) {
    u := "/sys/v1/credentials"
    if queryParameters != nil {
        q, err := encodeURLParams(queryParameters)
        if err != nil {
            return nil, err
        }
        u = fmt.Sprintf("%v?%v", u, q)
    }
    var r ListCredentialsResponse
    if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Get a credential specified by id
func (c *Client) GetCredential(ctx context.Context, cred_id string) (*IntegrationCredential, error) {
    u := "/sys/v1/credentials/:cred_id"
    u = strings.NewReplacer(":cred_id", cred_id).Replace(u)
    var r IntegrationCredential
    if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Rotate a specified credential
func (c *Client) RotateCredential(ctx context.Context, cred_id string, body IntegrationCredentialRotationRequest) (*IntegrationCredential, error) {
    u := "/sys/v1/credentials/:cred_id/rotate"
    u = strings.NewReplacer(":cred_id", cred_id).Replace(u)
    var r IntegrationCredential
    if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Update a credential object
func (c *Client) UpdateCredential(ctx context.Context, cred_id string, body IntegrationCredentialUpdateRequest) (*IntegrationCredential, error) {
    u := "/sys/v1/credentials/:cred_id"
    u = strings.NewReplacer(":cred_id", cred_id).Replace(u)
    var r IntegrationCredential
    if err := c.fetch(ctx, http.MethodPatch, u, &body, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

