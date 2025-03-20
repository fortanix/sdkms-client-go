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

type GetAllServicesResponse struct {
    Items []Service `json:"items"`
}

type HealthCheckInfo struct {
    // The time the health check was initiated.
    InitiatedAt Time `json:"initiated_at"`
    // The time the health check finished (regardless of its outcome).
    FinishedAt Time `json:"finished_at"`
    // The result of the health check.
    Result string `json:"result"`
}

type HealthParams struct {
    Consistency *string `json:"consistency,omitempty"`
    CheckQueues *bool `json:"check_queues,omitempty"`
}
func (x HealthParams) urlEncode(v map[string][]string) error {
    if x.Consistency != nil {
        v["consistency"] = []string{fmt.Sprintf("%v", *x.Consistency)}
    }
    if x.CheckQueues != nil {
        v["check_queues"] = []string{fmt.Sprintf("%v", *x.CheckQueues)}
    }
    return nil
}

type HealthStatus string

// List of supported HealthStatus values
const (
    HealthStatusHealthy HealthStatus = "Healthy"
    HealthStatusUnhealthy HealthStatus = "Unhealthy"
)

type HostnameInfo struct {
    // The health status of the hostname.
    HealthStatus HealthStatus `json:"health_status"`
    // Information about the last completed active health check on the hostname.
    LastHealthCheck *HealthCheckInfo `json:"last_health_check,omitempty"`
}

type LdapPrincipal struct {
    Unresolved *LdapPrincipalUnresolved
    Resolved *LdapPrincipalResolved
}
type LdapPrincipalUnresolved struct {
    Email string `json:"email"`
}
type LdapPrincipalResolved struct {
    Dn string `json:"dn"`
}
func (x LdapPrincipal) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "LdapPrincipal", 
                  []bool{ x.Unresolved != nil,
                  x.Resolved != nil });
                  err != nil {
        return nil, err
    }
    if x.Unresolved != nil {
        return json.Marshal(x.Unresolved)
    }
    if x.Resolved != nil {
        return json.Marshal(x.Resolved)
    }
    panic("unreachable")
}
func (x *LdapPrincipal) UnmarshalJSON(data []byte) error {
    x.Unresolved = nil
    x.Resolved = nil
    var unresolved LdapPrincipalUnresolved
    if err := json.Unmarshal(data, &unresolved); err == nil {
        x.Unresolved = &unresolved
        return nil
    }
    var resolved LdapPrincipalResolved
    if err := json.Unmarshal(data, &resolved); err == nil {
        x.Resolved = &resolved
        return nil
    }
    return errors.Errorf("not a valid LdapPrincipal")
}

type LdapSearchFilter struct {
    Name string `json:"name"`
    Value string `json:"value"`
}

type LdapSearchRequest struct {
    BaseDn *string `json:"base_dn,omitempty"`
    Filters []LdapSearchFilter `json:"filters"`
    ObjectClass *string `json:"object_class,omitempty"`
    Scope LdapSearchScope `json:"scope"`
}

type LdapSearchResultEntry struct {
    DistinguishedName string `json:"distinguished_name"`
    LdapObjectID UUID `json:"ldap_object_id"`
    CommonName []string `json:"common_name"`
    Description []string `json:"description"`
    ObjectClass []string `json:"object_class"`
    Mail *string `json:"mail,omitempty"`
    UserPrincipalName *string `json:"user_principal_name,omitempty"`
}

type LdapSearchScope string

// List of supported LdapSearchScope values
const (
    LdapSearchScopeSingleLevel LdapSearchScope = "single-level"
    LdapSearchScopeWholeSubtree LdapSearchScope = "whole-subtree"
)

type LdapTestCredentials struct {
    ID LdapPrincipal `json:"id"`
    Password ZeroizedString `json:"password"`
    AccountRole *LdapAccountRole `json:"account_role,omitempty"`
}
func (x LdapTestCredentials) MarshalJSON() ([]byte, error) {
    m := make(map[string]interface{})
    { // x.ID is flattened
        b, err := json.Marshal(&x.ID)
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
    m["password"] = x.Password
    if x.AccountRole != nil {
        m["account_role"] = x.AccountRole
    }
    return json.Marshal(&m)
}
func (x *LdapTestCredentials) UnmarshalJSON(data []byte) error {
    if err := json.Unmarshal(data, &x.ID); err != nil {
        return err
    }
    var r struct {
    Password ZeroizedString `json:"password"`
    AccountRole *LdapAccountRole `json:"account_role,omitempty"`
    }
    if err := json.Unmarshal(data, &r); err != nil {
        return err
    }
    x.Password = r.Password
    x.AccountRole = r.AccountRole
    return nil
}

type LdapTestRequest struct {
    Ldap AuthConfigLdap `json:"ldap"`
    TestCredentials *LdapTestCredentials `json:"test_credentials,omitempty"`
}

type Service struct {
    Name string `json:"name"`
    Hostnames map[string]HostnameInfo `json:"hostnames"`
}

// Check information about all connected services
//
// Returns the information regarding the status of all the connected services.
func (c *Client) GetAllServices(ctx context.Context) (*GetAllServicesResponse, error) {
    u := "/sys/v1/services"
    var r GetAllServicesResponse
    if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Check whether the server is handling requests
//
// Returns a 200-class status code if the server is handling requests,
// or a 500-class status code if the server is having problems.
func (c *Client) GetHealth(ctx context.Context, queryParameters *HealthParams) error {
    u := "/sys/v1/health"
    if queryParameters != nil {
        q, err := encodeURLParams(queryParameters)
        if err != nil {
            return err
        }
        u = fmt.Sprintf("%v?%v", u, q)
    }
    if err := c.fetch(ctx, http.MethodGet, u, nil, nil); err != nil {
        return err
    }
    return nil
}

// Check information about the specified service
//
// Returns the information regarding the status of the specified service.
func (c *Client) GetService(ctx context.Context, name string) (*Service, error) {
    u := "/sys/v1/services/:name"
    u = strings.NewReplacer(":name", name).Replace(u)
    var r Service
    if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Searches for LDAP objects in the specified LDAP directory.
func (c *Client) LdapSearch(ctx context.Context, ldap_id string, body LdapSearchRequest) ([]LdapSearchResultEntry, error) {
    u := "/sys/v1/ldap/search/:ldap_id"
    u = strings.NewReplacer(":ldap_id", ldap_id).Replace(u)
    var r []LdapSearchResultEntry
    if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
        return nil, err
    }
    return r, nil
}

// Get the SP metadata file for SAML configuration
//
// Returns the Service Provider metadata file of this cluster, for SAML
// configuration. If this cluster has a SAML signing key, the public key is
// included in the SPSSODescriptor.
func (c *Client) SamlSpMetadata(ctx context.Context) ([]uint8, error) {
    u := "/saml/metadata.xml"
    var r []uint8
    if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
        return nil, err
    }
    return r, nil
}

// Test connection using the ldap SSO configuration saved in the account.
func (c *Client) TestLdapConfig(ctx context.Context, body LdapTestRequest) error {
    u := "/sys/v1/ldap/test"
    if err := c.fetch(ctx, http.MethodPost, u, &body, nil); err != nil {
        return err
    }
    return nil
}

