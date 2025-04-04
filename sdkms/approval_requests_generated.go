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

type ApprovalRequest struct {
    AcctID UUID `json:"acct_id"`
    Approvers []ReviewerPrincipal `json:"approvers"`
    Body interface{} `json:"body,omitempty"`
    CreatedAt Time `json:"created_at"`
    DenialReason *string `json:"denial_reason,omitempty"`
    Denier *ReviewerPrincipal `json:"denier,omitempty"`
    Description *string `json:"description,omitempty"`
    Expiry Time `json:"expiry"`
    Method string `json:"method"`
    Operation string `json:"operation"`
    RequestID UUID `json:"request_id"`
    Requester Principal `json:"requester"`
    ResultViewed bool `json:"result_viewed"`
    Reviewers *[]Reviewer `json:"reviewers,omitempty"`
    Status ApprovalStatus `json:"status"`
    Subjects *[]ApprovalSubject `json:"subjects,omitempty"`
}

type ApprovalRequestRequest struct {
    Body interface{} `json:"body,omitempty"`
    Description *string `json:"description,omitempty"`
    Method *string `json:"method,omitempty"`
    Operation *string `json:"operation,omitempty"`
}

// Approval request status.
type ApprovalStatus string

// List of supported ApprovalStatus values
const (
    ApprovalStatusPending ApprovalStatus = "PENDING"
    ApprovalStatusApproved ApprovalStatus = "APPROVED"
    ApprovalStatusDenied ApprovalStatus = "DENIED"
    ApprovalStatusFailed ApprovalStatus = "FAILED"
)

// Identifies an object acted upon by an approval request.
type ApprovalSubject struct {
    Group *UUID
    Sobject *UUID
    App *UUID
    Plugin *UUID
    Account *UUID
    NewAccount *struct{}
    Role *UUID
}
func (x ApprovalSubject) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "ApprovalSubject", 
                  []bool{ x.Group != nil,
                  x.Sobject != nil,
                  x.App != nil,
                  x.Plugin != nil,
                  x.Account != nil,
                  x.NewAccount != nil,
                  x.Role != nil });
                  err != nil {
        return nil, err
    }
    switch {
    case x.NewAccount != nil:
        return []byte(`"newaccount"`), nil
    }
    var obj struct {
        Group *UUID `json:"group,omitempty"`
        Sobject *UUID `json:"sobject,omitempty"`
        App *UUID `json:"app,omitempty"`
        Plugin *UUID `json:"plugin,omitempty"`
        Account *UUID `json:"account,omitempty"`
        Role *UUID `json:"role,omitempty"`
    }
    obj.Group = x.Group
    obj.Sobject = x.Sobject
    obj.App = x.App
    obj.Plugin = x.Plugin
    obj.Account = x.Account
    obj.Role = x.Role
    return json.Marshal(obj)
}
func (x *ApprovalSubject) UnmarshalJSON(data []byte) error {
    x.Group = nil
    x.Sobject = nil
    x.App = nil
    x.Plugin = nil
    x.Account = nil
    x.NewAccount = nil
    x.Role = nil
    var str string
    if err := json.Unmarshal(data, &str); err == nil {
        switch str {
        case "newaccount":
            x.NewAccount = &struct{}{}
        default:
            return errors.Errorf("invalid value for ApprovalSubject: %v", str)
        }
        return nil
    }
    var obj struct {
        Group *UUID `json:"group,omitempty"`
        Sobject *UUID `json:"sobject,omitempty"`
        App *UUID `json:"app,omitempty"`
        Plugin *UUID `json:"plugin,omitempty"`
        Account *UUID `json:"account,omitempty"`
        Role *UUID `json:"role,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.Group = obj.Group
    x.Sobject = obj.Sobject
    x.App = obj.App
    x.Plugin = obj.Plugin
    x.Account = obj.Account
    x.Role = obj.Role
    return nil
}

type ApproveRequest struct {
    // Password is required if the approval policy requires password authentication.
    Password *ZeroizedString `json:"password,omitempty"`
    // Use of U2F is deprecated, use FIDO2 for second factor authentication.
    U2f *U2fAuthRequest `json:"u2f,omitempty"`
    // FIDO2 assertion is required if the approval policy requires two factor authentication.
    Fido2AuthRequest *PublicKeyCredentialAuthenticatorAssertionResponse `json:"fido2_auth_request,omitempty"`
    // Data associated with the approval
    Body interface{} `json:"body,omitempty"`
}

type DenyRequest struct {
    Reason *string `json:"reason,omitempty"`
}

type ListApprovalRequestsParams struct {
    Requester *UUID `json:"requester,omitempty"`
    Reviewer *UUID `json:"reviewer,omitempty"`
    Subject *UUID `json:"subject,omitempty"`
    Status *ApprovalStatus `json:"status,omitempty"`
}
func (x ListApprovalRequestsParams) urlEncode(v map[string][]string) error {
    if x.Requester != nil {
        v["requester"] = []string{fmt.Sprintf("%v", *x.Requester)}
    }
    if x.Reviewer != nil {
        v["reviewer"] = []string{fmt.Sprintf("%v", *x.Reviewer)}
    }
    if x.Subject != nil {
        v["subject"] = []string{fmt.Sprintf("%v", *x.Subject)}
    }
    if x.Status != nil {
        v["status"] = []string{fmt.Sprintf("%v", *x.Status)}
    }
    return nil
}

// Reviewer of an approval request.
type Reviewer struct {
    Entity ReviewerPrincipal `json:"entity"`
    RequiresPassword *bool `json:"requires_password,omitempty"`
    Requires2fa *bool `json:"requires_2fa,omitempty"`
}
func (x Reviewer) MarshalJSON() ([]byte, error) {
    m := make(map[string]interface{})
    { // x.Entity is flattened
        b, err := json.Marshal(&x.Entity)
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
    if x.RequiresPassword != nil {
        m["requires_password"] = x.RequiresPassword
    }
    if x.Requires2fa != nil {
        m["requires_2fa"] = x.Requires2fa
    }
    return json.Marshal(&m)
}
func (x *Reviewer) UnmarshalJSON(data []byte) error {
    if err := json.Unmarshal(data, &x.Entity); err != nil {
        return err
    }
    var r struct {
    RequiresPassword *bool `json:"requires_password,omitempty"`
    Requires2fa *bool `json:"requires_2fa,omitempty"`
    }
    if err := json.Unmarshal(data, &r); err != nil {
        return err
    }
    x.RequiresPassword = r.RequiresPassword
    x.Requires2fa = r.Requires2fa
    return nil
}

// A Principal who can approve or deny an approval request.
type ReviewerPrincipal struct {
    App *UUID
    User *UUID
}
func (x ReviewerPrincipal) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "ReviewerPrincipal", 
                  []bool{ x.App != nil,
                  x.User != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        App *UUID `json:"app,omitempty"`
        User *UUID `json:"user,omitempty"`
    }
    obj.App = x.App
    obj.User = x.User
    return json.Marshal(obj)
}
func (x *ReviewerPrincipal) UnmarshalJSON(data []byte) error {
    x.App = nil
    x.User = nil
    var obj struct {
        App *UUID `json:"app,omitempty"`
        User *UUID `json:"user,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.App = obj.App
    x.User = obj.User
    return nil
}

// Approve an approval request.
//
// If the quorum policy was configured to require extra things
// like 2FA, then, relevant info needs to be added to the request.
func (c *Client) ApproveRequest(ctx context.Context, req_id string, body ApproveRequest) (*ApprovalRequest, error) {
    u := "/sys/v1/approval_requests/:req_id/approve"
    u = strings.NewReplacer(":req_id", req_id).Replace(u)
    var r ApprovalRequest
    if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Create a new approval request.
func (c *Client) CreateApprovalRequest(ctx context.Context, body ApprovalRequestRequest) (*ApprovalRequest, error) {
    u := "/sys/v1/approval_requests"
    var r ApprovalRequest
    if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Delete an approval request.
func (c *Client) DeleteApprovalRequest(ctx context.Context, req_id string) error {
    u := "/sys/v1/approval_requests/:req_id"
    u = strings.NewReplacer(":req_id", req_id).Replace(u)
    if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
        return err
    }
    return nil
}

// Deny an approval request.
func (c *Client) DenyRequest(ctx context.Context, req_id string, body DenyRequest) (*ApprovalRequest, error) {
    u := "/sys/v1/approval_requests/:req_id/deny"
    u = strings.NewReplacer(":req_id", req_id).Replace(u)
    var r ApprovalRequest
    if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Lookup a specific approval request.
func (c *Client) GetApprovalRequest(ctx context.Context, req_id string) (*ApprovalRequest, error) {
    u := "/sys/v1/approval_requests/:req_id"
    u = strings.NewReplacer(":req_id", req_id).Replace(u)
    var r ApprovalRequest
    if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Get the result for an approved or failed request.
func (c *Client) GetApprovalRequestResult(ctx context.Context, req_id string) (*ApprovableResult, error) {
    u := "/sys/v1/approval_requests/:req_id/result"
    u = strings.NewReplacer(":req_id", req_id).Replace(u)
    var r ApprovableResult
    if err := c.fetch(ctx, http.MethodPost, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Get all approval requests.
func (c *Client) ListApprovalRequests(ctx context.Context, queryParameters *ListApprovalRequestsParams) ([]ApprovalRequest, error) {
    u := "/sys/v1/approval_requests"
    if queryParameters != nil {
        q, err := encodeURLParams(queryParameters)
        if err != nil {
            return nil, err
        }
        u = fmt.Sprintf("%v?%v", u, q)
    }
    var r []ApprovalRequest
    if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
        return nil, err
    }
    return r, nil
}

// Creates a challenge for the FIDO2/U2F device to sign.
//
// If the quorum policy is configured to require 2FA, then a call to this API
// produces a challenge that needs to be signed by the respective FIDO2/U2F device.
// The signed data that U2F device provides can be then used with
// `POST /sys/v1/approval_requests/:req_id/approve` to successfully approve the
// request.
func (c *Client) MfaChallenge(ctx context.Context, req_id string, queryParameters *MfaChallengeParams) (*MfaChallengeResponse, error) {
    u := "/sys/v1/approval_requests/:req_id/challenge"
    u = strings.NewReplacer(":req_id", req_id).Replace(u)
    if queryParameters != nil {
        q, err := encodeURLParams(queryParameters)
        if err != nil {
            return nil, err
        }
        u = fmt.Sprintf("%v?%v", u, q)
    }
    var r MfaChallengeResponse
    if err := c.fetch(ctx, http.MethodPost, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

