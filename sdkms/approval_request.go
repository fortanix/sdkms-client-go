package sdkms

import (
	"context"
	"encoding/json"
	"net/http"
)

// ApprovalRequestRequest is a request to create an ApprovalRequest
type ApprovalRequestRequest struct {
	// Operation URL path, e.g. `/crypto/v1/keys`, `/crypto/v1/groups/<id>`.
	Operation string `json:"operation"`
	// HTTP method, defaults to POST
	Method *string `json:"method,omitempty"`
	// Body of the HTTP request, must be JSON-serializable
	Body interface{} `json:"body,omitempty"`
	// Optional comment about the approval request for the reviewer.
	Description *string `json:"description,omitempty"`
}

// ApprovalRequest is a request to approve an operation, e.g. use a particular key to encrypt some data
type ApprovalRequest struct {
	RequestID   string            `json:"request_id"`
	Requester   Principal         `json:"requester"`
	CreatedAt   string            `json:"created_at"`
	Expiry      string            `json:"expiry"`
	AccountID   string            `json:"acct_id"`
	Operation   string            `json:"operation"`
	Method      string            `json:"method"`
	Body        interface{}       `json:"body"`
	Status      ApprovalStatus    `json:"status"`
	Subjects    []ApprovalSubject `json:"subjects"`
	Reviewers   []Principal       `json:"reviewers"`
	Approvers   []Principal       `json:"approvers"`
	Denier      *Principal        `json:"denier,omitempty"`
	Description *string           `json:"description,omitempty"`
}

// CreateApprovalRequest creates an approval request
func (c *Client) CreateApprovalRequest(ctx context.Context, body ApprovalRequestRequest) (*ApprovalRequest, error) {
	var response ApprovalRequest
	if err := c.fetch(ctx, http.MethodPost, "/sys/v1/approval_requests", body, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// GetApprovalRequest retrieves the approval request object identified by requestID
func (c *Client) GetApprovalRequest(ctx context.Context, requestID string) (*ApprovalRequest, error) {
	var response ApprovalRequest
	if err := c.fetch(ctx, http.MethodGet, "/sys/v1/approval_requests/"+requestID, nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

type approvableResult struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

// ApprovableResult is the result of an operation performed through approval requests
type ApprovableResult struct {
	inner approvableResult
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

// GetApprovalRequestOperationResult retrieves the result of the operation after the operation is approved and executed
func (c *Client) GetApprovalRequestOperationResult(ctx context.Context, requestID string) (*ApprovableResult, error) {
	var response approvableResult
	if err := c.fetch(ctx, http.MethodPost, "/sys/v1/approval_requests/"+requestID+"/result", nil, &response); err != nil {
		return nil, err
	}
	return &ApprovableResult{inner: response}, nil
}
