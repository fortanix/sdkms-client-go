/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package sdkms

import (
    "context"
    "encoding/json"
    "net/http"
)

type BatchExecutionType string

// List of supported BatchExecutionType values
const (
    BatchExecutionTypeSerial BatchExecutionType = "Serial"
    BatchExecutionTypeUnordered BatchExecutionType = "Unordered"
)

type BatchRequest struct {
    Batch *BatchRequestList
    SingleItem *BatchRequestItem
}
func (x BatchRequest) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "BatchRequest", 
                  []bool{ x.Batch != nil,
                  x.SingleItem != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Batch *BatchRequestList `json:"Batch,omitempty"`
        SingleItem *BatchRequestItem `json:"SingleItem,omitempty"`
    }
    obj.Batch = x.Batch
    obj.SingleItem = x.SingleItem
    return json.Marshal(obj)
}
func (x *BatchRequest) UnmarshalJSON(data []byte) error {
    x.Batch = nil
    x.SingleItem = nil
    var obj struct {
        Batch *BatchRequestList `json:"Batch,omitempty"`
        SingleItem *BatchRequestItem `json:"SingleItem,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.Batch = obj.Batch
    x.SingleItem = obj.SingleItem
    return nil
}

type BatchRequestItem struct {
    Method string `json:"method"`
    Operation string `json:"operation"`
    Body interface{} `json:"body,omitempty"`
}

type BatchRequestList struct {
    BatchExecutionType BatchExecutionType `json:"batch_execution_type"`
    Items []BatchRequest `json:"items"`
}

type BatchResponse struct {
    Batch *BatchResponseList
    SingleItem *BatchResponseObject
}
func (x BatchResponse) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "BatchResponse", 
                  []bool{ x.Batch != nil,
                  x.SingleItem != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Batch *BatchResponseList `json:"Batch,omitempty"`
        SingleItem *BatchResponseObject `json:"SingleItem,omitempty"`
    }
    obj.Batch = x.Batch
    obj.SingleItem = x.SingleItem
    return json.Marshal(obj)
}
func (x *BatchResponse) UnmarshalJSON(data []byte) error {
    x.Batch = nil
    x.SingleItem = nil
    var obj struct {
        Batch *BatchResponseList `json:"Batch,omitempty"`
        SingleItem *BatchResponseObject `json:"SingleItem,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.Batch = obj.Batch
    x.SingleItem = obj.SingleItem
    return nil
}

type BatchResponseList struct {
    Items []BatchResponse `json:"items"`
}

type BatchResponseObject struct {
    Result *BatchResponseObjectResult
    Skipped *BatchResponseObjectSkipped
}
type BatchResponseObjectResult struct {
    Status uint16 `json:"status"`
    Body interface{} `json:"body,omitempty"`
}
type BatchResponseObjectSkipped struct {
    Reason string `json:"reason"`
}
func (x BatchResponseObject) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "BatchResponseObject", 
                  []bool{ x.Result != nil,
                  x.Skipped != nil });
                  err != nil {
        return nil, err
    }
    var obj struct {
        Result *BatchResponseObjectResult `json:"Result,omitempty"`
        Skipped *BatchResponseObjectSkipped `json:"Skipped,omitempty"`
    }
    obj.Result = x.Result
    obj.Skipped = x.Skipped
    return json.Marshal(obj)
}
func (x *BatchResponseObject) UnmarshalJSON(data []byte) error {
    x.Result = nil
    x.Skipped = nil
    var obj struct {
        Result *BatchResponseObjectResult `json:"Result,omitempty"`
        Skipped *BatchResponseObjectSkipped `json:"Skipped,omitempty"`
    }
    if err := json.Unmarshal(data, &obj); err != nil {
        return err
    }
    x.Result = obj.Result
    x.Skipped = obj.Skipped
    return nil
}

// Create a new batch request
//
// This API support for quorum approval operations like encrypt, decrypt, sign, wrap, unwrap etc.
//
// Sobject operations like rotate, copy, delete, destroy, update profile,
// revoke, revert, update operations, update policies, update enabled/ disabled
// state, export as components.
//
// Create and update accounts, groups etc
func (c *Client) Batch(ctx context.Context, body BatchRequest) (*BatchResponse, error) {
    u := "/batch/v1"
    var r BatchResponse
    if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

func (c *Client) RequestApprovalToBatch(
    ctx context.Context,    
body BatchRequest,
    description *string) (*ApprovalRequest, error) {
    u := "/batch/v1"
    req := ApprovalRequestRequest{
        Method:      Some(http.MethodPost),
        Operation:   &u,
        Body:        &body,
        Description: description,
    }
    return c.CreateApprovalRequest(ctx, req)
}

