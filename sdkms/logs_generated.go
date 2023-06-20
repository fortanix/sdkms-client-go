/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package sdkms

import (
	"context"
	"fmt"
	"net/http"
)

type ActionType string

// List of supported ActionType values
const (
	ActionTypeAdministrative  ActionType = "ADMINISTRATIVE"
	ActionTypeAuth            ActionType = "AUTH"
	ActionTypeCryptoOperation ActionType = "CRYPTOOPERATION"
	ActionTypeRunPlugin       ActionType = "RUNPLUGIN"
	ActionTypeCustom          ActionType = "CUSTOM"
	ActionTypeOther           ActionType = "OTHER"
)

// Response parameters to show Audit log details.
type EsAuditLog struct {
	// Action Type
	ActionType ActionType `json:"action_type"`
	// Actor Type
	// Available values are: User, App & Plugin.
	ActorType string `json:"actor_type"`
	// Audit log message
	Message string `json:"message"`
	// Severity of event
	Severity SeverityLevel `json:"severity"`
	// Time of Event
	Time AuditLogTime `json:"time"`
	// UUID of account
	AcctID UUID `json:"acct_id"`
	// UUID of Actor (User, App or Plugin)
	ActorID UUID `json:"actor_id"`
	// UUIDs of groups involved/used in event
	GroupIds []UUID `json:"group_ids"`
	// UUID of entity affected by event. For instance, if a group is created object_id will be UUID of group.
	ObjectID UUID `json:"object_id"`
	// IP Address of client
	ClientIp *IpAddr `json:"client_ip,omitempty"`
	// Time taken for event/operation completion
	ResponseTime *Duration `json:"response_time,omitempty"`
}

// Response structure of a single log.
type EsAuditLogOuter struct {
	// UUID of audit log
	ID string `json:"_id"`
	// Source of audit log
	Source EsAuditLog `json:"_source"`
}

// Response for Audit log Query.
type EsAuditQueryResponse struct {
	// List of audit logs.
	Hits []EsAuditLogOuter `json:"hits"`
}

// Query parameters to get audit logs.
type LogsParams struct {
	// Maximum number of entries to return. Upper limit for max entries is 1000.
	Size *uint32 `json:"size,omitempty"`
	// Starting offset
	From *uint32 `json:"from,omitempty"`
	// Starting time for search. This is EPOCH time.
	RangeFrom *uint64 `json:"range_from,omitempty"`
	// Ending time for search. This is EPOCH time.
	RangeTo *uint64 `json:"range_to,omitempty"`
	// Action Type
	ActionType *[]ActionType `json:"action_type,omitempty"`
	// Actor Type
	// Available values are: User, App & Plugin.
	ActorType *[]string `json:"actor_type,omitempty"`
	// UUID of Actor (User, App or Plugin)
	ActorID *UUID `json:"actor_id,omitempty"`
	// UUID of entity affected by event. For instance, if a group is created object_id will be UUID of group.
	ObjectID *UUID `json:"object_id,omitempty"`
	// UUID of log after which further logs are required.
	PreviousID *UUID `json:"previous_id,omitempty"`
	// Severity of event
	Severity *[]SeverityLevel `json:"severity,omitempty"`
}

func (x LogsParams) urlEncode(v map[string][]string) error {
	if x.Size != nil {
		v["size"] = []string{fmt.Sprintf("%v", *x.Size)}
	}
	if x.From != nil {
		v["from"] = []string{fmt.Sprintf("%v", *x.From)}
	}
	if x.RangeFrom != nil {
		v["range_from"] = []string{fmt.Sprintf("%v", *x.RangeFrom)}
	}
	if x.RangeTo != nil {
		v["range_to"] = []string{fmt.Sprintf("%v", *x.RangeTo)}
	}
	if x.ActionType != nil {
		v["action_type"] = []string{fmt.Sprintf("%v", *x.ActionType)}
	}
	if x.ActorType != nil {
		v["actor_type"] = []string{fmt.Sprintf("%v", *x.ActorType)}
	}
	if x.ActorID != nil {
		v["actor_id"] = []string{fmt.Sprintf("%v", *x.ActorID)}
	}
	if x.ObjectID != nil {
		v["object_id"] = []string{fmt.Sprintf("%v", *x.ObjectID)}
	}
	if x.PreviousID != nil {
		v["previous_id"] = []string{fmt.Sprintf("%v", *x.PreviousID)}
	}
	if x.Severity != nil {
		v["severity"] = []string{fmt.Sprintf("%v", *x.Severity)}
	}
	return nil
}

type SeverityLevel string

// List of supported SeverityLevel values
const (
	SeverityLevelInfo     SeverityLevel = "INFO"
	SeverityLevelWarning  SeverityLevel = "WARNING"
	SeverityLevelError    SeverityLevel = "ERROR"
	SeverityLevelCritical SeverityLevel = "CRITICAL"
)

// Get all logs visible to the requester.
func (c *Client) GetAllLogs(ctx context.Context, queryParameters *LogsParams) (*EsAuditQueryResponse, error) {
	u := "/sys/v1/logs"
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	var r EsAuditQueryResponse
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
