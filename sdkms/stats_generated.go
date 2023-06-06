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
	"strings"
)

type EsCountStatsLog struct {
	Buckets []OuterEsBucket `json:"buckets"`
}

type EsStatsCountQueryResponse struct {
	Time EsCountStatsLog `json:"time"`
}

type EsTotalTxn struct {
	Buckets []InnerEsBucket `json:"buckets"`
}

type InnerEsBucket struct {
	DocCount              uint64                 `json:"doc_count"`
	Key                   UUID                   `json:"key"`
	UniqueOperationsCount *UniqueOperationsCount `json:"unique_operations_count,omitempty"`
	UniqueActiveSobjCount *UniqueOperationsCount `json:"unique_active_sobj_count,omitempty"`
	UniqueActiveAppCount  *UniqueOperationsCount `json:"unique_active_app_count,omitempty"`
}

type OuterEsBucket struct {
	DocCount    uint64     `json:"doc_count"`
	Key         uint64     `json:"key"`
	KeyAsString string     `json:"key_as_string"`
	TotalTxn    EsTotalTxn `json:"total_txn"`
}

type StatsParams struct {
	NumPoints *uint64 `json:"num_points,omitempty"`
	TopCount  *uint32 `json:"top_count,omitempty"`
	RangeFrom *uint64 `json:"range_from,omitempty"`
	RangeTo   *uint64 `json:"range_to,omitempty"`
}

func (x StatsParams) urlEncode(v map[string][]string) error {
	if x.NumPoints != nil {
		v["num_points"] = []string{fmt.Sprintf("%v", *x.NumPoints)}
	}
	if x.TopCount != nil {
		v["top_count"] = []string{fmt.Sprintf("%v", *x.TopCount)}
	}
	if x.RangeFrom != nil {
		v["range_from"] = []string{fmt.Sprintf("%v", *x.RangeFrom)}
	}
	if x.RangeTo != nil {
		v["range_to"] = []string{fmt.Sprintf("%v", *x.RangeTo)}
	}
	return nil
}

type UniqueOperationsCount struct {
	Value uint64 `json:"value"`
}

// Get app aggregate transaction statistics.
func (c *Client) GetAppAggregate(ctx context.Context, queryParameters *StatsParams) (*EsStatsCountQueryResponse, error) {
	u := "/sys/v1/stats/apps"
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	var r EsStatsCountQueryResponse
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Get transaction statistics for a specific application.
func (c *Client) GetAppStats(ctx context.Context, id string, queryParameters *StatsParams) (*EsStatsCountQueryResponse, error) {
	u := "/sys/v1/stats/:id/app"
	u = strings.NewReplacer(":id", id).Replace(u)
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	var r EsStatsCountQueryResponse
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Get group aggregate transaction statistics.
func (c *Client) GetGroupAggregate(ctx context.Context, queryParameters *StatsParams) (*EsStatsCountQueryResponse, error) {
	u := "/sys/v1/stats/groups"
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	var r EsStatsCountQueryResponse
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Get transaction statistics for a specific group.
func (c *Client) GetGroupStats(ctx context.Context, id string, queryParameters *StatsParams) (*EsStatsCountQueryResponse, error) {
	u := "/sys/v1/stats/:id/group"
	u = strings.NewReplacer(":id", id).Replace(u)
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	var r EsStatsCountQueryResponse
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Get transaction statistics for a specific security object.
func (c *Client) GetSobjectStats(ctx context.Context, id string, queryParameters *StatsParams) (*EsStatsCountQueryResponse, error) {
	u := "/sys/v1/stats/:id/key"
	u = strings.NewReplacer(":id", id).Replace(u)
	if queryParameters != nil {
		q, err := encodeURLParams(queryParameters)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("%v?%v", u, q)
	}
	var r EsStatsCountQueryResponse
	if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
