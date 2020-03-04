/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package sdkms

import (
	"fmt"
	"testing"
)

func Test_CountParams(t *testing.T) {
	tt := []struct {
		input CountParams
		want  string
	}{
		{input: CountParams{}, want: ""},
		{input: CountParams{RangeFrom: someUint64(5)}, want: "range_from=5"},
		{input: CountParams{RangeFrom: someUint64(5), RangeTo: someUint64(42)}, want: "range_from=5&range_to=42"},
	}
	for i, tc := range tt {
		t.Run(fmt.Sprintf("Encode-%v", i), func(t *testing.T) {
			got, err := encodeURLParams(&tc.input)
			if err != nil {
				t.Errorf("failed to encode URL params: %v", err)
			}
			if got != tc.want {
				t.Errorf("Expected value %#v, got %#v", tc.want, got)
			}
		})
	}
}

func Test_GetAccountParams(t *testing.T) {
	tt := []struct {
		input GetAccountParams
		want  string
	}{
		{input: GetAccountParams{}, want: "with_totals=false"},
		{input: GetAccountParams{WithTotals: true}, want: "with_totals=true"},
	}
	for i, tc := range tt {
		t.Run(fmt.Sprintf("Encode-%v", i), func(t *testing.T) {
			got, err := encodeURLParams(&tc.input)
			if err != nil {
				t.Errorf("failed to encode URL params: %v", err)
			}
			if got != tc.want {
				t.Errorf("Expected value %#v, got %#v", tc.want, got)
			}
		})
	}
}

func Test_ListApprovalRequestsParams(t *testing.T) {
	tt := []struct {
		input ListApprovalRequestsParams
		want  string
	}{
		{input: ListApprovalRequestsParams{}, want: ""},
		{
			input: ListApprovalRequestsParams{
				Requester: someString("b0814e50-41b9-4913-be93-6184294a55ea"),
			},
			want: "requester=b0814e50-41b9-4913-be93-6184294a55ea",
		},
		{
			input: ListApprovalRequestsParams{
				Reviewer: someString("b0814e50-41b9-4913-be93-6184294a55ea"),
				Status:   someApprovalStatus(ApprovalStatusApproved),
			},
			want: "reviewer=b0814e50-41b9-4913-be93-6184294a55ea&status=APPROVED",
		},
		{
			input: ListApprovalRequestsParams{
				Requester: someString("8ecb8bd8-5da6-469e-b114-aed52519f03e"),
				Reviewer:  someString("b0814e50-41b9-4913-be93-6184294a55ea"),
				Status:    someApprovalStatus(ApprovalStatusDenied),
			},
			want: "requester=8ecb8bd8-5da6-469e-b114-aed52519f03e&reviewer=b0814e50-41b9-4913-be93-6184294a55ea&status=DENIED",
		},
	}
	for i, tc := range tt {
		t.Run(fmt.Sprintf("Encode-%v", i), func(t *testing.T) {
			got, err := encodeURLParams(&tc.input)
			if err != nil {
				t.Errorf("failed to encode URL params: %v", err)
			}
			if got != tc.want {
				t.Errorf("Expected value %#v, got %#v", tc.want, got)
			}
		})
	}
}

func Test_ListAppsParams(t *testing.T) {
	tt := []struct {
		input ListAppsParams
		want  string
	}{
		{input: ListAppsParams{}, want: "group_permissions=false"},
		{
			input: ListAppsParams{
				GroupID: someString("75814e50-41b9-4913-be93-6184294a55ea"),
				Limit:   someUint(65),
			},
			want: "group_id=75814e50-41b9-4913-be93-6184294a55ea&group_permissions=false&limit=65",
		},
		{
			input: ListAppsParams{
				Limit: someUint(65),
				Sort: AppSort{
					ByAppID: &AppSortByAppId{},
				},
			},
			want: "group_permissions=false&limit=65&sort=app_id",
		},
		{
			input: ListAppsParams{
				Limit: someUint(65),
				Sort: AppSort{
					ByAppID: &AppSortByAppId{
						Start: someString("myApp"),
					},
				},
			},
			want: "group_permissions=false&limit=65&sort=app_id&start=myApp",
		},
		{
			input: ListAppsParams{
				GroupID: someString("75814e50-41b9-4913-be93-6184294a55ea"),
				Limit:   someUint(65),
				Sort: AppSort{
					ByAppID: &AppSortByAppId{
						Order: OrderAscending,
						Start: someString("myApp"),
					},
				},
			},
			want: "group_id=75814e50-41b9-4913-be93-6184294a55ea&group_permissions=false&limit=65&sort=app_id%3Aasc&start=myApp",
		},
	}
	for i, tc := range tt {
		t.Run(fmt.Sprintf("Encode-%v", i), func(t *testing.T) {
			got, err := encodeURLParams(&tc.input)
			if err != nil {
				t.Errorf("failed to encode URL params: %v", err)
			}
			if got != tc.want {
				t.Errorf("Expected value %#v, got %#v", tc.want, got)
			}
		})
	}
}

func someUint(x uint) *uint                               { return &x }
func someUint64(x uint64) *uint64                         { return &x }
func someApprovalStatus(x ApprovalStatus) *ApprovalStatus { return &x }
