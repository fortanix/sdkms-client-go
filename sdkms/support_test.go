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

func Test_CustomMetadata(t *testing.T) {
	tt := []struct {
		input *CustomMetadata
		want  string
	}{
		{input: nil, want: ""},
		{input: Some(CustomMetadata(nil)), want: ""},
		{input: Some(CustomMetadata(map[string]string{})), want: ""},
		{input: Some(CustomMetadata(map[string]string{"hello": "world"})), want: "custom_metadata.hello=world"},
		{input: Some(CustomMetadata(map[string]string{"hello": "world", "test": "abcd"})), want: "custom_metadata.hello=world&custom_metadata.test=abcd"},
	}
	for i, tc := range tt {
		t.Run(fmt.Sprintf("Encode-%v", i), func(t *testing.T) {
			got, err := encodeURLParams(tc.input)
			if err != nil {
				t.Errorf("failed to encode URL params: %v", err)
			}
			if got != tc.want {
				t.Errorf("Expected value %#v, got %#v", tc.want, got)
			}
		})
	}
}

func ExampleSome() {
	test := func(x *string) {
		if x != nil {
			fmt.Printf("%v\n", *x)
		}
	}

	test(Some("hello"))
	test(nil)
	// Output:
	// hello
}
