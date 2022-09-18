// Copyright 2022 Baptiste Canton.
// SPDX-License-Identifier: MIT

package hibp_test

import (
	"testing"

	"github.com/batmac/go-hibp"
)

func Test_has_beed_pwned(t *testing.T) {
	type args struct {
		password string
	}
	tests := []struct {
		name        string
		args        args
		wantAtLeast uint64
		wantErr     bool
	}{
		{
			name: "Test with password 'password'",
			args: args{
				password: "password",
			},
			wantAtLeast: 9_000_000,
			wantErr:     false,
		},
		{
			name: "Test with password '123456'",
			args: args{
				password: "123456",
			},
			wantAtLeast: 30_000_000,
			wantErr:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hibp.HasBeenPwned(tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("has_beed_pwned() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got < tt.wantAtLeast {
				t.Errorf("has_beed_pwned() = %v, want %v", got, tt.wantAtLeast)
			}
		})
	}
}
