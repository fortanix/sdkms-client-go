package sdkms

import (
	"context"
	"net/http"
)

// A challenge used for multi-factor authentication.
type MfaChallengeResponse struct {
	U2fChallenge string             `json:"u2f_challenge"`
	U2fKeys      []U2fRegisteredKey `json:"u2f_keys"`
}

// Description of a registered U2F device.
type U2fRegisteredKey struct {
	KeyHandle string `json:"keyHandle"`
	Version   string `json:"version"`
}

// Request to select an account.
type SelectAccountRequest struct {
	AcctID UUID `json:"acct_id"`
}

// Response to select account request.
type SelectAccountResponse struct {
	Cookie *string `json:"cookie,omitempty"`
}

// Request to start configuring U2F.
type Config2faAuthRequest struct {
	Password string `json:"password"`
}

type Config2faAuthResponse struct {
}

// Request to authenticate using U2F recovery code.
type RecoveryCodeAuthRequest struct {
	RecoveryCode string `json:"recovery_code"`
}

// Perform a no-op to keep session from expiring.
func (c *Client) Refresh(ctx context.Context) error {
	u := "/sys/v1/session/refresh"
	if err := c.fetch(ctx, http.MethodPost, u, nil, nil); err != nil {
		return err
	}
	return nil
}

// Select a user's account to work on.
func (c *Client) SelectAccount(ctx context.Context, body SelectAccountRequest) (*SelectAccountResponse, error) {
	u := "/sys/v1/session/select_account"
	var r SelectAccountResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Use a U2F key to complete authentication.
func (c *Client) U2fAuth(ctx context.Context, body U2fAuthRequest) error {
	u := "/sys/v1/session/auth/2fa/u2f"
	if err := c.fetch(ctx, http.MethodPost, u, &body, nil); err != nil {
		return err
	}
	return nil
}

// Use a backup recovery code to complete authentication.
func (c *Client) RecoveryCodeAuth(ctx context.Context, body RecoveryCodeAuthRequest) error {
	u := "/sys/v1/session/auth/2fa/recovery_code"
	if err := c.fetch(ctx, http.MethodPost, u, &body, nil); err != nil {
		return err
	}
	return nil
}

// Unlock two factor configuration.
func (c *Client) Config2faAuth(ctx context.Context, body Config2faAuthRequest) (*Config2faAuthResponse, error) {
	u := "/sys/v1/session/config_2fa/auth"
	var r Config2faAuthResponse
	if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Lock two factor configuration. If this API is not called,
// two factor configuration will be locked automatically ten minutes after unlocking.
func (c *Client) Config2faTerminate(ctx context.Context) error {
	u := "/sys/v1/session/config_2fa/terminate"
	if err := c.fetch(ctx, http.MethodPost, u, nil, nil); err != nil {
		return err
	}
	return nil
}

// Generate a new challenge for registering a U2F device.
func (c *Client) U2fNewChallenge(ctx context.Context) (*MfaChallengeResponse, error) {
	u := "/sys/v1/session/config_2fa/new_challenge"
	var r MfaChallengeResponse
	if err := c.fetch(ctx, http.MethodPost, u, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
