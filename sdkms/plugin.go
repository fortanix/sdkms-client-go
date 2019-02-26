package sdkms

import (
	"context"
	"net/http"
)

// InvokePlugin invokes a plugin. input must be either nil or JSON-serializable
func (c *Client) InvokePlugin(ctx context.Context, pluginID string, input, output interface{}) error {
	return c.fetch(ctx, http.MethodPost, "/sys/v1/plugins/"+pluginID, input, output)
}

// RequestApprovalToInvokePlugin requests approval to invoke a plugin
func (c *Client) RequestApprovalToInvokePlugin(ctx context.Context, pluginID string, input interface{}, description *string) (*ApprovalRequest, error) {
	req := ApprovalRequestRequest{
		Method:      someString(http.MethodPost),
		Operation:   "/sys/v1/plugins/" + pluginID,
		Body:        input,
		Description: description,
	}
	return c.CreateApprovalRequest(ctx, req)
}
