// Approval Request example
// This program demonstrates how to use approval request APIs for signing
package main

import (
	"context"
	"encoding/base64"
	"log"
	"net/http"
	"time"

	"github.com/fortanix/sdkms-client-go/sdkms"
	"github.com/pkg/errors"
)

const (
	myAPIKey string = "NjNmNmRlM2ItYjQ4YS00YjJkLWJkNGQtY2Y2Y2Y4YTEwOGVlOm9mYzdKdzhpVmJEaGZBTzU2aWtCNzNGV0pJYlhkMkE4RnJvLXo5eE53LUI3Zkp5WWlSNWIxdWZ5a0E3ekNkMWlDSGYxcjg2aUNDR29qNmE2aEpFcGJB"
	keyName  string = "RSA_Key"
)

func main() {
	client := sdkms.Client{
		HTTPClient: http.DefaultClient,
		Auth:       sdkms.APIKey(myAPIKey),
		Endpoint:   "https://sit.smartkey.io",
	}
	signReq := sdkms.SignRequest{
		Data:    sdkms.Some([]byte("hello, world")),
		HashAlg: sdkms.DigestAlgorithmSha256,
		Key:     sdkms.SobjectByName(keyName),
		Mode:    sdkms.SignatureModeRSA(sdkms.RsaSignaturePaddingPKCS1V15()),
	}
	signResp, err := sign(&client, signReq)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Signature: %v\n", base64.StdEncoding.EncodeToString(signResp.Signature))
}

func sign(client *sdkms.Client, req sdkms.SignRequest) (*sdkms.SignResponse, error) {
	ctx := context.Background()
	log.Println("trying direct call to Sign API first...")
	resp, err := client.Sign(ctx, req)
	if err == nil {
		return resp, nil
	}
	if backendError, ok := err.(*sdkms.BackendError); ok {
		if backendError.Message == "This operation requires approval" {
			log.Println("trying approval request path...")
			return signWithApproval(client, req)
		}
	}
	return nil, errors.Wrap(err, "Sign failed")
}

func signWithApproval(client *sdkms.Client, req sdkms.SignRequest) (*sdkms.SignResponse, error) {
	ctx := context.Background()
	description := "Pretty please"
	approvalRequest, err := client.RequestApprovalToSign(ctx, req, &description)
	if err != nil {
		return nil, errors.Wrap(err, "RequestApprovalToSign failed")
	}
	log.Printf("Status = %v\n", approvalRequest.Status)
	for approvalRequest.Status == sdkms.ApprovalStatusPending {
		time.Sleep(10 * time.Second)
		approvalRequest, err = client.GetApprovalRequest(ctx, approvalRequest.RequestID)
		if err != nil {
			return nil, errors.Wrap(err, "GetApprovalRequest failed")
		}
		log.Printf("Status = %v\n", approvalRequest.Status)
	}
	switch approvalRequest.Status {
	case sdkms.ApprovalStatusApproved, sdkms.ApprovalStatusFailed:
		res, err := client.GetApprovalRequestResult(ctx, approvalRequest.RequestID)
		if err != nil {
			return nil, errors.Wrap(err, "GetApprovalRequestResult failed")
		}
		var signResp sdkms.SignResponse
		if err := res.Parse(&signResp); err != nil {
			return nil, err
		}
		return &signResp, nil
	default:
		return nil, errors.Errorf("request was denied")
	}
}
