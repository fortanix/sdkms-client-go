// Invoke plugin approval request example
//
// This program demonstrates how to request approval to invoke an SDKMS plugin.
// The Lua code for the plugin is listed below:
//
//	function check(input)
//	   key = assert(Sobject { name = "very important key" })
//	   require_approval_for(key)
//	end
//
//	function run(input)
//	   return key:sign(input)
//	end
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/fortanix/sdkms-client-go/sdkms"
)

const (
	myAPIKey string = "M2VkNjg4ODgtMTFmOC00YTNiLTg0NmEt..."
	pluginID string = "3c846349-ee93-..."
)

func main() {
	client := sdkms.Client{
		HTTPClient: http.DefaultClient,
		Auth:       sdkms.APIKey(myAPIKey),
		Endpoint:   "https://sdkms.fortanix.com",
	}
	ctx := context.Background()
	input := pluginInput{
		Data:    someBlob([]byte("hello, world!")),
		HashAlg: sdkms.DigestAlgorithmSha256,
	}
	approvalReq, err := client.RequestApprovalToInvokePlugin(ctx, pluginID, input, nil)
	if err != nil {
		log.Fatalf("RequestApprovalToInvokePlugin failed: %v", err)
	}
	log.Printf("Status = %v\n", approvalReq.Status)
	for approvalReq.Status == sdkms.ApprovalStatusPending {
		time.Sleep(10 * time.Second)
		approvalReq, err = client.GetApprovalRequest(ctx, approvalReq.RequestID)
		if err != nil {
			log.Fatalf("GetApprovalRequest failed: %v", err)
		}
		log.Printf("Status = %v\n", approvalReq.Status)
	}
	if approvalReq.Status != sdkms.ApprovalStatusApproved {
		log.Fatalf("request failed or was denied")
	}
	res, err := client.GetApprovalRequestResult(ctx, approvalReq.RequestID)
	if err != nil {
		log.Fatalf("GetApprovalRequestResult failed: %v", err)
	}
	var output sdkms.SignResponse
	if err := res.Parse(&output); err != nil {
		log.Fatalf("Plugin returned error: %v", err)
	}
	fmt.Printf("Signature: %v\n", base64.StdEncoding.EncodeToString(output.Signature))
}

type pluginInput = sdkms.SignRequest

func someBlob(blob sdkms.Blob) *sdkms.Blob { return &blob }
