// Sign/Verify example
// This program demonstrates the Sign and Verify APIs
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/fortanix/sdkms-client-go/sdkms"
)

const (
	myAPIKey string = "N2MwYThlYjgtMGZkNS00OWIxLWFkOWUt..."
	keyName  string = "RSA Key"
)

func main() {
	client := sdkms.Client{
		HTTPClient: http.DefaultClient,
		Auth:       sdkms.APIKey(myAPIKey),
		Endpoint:   "https://sdkms.fortanix.com",
	}
	ctx := context.Background()
	signReq := sdkms.SignRequest{
		Data:    someBlob([]byte("hello, world")),
		HashAlg: sdkms.DigestAlgorithmSha256,
		Key:     sdkms.SobjectByName(keyName),
		Mode:    sdkms.SignatureModeRSA(sdkms.RsaSignaturePaddingPSSMGF1(sdkms.DigestAlgorithmSha1)),
	}
	signResp, err := client.Sign(ctx, signReq)
	if err != nil {
		log.Fatalf("Sign failed: %v", err)
	}
	verifyReq := sdkms.VerifyRequest{
		Signature: signResp.Signature,
		Key:       sdkms.SobjectByName(keyName),
		HashAlg:   sdkms.DigestAlgorithmSha256,
		Data:      someBlob([]byte("hello, world")),
		Mode:      sdkms.SignatureModeRSA(sdkms.RsaSignaturePaddingPSSMGF1(sdkms.DigestAlgorithmSha1)),
	}
	verifyResp, err := client.Verify(ctx, verifyReq)
	if err != nil {
		log.Fatalf("Verify failed: %v", err)
	}
	fmt.Printf("Verify result: %v\n", verifyResp.Result)
}

func someBlob(blob sdkms.Blob) *sdkms.Blob { return &blob }
