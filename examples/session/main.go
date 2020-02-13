// Session example
// This program demonstrates how to use the Authentication APIs to establish a session
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
		Endpoint:   "https://sdkms.fortanix.com",
	}
	ctx := context.Background()
	// Establish a session
	_, err := client.AuthenticateWithAPIKey(ctx, myAPIKey)
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}
	// Terminate the session on exit
	defer client.TerminateSession(ctx)

	encryptReq := sdkms.EncryptRequest{
		Plain: []byte("hello, world!"),
		Alg:   sdkms.AlgorithmRsa,
		Key:   sdkms.SobjectByName(keyName),
		Mode:  sdkms.CryptModeRSA(sdkms.RsaEncryptionPaddingOAEPMGF1(sdkms.DigestAlgorithmSha1)),
	}
	encryptResp, err := client.Encrypt(ctx, encryptReq)
	if err != nil {
		log.Fatalf("Encrypt failed: %v", err)
	}

	decryptReq := sdkms.DecryptRequest{
		Cipher: encryptResp.Cipher,
		Iv:     encryptResp.Iv,
		Key:    sdkms.SobjectByName(keyName),
		Mode:   sdkms.CryptModeRSA(sdkms.RsaEncryptionPaddingOAEPMGF1(sdkms.DigestAlgorithmSha1)),
	}
	decryptResp, err := client.Decrypt(ctx, decryptReq)
	if err != nil {
		log.Fatalf("Decrypt failed: %v", err)
	}
	fmt.Println(string(decryptResp.Plain))
}
