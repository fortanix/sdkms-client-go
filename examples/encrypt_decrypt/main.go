// Encrypt/Decrypt example
// This program demonstrates how to do basic cryptographic operations with the SDKMS Go SDK
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/fortanix/sdkms-go-sdk/sdkms"
)

const (
	myAPIKey string = "N2MwYThlYjgtMGZkNS00OWIxLWFkOWUt..."
	keyName  string = "AES Key"
)

func main() {
	client := sdkms.Client{
		HTTPClient: http.DefaultClient,
		Auth:       sdkms.APIKey(myAPIKey),
	}
	ctx := context.Background()
	encryptReq := sdkms.EncryptRequest{
		Plain: []byte("hello, world!"),
		Alg:   sdkms.AlgorithmAES,
		Key:   sdkms.SobjectByName(keyName),
		Mode:  sdkms.CryptModeSymmetric(sdkms.CipherModeCBC),
	}
	encryptResp, err := client.Encrypt(ctx, encryptReq)
	if err != nil {
		log.Fatalf("Encrypt failed: %v", err)
	}

	decryptReq := sdkms.DecryptRequest{
		Cipher: encryptResp.Cipher,
		Iv:     encryptResp.Iv,
		Key:    sdkms.SobjectByName(keyName),
		Mode:   sdkms.CryptModeSymmetric(sdkms.CipherModeCBC),
	}
	decryptResp, err := client.Decrypt(ctx, decryptReq)
	if err != nil {
		log.Fatalf("Decrypt failed: %v", err)
	}
	fmt.Println(string(decryptResp.Plain)) // Expected output: hello, world!
}
