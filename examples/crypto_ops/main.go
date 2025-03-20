// Encrypt/Decrypt example
// This program demonstrates how to do basic cryptographic operations with the SDKMS Go SDK
package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/fortanix/sdkms-client-go/sdkms"
)

const (
	myAPIEndpoint string = "https://sit.smartkey.io"
	myAPIKey      string = "InputYourAPIKeyHere...."
)

func main() {
	client := sdkms.Client{
		HTTPClient: http.DefaultClient,
		Auth:       sdkms.APIKey(myAPIKey),
		Endpoint:   myAPIEndpoint,
	}
	ctx := context.Background()
	// Import a secret
	KeyVal := generateRandom(32)
	req := sdkms.SobjectRequest{
		Name:    sdkms.Some(fmt.Sprintf("TestKey-%v", generateRandom(8))),
		ObjType: sdkms.Some(sdkms.ObjectTypeSecret),
		KeySize: sdkms.Some(uint32(256)),
		KeyOps:  sdkms.Some(sdkms.KeyOperationsExport | sdkms.KeyOperationsAppmanageable | sdkms.KeyOperationsDerivekey),
		Value:   &KeyVal,
	}
	secretKey, err := client.ImportSobject(ctx, req)
	if err != nil {
		log.Fatalf("Error importing Sobject %v: ", err)
	}
	log.Printf("Imported %v sobject %#v\n", secretKey.ObjType, *secretKey.Name)

	// Generate an AES key
	req = sdkms.SobjectRequest{
		Name:    sdkms.Some(fmt.Sprintf("TestKey-%v", generateRandom(8))),
		ObjType: sdkms.Some(sdkms.ObjectTypeAes),
		KeySize: sdkms.Some(uint32(256)),
		KeyOps:  sdkms.Some(sdkms.KeyOperationsEncrypt | sdkms.KeyOperationsDecrypt | sdkms.KeyOperationsAppmanageable),
	}
	aesKey, err := client.CreateSobject(ctx, req)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Created %v sobject: %#v\n", aesKey.ObjType, *aesKey.Name)

	sample_derive_key(&client, *secretKey.Kid)
	sample_encrypt_decrypt(&client, *aesKey.Kid)
}

func generateRandom(length int) []byte {
	rand.Seed(time.Now().Unix())
	ran_str := make([]byte, length)
	for i := 0; i < length; i++ {
		ran_str[i] = byte(65 + rand.Intn(25))
	}
	return ran_str
}
