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
	myAPIKey      string = "....J4dXVEWWw4MjRBQlFpRmpyR01OS3pwSDdTTEF6RUZfb25kZVk5enJOQkh...."
	keyName       string = "< >"
)

func generateRandom(length int) []byte {
	rand.Seed(time.Now().Unix())
	ran_str := make([]byte, length)
	for i := 0; i < length; i++ {
		ran_str[i] = byte(65 + rand.Intn(25))
	}
	return ran_str
}

func main() {
	client := sdkms.Client{
		HTTPClient: http.DefaultClient,
		Auth:       sdkms.APIKey(myAPIKey),
		Endpoint:   myAPIEndpoint,
	}
	ctx := context.Background()
	KeyVal := generateRandom(32)
	sobjectReq := sdkms.SobjectRequest{
		Name:    someString(fmt.Sprintf("TestKey-%v", generateRandom(8))),
		ObjType: someObjectType(sdkms.ObjectTypeSecret),
		KeySize: someUInt32(uint32(256)),
		KeyOps:  someKeyOperations(sdkms.KeyOperationsExport | sdkms.KeyOperationsAppmanageable | sdkms.KeyOperationsDerivekey),
		Value:   &KeyVal,
	}
	sobjectResp, err := client.ImportSobject(ctx, sobjectReq)
	if err != nil {
		log.Fatalf("!!! Error importing Sobject %v: ", err)
	}
	log.Printf("%v sobject imported successfully", sdkms.ObjectTypeSecret)
	// ---- Use this function to run encrypt_decrypt example case ----
	// sample_encrypt_decrypt(&client, *sobjectResp.Kid)

	// ---- Use this function to run derivation example case ----
	sample_derive_key(&client, *sobjectResp.Kid)
}

func someString(val string) *string { return &val }
func someUInt32(val uint32) *uint32 { return &val }
func someBytes(val []byte) *[]byte  { return &val }

func someObjectType(val sdkms.ObjectType) *sdkms.ObjectType          { return &val }
func someKeyOperations(val sdkms.KeyOperations) *sdkms.KeyOperations { return &val }
