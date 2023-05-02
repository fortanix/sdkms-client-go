// Encrypt/Decrypt example
// This program demonstrates how to do basic cryptographic operations with the SDKMS Go SDK
package crypto_ops

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
	myAPIEndpoint string = "https://sdkms.fortanix.com"
	myAPIKey string = "N2MwYThlYjgtMGZkNS00OWIxLWFkOWUt..."
	keyName  string = "AES Key"
)

func generateRandom(length int) string {
	rand.Seed(time.Now().Unix())
	ran_str := make([]byte, length)
	for i := 0; i < length; i++ {
		ran_str[i] = byte(65 + rand.Intn(25))
	}
	return string(ran_str)
}

func main() {
	client := sdkms.Client{
		HTTPClient: http.DefaultClient,
		Auth:       sdkms.APIKey(myAPIKey),
		Endpoint:   myAPIEndpoint,
	}
	ctx := context.Background()

	sobjectReq := sdkms.SobjectRequest{
		Name:    someString(fmt.Sprintf("TestKey-%v", generateRandom(8))),
		ObjType: someObjectType(sdkms.ObjectTypeAes),
		KeySize: someUInt32(uint32(256)),
		KeyOps:  someKeyOperations(sdkms.KeyOperationsEncrypt | sdkms.KeyOperationsDecrypt | sdkms.KeyOperationsAppmanageable | sdkms.KeyOperationsDerivekey),
	}
	sobjectResp, err := client.CreateSobject(ctx, sobjectReq)
	if err != nil {
		log.Fatalf("!!Error creating Sobject %v: ", err)
	}

	sample_encrypt_decrypt(&client, *sobjectResp.Kid)
	
	sample_derive_key(&client, *sobjectResp.Kid)
}

func someString(val string) *string { return &val }
func someUInt32(val uint32) *uint32 { return &val }

func someObjectType(val sdkms.ObjectType) *sdkms.ObjectType          { return &val }
func someKeyOperations(val sdkms.KeyOperations) *sdkms.KeyOperations { return &val }