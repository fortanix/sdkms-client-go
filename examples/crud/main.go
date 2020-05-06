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
	myAPIKey string = "N2MwYThlYjgtMGZkNS00OWIxLWFkOWUt..."
)

func main() {
	rand.Seed(time.Now().UnixNano())
	client := sdkms.Client{
		HTTPClient: http.DefaultClient,
		Auth:       sdkms.APIKey(myAPIKey),
		Endpoint:   "https://sdkms.fortanix.com",
	}
	ctx := context.Background()
	// Create a new sobject
	sobjectReq := sdkms.SobjectRequest{
		Name:    someString(fmt.Sprintf("TestKey-%v", randomName(8))),
		ObjType: someObjectType(sdkms.ObjectTypeAes),
		KeySize: someUInt32(uint32(256)),
		KeyOps:  someKeyOperations(sdkms.KeyOperationsEncrypt | sdkms.KeyOperationsDecrypt | sdkms.KeyOperationsAppmanageable),
	}
	sobject, err := client.CreateSobject(ctx, sobjectReq)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Created sobject: %v\n", sobjectToString(sobject))

	// List all sobjects
	queryParams := sdkms.ListSobjectsParams{
		Sort: sdkms.SobjectSort{
			ByName: &sdkms.SobjectSortByName{},
		},
	}
	keys, err := client.ListSobjects(ctx, &queryParams)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\n\nListing all sobjects (%v):\n", len(keys))
	for _, key := range keys {
		fmt.Printf("  %v\n", sobjectToString(&key))
	}

	// Delete the sobject that was created before
	if err := client.DeleteSobject(ctx, *sobject.Kid); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\n\nSobject %v deleted\n", *sobject.Kid)
}

func sobjectToString(sobject *sdkms.Sobject) string {
	created, err := sobject.CreatedAt.Std()
	if err != nil {
		log.Fatalf("Failed to convert sobject.CreatedAt: %v", err)
	}
	return fmt.Sprintf("{ %v %#v group(%v) enabled: %v created: %v }",
		*sobject.Kid, *sobject.Name, *sobject.GroupID, sobject.Enabled,
		created.Local())
}

func randomName(size uint) string {
	charSet := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
	b := make([]rune, size)
	for i := range b {
		b[i] = charSet[rand.Intn(len(charSet))]
	}
	return string(b)
}

func someString(val string) *string { return &val }
func someUInt32(val uint32) *uint32 { return &val }

func someObjectType(val sdkms.ObjectType) *sdkms.ObjectType          { return &val }
func someKeyOperations(val sdkms.KeyOperations) *sdkms.KeyOperations { return &val }
