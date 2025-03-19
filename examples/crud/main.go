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
	myAPIKey string = "InputYourAPIKeyHere"
)

func main() {
	rand.Seed(time.Now().UnixNano())
	client := sdkms.Client{
		HTTPClient: http.DefaultClient,
		Auth:       sdkms.APIKey(myAPIKey),
		Endpoint:   "https://sit.smartkey.io",
	}
	ctx := context.Background()
	// Create a new sobject
	sobjectReq := sdkms.SobjectRequest{
		Name:    sdkms.Some(fmt.Sprintf("TestKey-%v", randomName(8))),
		ObjType: sdkms.Some(sdkms.ObjectTypeAes),
		KeySize: sdkms.Some(uint32(256)),
		KeyOps:  sdkms.Some(sdkms.KeyOperationsEncrypt | sdkms.KeyOperationsDecrypt | sdkms.KeyOperationsAppmanageable),
	}
	sobject, err := client.CreateSobject(ctx, sobjectReq)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Created sobject: %v\n", sobjectToString(sobject))

	// List all sobjects
	var start *sdkms.UUID
	for {
		queryParams := sdkms.ListSobjectsParams{
			Sort: &sdkms.SobjectSort{
				ByKid: &sdkms.SobjectSortByKid{
					Start: start,
				},
			},
		}
		keys, err := client.ListSobjects(ctx, &queryParams)
		if err != nil {
			log.Fatal(err)
		}
		n := len(keys.Items)
		if n == 0 {
			break
		}
		fmt.Printf("\nListing %v security objects:\n", n)
		for _, key := range keys.Items {
			fmt.Printf("%v\n", sobjectToString(&key))
		}
		start = keys.Items[n-1].Kid
	}

	// Delete the sobject that was created before
	if err := client.DeleteSobject(ctx, *sobject.Kid); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\n\nSobject %v deleted\n", *sobject.Kid)
}

func sobjectToString(key *sdkms.Sobject) string {
	return fmt.Sprintf("%11v %v %#v", key.ObjType, *key.Kid, *key.Name)
}

func randomName(size uint) string {
	charSet := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
	b := make([]rune, size)
	for i := range b {
		b[i] = charSet[rand.Intn(len(charSet))]
	}
	return string(b)
}
