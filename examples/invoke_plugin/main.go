// Invoke plugin example
//
// This program demonstrates how to invoke an SDKMS plugin.
// The Lua code for the plugin is listed below:
//
//	function run(input)
//	   return { Sum = input.X + input.Y }
//	end
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
	pluginID string = "3760ecfe-b6f5-..."
)

func main() {
	client := sdkms.Client{
		HTTPClient: http.DefaultClient,
		Auth:       sdkms.APIKey(myAPIKey),
		Endpoint:   "https://sdkms.fortanix.com",
	}
	ctx := context.Background()
	input := pluginInput{
		X: 10,
		Y: 20,
	}
	res, err := client.InvokePlugin(ctx, pluginID, input)
	if err != nil {
		log.Fatalf("InvokePlugin failed: %v", err)
	}
	var output pluginOutput
	if err := res.Parse(&output); err != nil {
		log.Fatalf("Failed to parse plugin output: %v", err)
	}
	fmt.Printf("%v + %v = %v\n", input.X, input.Y, output.Sum) // Expected output: 10 + 20 = 30
}

type pluginInput struct {
	X int
	Y int
}

type pluginOutput struct {
	Sum int
}
