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
	myUsername = "name@example.com"
	myPassword = "password"
	myAcctID   = "b6480ec0-df2e-..."
)

func main() {
	rand.Seed(time.Now().UnixNano())
	client := sdkms.Client{
		HTTPClient: http.DefaultClient,
		Endpoint:   "https://sdkms.fortanix.com",
	}
	ctx := context.Background()
	// Establish a session
	_, err := client.AuthenticateWithUserPass(ctx, myUsername, myPassword)
	if err != nil {
		log.Fatalf("Could not authenticate: %v", err)
	}
	// Terminate the session on exit
	defer client.TerminateSession(ctx)

	// Select account
	_, err = client.SelectAccount(ctx, sdkms.SelectAccountRequest{AcctID: myAcctID})
	if err != nil {
		log.Fatalf("Could not select account: %v", err)
	}

	// Create a new group
	groupName := fmt.Sprintf("TestGroup-%v", randomName(8))
	group, err := client.CreateGroup(ctx, sdkms.GroupRequest{
		Name: &groupName,
	})
	if err != nil {
		log.Fatalf("Could not create group: %v", err)
	}
	groupID := group.GroupID
	fmt.Printf("Created group: %v %v\n", group.GroupID, group.Name)

	// Create a new app
	permissions := sdkms.AppPermissionsEncrypt | sdkms.AppPermissionsDecrypt
	app, err := client.CreateApp(ctx, nil, sdkms.AppRequest{
		Name:         someString(fmt.Sprintf("TestApp-%v", randomName(8))),
		AddGroups:    &sdkms.AppGroups{groupID: &permissions},
		DefaultGroup: &groupID,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Created app: %v\n", appToString(app))

	// List all apps
	apps, err := client.ListApps(ctx, &sdkms.ListAppsParams{
		GroupPermissions: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\n\nListing all apps (%v):\n", len(apps))
	for _, app := range apps {
		fmt.Printf("  %v\n", appToString(&app))
	}

	// Delete the app that was created before
	if err := client.DeleteApp(ctx, app.AppID); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\n\nApp %v deleted\n", app.AppID)
	// Delete the group that was created before
	if err := client.DeleteGroup(ctx, groupID); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Group %v deleted\n", groupID)
}

func appToString(app *sdkms.App) string {
	created, err := app.CreatedAt.Std()
	if err != nil {
		log.Fatalf("Failed to convert app.CreatedAt: %v", err)
	}
	return fmt.Sprintf("{ %v %#v group(%v) auth: %v created: %v }",
		app.AppID, app.Name, *app.DefaultGroup, *app.AuthType,
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
