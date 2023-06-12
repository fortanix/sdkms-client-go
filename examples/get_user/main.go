package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/fortanix/sdkms-client-go/sdkms"
)

const (
	myUsername = "name@example.com"
	myPassword = "password"
	myAcctID   = "b6480ec0-df2e-..."
)

func main() {
	client := sdkms.Client{
		HTTPClient: http.DefaultClient,
		Endpoint:   "https://sdkms.fortanix.com",
	}
	ctx := context.Background()
	// Establish a session
	auth, err := client.AuthenticateWithUserPass(ctx, myUsername, myPassword)
	if err != nil {
		log.Fatalf("Could not authenticate: %v", err)
	}
	// Terminate the session on exit
	defer client.TerminateSession(ctx)

	_, err = client.SelectAccount(ctx, sdkms.SelectAccountRequest{AcctID: myAcctID})
	if err != nil {
		log.Fatalf("Could not select account: %v", err)
	}

	userID := auth.EntityID
	user, err := client.GetUser(ctx, userID)
	if err != nil {
		log.Fatalf("Could not get user object: %v", err)
	}

	fmt.Println("User:")
	fmt.Printf("  AccountRole: %v\n", accountRoleToString(user.AccountRole))
	fmt.Printf("  CreatedAt: %v\n", *user.CreatedAt)
	fmt.Printf("  Description: %v\n", user.Description)
	fmt.Printf("  EmailVerified: %v\n", *user.EmailVerified)
	fmt.Printf("  FirstName: %v\n", user.FirstName)
	fmt.Printf("  Groups: %v\n", user.Groups)
	fmt.Printf("  HasPassword: %v\n", *user.HasPassword)
	fmt.Printf("  LastLoggedInAt: %v\n", *user.LastLoggedInAt)
	fmt.Printf("  LastName: %v\n", user.LastName)
	fmt.Printf("  NewEmail: %v\n", user.NewEmail)
	fmt.Printf("  U2fDevices: %v\n", user.U2fDevices)
	fmt.Printf("  UserEmail: %v\n", *user.UserEmail)
	fmt.Printf("  UserID: %v\n", user.UserID)
}

func accountRoleToString(role sdkms.UserAccountFlags) string {
	var s string = ""
	for _, val := range role {
		if val.Flag != nil {
			s = s + fmt.Sprintf("UserAccountFlag: %s", *val.Flag)
		}
		if val.LegacyRole != nil {
			s = s + fmt.Sprintf("LegacyUserAccountRole: %s", *val.LegacyRole)
		}
		if val.RoleID != nil {
			s = s + fmt.Sprintf("Role ID: %s", *val.RoleID)
		}
		s = s + ", "
	}
	return s
}
