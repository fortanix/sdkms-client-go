package crypto_ops

import (
	"context"
	"log"

	"github.com/fortanix/sdkms-client-go/sdkms"
)

func sample_encrypt_decrypt(client *sdkms.Client, objId string) {

	ctx := context.Background()
	var plainText string = "Hello World!"
	var key sdkms.SobjectDescriptor

	if objId != "" {
		key = *sdkms.SobjectByID(objId)
	} else {
		key = *sdkms.SobjectByName(keyName)
	}

	encryptReq := sdkms.EncryptRequest{
		Plain: []byte(plainText),
		Alg:   sdkms.AlgorithmAes,
		Key:   &key,
		Mode:  sdkms.CryptModeSymmetric(sdkms.CipherModeCbc),
	}
	log.Printf("Plain Text before encryption %v", plainText)
	encryptResp, err := client.Encrypt(ctx, encryptReq)
	if err != nil {
		log.Fatalf("Encrypt failed: %v", err)
		return
	}
	decryptReq := sdkms.DecryptRequest{
		Cipher: encryptResp.Cipher,
		Iv:     encryptResp.Iv,
		Key:    sdkms.SobjectByName(keyName),
		Mode:   sdkms.CryptModeSymmetric(sdkms.CipherModeCbc),
	}
	decryptResp, err := client.Decrypt(ctx, decryptReq)
	if err != nil {
		log.Fatalf("Decrypt failed: %v", err)
		return
	}
	log.Printf("Plain text after decryption %v", string(decryptResp.Plain))

}
