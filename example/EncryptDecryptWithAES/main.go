package main

import (
	"fmt"
	"log"
	"os"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"

	kk "github.com/kriptakey/kk-go-sdk-v24.1/kriptakey"
	kkreq "github.com/kriptakey/kk-go-sdk-v24.1/kriptakey/api/request"
)

func main() {

	// Change these constants to the actual value in your environment
	DEMO_HOSTNAME := "target-kk-cs.com"
	DEMO_PORT := 7005

	DEMO_PARTITION_ID := 1
	DEMO_PARTITION_PASSWORD := "Password1!"

	DEMO_CLIENT_CERTIFICATE := "/PathToClient/Cert.pem"
	DEMO_CLIENT_PRIVATE_KEY := "/PathToClientKey/Priv.key"

	DEMO_KEY_ID := "AESEncryptionKey"

	connection, err := kk.KK_InitializeConnection(DEMO_HOSTNAME, uint16(DEMO_PORT), DEMO_CLIENT_CERTIFICATE, DEMO_CLIENT_PRIVATE_KEY)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	session, err := connection.KK_AppAuthenticate(uint32(DEMO_PARTITION_ID), DEMO_PARTITION_PASSWORD)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Println("- Session: ", protojson.Format(session))

	plaintexts := []*kkreq.APIRequestSingleEncrypt{}
	plaintexts = append(plaintexts, &kkreq.APIRequestSingleEncrypt{
		Text: wrapperspb.String("Klavis"),
		Aad:  wrapperspb.String("aad1"),
	})

	encrypted, err := connection.KK_Encrypt_AES(1, session.SessionToken, DEMO_KEY_ID, plaintexts)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Println("- KK_Encrypt_AES: ", protojson.Format(encrypted))

	var ciphertexts []*kkreq.APIRequestSingleDecrypt

	for _, el := range encrypted.Ciphertext {
		ciphertexts = append(ciphertexts, &kkreq.APIRequestSingleDecrypt{
			Iv:                el.Iv,
			Mac:               el.Mac,
			Aad:               wrapperspb.String("aad1"),
			KeyId:             wrapperspb.String(DEMO_KEY_ID),
			KeyVersion:        encrypted.KeyVersion,
			Text:              wrapperspb.String(el.Text),
			WrappedSessionKey: el.WrappedSessionKey,
		})
	}
	decrypted, err := connection.KK_Decrypt(1, session.SessionToken, ciphertexts)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	fmt.Println("- KK_Decrypt: ", protojson.Format(decrypted))

}
