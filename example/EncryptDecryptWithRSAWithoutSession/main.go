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

	var plaintexts []*kkreq.APIRequestSingleEncrypt
	plaintexts = append(plaintexts, &kkreq.APIRequestSingleEncrypt{Text: wrapperspb.String("Klavis")})
	encrypted, err := connection.KK_Encrypt_RSA(1, session.SessionToken, "01rsa4096", false, plaintexts)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	fmt.Println("- KK_Encrypt_RSA: ", protojson.Format(encrypted))

	var ciphertexts []*kkreq.APIRequestSingleDecrypt
	for i, _ := range encrypted.Ciphertext {
		ciphertexts = append(ciphertexts, &kkreq.APIRequestSingleDecrypt{Text: wrapperspb.String(encrypted.Ciphertext[i].Text), Iv: encrypted.Ciphertext[i].Iv, Mac: encrypted.Ciphertext[i].Mac, KeyId: wrapperspb.String("01rsa4096"), KeyVersion: encrypted.KeyVersion, WrappedSessionKey: encrypted.Ciphertext[i].WrappedSessionKey})
	}
	decrypted, err := connection.KK_Decrypt(1, session.SessionToken, ciphertexts)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	fmt.Println("- KK_Decrypt: ", protojson.Format(decrypted))

}
