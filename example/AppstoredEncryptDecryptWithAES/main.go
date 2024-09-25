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

	DEMO_WRAPPING_KEY_ID := "AESWrappingKey"
	DEMO_WRAPPED_KEY := "Egx2O0vNhkypFeq3TbIaIEZ9j+Zz65OeGPJgJ6GlrbEeI2q6iGXJcPNgo54CLN6rIhAqHDvMJOowhjdQo68HSE/3"

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
	plaintexts = append(plaintexts, &kkreq.APIRequestSingleEncrypt{Text: wrapperspb.String("Klavis"), Aad: wrapperspb.String("aad1")})
	encrypted, err := connection.KK_AppstoredEncrypt_AES(1, session.SessionToken, DEMO_WRAPPING_KEY_ID, DEMO_WRAPPED_KEY, plaintexts)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Println("- KK_AppstoredEncrypt_AES: ", protojson.Format(encrypted))

	var ciphertexts []*kkreq.APIRequestSingleAppstoredDecrypt
	for i := range encrypted.Ciphertext {
		ciphertexts = append(ciphertexts, &kkreq.APIRequestSingleAppstoredDecrypt{Text: wrapperspb.String(encrypted.Ciphertext[i].Text), Iv: encrypted.Ciphertext[i].Iv, Mac: encrypted.Ciphertext[i].Mac, Aad: wrapperspb.String("aad1")})
	}
	decrypted, err := connection.KK_AppstoredDecrypt(1, session.SessionToken, DEMO_WRAPPING_KEY_ID, DEMO_WRAPPED_KEY, ciphertexts)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	fmt.Println("- KK_AppstoredDecrypt: ", protojson.Format(decrypted))

}
