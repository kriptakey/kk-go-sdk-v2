package main

import (
	"fmt"
	"log"
	"os"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"

	kk "github.com/kriptakey/kk-go-sdk-v24.1/kriptakey"
	kkreq "github.com/kriptakey/kk-go-sdk-v24.1/kriptakey/deprecated/request"
)

func main() {

	// Change these constants to the actual value in your environment
	DEMO_HOSTNAME := "target-kk-cs.com"
	DEMO_PORT := 7005

	DEMO_PARTITION_ID := 1
	DEMO_PARTITION_PASSWORD := "Password1!"

	DEMO_CLIENT_CERTIFICATE := "/PathToClient/Cert.pem"
	DEMO_CLIENT_PRIVATE_KEY := "/PathToClientKey/Priv.key"
	DEMO_CA_CERTIFICATE := "/PathToClient/Cert.pem"

	DEMO_KEY_ID := "AESEncryptionKey"
	DEMO_DESTINATION_KEY_ID := "AESEncryptionKey2"

	connection, err := kk.InitializeConnection(DEMO_HOSTNAME, uint16(DEMO_PORT), DEMO_CLIENT_CERTIFICATE, DEMO_CLIENT_PRIVATE_KEY, DEMO_CA_CERTIFICATE)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	session, err := connection.Login(uint32(DEMO_PARTITION_ID), DEMO_PARTITION_PASSWORD)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Println("- Session: ", protojson.Format(session))

	var encryptRequest kkreq.APIRequest_Encrypt
	encryptRequest.Plaintext = append(encryptRequest.Plaintext, &kkreq.APIRequest_SingleEncrypt{Plaintext: "Klavis", Aad: wrapperspb.String("aad1")})
	encrypted, err := connection.EncryptAES(1, session.SessionToken, DEMO_KEY_ID, &encryptRequest)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Println("- EncryptAES: ", protojson.Format(encrypted))

	var decryptRequest kkreq.APIRequest_Reencrypt
	for i, _ := range encrypted.Ciphertext {
		decryptRequest.Ciphertext = append(decryptRequest.Ciphertext, &kkreq.APIRequest_SingleReencrypt{Ciphertext: encrypted.Ciphertext[i].Ciphertext, Iv: encrypted.Ciphertext[i].Iv, Mac: encrypted.Ciphertext[i].Mac, Aad: wrapperspb.String("aad1"), KeyVersion: encrypted.KeyVersion})
	}
	decrypted, err := connection.Reencrypt(1, session.SessionToken, DEMO_KEY_ID, DEMO_DESTINATION_KEY_ID, &decryptRequest)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	fmt.Println("- ReEncrypt: ", protojson.Format(decrypted))

}
