package main

import (
	"fmt"
	"log"
	"os"

	"google.golang.org/protobuf/encoding/protojson"

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
	encryptRequest.Plaintext = append(encryptRequest.Plaintext, &kkreq.APIRequest_SingleEncrypt{Plaintext: "Klavis"})
	encrypted, err := connection.EncryptRSA(1, session.SessionToken, "01rsa4096", false, &encryptRequest)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	fmt.Println("- EncryptRSA: ", protojson.Format(encrypted))

	var decryptRequest kkreq.APIRequest_Decrypt
	for i, _ := range encrypted.Ciphertext {
		decryptRequest.Ciphertext = append(decryptRequest.Ciphertext, &kkreq.APIRequest_SingleDecrypt{Ciphertext: encrypted.Ciphertext[i].Ciphertext, Iv: encrypted.Ciphertext[i].Iv, Mac: encrypted.Ciphertext[i].Mac, KeyID: "01rsa4096", KeyVersion: encrypted.KeyVersion, WrappedSessionKey: encrypted.Ciphertext[i].WrappedSessionKey})
	}
	decrypted, err := connection.Decrypt(1, session.SessionToken, "01rsa4096", &decryptRequest)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	fmt.Println("- DecryptRSA: ", protojson.Format(decrypted))

}
