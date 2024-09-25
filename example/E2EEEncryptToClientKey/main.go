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
	DEMO_SESSION_KEY_ALGO := "AES"
	DEMO_ENCRYPTED_CLIENT_KEY := "EgxXXEj2pm6XllA3leoaIIq7HmBt7npzUeBaNr6PiYhzwiDZT40FER00hExAOP77IhDS+N2ZkQNpntScjMjcUXQr"
	DEMO_ENCRYPTED_CLIENT_KEY_METADATA := "+3XGiJVrbup9DHgNzgvRpwAAAAAAAAAAAAAAABAAAADOGzh/zDjI2qXtWqL/F1YA"

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

	var e2eeSourceRequest kkreq.APIRequestE2EEEncryptToClientKey_Source
	e2eeSourceRequest.WrappingKeyId = wrapperspb.String(DEMO_WRAPPING_KEY_ID)
	e2eeSourceRequest.EncryptedClientKey = wrapperspb.String(DEMO_ENCRYPTED_CLIENT_KEY)
	e2eeSourceRequest.EncryptedClientKeyMetadata = wrapperspb.String(DEMO_ENCRYPTED_CLIENT_KEY_METADATA)
	e2eeSourceRequest.Algo = wrapperspb.String(DEMO_SESSION_KEY_ALGO)
	e2eeSourceRequest.Plaintext = []string{"admin", "admin", "123456"}

	var e2eeDestinationRequest kkreq.APIRequestE2EEEncryptToClientKey_Destination
	e2eeDestinationRequest.ClientKeyAlgo = wrapperspb.String(DEMO_SESSION_KEY_ALGO)

	e2eeEncryptToClientKeyResponse, err := connection.KK_E2EEEncryptToClientKey(uint32(DEMO_PARTITION_ID), session.SessionToken, &e2eeSourceRequest, &e2eeDestinationRequest)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Printf("- E2EEEncryptToClientKey: %s", protojson.Format(e2eeEncryptToClientKeyResponse))
}
