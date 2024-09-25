package main

import (
	"fmt"
	"log"
	"os"

	"google.golang.org/protobuf/encoding/protojson"

	kk "github.com/kriptakey/kk-go-sdk-v24.1/kriptakey"
)

func main() {

	// Change these constants to the actual value in your environment
	DEMO_HOSTNAME := "target-kk-cs.com"
	DEMO_PORT := 7005

	DEMO_PARTITION_ID := 1
	DEMO_PARTITION_PASSWORD := "Password1!"

	DEMO_CLIENT_CERTIFICATE := "/PathToClient/Cert.pem"
	DEMO_CLIENT_PRIVATE_KEY := "/PathToClientKey/Priv.key"

	DEMO_KEY_ID := "RSASigningKey"

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

	signResponse, err := connection.KK_SignData(1, session.SessionToken, DEMO_KEY_ID, "SHA256", "RSASSA-PKCS1-v1_5", "datatobesigned")
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Printf("- Sign: %s", protojson.Format(signResponse))

	verify, err := connection.KK_VerifyData(1, session.SessionToken, DEMO_KEY_ID, "SHA256", "RSASSA-PKCS1-v1_5", "datatobesigned", signResponse.Signature)
	fmt.Println(verify)
}
