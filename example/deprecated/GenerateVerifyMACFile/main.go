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
	DEMO_CA_CERTIFICATE := "/PathToClient/Cert.pem"

	DEMO_KEY_ID := "AESMACKey"
	DEMO_FILE_DATA := "Plaintext"

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

	filePath := "/tmp/data.bin"
	os.Remove(filePath)

	err = os.WriteFile(filePath, []byte(DEMO_FILE_DATA), 0644)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	fileHmacResponse, err := connection.FileGenerateHMAC(1, session.SessionToken, DEMO_KEY_ID, filePath)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	verifyResponse, err := connection.FileVerifyHMAC(1, session.SessionToken, DEMO_KEY_ID, filePath, fileHmacResponse.Tag)
	fmt.Println(verifyResponse)
}
