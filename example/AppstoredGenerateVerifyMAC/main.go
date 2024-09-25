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

	mac, err := connection.KK_AppstoredGenerateMAC(1, session.SessionToken, DEMO_WRAPPING_KEY_ID, DEMO_WRAPPED_KEY, "CMAC", "klavis")
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Printf("- KK_AppstoredGenerateMAC %s", protojson.Format(mac))

	verifyMAC, err := connection.KK_AppstoredVerifyMAC(1, session.SessionToken, DEMO_WRAPPING_KEY_ID, DEMO_WRAPPED_KEY, "CMAC", "klavis", mac.Mac, nil)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Printf("- KK_AppstoredVerifyMAC %s", protojson.Format(verifyMAC))

}
