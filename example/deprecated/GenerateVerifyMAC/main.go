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

	DEMO_KEY_ID := "AESMACKey"

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

	mac, err := connection.GenerateMAC(1, session.SessionToken, DEMO_KEY_ID, "CMAC", []string{"Klavis", "Kripta", "Inovasi"})
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	fmt.Printf("- GenerateMAC %s", protojson.Format(mac))

	verifyMACRequest := &kkreq.APIRequest_VerifyMAC{
		Mac: []*kkreq.APIRequest_SingleVerifyMAC{
			{
				Data: "Klavis",
				Mac:  mac.GetMac()[0].GetMac(),
				Iv:   mac.GetMac()[0].Iv,
			},
			{
				Data: "Kripta",
				Mac:  mac.GetMac()[1].GetMac(),
				Iv:   mac.GetMac()[1].Iv,
			},
			{
				Data: "Inovasi",
				Mac:  mac.GetMac()[2].GetMac(),
				Iv:   mac.GetMac()[2].Iv,
			},
		},
	}

	verifyMAC, err := connection.VerifyMAC(1, session.SessionToken, DEMO_KEY_ID, "CMAC", verifyMACRequest)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	fmt.Printf("- VerifyMAC % %s", protojson.Format(verifyMAC))

}
