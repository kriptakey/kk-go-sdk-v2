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

	DEMO_KEY_ID := "AESMACKey"

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

	mac, err := connection.KK_GenerateMAC(1, session.SessionToken, DEMO_KEY_ID, "CMAC", []string{"Klavis", "Kripta", "Inovasi"})
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	fmt.Printf("- KK_GenerateMAC %s", protojson.Format(mac))

	verifyMACRequest := []*kkreq.SingleVerifyMAC{
		{
			Data: wrapperspb.String("Klavis"),
			Mac:  wrapperspb.String(mac.GetMac()[0].GetMac()),
			Iv:   mac.GetMac()[0].Iv,
		},
		{
			Data: wrapperspb.String("Kripta"),
			Mac:  wrapperspb.String(mac.GetMac()[1].GetMac()),
			Iv:   mac.GetMac()[1].Iv,
		},
		{
			Data: wrapperspb.String("Inovasi"),
			Mac:  wrapperspb.String(mac.GetMac()[2].GetMac()),
			Iv:   mac.GetMac()[2].Iv,
		},
	}

	verifyMAC, err := connection.KK_VerifyMAC(1, session.SessionToken, DEMO_KEY_ID, "CMAC", verifyMACRequest)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	fmt.Printf("- KK_VerifyMAC % %s", protojson.Format(verifyMAC))

}
