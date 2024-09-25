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
	DEMO_PUBLIC_KEY := `-----BEGIN PUBLIC KEY-----
	MIIBigKCAYEAtTgJkzcjC4n1zLnnQ0VaXt4PCCjqHgya1w6OBvvg3RKunIp7CZSi
	gDD8M9Rf+LwdZ3FDZH8YKoepqPJD2FgiP7SICmRRRXIj/KNRgfk8vkqBAlAidUPk
	iPDsyPUrWHfzhoM+2W97QGG52jheJIVFNHxGlk/2TTSEh8BdZurcopGP7H2hOUp+
	7mVgpdYMdm29kFXC9qkKZ7qxR4qIAPW2587Woxc6mEwGSJED4LR1vpvJUtYJEON6
	cW3ttcYTVebtphvjFSugWR3uJyO4r52JCJfENYSJYqSAyx2+1fu1TRXT0viZnKwf
	KIA2UZohG8kZELWj7LnSbBGWaZGgQnDzicBt8DnifDCRyeQFhWl/BelNChXhsVHh
	MpUJ+bSK7q2ByLuYk74TfSaVniJrVbulvhVEzaxTPD/Ve+uhifCjyhKP4Ta/V1Ag
	8E6rxivoxMG+e17SQXkGgOwNw7EwvThZn/KVc3bIGOpwnJdrVPeTfl5gtcPQlbQA
	ev6pZbnmyRRjAgMBAAE=
	 -----END PUBLIC KEY-----`

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

	response, err := connection.KK_GenerateAppstoredKey_AES(1, session.SessionToken, "internalKey", DEMO_WRAPPING_KEY_ID, DEMO_PUBLIC_KEY, 256)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Println("- KK_GenerateAppstoredKey_AES: ", protojson.Format(response))
}
