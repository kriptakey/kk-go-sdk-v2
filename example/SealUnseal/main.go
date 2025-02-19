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
	DEMO_WRAPPED_KEY := "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"

	DEMO_PUBLIC_KEY := "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA64HLM7aM9F5bu8ih7wg/\n1OX1jKO9TgFQRj25cddURYme6vzr2ztXM/x2JVtJALLPeWJchR5rZs2HzC657R42\neNrS90m8GC/GJGlGWt9YR9ZAXiADOgIDBdRNH0qy1VqdELDd9btYrEC+KObVl3IW\nY94k2PhVS38stGxmmyZhRAqpnUTlOLLA3n+g8RnDsvAEtBC7S3/OSwqLG83cbogg\n0HtCjkc2Ab/f4egM7luhcyS4SPneLOYsGMY7CRUeXfnFYgd0pWK2H92d/I51L2M5\nlQlCwsaz7ymJi/GsrtR8+EskxcS6pF0lnWbJPU8h4anXw1NXU2t4K2yT9iAiBKuE\nrgf9TuYjnbNgqY+4RdpzvNJ8G4C5nUsZqHgBF2nV3lTFsOdffqzofVW3uVkzpj3T\nXVCEeJZ0fjCDce4eWRk8WmgcjhGVG/QQlpmLddUGQdmSELk98beFA2RnNHGmMTfT\nvcztf6zZnqwm/kGhrejZA6q0w7NAeKebnkaK6YfNL8fXAgMBAAE=\n-----END PUBLIC KEY-----\n"

	DEMO_PLAINTEXT := "Hello World"

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

	ciphertext, err := kk.KK_SealForTransit([]byte(DEMO_PLAINTEXT), DEMO_PUBLIC_KEY)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Println("- SealForTransit: ", ciphertext)

	unsealResponse, err := connection.KK_UnsealDataFromTransit(uint32(DEMO_PARTITION_ID), session.SessionToken, DEMO_WRAPPING_KEY_ID, DEMO_WRAPPED_KEY, ciphertext)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Println("- UnsealDataFromTransit: ", unsealResponse)

}
