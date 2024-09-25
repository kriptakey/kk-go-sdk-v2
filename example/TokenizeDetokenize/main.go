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

	plaintexts := []*kkreq.APIRequestSingleTokenize{
		{Usv: wrapperspb.String("4281 5790 7311 2819"), FormatChar: wrapperspb.String("$$$$%%%%%%%%%%%$$$$"), TokenizedWith: wrapperspb.String("cipher")},
	}
	encrypted, err := connection.KK_Tokenize(1, session.SessionToken, "AESEncryptionKey", plaintexts)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Println("- KK_Tokenize: ", protojson.Format(encrypted))

	var ciphertexts []*kkreq.APIRequestSingleDetokenize
	for _, _ciphertext := range encrypted.Ciphertext {
		ciphertexts = append(ciphertexts, &kkreq.APIRequestSingleDetokenize{Token: wrapperspb.String(_ciphertext.Token), Metadata: wrapperspb.String(_ciphertext.Metadata)})
	}

	decrypted, err := connection.KK_Detokenize(1, session.SessionToken, ciphertexts)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	fmt.Println("- KK_Detokenize: ", protojson.Format(decrypted))
}
