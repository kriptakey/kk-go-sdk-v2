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

	DEMO_WRAPPING_KEY_ID := "WrappingKey"
	DEMO_WRAPPED_KEY := "UAHIdhiahebUHAD2n8bjd1IHGGalheaubfa98l=="

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

	var tokenizeRequest kkreq.APIRequest_Tokenize
	tokenizeRequest.Text = append(tokenizeRequest.Text, &kkreq.APIRequest_SingleTokenize{Text: "4281 5790 7311 2819", FormatChar: "$$$$%%%%%%%%%%%$$$$", TokenizedWith: kkreq.TokenizeType_CIPHER})
	encrypted, err := connection.ExternalTokenize(1, session.SessionToken, DEMO_WRAPPING_KEY_ID, DEMO_WRAPPED_KEY, &tokenizeRequest)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Println("- Tokenize: ", protojson.Format(encrypted))

	var detokenizeRequest kkreq.APIRequest_Detokenize
	for _, _ciphertext := range encrypted.Ciphertext {
		detokenizeRequest.Token = append(detokenizeRequest.Token, &kkreq.APIRequest_SingleDetokenize{Token: _ciphertext.Token, Metadata: _ciphertext.Metadata})
	}
	decrypted, err := connection.ExternalDetokenize(1, session.SessionToken, DEMO_WRAPPING_KEY_ID, DEMO_WRAPPED_KEY, &detokenizeRequest)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	fmt.Println("- Detokenize: ", protojson.Format(decrypted))

}
