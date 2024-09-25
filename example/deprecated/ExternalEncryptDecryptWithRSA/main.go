package main

import (
	"fmt"
	"log"
	"os"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"

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

	var encryptRequest kkreq.APIRequest_Encrypt
	encryptRequest.Plaintext = append(encryptRequest.Plaintext, &kkreq.APIRequest_SingleEncrypt{Plaintext: "Klavis", Aad: wrapperspb.String("aad1")})
	encrypted, err := connection.ExternalEncryptRSA(1, session.SessionToken, DEMO_PUBLIC_KEY, false, &encryptRequest)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Println("- ExternalEncryptRSA: ", protojson.Format(encrypted))

	var decryptRequest kkreq.APIRequest_ExternalDecrypt
	for i, _ := range encrypted.Ciphertext {
		decryptRequest.Ciphertext = append(decryptRequest.Ciphertext, &kkreq.APIRequest_SingleExternalDecrypt{Ciphertext: encrypted.Ciphertext[i].Ciphertext, Iv: encrypted.Ciphertext[i].Iv, Mac: encrypted.Ciphertext[i].Mac, Aad: nil, WrappedSessionKey: encrypted.Ciphertext[i].WrappedSessionKey})
	}
	decrypted, err := connection.ExternalDecrypt(1, session.SessionToken, DEMO_WRAPPING_KEY_ID, DEMO_WRAPPED_KEY, &decryptRequest)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	fmt.Println("- ExternalDecryptRSA: ", protojson.Format(decrypted))

}
