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

	DEMO_WRAPPING_KEY_ID := "AESWrappingKey"
	DEMO_WRAPPED_KEY := "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"

	DEMO_PUBLIC_KEY := "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wDKpUeU96FQ9ofPN/MP\n3ME4Wr3HROhT4cp7CdgxbyCNez2yYEHnRnGg+4t4GK19n+6YVgxQYUQK+ZR4fDNY\nsBkftTaM2BRt2OkyIQqPEC/5VJ3wXmUrPNBAPDij6+0XLYn7xVgZFHnMd7hGlEf+\nxtVj0R/6Ns/IzJmJvCQmClJpptoW+z1JLanFK5SMQCzbpJg29N19DsIJKL4UBlwA\nM5yhIfPF1PVPqh7anMyclIdFiJ8tEQsUE/BW9KS4H9BlvLPDAPvnXSOMC+qNOlME\n/DugDFyZHp6tppmOQqT4nil8d2b9IBkmhjoenzFcKPPBt0BWb4/hstKvyCSCDf0Z\n/QIDAQAB\n-----END PUBLIC KEY-----\n"

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

	var plaintexts []*kkreq.APIRequestSingleEncrypt
	plaintexts = append(plaintexts, &kkreq.APIRequestSingleEncrypt{Text: wrapperspb.String("Klavis")})
	encrypted, err := connection.KK_AppstoredEncrypt_RSA(1, session.SessionToken, DEMO_PUBLIC_KEY, false, plaintexts)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Println("- KK_AppstoredEncrypt_RSA: ", protojson.Format(encrypted))

	var ciphertexts []*kkreq.APIRequestSingleAppstoredDecrypt
	for i := range encrypted.Ciphertext {
		ciphertexts = append(ciphertexts, &kkreq.APIRequestSingleAppstoredDecrypt{Text: wrapperspb.String(encrypted.Ciphertext[i].Text), Iv: encrypted.Ciphertext[i].Iv, Mac: encrypted.Ciphertext[i].Mac, Aad: nil, WrappedSessionKey: encrypted.Ciphertext[i].WrappedSessionKey})
	}
	decrypted, err := connection.KK_AppstoredDecrypt(1, session.SessionToken, DEMO_WRAPPING_KEY_ID, DEMO_WRAPPED_KEY, ciphertexts)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	fmt.Println("- KK_AppstoredDecrypt: ", protojson.Format(decrypted))

}
