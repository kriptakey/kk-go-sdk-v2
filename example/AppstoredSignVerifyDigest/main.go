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
	DEMO_PUBLIC_KEY := "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2ZcvCT+y68MO9ffwtmol\nkaRprpRx9Pv1l7PRl9QAiP8CCK/D8OfTDlA2ThQXp3E/j8k4xWHvVoxrWtt0CqA0\nfGPAfJSKqHLD5CHJ6fu9in5JwZN3k3/kJrXGRA3Wf7awHtG3Mx8J1wMpnCM5IHt/\nPtHG6rlyzJW0M7U8csdk21D/TQEj0K0pGCG9LT0C/XoXos4JfrkVesWKo/qcGYPr\nHzQBD/Atwzp4Pg6fs/Zb4Ih0eG3Dp0JtLcOjPMgA08EXpOa33UEXY5Cq8LLU1Cjz\nkmOhp/z0YjhQSSsaVomlCOXFZqJG8Mvu/Yu1El6/Sk5BLEQK0YJuJqS5uaAVcXpc\npwIDAQAB\n-----END PUBLIC KEY-----\n"

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

	signResponse, err := connection.KK_AppstoredSignDigest(1, session.SessionToken, DEMO_WRAPPING_KEY_ID, DEMO_WRAPPED_KEY, "sha256Hashed", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Printf("- KK_AppstoredSignDigest  %s", protojson.Format(signResponse))

	verify, err := connection.KK_AppstoredVerifyDigest(1, session.SessionToken, DEMO_PUBLIC_KEY, "sha256Hashed", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", signResponse.Signature)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	fmt.Println(protojson.Format(verify))

}
