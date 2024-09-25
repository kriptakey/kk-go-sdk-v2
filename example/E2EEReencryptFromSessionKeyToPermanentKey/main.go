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
	DEMO_PERMANENT_KEY_ID := "AESEncryptionKey"
	DEMO_SESSION_KEY_ALGO := "AES"
	DEMO_MAC_ALGO := "HMAC-SHA512"
	DEMO_OAEP_LABEL := "SEpOAsYzxFJfc3l1"
	DEMO_METADATA := "fo5YQIfoJKk/1TzhA1ajWXVGgUJOqjMhg9LmWc45Kc6RVBFvkJNxYB+qVw25BI+4QXT5HFq9EYdTrr5y4JbvbWPthFbMtt0gTnZTUTUS/zTlHdL1WjynfByTYyjd08DvrHa7ZpMwwGVET18XCIy9RDflTuMclMoPqtkLp22GGtDGUn8RMKoGWKOW+sN4qgQQtHxbB4ydnS6PnHk0E1ip/M9AH1aTC30BlRW8ruGAKSZmfGlmYGKKphu+/cWegsyU4uNG3Ep8NNbdZlqZ1xvS3SseHn67MczpBXtPhky/odECB2FCgTaxmJLRyOxeXfwtFruaLsGohXd3G0r0GYrsUmZ+nIIO7h8u6h+FVlivzUHicPw6xy8ZN4enJwLZOVSjfctTXfsjxlQAYxuTPG9WaewfDAE7qXcIPmpM7upgL/c="
	DEMO_WRAPPED_PRIVATE_KEY := "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"

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

	var e2eeSourceRequest kkreq.E2EESourceCipher
	e2eeSourceRequest.WrappingKeyId = wrapperspb.String(DEMO_WRAPPING_KEY_ID)
	e2eeSourceRequest.WrappedPrivateKey = wrapperspb.String(DEMO_WRAPPED_PRIVATE_KEY)
	e2eeSourceRequest.SessionKeyAlgo = wrapperspb.String(DEMO_SESSION_KEY_ALGO)
	e2eeSourceRequest.MacAlgo = wrapperspb.String(DEMO_MAC_ALGO)
	e2eeSourceRequest.OaepLabel = wrapperspb.String(DEMO_OAEP_LABEL)
	e2eeSourceRequest.Metadata = wrapperspb.String(DEMO_METADATA)
	e2eeSourceRequest.Ciphertext = []string{"nZu0ENITZ0KU1eqKPO8K4fJxvtAT14LeUrrufQUAAADXyTbHXA==", "0WLkDH2W0zSnUwLm3bT+RRrQseMQFyh/pjw3eAUAAABoGhTM2Q=="}

	var e2eeDestinationRequest kkreq.APIRequestE2EEReencryptFromSessionKeyToPermanentKey_Destination
	e2eeDestinationRequest.PermanentKeyId = wrapperspb.String(DEMO_PERMANENT_KEY_ID)
	e2eeDestinationRequest.Algo = wrapperspb.String(DEMO_SESSION_KEY_ALGO)

	e2eeReencryptFromSessionKeyToPermanentKeyResponse, err := connection.KK_E2EEReencryptFromSessionKeyToPermanentKey(uint32(DEMO_PARTITION_ID), session.SessionToken, &e2eeSourceRequest, &e2eeDestinationRequest)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Printf("- E2EEReencryptFromSessionKeyToPermanentKey: %s", protojson.Format(e2eeReencryptFromSessionKeyToPermanentKeyResponse))
}
