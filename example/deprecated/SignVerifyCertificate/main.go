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
	DEMO_CA_CERTIFICATE := "/PathToClient/Cert.pem"

	DEMO_KEY_ID := "CertSigningKey"

	DEMO_CSR :=
		`-----BEGIN CERTIFICATE REQUEST-----
MIICxDCCAawCAQAwfzELMAkGA1UEBhMCSUQxEDAOBgNVBAgMB0pha2FydGExEDAO
BgNVBAcMB0pha2FydGExDzANBgNVBAoMBktyaXB0YTELMAkGA1UECwwCSVQxDzAN
BgNVBAMMBmtyaXB0YTEdMBsGCSqGSIb3DQEJARYOa3JpcHRhQGRldi5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJ5ECbkAJRzAw9MGmhPiOc8kQ+
WBK+rnlb0menldoEY6lCMvAsFJcxmeTYxHlCdEvX6kFUJ+c4WlY9jjOVtMD+wXQL
fDe83wVHH6Ehe0kkjZBwqGylux0rZJln/gDVN1P3nZ3gd1xiHidr4eoJxgo5V6CF
BwT1Ox0C3FIOOBuzWGXK5gndfVwCMMsovIJJzEAzGP+JFiW/s5pnEvzET6bLtGjP
+QXN/3tgq3TbnjzxPISqLya5vhXWFNpRbc5Uj18IlmYDeY+XwrkMbvtW3y97nMlQ
UIR7j34iDJBGylM2uXKMKSfpPwK0eji+1onytsrCLkyWRD20oVxLin4w4yiBAgMB
AAGgADANBgkqhkiG9w0BAQsFAAOCAQEAIkaaZFNurrTpzF5d3KC6LdHISVAprf0h
bXU8GeqVpNqrapu7ZVgNGtwUzrizyin4k/F/gMKyLfVg3016M4LuXeXFuqUzgsik
RSlg8PEceGujAKchMbF9cGp4WbdLVP/Y3tnXLiYLfqnGzu4xXvDruDzefgfPi9HC
/Ba+MBGxAg/1K2pozVhCWX+xmtceROVjvoan3msxMr4bRu35Cuz3mcpsEbdxEkk8
L1mKGXU3rsJh2cJvu7AuTPQCW3eES+DZAhGUT/b1AtWvR2+q354uRXbmRhDu6hHO
sr6d6hZt1l6eUeqm01OlojYvJ827Zbm73A0DH1k5sRloqej+aLb/xA==
-----END CERTIFICATE REQUEST-----`

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

	csrResponse, err := connection.SignCertificate(1, session.SessionToken, DEMO_KEY_ID, 365, "SHA256", DEMO_CSR)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Println("- SignCertificate: ", protojson.Format(csrResponse))

	verifyResponse, err := connection.VerifyCertificate(1, session.SessionToken, DEMO_KEY_ID, csrResponse.Certificate)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}
	fmt.Println("- VerifyCertificate: ", protojson.Format(verifyResponse))

}
