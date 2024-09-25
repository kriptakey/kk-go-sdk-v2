package kriptakey

/*
#cgo pkg-config: KK-NativeSDK
#include <kriptakey/api.h>

int32_t kk_gosdk_assign(void const*, int32_t, void*);

*/
import "C"
import (
	kkreq "github.com/kriptakey/kk-go-sdk-v24.1/kriptakey/api/request"
	dep_kkreq "github.com/kriptakey/kk-go-sdk-v24.1/kriptakey/deprecated/request"
	dep_kkresp "github.com/kriptakey/kk-go-sdk-v24.1/kriptakey/deprecated/response"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// NOTE: `caCertPath` parameter is unused and will be ignored
func InitializeConnection(host string, port uint16, clientCertificatePath string, privateKeyPath string, caCertPath string) (*ConnectionHandler, error) {
	return KK_InitializeConnection(host, port, clientCertificatePath, privateKeyPath)
}

// NOTE: `caCertBuffer` parameter is unused and will be ignored
func InitializeConnectionUsingPEMBuffer(host string, port uint16, clientCertificateBuffer string, privateKeyBuffer string, caCertBuffer string) (*ConnectionHandler, error) {
	return KK_InitializeConnectionUsingPEMBuffer(host, port, clientCertificateBuffer, privateKeyBuffer)
}

// Deprecated: Use KK_AppAuthenticate(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) Login(slotId uint32, password string) (*dep_kkresp.APIResponse_SessionInformation, error) {
	instance, err := x.KK_AppAuthenticate(slotId, password)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_SessionInformation{
		SessionToken:      instance.SessionToken,
		AgentDN:           instance.AgentDN,
		LastUsedTime:      int64(instance.LastUsedTime),
		IdleTimeoutInMins: instance.IdleTimeoutInMins,
		ExpiredAt:         int64(instance.ExpiredAt),
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_AppRefresh(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) RefreshSession(slotId uint32, sessionToken string) (*dep_kkresp.APIResponse_SessionInformation, error) {
	instance, err := x.KK_AppRefresh(slotId, sessionToken)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_SessionInformation{
		SessionToken:      instance.SessionToken,
		AgentDN:           instance.AgentDN,
		LastUsedTime:      int64(instance.LastUsedTime),
		IdleTimeoutInMins: instance.IdleTimeoutInMins,
		ExpiredAt:         int64(instance.ExpiredAt),
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_GenerateRandomNumber(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) GenerateRandomNumber(slotId uint32, sessionToken string, length uint32) (*dep_kkresp.APIResponse_RandomGenerator, error) {
	instance, err := x.KK_GenerateRandomNumber(slotId, sessionToken, length)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, len(instance.Random))
	for i, el := range instance.Random {
		buf[i] = byte(el)
	}

	deprecated_instance := &dep_kkresp.APIResponse_RandomGenerator{
		RandomNumber: buf,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_GenerateMAC(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) GenerateMAC(slotId uint32, sessionToken string, keyId string, hashAlgo string, data []string) (*dep_kkresp.APIResponse_GenerateMAC, error) {
	instance, err := x.KK_GenerateMAC(slotId, sessionToken, keyId, hashAlgo, data)
	if err != nil {
		return nil, err
	}

	single_response := make([]*dep_kkresp.APIResponse_SingleGenerateMAC, len(instance.Mac))
	for i, el := range instance.Mac {
		single_response[i] = &dep_kkresp.APIResponse_SingleGenerateMAC{
			Mac: el.Mac,
			Iv:  el.Iv,
		}
	}

	deprecated_instance := &dep_kkresp.APIResponse_GenerateMAC{
		Mac: single_response,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_VerifyMAC(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) VerifyMAC(slotId uint32, sessionToken string, keyId string, hashAlgo string, verifyMACRequest *dep_kkreq.APIRequest_VerifyMAC) (*dep_kkresp.APIResponse_VerifyMAC, error) {
	single_request := make([]*kkreq.SingleVerifyMAC, len(verifyMACRequest.Mac))
	for i, el := range verifyMACRequest.Mac {
		single_request[i] = &kkreq.SingleVerifyMAC{
			Data: wrapperspb.String(el.Data),
			Mac:  wrapperspb.String(el.Mac),
			Iv:   el.Iv,
		}
	}

	instance, err := x.KK_VerifyMAC(slotId, sessionToken, keyId, hashAlgo, single_request)
	if err != nil {
		return nil, err
	}

	single_response := make([]*dep_kkresp.APIResponse_SingleVerifyMAC, len(instance.Verified))
	for i, el := range instance.Verified {
		single_response[i] = &dep_kkresp.APIResponse_SingleVerifyMAC{
			Verified: el.Verified.GetValue(),
		}
	}

	deprecated_instance := &dep_kkresp.APIResponse_VerifyMAC{
		Verified: single_response,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_Encrypt_AES(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) EncryptAES(slotId uint32, sessionToken string, keyId string, encryptRequest *dep_kkreq.APIRequest_Encrypt) (*dep_kkresp.APIResponse_Encrypt, error) {
	single_request := make([]*kkreq.APIRequestSingleEncrypt, len(encryptRequest.Plaintext))
	for i, el := range encryptRequest.Plaintext {
		single_request[i] = &kkreq.APIRequestSingleEncrypt{
			Text: wrapperspb.String(el.Plaintext),
			Aad:  el.Aad,
		}
	}

	instance, err := x.KK_Encrypt_AES(slotId, sessionToken, keyId, single_request)
	if err != nil {
		return nil, err
	}

	single_response := make([]*dep_kkresp.APIResponse_SingleEncrypt, len(instance.Ciphertext))
	for i, el := range instance.Ciphertext {
		single_response[i] = &dep_kkresp.APIResponse_SingleEncrypt{
			Ciphertext:        el.Text,
			Mac:               el.Mac,
			Iv:                el.Iv,
			WrappedSessionKey: el.WrappedSessionKey,
		}
	}

	deprecated_instance := &dep_kkresp.APIResponse_Encrypt{
		Ciphertext: single_response,
		KeyVersion: instance.KeyVersion,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_Encrypt_RSA(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) EncryptRSA(slotId uint32, sessionToken string, keyId string, useSessionKey bool, encryptRequest *dep_kkreq.APIRequest_Encrypt) (*dep_kkresp.APIResponse_Encrypt, error) {
	single_request := make([]*kkreq.APIRequestSingleEncrypt, len(encryptRequest.Plaintext))
	for i, el := range encryptRequest.Plaintext {
		single_request[i] = &kkreq.APIRequestSingleEncrypt{
			Text: wrapperspb.String(el.Plaintext),
			Aad:  el.Aad,
		}
	}

	instance, err := x.KK_Encrypt_RSA(slotId, sessionToken, keyId, useSessionKey, single_request)
	if err != nil {
		return nil, err
	}

	single_response := make([]*dep_kkresp.APIResponse_SingleEncrypt, len(instance.Ciphertext))
	for i, el := range instance.Ciphertext {
		single_response[i] = &dep_kkresp.APIResponse_SingleEncrypt{
			Ciphertext:        el.Text,
			Mac:               el.Mac,
			Iv:                el.Iv,
			WrappedSessionKey: el.WrappedSessionKey,
		}
	}

	deprecated_instance := &dep_kkresp.APIResponse_Encrypt{
		Ciphertext: single_response,
		KeyVersion: instance.KeyVersion,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_Decrypt(...) instead for KriptaKey v24.1 compatibility
// Note: `keyId` parameter is unused and will be ignored
func (x *ConnectionHandler) Decrypt(slotId uint32, sessionToken string, keyId string, decryptRequest *dep_kkreq.APIRequest_Decrypt) (*dep_kkresp.APIResponse_Decrypt, error) {
	single_request := make([]*kkreq.APIRequestSingleDecrypt, len(decryptRequest.Ciphertext))
	for i, el := range decryptRequest.Ciphertext {
		single_request[i] = &kkreq.APIRequestSingleDecrypt{
			Text:              wrapperspb.String(el.Ciphertext),
			Aad:               el.Aad,
			Mac:               el.Mac,
			Iv:                el.Iv,
			KeyId:             wrapperspb.String(el.KeyID),
			WrappedSessionKey: el.WrappedSessionKey,
			KeyVersion:        el.KeyVersion,
		}
	}

	instance, err := x.KK_Decrypt(slotId, sessionToken, single_request)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_Decrypt{
		Plaintext: instance.Plaintext,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_Reencrypt(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) Reencrypt(slotId uint32, sessionToken string, sourceKeyId string, destinationKeyId string, decryptRequest *dep_kkreq.APIRequest_Reencrypt) (*dep_kkresp.APIResponse_Reencrypt, error) {
	single_request := make([]*kkreq.APIRequestSingleReEncrypt, len(decryptRequest.Ciphertext))
	for i, el := range decryptRequest.Ciphertext {
		single_request[i] = &kkreq.APIRequestSingleReEncrypt{
			Text:              wrapperspb.String(el.Ciphertext),
			Aad:               el.Aad,
			Mac:               el.Mac,
			Iv:                el.Iv,
			WrappedSessionKey: el.WrappedSessionKey,
			KeyVersion:        el.KeyVersion,
		}
	}

	instance, err := x.KK_Reencrypt(slotId, sessionToken, sourceKeyId, destinationKeyId, single_request)
	if err != nil {
		return nil, err
	}

	single_response := make([]*dep_kkresp.APIResponse_SingleEncrypt, len(instance.Ciphertext))
	for i, el := range instance.Ciphertext {
		single_response[i] = &dep_kkresp.APIResponse_SingleEncrypt{
			Ciphertext:        el.Text,
			Mac:               el.Mac,
			Iv:                el.Iv,
			WrappedSessionKey: el.WrappedSessionKey,
		}
	}

	deprecated_instance := &dep_kkresp.APIResponse_Reencrypt{
		Ciphertext: single_response,
		KeyVersion: instance.KeyVersion,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_Seal(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) Seal(slotId uint32, sessionToken string, keyId string, plaintext []string) (*dep_kkresp.APIResponse_Seal, error) {
	instance, err := x.KK_Seal(slotId, sessionToken, keyId, plaintext)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_Seal{
		Ciphertext: instance.Ciphertext,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_Unseal(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) Unseal(slotId uint32, sessionToken string, ciphertext []string) (*dep_kkresp.APIResponse_Unseal, error) {
	instance, err := x.KK_Unseal(slotId, sessionToken, ciphertext)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_Unseal{
		Plaintext: instance.Plaintext,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_Tokenize(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) Tokenize(slotId uint32, sessionToken string, keyId string, tokenizeRequest *dep_kkreq.APIRequest_Tokenize) (*dep_kkresp.APIResponse_Tokenize, error) {
	single_request := make([]*kkreq.APIRequestSingleTokenize, len(tokenizeRequest.Text))
	for i, el := range tokenizeRequest.Text {
		single_request[i] = &kkreq.APIRequestSingleTokenize{
			Usv:        wrapperspb.String(el.Text),
			FormatChar: wrapperspb.String(el.FormatChar),
			TokenizedWith: wrapperspb.String(func() string {
				switch tw := el.TokenizedWith; tw {
				case dep_kkreq.TokenizeType_CIPHER:
					return "cipher"
				case dep_kkreq.TokenizeType_MASKING:
					return "masking"
				case dep_kkreq.TokenizeType_ALPHA:
					return "alpha"
				case dep_kkreq.TokenizeType_NUMERIC:
					return "num"
				case dep_kkreq.TokenizeType_ALPHA_NUMERIC:
					return "alphanum"
				}
				return ""
			}()),
		}
	}

	instance, err := x.KK_Tokenize(slotId, sessionToken, keyId, single_request)
	if err != nil {
		return nil, err
	}

	single_response := make([]*dep_kkresp.APIResponse_SingleTokenize, len(instance.Ciphertext))
	for i, el := range instance.Ciphertext {
		single_response[i] = &dep_kkresp.APIResponse_SingleTokenize{
			Token:    el.Token,
			Metadata: el.Metadata,
		}
	}

	deprecated_instance := &dep_kkresp.APIResponse_Tokenize{
		Ciphertext: single_response,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_Detokenize(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) Detokenize(slotId uint32, sessionToken string, detokenizeRequest *dep_kkreq.APIRequest_Detokenize) (*dep_kkresp.APIResponse_Detokenize, error) {
	single_request := make([]*kkreq.APIRequestSingleDetokenize, len(detokenizeRequest.Token))
	for i, el := range detokenizeRequest.Token {
		single_request[i] = &kkreq.APIRequestSingleDetokenize{
			Token:    wrapperspb.String(el.Token),
			Metadata: wrapperspb.String(el.Metadata),
		}
	}

	instance, err := x.KK_Detokenize(slotId, sessionToken, single_request)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_Detokenize{
		Plaintext: instance.Usv,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_SignData(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) SignData(slotId uint32, sessionToken string, keyId string, hashAlgo string, signatureScheme string, data string) (*dep_kkresp.APIResponse_Sign, error) {
	instance, err := x.KK_SignData(slotId, sessionToken, keyId, hashAlgo, signatureScheme, data)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_Sign{
		Signature: instance.Signature,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_SignDigest(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) SignDigest(slotId uint32, sessionToken string, keyId string, inputType string, signatureScheme string, digest string) (*dep_kkresp.APIResponse_Sign, error) {
	instance, err := x.KK_SignDigest(slotId, sessionToken, keyId, inputType, signatureScheme, digest)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_Sign{
		Signature: instance.Signature,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_VerifyData(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) VerifyData(slotId uint32, sessionToken string, keyId string, hashAlgo string, signatureScheme string, data string, signature string) (*dep_kkresp.APIResponse_Verify, error) {
	instance, err := x.KK_VerifyData(slotId, sessionToken, keyId, hashAlgo, signatureScheme, data, signature)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_Verify{
		Verified: instance.Verified,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_VerifyDigest(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) VerifyDigest(slotId uint32, sessionToken string, keyId string, inputType string, signatureScheme string, digest string, signature string) (*dep_kkresp.APIResponse_Verify, error) {
	instance, err := x.KK_VerifyDigest(slotId, sessionToken, keyId, inputType, signatureScheme, digest, signature)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_Verify{
		Verified: instance.Verified,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_SignCertificate(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) SignCertificate(slotId uint32, sessionToken string, keyId string, validityPeriod uint32, hashAlgo string, csr string) (*dep_kkresp.APIResponse_CertificateSign, error) {
	instance, err := x.KK_SignCertificate(slotId, sessionToken, keyId, validityPeriod, hashAlgo, csr)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_CertificateSign{
		Certificate: instance.Certificate,
		PublicKey:   instance.PublicKey,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_VerifyCertificate(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) VerifyCertificate(slotId uint32, sessionToken string, keyId string, certificate string) (*dep_kkresp.APIResponse_CertificateVerify, error) {
	instance, err := x.KK_VerifyCertificate(slotId, sessionToken, keyId, certificate)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_CertificateVerify{
		Verified: instance.Verified.GetValue(),
	}
	return deprecated_instance, nil
}

// TODO: Fix this deprecated functions, APIResponse_KeyInfo not found!
// Deprecated: Use KK_GetKeyInfo(...) instead for KriptaKey v24.1 compatibility
// func (x *ConnectionHandler) GetKeyInfo(slotId uint32, sessionToken string, keyId string, keyVersion *uint) (*dep_kkresp.APIResponse_KeyInfo, error) {
// 	instance, err := x.KK_GetKeyInfo(slotId, sessionToken, keyId, func() *uint32 {
// 		if keyVersion != nil {
// 			kv := uint32(*keyVersion)
// 			return &kv
// 		}
// 		return nil
// 	}())
// 	if err != nil {
// 		return nil, err
// 	}

// 	deprecated_instance := &dep_kkresp.APIResponse_KeyInfo{
// 		SlotId:             instance.PartitionId.GetValue(),
// 		KeyId:              instance.KeyId,
// 		KeyLabel:           instance.KeyLabel,
// 		KeyAlgo:            instance.KeyAlgo,
// 		KeyLength:          instance.KeyLength,
// 		KeyPurpose:         instance.KeyPurpose,
// 		IsExtractable:      instance.IsExtractable,
// 		IsRotatable:        instance.IsRotatable,
// 		CreationDate:       int64(instance.CreationDate),
// 		ExpiryDate:         int64(instance.ExpiredAt),
// 		PublicKey:          instance.PublicKey,
// 		Certificate:        instance.Certificate,
// 		KeyVersion:         instance.KeyVersion,
// 		EncodedModulus:     instance.Modulus,
// 		EncodedExponent:    instance.Exponent,
// 		EncodedECPoint:     instance.EcPoint,
// 		EncodedECParams:    instance.EcParams,
// 		AutoRotateDuration: instance.AutoRotateDuration,
// 	}
// 	return deprecated_instance, nil
// }

// Deprecated: Use KK_GetSecret(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) GetSecret(slotId uint32, sessionToken string, secretId string) (*dep_kkresp.APIResponse_GetSecret, error) {
	instance, err := x.KK_GetSecret(slotId, sessionToken, secretId)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_GetSecret{
		SecretId:    instance.SecretId,
		SecretLabel: instance.SecretLabel,
		SecretData:  instance.SecretData,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_FileEncrypt(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) FileEncrypt(slotId uint32, sessionToken string, keyId string, plaintextInputFilePath string, ciphertextOutputFilePath string) (*dep_kkresp.APIResponse_FileEncrypt, error) {
	instance, err := x.KK_FileEncrypt(slotId, sessionToken, keyId, plaintextInputFilePath, ciphertextOutputFilePath)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_FileEncrypt{
		KeyVersion: instance.KeyVersion,
		Iv:         instance.Iv,
		Tag:        instance.Tag,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_FileDecrypt_WithoutIntegrity(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) FileDecryptWithoutIntegrity(slotId uint32, sessionToken string, keyId string, keyVersion uint32, iv []byte, ciphertextInputFilePath string, plaintextOutputFilePath string) error {
	return x.KK_FileDecrypt_WithoutIntegrity(slotId, sessionToken, keyId, keyVersion, iv, ciphertextInputFilePath, plaintextOutputFilePath)
}

// Deprecated: Use KK_FileDecrypt_WithIntegrity(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) FileDecryptWithIntegrity(slotId uint32, sessionToken string, keyId string, keyVersion uint32, iv []byte, tag []byte, ciphertextInputFilePath string, plaintextOutputFilePath string) error {
	return x.KK_FileDecrypt_WithIntegrity(slotId, sessionToken, keyId, keyVersion, iv, tag, ciphertextInputFilePath, plaintextOutputFilePath)
}

// Deprecated: Use KK_FileGenerateHMAC(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) FileGenerateHMAC(slotId uint32, sessionToken string, keyId string, inputFilePath string) (*dep_kkresp.APIResponse_FileGenerateHMAC, error) {
	instance, err := x.KK_FileGenerateHMAC(slotId, sessionToken, keyId, inputFilePath)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_FileGenerateHMAC{
		Tag: instance.Tag,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_FileVerifyHMAC(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) FileVerifyHMAC(slotId uint32, sessionToken string, keyId string, inputFilePath string, tag []byte) (*dep_kkresp.APIResponse_FileVerifyHMAC, error) {
	instance, err := x.KK_FileVerifyHMAC(slotId, sessionToken, keyId, inputFilePath, tag)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_FileVerifyHMAC{
		Verified: instance.Verified,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_GenerateAppstoredKeypair(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) GenerateExternalKeypair(slotId uint32, sessionToken string, wrappingMethod string, externalPublicKeyorWrappingKeyId string, keyAlgo string, keyLength *uint32, withCert bool) (*dep_kkresp.APIResponse_GenerateKeypair, error) {
	instance, err := x.KK_GenerateAppstoredKeypair(slotId, sessionToken, wrappingMethod, externalPublicKeyorWrappingKeyId, "", keyAlgo, keyLength, withCert)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_GenerateKeypair{
		EncryptedKey:           instance.WrappedPrivateKey,
		PublicKeyOrCertificate: instance.PublicKeyOrCert,
		ZipPassword:            instance.ZipPassword,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_GenerateAppstoredKey_AES(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) GenerateExternalKey(slotId uint32, sessionToken string, wrappingMethod string, internalWrappingKeyId string, externalPublicKey string, keyLength uint32) (*dep_kkresp.APIResponse_GenerateKey, error) {
	instance, err := x.KK_GenerateAppstoredKey_AES(slotId, sessionToken, wrappingMethod, internalWrappingKeyId, externalPublicKey, keyLength)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_GenerateKey{
		EncryptedKey:            instance.WrappedKey,
		ZipPassword:             instance.ZipPassword,
		WrappedKeyByExternalKey: instance.WrappedKeyByAppstoredKey,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_AppstoredGenerateMAC(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) ExternalGenerateMAC(slotId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, hashAlgo string, data string) (*dep_kkresp.APIResponse_ExternalGenerateMAC, error) {
	instance, err := x.KK_AppstoredGenerateMAC(slotId, sessionToken, wrappingKeyId, wrappedKey, hashAlgo, data)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_ExternalGenerateMAC{
		Mac: instance.Mac,
		Iv:  instance.Iv,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_AppstoredVerifyMAC(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) ExternalVerifyMAC(slotId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, hashAlgo string, data string, mac string, iv *string) (*dep_kkresp.APIResponse_ExternalVerifyMAC, error) {
	instance, err := x.KK_AppstoredVerifyMAC(slotId, sessionToken, wrappingKeyId, wrappedKey, hashAlgo, data, mac, iv)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_ExternalVerifyMAC{
		Verified: instance.Verified.GetValue(),
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_AppstoredEncrypt_AES(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) ExternalEncryptAES(slotId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, encryptRequest *dep_kkreq.APIRequest_Encrypt) (*dep_kkresp.APIResponse_ExternalEncrypt, error) {
	single_request := make([]*kkreq.APIRequestSingleEncrypt, len(encryptRequest.Plaintext))
	for i, el := range encryptRequest.Plaintext {
		single_request[i] = &kkreq.APIRequestSingleEncrypt{
			Text: wrapperspb.String(el.Plaintext),
			Aad:  el.Aad,
		}
	}

	instance, err := x.KK_AppstoredEncrypt_AES(slotId, sessionToken, wrappingKeyId, wrappedKey, single_request)
	if err != nil {
		return nil, err
	}

	single_response := make([]*dep_kkresp.APIResponse_SingleEncrypt, len(instance.Ciphertext))
	for i, el := range instance.Ciphertext {
		single_response[i] = &dep_kkresp.APIResponse_SingleEncrypt{
			Ciphertext:        el.Text,
			Mac:               el.Mac,
			Iv:                el.Iv,
			WrappedSessionKey: el.WrappedSessionKey,
		}
	}

	deprecated_instance := &dep_kkresp.APIResponse_ExternalEncrypt{
		Ciphertext: single_response,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_AppstoredEncrypt_RSA(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) ExternalEncryptRSA(slotId uint32, sessionToken string, publicKeyOrCert string, useSessionKey bool, encryptRequest *dep_kkreq.APIRequest_Encrypt) (*dep_kkresp.APIResponse_ExternalEncrypt, error) {
	single_request := make([]*kkreq.APIRequestSingleEncrypt, len(encryptRequest.Plaintext))
	for i, el := range encryptRequest.Plaintext {
		single_request[i] = &kkreq.APIRequestSingleEncrypt{
			Text: wrapperspb.String(el.Plaintext),
			Aad:  el.Aad,
		}
	}

	instance, err := x.KK_AppstoredEncrypt_RSA(slotId, sessionToken, publicKeyOrCert, useSessionKey, single_request)
	if err != nil {
		return nil, err
	}

	single_response := make([]*dep_kkresp.APIResponse_SingleEncrypt, len(instance.Ciphertext))
	for i, el := range instance.Ciphertext {
		single_response[i] = &dep_kkresp.APIResponse_SingleEncrypt{
			Ciphertext:        el.Text,
			Mac:               el.Mac,
			Iv:                el.Iv,
			WrappedSessionKey: el.WrappedSessionKey,
		}
	}

	deprecated_instance := &dep_kkresp.APIResponse_ExternalEncrypt{
		Ciphertext: single_response,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_AppstoredDecrypt(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) ExternalDecrypt(slotId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, decryptRequest *dep_kkreq.APIRequest_ExternalDecrypt) (*dep_kkresp.APIResponse_ExternalDecrypt, error) {
	single_request := make([]*kkreq.APIRequestSingleAppstoredDecrypt, len(decryptRequest.Ciphertext))
	for i, el := range decryptRequest.Ciphertext {
		single_request[i] = &kkreq.APIRequestSingleAppstoredDecrypt{
			Text:              wrapperspb.String(el.Ciphertext),
			Aad:               el.Aad,
			Iv:                el.Iv,
			Mac:               el.Mac,
			WrappedSessionKey: el.WrappedSessionKey,
		}
	}

	instance, err := x.KK_AppstoredDecrypt(slotId, sessionToken, wrappingKeyId, wrappedKey, single_request)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_ExternalDecrypt{
		Plaintext: instance.Plaintext,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_AppstoredSeal_AES(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) ExternalSealAES(slotId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, plaintext []string) (*dep_kkresp.APIResponse_ExternalSeal, error) {
	instance, err := x.KK_AppstoredSeal_AES(slotId, sessionToken, wrappingKeyId, wrappedKey, plaintext)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_ExternalSeal{
		Ciphertext: instance.Ciphertext,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_AppstoredSeal_RSA(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) ExternalSealRSA(slotId uint32, sessionToken string, publicKeyOrCert string, plaintext []string) (*dep_kkresp.APIResponse_ExternalSeal, error) {
	instance, err := x.KK_AppstoredSeal_RSA(slotId, sessionToken, publicKeyOrCert, plaintext)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_ExternalSeal{
		Ciphertext: instance.Ciphertext,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_AppstoredUnseal(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) ExternalUnseal(slotId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, ciphertext []string) (*dep_kkresp.APIResponse_ExternalUnseal, error) {
	instance, err := x.KK_AppstoredUnseal(slotId, sessionToken, wrappingKeyId, wrappedKey, ciphertext)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_ExternalUnseal{
		Plaintext: instance.Plaintext,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_AppstoredTokenize(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) ExternalTokenize(slotId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, tokenizeRequest *dep_kkreq.APIRequest_Tokenize) (*dep_kkresp.APIResponse_ExternalTokenize, error) {
	single_request := make([]*kkreq.APIRequestSingleTokenize, len(tokenizeRequest.Text))
	for i, el := range tokenizeRequest.Text {
		single_request[i] = &kkreq.APIRequestSingleTokenize{
			Usv:        wrapperspb.String(el.Text),
			FormatChar: wrapperspb.String(el.FormatChar),
			TokenizedWith: wrapperspb.String(func() string {
				switch tw := el.TokenizedWith; tw {
				case dep_kkreq.TokenizeType_CIPHER:
					return "cipher"
				case dep_kkreq.TokenizeType_MASKING:
					return "masking"
				case dep_kkreq.TokenizeType_ALPHA:
					return "alpha"
				case dep_kkreq.TokenizeType_NUMERIC:
					return "num"
				case dep_kkreq.TokenizeType_ALPHA_NUMERIC:
					return "alphanum"
				}
				return ""
			}()),
		}
	}

	instance, err := x.KK_AppstoredTokenize(slotId, sessionToken, wrappingKeyId, wrappedKey, single_request)
	if err != nil {
		return nil, err
	}

	single_response := make([]*dep_kkresp.APIResponse_SingleTokenize, len(instance.Ciphertext))
	for i, el := range instance.Ciphertext {
		single_response[i] = &dep_kkresp.APIResponse_SingleTokenize{
			Token:    el.Token,
			Metadata: el.Metadata,
		}
	}

	deprecated_instance := &dep_kkresp.APIResponse_ExternalTokenize{
		Ciphertext: single_response,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_AppstoredDetokenize(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) ExternalDetokenize(slotId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, detokenizeRequest *dep_kkreq.APIRequest_Detokenize) (*dep_kkresp.APIResponse_ExternalDetokenize, error) {
	single_request := make([]*kkreq.APIRequestSingleDetokenize, len(detokenizeRequest.Token))
	for i, el := range detokenizeRequest.Token {
		single_request[i] = &kkreq.APIRequestSingleDetokenize{
			Token:    wrapperspb.String(el.Token),
			Metadata: wrapperspb.String(el.Metadata),
		}
	}

	instance, err := x.KK_AppstoredDetokenize(slotId, sessionToken, wrappingKeyId, wrappedKey, single_request)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_ExternalDetokenize{
		Plaintext: instance.Usv,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_AppstoredSignData(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) ExternalSignData(slotId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, hashAlgo string, data string) (*dep_kkresp.APIResponse_ExternalSign, error) {
	instance, err := x.KK_AppstoredSignData(slotId, sessionToken, wrappingKeyId, wrappedKey, hashAlgo, data)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_ExternalSign{
		Signature: instance.Signature,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_AppstoredSignDigest(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) ExternalSignDigest(slotId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, inputType string, data string) (*dep_kkresp.APIResponse_ExternalSign, error) {
	instance, err := x.KK_AppstoredSignDigest(slotId, sessionToken, wrappingKeyId, wrappedKey, inputType, data)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_ExternalSign{
		Signature: instance.Signature,
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_AppstoredVerifyData(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) ExternalVerifyData(slotId uint32, sessionToken string, publicKeyOrCert string, hashAlgo string, data string, signature string) (*dep_kkresp.APIResponse_ExternalVerify, error) {
	instance, err := x.KK_AppstoredVerifyData(slotId, sessionToken, publicKeyOrCert, hashAlgo, data, signature)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_ExternalVerify{
		Verified: instance.Verified.GetValue(),
	}
	return deprecated_instance, nil
}

// Deprecated: Use KK_AppstoredVerifyDigest(...) instead for KriptaKey v24.1 compatibility
func (x *ConnectionHandler) ExternalVerifyDigest(slotId uint32, sessionToken string, publicKeyOrCert string, inputType string, data string, signature string) (*dep_kkresp.APIResponse_ExternalVerify, error) {
	instance, err := x.KK_AppstoredVerifyDigest(slotId, sessionToken, publicKeyOrCert, inputType, data, signature)
	if err != nil {
		return nil, err
	}

	deprecated_instance := &dep_kkresp.APIResponse_ExternalVerify{
		Verified: instance.Verified.GetValue(),
	}
	return deprecated_instance, nil
}
