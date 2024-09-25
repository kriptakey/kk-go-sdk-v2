/*
# Introduction

This SDK is designed to help developers integrate Kripta Key into their Go applications quickly and efficiently. Whether you are building a web application or a desktop software, this SDK provides the tools and resources you need to interact with the Kripta Key API.

# Key Features

  - Easy Integration: Kripta Key Go package offers a straightforward integration process with clear and concise APIs.
  - Authentication: Learn how to authenticate your application with Kripta Key securely.
  - API Endpoints: Explore the available API endpoints and their functionalities.
  - Error Handling: Understand how to handle errors and exceptions gracefully.
  - Code Samples: Find code samples and examples to help you get started quickly.

# Support and Resources

If you encounter any issues, have questions, or need further assistance, please don't hesitate to reach out to our support team or consult the following resources:

Contact our support@klaviskripta.com
This SDK is distributed under the terms of the Klavis Kripta License.
*/
package kriptakey

/*
#cgo pkg-config: KK-NativeSDK
#include <kriptakey/api.h>

int32_t kk_gosdk_assign(void const*, int32_t, void*);
*/
import "C"
import (
	"runtime"
	"unsafe"

	kkreq "github.com/kriptakey/kk-go-sdk-v24.1/kriptakey/api/request"
	kkresp "github.com/kriptakey/kk-go-sdk-v24.1/kriptakey/api/response"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type ConnectionHandler struct {
	handler *C.KK_OpaqueConnectionHandlerPtr
}

// The API to get the version of SDK.
//
// Return the string contain the full version of SDK.
func GetSDKVersion() string {
	c_version := C.kk_nativesdk_getVersion()
	return C.GoString(c_version)
}

func baseInitializeConnection(request *kkreq.SDKRequestConnection) (*ConnectionHandler, error) {
	instance := &ConnectionHandler{
		handler: new(C.KK_OpaqueConnectionHandlerPtr),
	}

	serialized_request, err := proto.Marshal(request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_initializeConnection((*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), instance.handler)
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	runtime.SetFinalizer(instance, func(connection *ConnectionHandler) {
		defer C.kk_nativesdk_freeConnection(*connection.handler)
	})

	return instance, nil
}

// Convenient utility to create connection handler.
//
//   - param host: 					the server host address.
//   - param port: 					the server port.
//   - param clientCertificatePath: the client certificate path used to establish connection with server.
//   - param privateKeyPath: 		the client private key path used to establish connection with server.
//
// Return [api.go.ConnectionHandler] if success and error if failed.
func KK_InitializeConnection(host string, port uint16, clientCertificatePath string, privateKeyPath string) (*ConnectionHandler, error) {
	request := kkreq.SDKRequestConnection{
		Host: host,
		Port: int32(port),
		ClientCertificateObject: &kkreq.SDKRequestConnection_ClientCertificatePath{
			ClientCertificatePath: clientCertificatePath,
		},
		PrivateKeyObject: &kkreq.SDKRequestConnection_PrivateKeyPath{
			PrivateKeyPath: privateKeyPath,
		},
	}
	return baseInitializeConnection(&request)
}

// Convenient utility to create connection handler.
//
//   - param host: 						the server host address.
//   - param port: 						the server port.
//   - param clientCertificateBuffer:	the client certificate PEM used to establish connection with server.
//   - param privateKeyBuffer: 			the client private key PEM used to establish connection with server.
//
// Return [api.go.ConnectionHandler] if success and error if failed.
func KK_InitializeConnectionUsingPEMBuffer(host string, port uint16, clientCertificateBuffer string, privateKeyBuffer string) (*ConnectionHandler, error) {
	request := kkreq.SDKRequestConnection{
		Host: host,
		Port: int32(port),
		ClientCertificateObject: &kkreq.SDKRequestConnection_ClientCertificatePEM{
			ClientCertificatePEM: clientCertificateBuffer,
		},
		PrivateKeyObject: &kkreq.SDKRequestConnection_PrivateKeyPEM{
			PrivateKeyPEM: privateKeyBuffer,
		},
	}
	return baseInitializeConnection(&request)
}

// Authenticate the application and get session token for calling other API.
//
//   - param partitionId: 	partition ID where the key is located.
//   - param password: 		password of the partition.
//
// Return `APIResponseLogin` contains session token and other attributes such as idle timeout and expired time.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_AppAuthenticate(partitionId uint32, password string) (*kkresp.APIResponseLogin, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestLogin{
		PartitionId: wrapperspb.UInt32(partitionId),
		Password:    wrapperspb.String(password),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_appAuthenticate(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseLogin{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Refresh the session to get a new session token before the session expires.
// By renewing the session before it expires, the application will avoid requiring a re-login.
//
//   - param partitionId: 	partition ID where the key is located.
//   - param sessionToken: 	session token from [api.go.KK_AppAuthenticate].
//
// Return `APIResponseRefreshSession` contains session token and other attributes such as idle timeout and expired time.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_AppRefresh(partitionId uint32, sessionToken string) (*kkresp.APIResponseRefreshSession, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestRefreshSession{
		PartitionId:  wrapperspb.UInt32(partitionId),
		SessionToken: wrapperspb.String(sessionToken),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_appRefresh(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseRefreshSession{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Produce random byte values in accordance with the specified length.
//
//   - param partitionId: 	partition ID where the key is located.
//   - param sessionToken: 	session token from [api.go.KK_AppAuthenticate].
//   - param length: 		output length.
//
// Return the `APIResponseRNG` contains the sequence of random number.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_GenerateRandomNumber(partitionId uint32, sessionToken string, length uint32) (*kkresp.APIResponseRNG, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestRNG{
		PartitionId:  wrapperspb.UInt32(partitionId),
		SessionToken: wrapperspb.String(sessionToken),
		Length:       wrapperspb.UInt32(length),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_generateRandomNumber(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseRNG{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Generate Message Authentication Code (MAC) for specific data using a key stored in Kripta Key.
// Ensure that the key purpose is set to MACGeneration.
//
//   - param partitionId: 	partition ID where the key is located.
//   - param sessionToken: 	session token from [api.go.KK_AppAuthenticate].
//   - param keyId: 		key ID associated with the key used for MAC generation.
//   - param hashAlgo:	    hash algorihm of MAC. Available list: CMAC, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512, GMAC-256.
//   - param data:	        the data for which the MAC will be generated.
//
// Return the `APIResponseGenerateMAC` contains the multiple value MAC and IV (if using GMAC).
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_GenerateMAC(partitionId uint32, sessionToken string, keyId string, hashAlgo string, data []string) (*kkresp.APIResponseGenerateMAC, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestGenerateMAC{
		PartitionId:  wrapperspb.UInt32(partitionId),
		SessionToken: wrapperspb.String(sessionToken),
		KeyId:        wrapperspb.String(keyId),
		HashAlgo:     wrapperspb.String(hashAlgo),
		Data:         data,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_generateMAC(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseGenerateMAC{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Verify Message Authentication Code (MAC) of a data using key stored in Kripta Key.
//
//   - param partitionId:  	partition ID where the key is located.
//   - param sessionToken:	session token from [api.go.KK_AppAuthenticate].
//   - param keyId:	        key ID associated with the key used for MAC generation.
//   - param hashAlgo:	    hash algorihm of MAC. Available list: CMAC, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512, GMAC-256.
//   - param data:	        the data for which the MAC will be verified.
//
// Return the Generate MAC Result. contains the MAC of data and IV if using GMAC.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_VerifyMAC(partitionId uint32, sessionToken string, keyId string, hashAlgo string, data []*kkreq.SingleVerifyMAC) (*kkresp.APIResponseVerifyMAC, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestVerifyMAC{
		PartitionId:  wrapperspb.UInt32(partitionId),
		SessionToken: wrapperspb.String(sessionToken),
		KeyId:        wrapperspb.String(keyId),
		HashAlgo:     wrapperspb.String(hashAlgo),
		Data:         data,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_verifyMAC(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseVerifyMAC{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Encrypt multiple plaintexts using AES-256-GCM key.
// KMS will use the latest key version to encrypt plaintext.
//
//   - param partitionId:	partition ID where the key is located.
//   - param sessionToken:	session token from [api.go.KK_AppAuthenticate].
//   - param keyId:	        key ID associated with the key used to encrypt data with Encryption purpose.
//   - param plaintext:	    the `APIRequestSingleEncrypt` contains the plaintext value and additional authentication data (AAD).
//
// Return the `APIResponseEncrypt` contains ciphertext and attributes such as key version, MAC and IV.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_Encrypt_AES(partitionId uint32, sessionToken string, keyId string, plaintext []*kkreq.APIRequestSingleEncrypt) (*kkresp.APIResponseEncrypt, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestEncrypt{
		PartitionId:  wrapperspb.UInt32(partitionId),
		SessionToken: wrapperspb.String(sessionToken),
		KeyId:        wrapperspb.String(keyId),
		Plaintext:    plaintext,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_encrypt(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseEncrypt{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Encrypt multiple plaintexts using RSA key.
// Encrypting with the RSA key can occur either directly or through a session key.
//
// Encryption with session key is suitable for larger datasets.
//
//   - param partitionId:		partition ID where the key is located.
//   - param sessionToken:		session token from [api.go.KK_AppAuthenticate].
//   - param keyId:			    key ID associated with the key used to encrypt data with Encryption purpose.
//   - param plaintext:		    the `APIRequestSingleEncrypt` contains the plaintext value only.
//   - param useSessionKey:		the option to encrypt larger datasets with asymmetric key and session key.
//
// Return the `APIResponseEncrypt` contains ciphertext and attributes such MAC, IV and wrappedSessionKey (if useSessionKey is set to true).
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_Encrypt_RSA(partitionId uint32, sessionToken string, keyId string, useSessionKey bool, plaintext []*kkreq.APIRequestSingleEncrypt) (*kkresp.APIResponseEncrypt, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestEncrypt{
		PartitionId:   wrapperspb.UInt32(partitionId),
		SessionToken:  wrapperspb.String(sessionToken),
		KeyId:         wrapperspb.String(keyId),
		Plaintext:     plaintext,
		UseSessionKey: wrapperspb.Bool(useSessionKey),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_encrypt(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseEncrypt{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Decrypt multiple ciphertexts using specific key ID (AES-256-GCM or RSA) without metadata.
// For decryption with symmetric key, KMS will use the key version supplied in the ciphertext for decrypting the ciphertext value.
//
//   - param partitionId:	partition ID where the key is located.
//   - param sessionToken:	session token from [api.go.KK_AppAuthenticate].
//   - param ciphertext:	the array ciphertext value and ciphertext params `APIRequestSingleDecrypt`.
//
// Return the `APIResponseDecrypt` contains plaintext.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_Decrypt(partitionId uint32, sessionToken string, ciphertext []*kkreq.APIRequestSingleDecrypt) (*kkresp.APIResponseDecrypt, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestDecrypt{
		PartitionId:  wrapperspb.UInt32(partitionId),
		SessionToken: wrapperspb.String(sessionToken),
		Ciphertext:   ciphertext,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_decrypt(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseDecrypt{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Reencrypt the information held within an DecryptionRequest instance.
// Reencrypt an encrypted text using AES-256-GCM key or RSA key.
//
//   - param partitionId:		partition ID where the key is located.
//   - param sessionToken:		session token from [api.go.KK_AppAuthenticate].
//   - param sourceKeyId:		key ID used to encrypt the original plaintext.
//   - param destinationKeyId:	key ID used to reencrypt the ciphertext.
//   - param ciphertext:		the array of ciphertext value and ciphertext params `APIRequestSingleReEncrypt`.
//
// Return the `APIResponseEncrypt` contains plaintext and optional keyVersion.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_Reencrypt(partitionId uint32, sessionToken string, sourceKeyId string, destinationKeyId string, ciphertext []*kkreq.APIRequestSingleReEncrypt) (*kkresp.APIResponseEncrypt, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestReEncrypt{
		PartitionId:      wrapperspb.UInt32(partitionId),
		SessionToken:     wrapperspb.String(sessionToken),
		SourceKeyId:      wrapperspb.String(sourceKeyId),
		DestinationKeyId: wrapperspb.String(destinationKeyId),
		Ciphertext:       ciphertext,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_reencrypt(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseEncrypt{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Encrypt multiple plaintexts with metadata using AES-256-GCM key or RSA with session key.
//
//   - param partitionId:	partition ID where the key is located.
//   - param sessionToken: 	session token from [api.go.KK_AppAuthenticate].
//   - param keyId:			key ID associated with the key used for sealing data with Encryption purpose.
//   - param plaintext:		array of plaintexts to be sealed.
//
// Return the `APIResponseSeal` contains ciphertext.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_Seal(partitionId uint32, sessionToken string, keyId string, plaintext []string) (*kkresp.APIResponseSeal, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestSeal{
		PartitionId:  wrapperspb.UInt32(partitionId),
		SessionToken: wrapperspb.String(sessionToken),
		KeyId:        wrapperspb.String(keyId),
		Plaintext:    plaintext,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_seal(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseSeal{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Decrypt multiple ciphertexts using AES-256-GCM key or RSA with session key.
// Each ciphertext already contains metadata.
//
//   - param partitionId:	partition ID where the key is located.
//   - param sessionToken:	session token from [api.go.KK_AppAuthenticate].
//   - param ciphertext:	array of ciphertext values.
//
// Return the `APIResponseUnseal` contains plaintext values.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_Unseal(partitionId uint32, sessionToken string, ciphertext []string) (*kkresp.APIResponseUnseal, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestUnseal{
		PartitionId:  wrapperspb.UInt32(partitionId),
		SessionToken: wrapperspb.String(sessionToken),
		Ciphertext:   ciphertext,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_unseal(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseUnseal{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Tokenize multiple plaintext using last key version of AES-256-GCM key with encryption purpose by preserving its format and length.
//
//   - param partitionId:	partition ID where the key is located.
//   - param sessionToken:	session token from [api.go.KK_AppAuthenticate].
//   - param keyId:			key ID associated with the key used to encrypt data.
//   - param usv:			the `APIRequestSingleTokenize` contains the tokenization plaintext, format and tokenization type. Available list of tokenization types: cipher, alpha, num, alphanum, masking.
//
// Return the `APIResponseTokenize` contains the tokenized value and metadata.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_Tokenize(partitionId uint32, sessionToken string, keyId string, usv []*kkreq.APIRequestSingleTokenize) (*kkresp.APIResponseTokenize, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestTokenize{
		PartitionId:  wrapperspb.UInt32(partitionId),
		SessionToken: wrapperspb.String(sessionToken),
		KeyId:        wrapperspb.String(keyId),
		Plaintext:    usv,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_tokenize(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseTokenize{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Detokenize multiple ciphertexts (tokens) using specific version of AES-256-GCM key with encryption purpose.
// The version of the key is preserved in the metadata.
//
//   - param partitionId:	partition ID where the key is located.
//   - param sessionToken:	session token from [api.go.KK_AppAuthenticate].
//   - param ciphertext:	the `APIRequestSingleDetokenize` contains the tokenized values.
//
// Return the `APIResponseDetokenize` contains the detokenized values.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_Detokenize(partitionId uint32, sessionToken string, ciphertext []*kkreq.APIRequestSingleDetokenize) (*kkresp.APIResponseDetokenize, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestDetokenize{
		PartitionId:  wrapperspb.UInt32(partitionId),
		SessionToken: wrapperspb.String(sessionToken),
		Ciphertext:   ciphertext,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_detokenize(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseDetokenize{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Sign a data using asymmetric key with signing purpose and return a digital signature.
//
//   - param partitionId:		partition ID where the key is located.
//   - param sessionToken:		session token from [api.go.KK_AppAuthenticate].
//   - param keyId:				key ID associated with the key used for signing data.
//   - param data:				raw data to be signed.
//   - param hashAlgo:       	the hash algorithm for signing. Available list: SHA256, SHA384, SHA512
//   - param signatureScheme:	the signature scheme that will be used to sign the data. Available list: RSASSA-PKCS1-v1_5, RSASSA-PSS, ECDSA, EdDSA
//
// Return the `APIResponseSign` contains the signature value.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_SignData(partitionId uint32, sessionToken string, keyId string, hashAlgo string, signatureScheme string, data string) (*kkresp.APIResponseSign, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestSign{
		PartitionId:     wrapperspb.UInt32(partitionId),
		SessionToken:    wrapperspb.String(sessionToken),
		KeyId:           wrapperspb.String(keyId),
		InputType:       wrapperspb.String("raw"),
		HashAlgo:        wrapperspb.String(hashAlgo),
		SignatureScheme: wrapperspb.String(signatureScheme),
		Data:            wrapperspb.String(data),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_sign(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseSign{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Sign a data using asymmetric key with signing purpose and return a digital signature.
//
//   - param partitionId:		partition ID where the key is located.
//   - param sessionToken:		session token from [api.go.KK_AppAuthenticate].
//   - param keyId:				key ID associated with the key used for signing data.
//   - param digest:			digest to be signed. The data must be base64 encoded from digest.
//   - param inputType:      	type of data. Available list: raw, sha256Hashed, sha384Hashed, sha512Hashed.
//   - param signatureScheme:	the signature scheme that will be used to sign the data. Available list: RSASSA-PKCS1-v1_5, RSASSA-PSS, ECDSA, EdDSA.
//
// Return the `APIResponseSign` contains the signature value.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_SignDigest(partitionId uint32, sessionToken string, keyId string, inputType string, signatureScheme string, digest string) (*kkresp.APIResponseSign, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestSign{
		PartitionId:     wrapperspb.UInt32(partitionId),
		SessionToken:    wrapperspb.String(sessionToken),
		KeyId:           wrapperspb.String(keyId),
		InputType:       wrapperspb.String(inputType),
		SignatureScheme: wrapperspb.String(signatureScheme),
		Data:            wrapperspb.String(digest),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_sign(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseSign{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// The API to verify the digital signature of a data with internal keyId.
// The data and signature must be supplied for verification.
//
//   - param partitionId:		partition ID where the key is located.
//   - param sessionToken:		session token from [api.go.KK_AppAuthenticate].
//   - param keyId:				key ID associated with the key used for signing data.
//   - param data:				raw data to be verified.
//   - param signature:			generated signature in Base64.
//   - param hashAlgo:			digest function used to generate digital signature. Available list: SHA256, SHA384, SHA512.
//   - param signatureScheme:	signature scheme that will be used to verify the data. Available list: RSASSA-PKCS1-v1_5, RSASSA-PSS, ECDSA, EdDSA.
//
// Return the `APIResponseVerify` contains the verification result.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_VerifyData(partitionId uint32, sessionToken string, keyId string, hashAlgo string, signatureScheme string, data string, signature string) (*kkresp.APIResponseVerify, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestVerify{
		PartitionId:     wrapperspb.UInt32(partitionId),
		SessionToken:    wrapperspb.String(sessionToken),
		KeyId:           wrapperspb.String(keyId),
		InputType:       wrapperspb.String("raw"),
		HashAlgo:        wrapperspb.String(hashAlgo),
		SignatureScheme: wrapperspb.String(signatureScheme),
		Data:            wrapperspb.String(data),
		Signature:       wrapperspb.String(signature),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_verify(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseVerify{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// The API to verify the digital signature of a data with internal keyId.
// The data and signature must be supplied for verification.
//
//   - param partitionId:		partition ID where the key is located.
//   - param sessionToken:		session token from [api.go.KK_AppAuthenticate].
//   - param keyId:				key ID associated with the key used for signing data.
//   - param digest:			digest to be verified.The digest must be base64 encoded.
//   - param signature:			generated signature in Base64.
//   - param inputType:			type of data. Available list: raw, sha256Hashed, sha384Hashed, sha512Hashed.
//   - param signatureScheme:	signature scheme that will be used to verify the data. Available list: RSASSA-PKCS1-v1_5, RSASSA-PSS, ECDSA, EdDSA.
//
// Return the `APIResponseVerify` contains the verification result.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_VerifyDigest(partitionId uint32, sessionToken string, keyId string, inputType string, signatureScheme string, digest string, signature string) (*kkresp.APIResponseVerify, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestVerify{
		PartitionId:     wrapperspb.UInt32(partitionId),
		SessionToken:    wrapperspb.String(sessionToken),
		KeyId:           wrapperspb.String(keyId),
		InputType:       wrapperspb.String(inputType),
		SignatureScheme: wrapperspb.String(signatureScheme),
		Data:            wrapperspb.String(digest),
		Signature:       wrapperspb.String(signature),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_verify(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseVerify{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Digitally sign a CSR and provide a signed certificate in return.<br>
//
//   - param partitionId:	partition ID where the key is located.
//   - param sessionToken:	session token from [api.go.KK_AppAuthenticate].
//   - param validityPeriod:	validity period for signed certificate. Maximal period is 1825 (5 years).
//   - param keyId:			ID of Certificate Signing Key stored in Kripta Key. The key must be associated with a self-signed certificate.
//   - param csr:			the Certificate Signing Request in PEM (Privacy Enhanced Mail) format.
//   - param hashAlgo: 		digest function used to generate digital signature. Available list: SHA256, SHA384, SHA512.
//
// Return the `APIResponseCertificateSign` contains digitally signed certificate.
// Or return error if the request parameters are incorrect.
func (x *ConnectionHandler) KK_SignCertificate(partitionId uint32, sessionToken string, keyId string, validityPeriod uint32, hashAlgo string, csr string) (*kkresp.APIResponseCertificateSign, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestCertificateSign{
		PartitionId:    wrapperspb.UInt32(partitionId),
		SessionToken:   wrapperspb.String(sessionToken),
		KeyId:          wrapperspb.String(keyId),
		ValidityPeriod: wrapperspb.UInt32(validityPeriod),
		HashAlgo:       wrapperspb.String(hashAlgo),
		Csr:            wrapperspb.String(csr),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_signCertificate(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseCertificateSign{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Verify a digitally signed certificate with Certificate Signing Key stored in Kripta Key.
//
//   - param partitionId:	partition ID where the key is located.
//   - param sessionToken:	session token from [api.go.KK_AppAuthenticate].
//   - param keyId:			ID of Certificate Signing Key stored in Kripta Key. The key must be associated to a certificate.
//   - param certificate:	digitally signed certificate in PEM format.
//
// Return the `APIResponseCertificateVerify` contains the verification result.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_VerifyCertificate(partitionId uint32, sessionToken string, keyId string, certificate string) (*kkresp.APIResponseCertificateVerify, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestCertificateVerify{
		PartitionId:  wrapperspb.UInt32(partitionId),
		SessionToken: wrapperspb.String(sessionToken),
		KeyId:        wrapperspb.String(keyId),
		Certificate:  wrapperspb.String(certificate),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_verifyCertificate(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseCertificateVerify{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Retrieve key info from Kripta Key. The key is added via CLIKK command line.
// The key is centrally stored and protected in Kripta Key.
//
//   - param partitionId:	partition ID where the key is located.
//   - param sessionToken:	session token from [api.go.KK_AppAuthenticate].
//   - param keyId:			the ID of a key stored in Kripta Key.
//   - param keyVersion:	the version of a key stored in Kripta Key. This parameter is optional. If it is not passed, the system will automatically use the last version.
//
// Return the `APIResponseKeyInfo` contains the key info result.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_GetKeyInfo(partitionId uint32, sessionToken string, keyId string, keyVersion *uint32) (*kkresp.APIResponseKeyInfo, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestKeyInfo{
		PartitionId:  wrapperspb.UInt32(partitionId),
		SessionToken: wrapperspb.String(sessionToken),
		KeyId:        wrapperspb.String(keyId),
		KeyVersion: func() *wrapperspb.UInt32Value {
			if keyVersion != nil {
				return wrapperspb.UInt32(*keyVersion)
			}
			return nil
		}(),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_getKeyInfo(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseKeyInfo{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Retrieve the secret from Kripta Key such as password and connection string.
// The secret is added via CLIKK command line. The secret is centrally stored and protected in Kripta Key.
//
//   - param partitionId:	partition ID where the key is located.
//   - param sessionToken:	session token from [api.go.KK_AppAuthenticate].
//   - param secretId:		the ID of a secret stored in Kripta Key.
//
// Return the `APIResponseGetSecret` contains the secret value.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_GetSecret(partitionId uint32, sessionToken string, secretId string) (*kkresp.APIResponseGetSecret, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestGetSecret{
		PartitionId:  wrapperspb.UInt32(partitionId),
		SessionToken: wrapperspb.String(sessionToken),
		SecretId:     wrapperspb.String(secretId),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_getSecret(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseGetSecret{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Securely encrypt a file from the provided path and subsequently save the ciphertext to the specified output path.
//
//   - param partitionId:				partition ID where the key is located.
//   - param sessionToken:				session token from [api.go.KK_AppAuthenticate].
//   - param keyId:						key ID associated with the key used to encrypt data.
//   - param plaintextInputFilePath:		the input file path.
//   - param ciphertextOutputFilePath: 	the output file path where the ciphertext to be produced.
//
// Return the `SDKResponseMultipartEncrypt` contains ciphertext and attributes such as MAC, IV and key version.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_FileEncrypt(partitionId uint32, sessionToken string, keyId string, plaintextInputFilePath string, ciphertextOutputFilePath string) (*kkresp.SDKResponseMultipartEncrypt, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.SDKRequestMultipartEncrypt{
		PartitionId:          wrapperspb.UInt32(partitionId),
		SessionToken:         wrapperspb.String(sessionToken),
		KeyId:                wrapperspb.String(keyId),
		PlaintextInputFile:   wrapperspb.String(plaintextInputFilePath),
		CiphertextOutputFile: wrapperspb.String(ciphertextOutputFilePath),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_fileEncrypt(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.SDKResponseMultipartEncrypt{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Decrypt a file from the provided path and subsequently save the plaintext to the specified output path.
//
//   - param partitionId:				partition ID where the key is located.
//   - param sessionToken:				session token from [api.go.KK_AppAuthenticate].
//   - param keyId:						key ID associated with the key used to encrypt data with Encryption purpose.
//   - param keyVersion:				version of key used to encrypt.
//   - param iv:						initialization vector to decrypt the input file.
//   - param ciphertextInputFilePath:	input file path contains ciphertext.
//   - param plaintextOutputFilePath:	output file path where the plaintext to be produced.
//
// Return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_FileDecrypt_WithoutIntegrity(partitionId uint32, sessionToken string, keyId string, keyVersion uint32, iv []byte, ciphertextInputFilePath string, plaintextOutputFilePath string) error {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.SDKRequestMultipartDecrypt{
		PartitionId:         wrapperspb.UInt32(partitionId),
		SessionToken:        wrapperspb.String(sessionToken),
		KeyId:               wrapperspb.String(keyId),
		KeyVersion:          wrapperspb.UInt32(keyVersion),
		Iv:                  iv,
		CiphertextInputFile: wrapperspb.String(ciphertextInputFilePath),
		PlaintextOutputFile: wrapperspb.String(plaintextOutputFilePath),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return err
	}

	ret := C.kk_nativesdk_fileDecrypt(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return newFaultCode(uint(ret))
	}
	return nil
}

// Decrypt a file from the provided path and subsequently save the plaintext to the specified output path.
//
//   - param partitionId:				partition ID where the key is located.
//   - param sessionToken:				session token from [api.go.KK_AppAuthenticate].
//   - param keyId:						key ID associated with the key used to encrypt data with Encryption purpose.
//   - param keyVersion:				version of key used to encrypt.
//   - param iv:						initialization vector to decrypt the input file.
//   - param tag:						tag to decrypt the input file.
//   - param ciphertextInputFilePath:	input file path contains ciphertext.
//   - param plaintextOutputFilePath:	output file path where the plaintext to be produced.
//
// Return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_FileDecrypt_WithIntegrity(partitionId uint32, sessionToken string, keyId string, keyVersion uint32, iv []byte, tag []byte, ciphertextInputFilePath string, plaintextOutputFilePath string) error {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.SDKRequestMultipartDecrypt{
		PartitionId:         wrapperspb.UInt32(partitionId),
		SessionToken:        wrapperspb.String(sessionToken),
		KeyId:               wrapperspb.String(keyId),
		KeyVersion:          wrapperspb.UInt32(keyVersion),
		Iv:                  iv,
		Tag:                 tag,
		CiphertextInputFile: wrapperspb.String(ciphertextInputFilePath),
		PlaintextOutputFile: wrapperspb.String(plaintextOutputFilePath),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return err
	}

	ret := C.kk_nativesdk_fileDecrypt(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return newFaultCode(uint(ret))
	}
	return nil
}

// Generate an HMAC (Hash-based Message Authentication Code) of a file located at the given path.
//
//   - param partitionId: 	partition ID where the key is located.
//   - param sessionToken:	session token from [api.go.KK_AppAuthenticate].
//   - param keyId:			key ID associated with the key used for generating mac.
//   - param inputFilePath:	location of the file which hmac to be generated.
//
// Return the `SDKResponseMultipartHMACGenerate` contains the MAC value of file.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_FileGenerateHMAC(partitionId uint32, sessionToken string, keyId string, inputFilePath string) (*kkresp.SDKResponseMultipartHMACGenerate, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.SDKRequestMultipartHMACGenerate{
		PartitionId:   wrapperspb.UInt32(partitionId),
		SessionToken:  wrapperspb.String(sessionToken),
		KeyId:         wrapperspb.String(keyId),
		InputFilename: wrapperspb.String(inputFilePath),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_fileGenerateHMAC(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.SDKResponseMultipartHMACGenerate{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Verify a given HMAC (Hash-based Message Authentication Code) against an HMAC calculated from a file located at the given path.
//
//   - param partitionId:	partition ID where the key is located.
//   - param sessionToken:	session token from [api.go.KK_AppAuthenticate].
//   - param keyId:			key ID used for generating HMAC.
//   - param inputFilePath:	the location of the file which HMAC will be verified.
//   - param tag:			the tag or HMAC value of the input file.
//
// Return the `SDKResponseMultipartHMACVerify` contains the HMAC verification value of a file.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_FileVerifyHMAC(partitionId uint32, sessionToken string, keyId string, inputFilePath string, tag []byte) (*kkresp.SDKResponseMultipartHMACVerify, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.SDKRequestMultipartHMACVerify{
		PartitionId:   wrapperspb.UInt32(partitionId),
		SessionToken:  wrapperspb.String(sessionToken),
		KeyId:         wrapperspb.String(keyId),
		InputFilename: wrapperspb.String(inputFilePath),
		Tag:           tag,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_fileVerifyHMAC(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.SDKResponseMultipartHMACVerify{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Generate a key pair and protect the private key with a wrapping key.
// The wrapping key can be an AES-256-GCM key or RSA key.
//
//   - param partitionId: 				partition ID where the key is located.
//   - param sessionToken:				session token from [api.go.KK_AppAuthenticate].
//   - param wrappingMethod:			the method to wrap the generated asymmetric key. Available list: internalKey, passwordedZip, externalPGPKey, android, ios, androidWithSecureKeyImport, appstoredPublicKey, androidWithNonSecureKeyImport.
//   - param internalWrappingKeyId:     the key to wrap the generated asymmetric key. If the wrapping method is internalKey then the value should be the internal key ID.
//   - param appstoredPublicKey: 		the key to wrap the generated asymmetric key. If the wrapping method is appstoredPublicKey, pass the public key to wrap the generated asymmetric key.
//   - param keyAlgo:					the algorithm of asymmetric key being generated. Available list: RSA, ECDSA P-256, ECDSA P-384, ECDSA P-521, EdDSA Ed25519.
//   - param keyLength:					the optional length of generated asymmetric key in bit. Only required for RSA algo. Available list only for RSA: 2048, 3072, 4096.
//   - param withCert:					the option to generate keypair following by it's certificate.
//
// Return the `APIResponseGenerateKeyPair` contains public key and wrapped private key value.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_GenerateAppstoredKeypair(partitionId uint32, sessionToken string, wrappingMethod string, internalWrappingKeyId string, appstoredPublicKey string, keyAlgo string, keyLength *uint32, withCert bool) (*kkresp.APIResponseGenerateKeyPair, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestAppstoredGenerateKeyPair{
		PartitionId:           wrapperspb.UInt32(partitionId),
		SessionToken:          wrapperspb.String(sessionToken),
		WrappingMethod:        wrapperspb.String(wrappingMethod),
		InternalWrappingKeyId: wrapperspb.String(internalWrappingKeyId),
		AppstoredPublicKey:    wrapperspb.String(appstoredPublicKey),
		Algo:                  wrapperspb.String(keyAlgo),
		AlgoLength: func() *wrapperspb.UInt32Value {
			if keyLength != nil {
				return wrapperspb.UInt32(*keyLength)
			}
			return nil
		}(),
		WithCert: wrapperspb.Bool(withCert),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_appstoredGenerateKeyPair(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseGenerateKeyPair{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Generate an AES-256-GCM key and protect it with an AES-256-GCM wrapping key generated inside Kripta Key.
//
//   - param partitionId:			partition ID where the key is located.
//   - param sessionToken:			session token from [api.go.KK_AppAuthenticate].
//   - param wrappingMethod: 		the method to wrap the generated symmetric key. Available list: internalKey, passwordedZip, externalPGPKey, android, ios, androidWithSecureKeyImport, appstoredPublicKey, androidWithNonSecureKeyImport.
//   - param internalWrappingKeyId: the key to wrap the generated symmetric key. If the wrapping method is internalKey, ios, android, androidWithSecureKeyImport, or androidWithNonSecureKeyImport then the value should be the internal AES key ID. The wrapping key must be an AES key.
//   - param appstoredPublicKey:	the key to wrap the generated symmetric key. If the wrapping method is ios or android, androidWithSecureKeyImport, or androidWithNonSecureKeyImport then the value should be PEM encoded public key. If the internalKey then this field must not be passed.
//   - param keyLength:             the length of generated symmetric key in bit. Available value: 256
//
// Return the `APIResponseGenerateKey` contains the wrapped symmetric key.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_GenerateAppstoredKey_AES(partitionId uint32, sessionToken string, wrappingMethod string, internalWrappingKeyId string, appstoredPublicKey string, keyLength uint32) (*kkresp.APIResponseGenerateKey, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestAppstoredGenerateKey{
		PartitionId:           wrapperspb.UInt32(partitionId),
		SessionToken:          wrapperspb.String(sessionToken),
		InternalWrappingKeyId: wrapperspb.String(internalWrappingKeyId),
		WrappingMethod:        wrapperspb.String(wrappingMethod),
		Algo:                  wrapperspb.String("AES"),
		AlgoLength:            wrapperspb.UInt32(keyLength),
		AppstoredPublicKey:    wrapperspb.String(appstoredPublicKey),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_appstoredGenerateKey(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseGenerateKey{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Generate Message Authentication Code (MAC) for specific data using a key stored in Kripta Key. Ensure that the key purpose is set to MACGeneration.
// The key was generated by calling [api.go.KK_GenerateAppstoredKey_AES].
//
//   - param partitionId:		partition ID where the key is located.
//   - param sessionToken:		session token from [api.go.KK_AppAuthenticate].
//   - param wrappingKeyId:		key id to unwrap the wrapped key.
//   - param wrappedKey:	    wrapped symmetric key in Base64.
//   - param hashAlgo:       	hash algorihm of MAC. Available list: CMAC, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512, GMAC-256.
//   - param data:				the data which MAC to be generated.
//
// Return the `APIResponseAppstoredGenerateMAC` contains the MAC of data and IV (if using GMAC).
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_AppstoredGenerateMAC(partitionId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, hashAlgo string, data string) (*kkresp.APIResponseAppstoredGenerateMAC, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestAppstoredGenerateMAC{
		PartitionId:   wrapperspb.UInt32(partitionId),
		SessionToken:  wrapperspb.String(sessionToken),
		WrappingKeyId: wrapperspb.String(wrappingKeyId),
		WrappedKey:    wrapperspb.String(wrappedKey),
		HashAlgo:      wrapperspb.String(hashAlgo),
		Data:          wrapperspb.String(data),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_appstoredGenerateMAC(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseAppstoredGenerateMAC{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Verify a Message Authentication Code (MAC) of a data using application-stored key that was generated and wrapped by Kripta Key.
// The key was generated by calling [api.go.KK_AppAuthenticate].
//
//   - param partitionId:		partition ID where the key is located.
//   - param sessionToken:		session token from [api.go.KK_AppAuthenticate].
//   - param wrappingKeyId:		key id to unwrap the wrapped key.
//   - param wrappedKey:		wrapped symmetric key in Base64.
//   - param hashAlgo:			hash algorihm of MAC. Available list: CMAC, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512, GMAC-256.
//   - param data:				the data which MAC to be verified.
//   - param mac:				the Base64 standard Encoded Message Authentication Code [api.go.KK_AppstoredGenerateMAC].
//   - param iv:				the initialization vector. Only required for GMAC hash algorithm.
//
// Return the `APIResponseAppstoredVerifyMAC` contains the MAC of data and IV (if using GMAC).
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_AppstoredVerifyMAC(partitionId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, hashAlgo string, data string, mac string, iv *string) (*kkresp.APIResponseAppstoredVerifyMAC, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestAppstoredVerifyMAC{
		PartitionId:   wrapperspb.UInt32(partitionId),
		SessionToken:  wrapperspb.String(sessionToken),
		WrappingKeyId: wrapperspb.String(wrappingKeyId),
		WrappedKey:    wrapperspb.String(wrappedKey),
		HashAlgo:      wrapperspb.String(hashAlgo),
		Data:          wrapperspb.String(data),
		Mac:           wrapperspb.String(mac),
		Iv: func() *wrapperspb.StringValue {
			if iv != nil {
				return wrapperspb.String(*iv)
			}
			return nil
		}(),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_appstoredVerifyMAC(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseAppstoredVerifyMAC{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Encrypt a plaintext with application-stored AES key that was generated and wrapped by Kripta Key.
// KMS will use the latest key version to encrypt plaintext.
//
//   - param partitionId:	partition ID where the key is located.
//   - param sessionToken:	session token from [api.go.KK_AppAuthenticate].
//   - param wrappingKeyId:	the wrapping key ID of application-stored key.
//   - param wrappedKey:	the application-stored AES key in Base64.
//   - param plaintext:		the `APIRequestSingleEncrypt` contains the plaintext value and additional authentication data.
//
// Return the `APIResponseAppstoredEncrypt` contains ciphertext and attributes such as key version.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_AppstoredEncrypt_AES(partitionId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, plaintext []*kkreq.APIRequestSingleEncrypt) (*kkresp.APIResponseAppstoredEncrypt, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestAppstoredEncrypt{
		PartitionId:   wrapperspb.UInt32(partitionId),
		SessionToken:  wrapperspb.String(sessionToken),
		WrappingKeyId: wrapperspb.String(wrappingKeyId),
		WrappedKey:    wrapperspb.String(wrappedKey),
		Plaintext:     plaintext,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_appstoredEncrypt(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseAppstoredEncrypt{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Encrypt a plaintext with application-stored RSA key that was generated and wrapped by Kripta Key.
// Plaintext encrypted with an application-stored generated asymmetric key can only be decrypted in the system where the private key exists.
//
//   - param partitionId:		partition ID where the key is located.
//   - param sessionToken:		session token from [api.go.KK_AppAuthenticate].
//   - param publicKeyOrCert:	the public key or certificate of application-stored RSA key in PEM format. Only applicable for RSA key.
//   - param useSessionKey:		the option to encrypt large plaintext with asymmetric key.
//   - param plaintext:			the `APIRequestSingleEncrypt` contains the plaintext value and additional authentication data.
//
// Return the `APIResponseAppstoredEncrypt` contains ciphertext and attributes such as key version.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_AppstoredEncrypt_RSA(partitionId uint32, sessionToken string, publicKeyOrCert string, useSessionKey bool, plaintext []*kkreq.APIRequestSingleEncrypt) (*kkresp.APIResponseAppstoredEncrypt, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestAppstoredEncrypt{
		PartitionId:     wrapperspb.UInt32(partitionId),
		SessionToken:    wrapperspb.String(sessionToken),
		PublicKeyOrCert: wrapperspb.String(publicKeyOrCert),
		UseSessionKey:   wrapperspb.Bool(useSessionKey),
		Plaintext:       plaintext,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_appstoredEncrypt(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseAppstoredEncrypt{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Decrypt multiple ciphertexts with application-stored key that was generated and wrapped by Kripta Key.
// KMS will use the key version supplied in param to decrypt ciphertext.
//
//   - param partitionId: 		partition ID where the key is located.
//   - param sessionToken: 		session token from [api.go.KK_AppAuthenticate].
//   - param wrappingKeyId: 	the wrapping key ID of application-stored key.
//   - param wrappedKey:		wrapped application-stored AES key or RSA private key in Base64.
//   - param ciphertext:		the encrypted value `APIRequestSingleAppstoredDecrypt` to be decrypted.
//
// Return the `APIResponseAppstoredDecrypt` contains plaintext.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_AppstoredDecrypt(partitionId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, ciphertext []*kkreq.APIRequestSingleAppstoredDecrypt) (*kkresp.APIResponseAppstoredDecrypt, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestAppstoredDecrypt{
		PartitionId:   wrapperspb.UInt32(partitionId),
		SessionToken:  wrapperspb.String(sessionToken),
		WrappingKeyId: wrapperspb.String(wrappingKeyId),
		WrappedKey:    wrapperspb.String(wrappedKey),
		Ciphertext:    ciphertext,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_appstoredDecrypt(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseAppstoredDecrypt{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Encrypt multiple plaintexts with metadata using application-stored AES key.
// This key was generated by calling [api.go.KK_GenerateAppstoredKey_AES].
//
//   - param partitionId:		partition ID where the key is located.
//   - param sessionToken:		session token from [api.go.KK_AppAuthenticate].
//   - param wrappingKeyId:		key ID to unwrap the wrapped key. Required for application-stored AES key.
//   - param wrappedKey:		wrapped AES key in Base64 generated by calling [api.go.KK_GenerateAppstoredKey_AES].
//   - param plaintext:			the array of string values to be sealed.
//
// Return the `APIResponseAppstoredSeal` contains ciphertext.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_AppstoredSeal_AES(partitionId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, plaintext []string) (*kkresp.APIResponseAppstoredSeal, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestAppstoredSeal{
		PartitionId:   wrapperspb.UInt32(partitionId),
		SessionToken:  wrapperspb.String(sessionToken),
		WrappingKeyId: wrapperspb.String(wrappingKeyId),
		WrappedKey:    wrapperspb.String(wrappedKey),
		Plaintext:     plaintext,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_appstoredSeal(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseAppstoredSeal{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Encrypt multiple plaintexts with metadata using application-stored RSA key.
// This key was generated by calling [api.go.KK_GenerateAppstoredKeypair].
//
//   - param partitionId:    	partition ID where the key is located.
//   - param sessionToken:		session token from [api.go.KK_AppAuthenticate].
//   - param publicKeyOrCert: 	the public key or certificate of application-stored RSA key in PEM format.
//   - param plaintext			the array of string values to be sealed
//
// Return the `APIResponseAppstoredSeal` contains ciphertext.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_AppstoredSeal_RSA(partitionId uint32, sessionToken string, publicKeyOrCert string, plaintext []string) (*kkresp.APIResponseAppstoredSeal, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestAppstoredSeal{
		PartitionId:     wrapperspb.UInt32(partitionId),
		SessionToken:    wrapperspb.String(sessionToken),
		PublicKeyOrCert: wrapperspb.String(publicKeyOrCert),
		Plaintext:       plaintext,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_appstoredSeal(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseAppstoredSeal{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Decrypt multiple ciphertexts with metadata using application-stored AES or RSA key that was generated and wrapped by Kripta Key.
// The key was generated by calling [api.go.KK_GenerateAppstoredKey_AES] or [api.go.KK_GenerateAppstoredKeypair].
//
//   - param partitionId:		partition ID where the key is located.
//   - param sessionToken:		session token from [api.go.KK_AppAuthenticate].
//   - param wrappingKeyId:		key ID to unwrap the wrapped key.
//   - param wrappedKey:		wrapped AES key or RSA private key in Base64.
//   - param ciphertext:		the array of ciphertext values to be unsealed.
//
// Return the `APIResponseAppstoredUnseal` contains unsealed value.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_AppstoredUnseal(partitionId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, ciphertext []string) (*kkresp.APIResponseAppstoredUnseal, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestAppstoredUnseal{
		PartitionId:   wrapperspb.UInt32(partitionId),
		SessionToken:  wrapperspb.String(sessionToken),
		WrappingKeyId: wrapperspb.String(wrappingKeyId),
		WrappedKey:    wrapperspb.String(wrappedKey),
		Ciphertext:    ciphertext,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_appstoredUnseal(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseAppstoredUnseal{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Tokenize multiple plaintexts with application-stored AES key by preserving its format and length.
// This key was generated and wrapped with Kripta Key by calling [api.go.KK_GenerateAppstoredKey_AES].
//
//   - param partitionId:		partition ID where the key is located.
//   - param sessionToken:		session token from [api.go.KK_AppAuthenticate].
//   - param wrappingKeyId:		key ID to unwrap the wrapped key. Required for application-stored AES key.
//   - param wrappedKey:		wrapped AES key in Base64.
//   - param plaintext:			the `APIRequestSingleTokenize` contains plaintext and format to be tokenized. Available list of tokenization types: cipher, alpha, num, alphanum, masking.
//
// Return the `APIResponseTokenize` contains the tokenized value.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_AppstoredTokenize(partitionId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, usv []*kkreq.APIRequestSingleTokenize) (*kkresp.APIResponseTokenize, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestAppstoredTokenize{
		PartitionId:   wrapperspb.UInt32(partitionId),
		SessionToken:  wrapperspb.String(sessionToken),
		WrappingKeyId: wrapperspb.String(wrappingKeyId),
		WrappedKey:    wrapperspb.String(wrappedKey),
		Plaintext:     usv,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_appstoredTokenize(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseTokenize{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Detokenize multiple ciphertexts with application-stored AES key by preserving its format and length.
// This key was generated and wrapped with Kripta Key by calling [api.go.KK_GenerateAppstoredKey_AES].
//
//   - param partitionId:		partition ID where the key is located.
//   - param sessionToken:		session token from [api.go.KK_AppAuthenticate].
//   - param wrappingKeyId:		the wrapping key ID of application-stored key.
//   - param wrappedKey:		the application-stored AES key in base64.
//   - param ciphertext: 		the `APIRequestSingleDetokenize` contains tokenized value of the data.
//
// Return the `APIResponseDetokenize` contains the detokenized value.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_AppstoredDetokenize(partitionId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, ciphertext []*kkreq.APIRequestSingleDetokenize) (*kkresp.APIResponseDetokenize, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestAppstoredDetokenize{
		PartitionId:   wrapperspb.UInt32(partitionId),
		SessionToken:  wrapperspb.String(sessionToken),
		WrappingKeyId: wrapperspb.String(wrappingKeyId),
		WrappedKey:    wrapperspb.String(wrappedKey),
		Ciphertext:    ciphertext,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_appstoredDetokenize(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseDetokenize{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Sign a data using application-stored asymmetric key that was generated and wrapped by Kripta Key and return a digital signature.
// This key was generated by calling [api.go.KK_GenerateAppstoredKeypair].
//
//   - param partitionId:		partition ID where the key is located.
//   - param sessionToken:		session token from [api.go.KK_AppAuthenticate].
//   - param wrappingKeyId:     key ID to unwrap the application-stored private key.
//   - param wrappedKey:		application-stored private key wrapped by Kripta Key.
//   - param data:				raw data to be signed.
//   - param hashAlgo:       	the hash algorithm for signing. Available list: SHA256, SHA384, SHA512.
//
// Return the `APIResponseAppstoredSign` contains the signature value.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_AppstoredSignData(partitionId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, hashAlgo string, data string) (*kkresp.APIResponseAppstoredSign, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestAppstoredSign{
		PartitionId:   wrapperspb.UInt32(partitionId),
		SessionToken:  wrapperspb.String(sessionToken),
		WrappingKeyId: wrapperspb.String(wrappingKeyId),
		WrappedKey:    wrapperspb.String(wrappedKey),
		InputType:     wrapperspb.String("raw"),
		HashAlgo:      wrapperspb.String(hashAlgo),
		Data:          wrapperspb.String(data),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_appstoredSign(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseAppstoredSign{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Sign a data using application-stored asymmetric key that was generated and wrapped by Kripta Key and return a digital signature.
// This key was generated by calling [api.go.KK_GenerateAppstoredKeypair].
//
//   - param partitionId:		partition ID where the key is located.
//   - param sessionToken:		session token from [api.go.KK_AppAuthenticate].
//   - param wrappingKeyId:     key ID to unwrap the application-stored private key.
//   - param wrappedKey:		application-stored private key wrapped by Kripta Key.
//   - param data:				digest to be signed. The data must be base64 encoded from digest.
//   - param inputType:      	type of data. Available list: raw, sha256Hashed, sha384Hashed, sha512Hashed.
//
// Return the `APIResponseAppstoredSign` contains the signature value.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_AppstoredSignDigest(partitionId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, inputType string, data string) (*kkresp.APIResponseAppstoredSign, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestAppstoredSign{
		PartitionId:   wrapperspb.UInt32(partitionId),
		SessionToken:  wrapperspb.String(sessionToken),
		WrappingKeyId: wrapperspb.String(wrappingKeyId),
		WrappedKey:    wrapperspb.String(wrappedKey),
		InputType:     wrapperspb.String(inputType),
		Data:          wrapperspb.String(data),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_appstoredSign(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseAppstoredSign{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// The API to verify the digital signature of a data with application-stored asymmetric key that was generated and wrapped by Kripta Key Id.
// The key was generated by calling [api.go.KK_GenerateAppstoredKeypair].
//
//   - param partitionId:		partition ID where the key is located.
//   - param sessionToken:		session token from [api.go.KK_AppAuthenticate].
//   - param publicKeyOrCert:	application-stored public key or certificate to verify the digital signature.
//   - param data:				raw data to be verified.
//   - param signature:			generated signature in Base64.
//   - param hashAlgo:			digest function used to generate digital signature. Available list: SHA256, SHA384, SHA512.
//
// Return the `APIResponseAppstoredVerify` contains the verification result.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_AppstoredVerifyData(partitionId uint32, sessionToken string, publicKeyOrCert string, hashAlgo string, data string, signature string) (*kkresp.APIResponseAppstoredVerify, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestAppstoredVerify{
		PartitionId:     wrapperspb.UInt32(partitionId),
		SessionToken:    wrapperspb.String(sessionToken),
		PublicKeyOrCert: wrapperspb.String(publicKeyOrCert),
		InputType:       wrapperspb.String("raw"),
		HashAlgo:        wrapperspb.String(hashAlgo),
		Data:            wrapperspb.String(data),
		Signature:       wrapperspb.String(signature),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_appstoredVerify(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseAppstoredVerify{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// The API to verify the digital signature of a data with application-stored asymmetric key that was generated and wrapped by Kripta Key Id.
// The key was generated by calling [api.go.KK_GenerateAppstoredKeypair].
//
//   - param partitionId:		partition ID where the key is located.
//   - param sessionToken:		session token from [api.go.KK_AppAuthenticate].
//   - param publicKeyOrCert:	application-stored public key or certificate to verify the digital signature.
//   - param data:				digest to be signed. The data must be base64 encoded from digest.
//   - param signature:			generated signature in Base64.
//   - param inputType:      	type of data. Available list: raw, sha256Hashed, sha384Hashed, sha512Hashed.
//
// Return the `APIResponseAppstoredVerify` contains the verification result.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_AppstoredVerifyDigest(partitionId uint32, sessionToken string, publicKeyOrCert string, inputType string, data string, signature string) (*kkresp.APIResponseAppstoredVerify, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestAppstoredVerify{
		PartitionId:     wrapperspb.UInt32(partitionId),
		SessionToken:    wrapperspb.String(sessionToken),
		PublicKeyOrCert: wrapperspb.String(publicKeyOrCert),
		InputType:       wrapperspb.String(inputType),
		Data:            wrapperspb.String(data),
		Signature:       wrapperspb.String(signature),
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_appstoredVerify(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseAppstoredVerify{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Re-encrypt multiple messages encrypted with session key of end user to permanent key. The result can be stored in app server securely.
// The session key is encrypted by using application-stored stored RSA key that was generated and wrapped by Kripta Key by calling [api.go.KK_GenerateAppstoredKeypair].
//
//   - param partitionId:				partition ID where the key is located.
//   - param sessionToken:				session token from [api.go.KK_AppAuthenticate].
//   - param e2eeSourceRequest:			the `E2EESourceCipher` contains encrypted data block (EDB) from the client/mobile app and will be reencrypted using permanent key.
//   - param e2eeDestinationRequest:	the `APIRequestE2EEReencryptFromSessionKeyToPermanentKey_Destination` contains the permanent key ID with Encryption purpose and algo with AES-GCM-256 type.
//
// Return the `APIResponseE2EEReEncryptFromSessionKeyToPermanentKey` contains the stored encrypted data (SED) encrypted value with permanent key.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_E2EEReencryptFromSessionKeyToPermanentKey(partitionId uint32, sessionToken string, e2eeSourceRequest *kkreq.E2EESourceCipher, e2eeDestinationRequest *kkreq.APIRequestE2EEReencryptFromSessionKeyToPermanentKey_Destination) (*kkresp.APIResponseE2EEReEncryptFromSessionKeyToPermanentKey, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestE2EEReencryptFromSessionKeyToPermanentKey{
		PartitionId:  wrapperspb.UInt32(partitionId),
		SessionToken: wrapperspb.String(sessionToken),
		Source:       e2eeSourceRequest,
		Destination:  e2eeDestinationRequest,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_e2eeReEncryptFromSessionKeyToPermanentKey(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseE2EEReEncryptFromSessionKeyToPermanentKey{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Securely compare two data within a trusted environment. The data are from end user and app server.
// The message to be compared is encrypted by using session key that is encrypted by using application-stored RSA key that was generated and wrapped by Kripta Key by calling [api.go.KK_GenerateAppstoredKeypair].
//
//   - param partitionId:				partition ID where the key is located.
//   - param sessionToken:				session token from [api.go.KK_AppAuthenticate].
//   - param e2eeSourceRequest: 		the `E2EESourceCipher` contains encrypted data block (EDB) from the client/mobile app.
//   - param e2eeCompareWithRequest:	the `APIRequestE2EECompare_Comparewith` contains the stored encrypted data (SED) in app server that was encrypted with permanent key.
//
// Return the `APIResponseE2EECompare` contains the compare result
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_E2EECompare(partitionId uint32, sessionToken string, e2eeSourceRequest *kkreq.E2EESourceCipher, e2eeCompareWithRequest *kkreq.APIRequestE2EECompare_Comparewith) (*kkresp.APIResponseE2EECompare, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestE2EECompare{
		PartitionId:  wrapperspb.UInt32(partitionId),
		SessionToken: wrapperspb.String(sessionToken),
		Source:       e2eeSourceRequest,
		CompareWith:  e2eeCompareWithRequest,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_e2eeCompare(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseE2EECompare{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Re-encrypt multiple messages encrypted with permanent key to client key. The result will be delivered to the end user.
//
//   - param partitionId:				partition ID where the key is located.
//   - param sessionToken:				session token from [api.go.KK_AppAuthenticate].
//   - param e2eeSourceRequest:			the `APIRequestE2EEReencryptFromPermanentKeyToClientKey_Source` contains the ciphertext that is encrypted by the permanent key and will be reencrypted using client key before being delivered to the end user.
//   - param e2eeDestinationRequest: 	the `APIRequestE2EEReencryptFromPermanentKeyToClientKey_Destination` is then re-encrypted with client key.
//
// Return the `APIResponseE2EEReEncryptFromPermanentKeyToSessionKey` contains the encrypted data block (EDB) encrypted with client key.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_E2EEReencryptFromPermanentKeyToClientKey(partitionId uint32, sessionToken string, e2eeSourceRequest *kkreq.APIRequestE2EEReencryptFromPermanentKeyToClientKey_Source, e2eeDestinationRequest *kkreq.APIRequestE2EEReencryptFromPermanentKeyToClientKey_Destination) (*kkresp.APIResponseE2EEReEncryptFromPermanentKeyToSessionKey, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestE2EEReencryptFromPermanentKeyToClientKey{
		PartitionId:  wrapperspb.UInt32(partitionId),
		SessionToken: wrapperspb.String(sessionToken),
		Source:       e2eeSourceRequest,
		Destination:  e2eeDestinationRequest,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_e2eeReEncryptFromPermanentKeyToClientKey(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseE2EEReEncryptFromPermanentKeyToSessionKey{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Decrypt multiple messages that are encrypted using session key.
// Each message by calling [api.go.KK_GenerateAppstoredKeypair].
//
//   - param partitionId:		partition ID where the key is located.
//   - param sessionToken:   	session token from [api.go.KK_AppAuthenticate].
//   - param wrappingKeyId:     the wrapping key ID of application-stored keypair.
//   - param wrappedPrivateKey: application-stored private key in Base64.
//   - param sessionKeyAlgo:    symmetric algorithm of session key. Only AES is provided.
//   - param macAlgo:           the algorithm used to generate Message Authentication Code (MAC). Only "HMAC_SHA512" is currently supported.
//   - param oaepLabel:         label that used for encrypting the session key in client side.
//   - param metadata:          the Base64 of concatenated wrapped client keys (session key, iv, and mac key) and the MAC of wrapped client keys and overall encrypted data blocks.
//   - param ciphertext:        the array of encrypted data blocks that each concatenates encrypted data and its MAC.
//
// Return the `APIResponseE2EEDecryptFromSessionKey` contains plaintext.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_E2EEDecryptFromSessionKey(partitionId uint32, sessionToken string, wrappingKeyId string, wrappedPrivateKey string, sessionKeyAlgo string, macAlgo string, oaepLabel string, metadata string, ciphertext []string) (*kkresp.APIResponseE2EEDecryptFromSessionKey, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestE2EEDecryptFromSessionKey{
		SessionToken:      wrapperspb.String(sessionToken),
		PartitionId:       wrapperspb.UInt32(partitionId),
		WrappingKeyId:     wrapperspb.String(wrappingKeyId),
		WrappedPrivateKey: wrapperspb.String(wrappedPrivateKey),
		SessionKeyAlgo:    wrapperspb.String(sessionKeyAlgo),
		MacAlgo:           wrapperspb.String(macAlgo),
		OaepLabel:         wrapperspb.String(oaepLabel),
		Metadata:          wrapperspb.String(metadata),
		Ciphertext:        ciphertext,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_e2eeDecryptFromSessionKey(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseE2EEDecryptFromSessionKey{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Encrypt multiple plaintexts with client key. Thus, the app server receives encrypted data (usually) will be sent to end user.
// "encryptedClientKey" and "encryptedClientKeyMetadata" is generated in client side using sdk.
//
//   - param partitionId:				partition ID where the key is located.
//   - param sessionToken:				session token from [api.go.KK_AppAuthenticate].
//   - param e2eeSourceRequest:			the `APIRequestE2EEEncryptToClientKey_Source` contains the plaintext is going to be encrypted by the client key, then will be delivered to the end user.
//   - param e2eeDestinationRequest:	the `APIRequestE2EEEncryptToClientKey_Destination` contains target encryption algorithm.
//
// Return the `APIResponseE2EEEncryptToClientKey` contains the ciphertext encrypted with session key.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_E2EEEncryptToClientKey(partitionId uint32, sessionToken string, e2eeSourceRequest *kkreq.APIRequestE2EEEncryptToClientKey_Source, e2eeDestinationRequest *kkreq.APIRequestE2EEEncryptToClientKey_Destination) (*kkresp.APIResponseE2EEEncryptToClientKey, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.APIRequestE2EEEncryptToClientKey{
		SessionToken: wrapperspb.String(sessionToken),
		PartitionId:  wrapperspb.UInt32(partitionId),
		Source:       e2eeSourceRequest,
		Destination:  e2eeDestinationRequest,
	}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_e2eeEncryptToClientKey(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponseE2EEEncryptToClientKey{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

// Encrypt data bigger than 700KB with metadata using AES-GCM-256 key.
//
//   - param plaintext: 		the input that want to be encrypted.
//   - param publicKeyOrCert: 	the public key or certificate of the key generated in KMS.
//
// Return error if failed.
func KK_SealForTransit(plaintext []byte, publicKeyOrCert string) ([]byte, error) {
	var err error

	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.SDKRequestSealForTransit{Plaintext: plaintext, PublicKeyOrCert: publicKeyOrCert}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_sealForTransit((*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &wrapperspb.BytesValue{}
	err = proto.Unmarshal(array, instance)

	runtime.KeepAlive(serialized_request)
	runtime.KeepAlive(array)
	runtime.KeepAlive(allocPtr)

	return instance.GetValue(), err
}

// Decrypt data bigger than 700KB with metadata using AES-GCM-256 key.
//
//   - param partitionId:		the partition ID where the key is located.
//   - param sessionToken:		the session token.
//   - param wrappingKeyId:		the ID of an internal key in KMS with purpose Encryption.
//   - param wrappedPrivateKey:	the key from external generate key pair
//   - param ciphertext:		the ciphertext
//
// Return the unsealed data response.
// Or return error when the SDK cannot connect to the API endpoint or if the request parameters are incorrect.
func (x *ConnectionHandler) KK_UnsealDataFromTransit(partitionId uint32, sessionToken string, wrappingKeyId string, wrappedPrivateKey string, ciphertext []byte) ([]byte, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	request := kkreq.SDKRequestUnSealFromTransit{PartitionId: partitionId, SessionToken: sessionToken, WrappingKeyId: wrappingKeyId, WrappedPrivateKey: wrappedPrivateKey, Ciphertext: ciphertext}

	serialized_request, err := proto.Marshal(&request)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_unsealDataFromTransit(*x.handler, (*C.uchar)(unsafe.Pointer(&serialized_request[0])), C.ulong(len(serialized_request)), C.KK_OpaqueOutputPtr(allocPtr), C.KK_AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &wrapperspb.BytesValue{}
	err = proto.Unmarshal(array, instance)

	runtime.KeepAlive(serialized_request)
	runtime.KeepAlive(array)
	runtime.KeepAlive(allocPtr)
	runtime.KeepAlive(x)

	return instance.GetValue(), err
}
