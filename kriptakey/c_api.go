package kriptakey

/*
#cgo pkg-config: KK-NativeSDK
#include <kriptakey/api.h>

int32_t kk_gosdk_assign(void*, int32_t, void*);
*/
import "C"
import (
	"unsafe"
)

//export kk_gosdk_assign
func kk_gosdk_assign(sourcePtr unsafe.Pointer, sourceSize C.int, targetPtr unsafe.Pointer) C.int {
	array := (*[]byte)(targetPtr)
	*array = C.GoBytes(sourcePtr, sourceSize)
	return C.int(len(*array))
}
