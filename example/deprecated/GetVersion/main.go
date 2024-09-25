package main

import (
	"fmt"

	kk "github.com/kriptakey/kk-go-sdk-v24.1/kriptakey"
)

func main() {

	sdkVersion := kk.GetSDKVersion()
	fmt.Println(sdkVersion)
}
