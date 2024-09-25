package kriptakey

import (
	"fmt"
)

type faultCodeError struct {
	faultcode uint
}

func (e *faultCodeError) Error() string {
	return fmt.Sprintf("KK SDK FaultResponseCode: %d", e.faultcode)
}

func (e *faultCodeError) GetFaultCode() uint {
	return e.faultcode
}

func newFaultCode(faultcode uint) error {
	return &faultCodeError{faultcode: faultcode}
}
