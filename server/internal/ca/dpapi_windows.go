//go:build windows

package ca

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// entropy must match studio/src/modigliani/dpapi.py.
var entropy = []byte("modigliani-local-ca-v1")

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]} //nolint:gosec // CA keys are a few KiB
}

// unprotect decrypts a DPAPI blob written by Studio for the same Windows user.
func unprotect(data []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(data), nil, blob(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	// DPAPI returns a LocalAlloc'd buffer; copy it out before LocalFree runs.
	defer func() { _, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data))) }() //nolint:gosec // freeing the DPAPI buffer
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil                  //nolint:gosec // required to read the DPAPI result
}
