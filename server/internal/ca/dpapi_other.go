//go:build !windows

package ca

import "errors"

// unprotect is unavailable off Windows: Studio writes an owner-only PEM key there instead.
func unprotect([]byte) ([]byte, error) {
	return nil, errors.New("this CA key was encrypted with Windows DPAPI; run the server on Windows as the same user, or re-create the CA here")
}
