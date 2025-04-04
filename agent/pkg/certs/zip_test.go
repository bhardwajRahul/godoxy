package certs

import (
	"testing"

	. "github.com/yusing/go-proxy/internal/utils/testing"
)

func TestZipCert(t *testing.T) {
	ca, crt, key := []byte("test1"), []byte("test2"), []byte("test3")
	zipData, err := ZipCert(ca, crt, key)
	ExpectNoError(t, err)

	ca2, crt2, key2, err := ExtractCert(zipData)
	ExpectNoError(t, err)
	ExpectEqual(t, ca, ca2)
	ExpectEqual(t, crt, crt2)
	ExpectEqual(t, key, key2)
}
