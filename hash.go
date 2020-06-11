package ntlmssp

import (
	"bytes"

	"golang.org/x/crypto/md4"
)

const (
	LmSalt = "KGS!@#$%"
)

func LmHash(pwd []byte) []byte {
	pwd = bytes.ToUpper(pwd)
	if len(pwd) < 14 {
		length := len(pwd)
		for i := 0; i < 14-length; i++ {
			pwd = append(pwd, 0)
		}
	}

	return append(desEnc(padding(pwd[:7]), []byte(LmSalt)), desEnc(padding(pwd[7:]), []byte(LmSalt))...)
}

func NtHash(pwd []byte) []byte {
	hsh := md4.New()
	hsh.Write(encodeUTF16LE(pwd))
	return hsh.Sum(nil)
}
