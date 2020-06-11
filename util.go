package ntlmssp

import (
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"reflect"
	"strings"
	"unicode/utf16"
	"unsafe"
)

func displayBits(offset int, set bool) string {
	buf := strings.Builder{}
	for i := 0; i < 8; i++ {
		for j := 0; j < 4; j++ {
			if offset == i*4+j {
				if set {
					buf.Write([]byte{'1'})
				} else {
					buf.Write([]byte{'0'})
				}
			} else {
				buf.Write([]byte{'.'})
			}
		}
		buf.Write([]byte{' '})
	}
	return buf.String()
}

func bytes2Uint(bs []byte, endian byte) uint64 {
	var u uint64
	if endian == '>' {
		for i := 0; i < len(bs); i++ {
			u += uint64(bs[i]) << (8 * (len(bs) - i - 1))
		}
	} else {
		for i := 0; i < len(bs); i++ {
			u += uint64(bs[len(bs)-i-1]) << (8 * (len(bs) - i - 1))
		}
	}
	return u
}

// Only for ascii
func encodeUTF16LE(bs []byte) []byte {
	output := make([]byte, 0, len(bs)*2)
	for i := 0; i < len(bs); i++ {
		output = append(output, bs[i])
		output = append(output, 0)
	}
	return output
}

// UTF16 multi bytes to string
func bytes2StringUTF16(bs []byte) string {
	ptr := (*reflect.SliceHeader)(unsafe.Pointer(&bs))
	(*ptr).Len = ptr.Len / 2

	s := (*[]uint16)(unsafe.Pointer(&bs))
	return string(utf16.Decode(*s))
}

func padding(bs []byte) []byte {
	output := make([]byte, 0, 8)
	output = append(output, 1+(bs[0]>>1)<<1)
	output = append(output, 1+((bs[0]&1)<<7)+((bs[1]&0b11111100)>>1))
	output = append(output, 1+((bs[1]&0b11)<<6)+((bs[2]&0b11111000)>>2))
	output = append(output, 1+((bs[2]&0b111)<<5)+((bs[3]&0b11110000)>>3))
	output = append(output, 1+((bs[3]&0b1111)<<4)+((bs[4]&0b11100000)>>4))
	output = append(output, 1+((bs[4]&0b11111)<<3)+((bs[5]&0b11000000)>>5))
	output = append(output, 1+((bs[5]&0b111111)<<2)+((bs[6]&0b10000000)>>6))
	output = append(output, 1+(bs[6]&0b1111111)<<1)
	return output
}

func desEnc(key []byte, plaintext []byte) []byte {
	cipher := make([]byte, 8)
	c, _ := des.NewCipher(key)
	c.Encrypt(cipher, plaintext)
	return cipher
}

func hmacMd5(key []byte, msg []byte) []byte {
	hsh := hmac.New(md5.New, key)
	hsh.Write(msg)
	return hsh.Sum(nil)
}

func md5Hash(msg []byte) []byte {
	hsh := md5.New()
	hsh.Write(msg)
	return hsh.Sum(nil)
}
