package ntlmssp

import (
	"fmt"
	"unsafe"
)

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e
type AVPair struct {
	AvId  uint16
	AvLen uint16
}

var avIds = map[uint16]string{
	0:  "MsvAvEOL",
	1:  "MsvAvNbComputerName",
	2:  "MsvAvNbDomainName",
	3:  "MsvAvDnsComputerName",
	4:  "MsvAvDnsDomainName",
	5:  "MsvAvDnsTreeName",
	6:  "MsvAvFlags",
	7:  "MsvAvTimestamp",
	8:  "MsvAvSingleHost",
	9:  "MsvAvTargetName",
	10: "MsvAvChannelBindings",
}

var avIdsRev = map[string]byte{
	"MsvAvEOL":             0,
	"MsvAvNbComputerName":  1,
	"MsvAvNbDomainName":    2,
	"MsvAvDnsComputerName": 3,
	"MsvAvDnsDomainName":   4,
	"MsvAvDnsTreeName":     5,
	"MsvAvFlags":           6,
	"MsvAvTimestamp":       7,
	"MsvAvSingleHost":      8,
	"MsvAvTargetName":      9,
	"MsvAvChannelBindings": 10,
}

func ParseAVPair(bs []byte) map[string]interface{} {
	output := map[string]interface{}{}
	var ptr uint16 = 0
	for {
		avId := uint16(bs[ptr]) + (uint16(bs[ptr+1]) << 8)
		if avId == 0 {
			break
		}

		length := uint16(bs[ptr+2]) + (uint16(bs[ptr+3]) << 8)
		value := bs[ptr+4 : ptr+4+length]
		ptr += 4 + length

		// Only parse unicode string
		if avId != 6 && avId != 7 && avId != 8 && avId != 10 {
			output[avIds[avId]] = bytes2StringUTF16(value)
		} else {
			output[avIds[avId]] = value
		}
	}

	return output
}

const (
	NEGOTIATE_56BIT_ENCRYPTION           = 0x80000000
	NEGOTIATE_EXPLICIT_KEY_EXCHANGE      = 0x40000000
	NEGOTIATE_128BIT_SESSION_KEY         = 0x20000000
	NEGOTIATE_R1_UNUSED                  = 0x10000000
	NEGOTIATE_R2_UNUSED                  = 0x8000000
	NEGOTIATE_R3_UNUSED                  = 0x4000000
	NEGOTIATE_VERSION                    = 0x2000000
	NEGOTIATE_R4_UNUSED                  = 0x1000000
	NEGOTIATE_TARGET_INFO                = 0x800000
	NEGOTIATE_REQUEST_NON_NT_SESSION_KEY = 0x400000
	NEGOTIATE_R5_UNUSED                  = 0x200000
	NEGOTIATE_IDENTITY_LEVEL_TOKEN       = 0x100000
	NEGOTIATE_EXTENDED_SESSION_SECURITY  = 0x80000
	NEGOTIATE_R6_UNUSED                  = 0x40000
	NEGOTIATE_TARGET_TYPE_SERVER         = 0x20000
	NEGOTIATE_TARGET_TYPE_DOMAIN         = 0x10000
	NEGOTIATE_ALWAYS_SIGN                = 0x8000
	NEGOTIATE_R7_UNUSED                  = 0x4000
	NEGOTIATE_OEM_WORKSTATION_SUPPLIED   = 0x2000
	NEGOTIATE_OEM_DOMAIN_SUPPLIED        = 0x1000
	NEGOTIATE_ANONYMOUS                  = 0x800
	NEGOTIATE_R8_UNUSED                  = 0x400
	NEGOTIATE_NTLM                       = 0x200
	NEGOTIATE_R9_UNUSED                  = 0x100
	NEGOTIATE_LM_SESSION_KEY             = 0x80
	NEGOTIATE_DATAGRAM_CONNECTIONLESS    = 0x40
	NEGOTIATE_SEAL                       = 0x20
	NEGOTIATE_SIGN                       = 0x10
	NEGOTIATE_R10_UNUSED                 = 0x8
	NEGOTIATE_REQUEST_TARGET_NAME        = 0x4
	NEGOTIATE_OEM_CHARSET                = 0x2
	NEGOTIATE_UNICODE_CHARSET            = 0x1
)

func ParseNegotiateFlags(ui uint32) *[32][2]string {
	flags := [32][2]string{
		[2]string{"NEGOTIATE_56BIT_ENCRYPTION", "0"},
		[2]string{"NEGOTIATE_EXPLICIT_KEY_EXCHANGE", "0"},
		[2]string{"NEGOTIATE_128BIT_SESSION_KEY", "0"},
		[2]string{"NEGOTIATE_R1_UNUSED", "0"},
		[2]string{"NEGOTIATE_R2_UNUSED", "0"},
		[2]string{"NEGOTIATE_R3_UNUSED", "0"},
		[2]string{"NEGOTIATE_VERSION", "0"},
		[2]string{"NEGOTIATE_R4_UNUSED", "0"},
		[2]string{"NEGOTIATE_REQUEST_TARGET_INFO", "0"},
		[2]string{"NEGOTIATE_REQUEST_NON_NT_SESSION_KEY", "0"},
		[2]string{"NEGOTIATE_R5_UNUSED", "0"},
		[2]string{"NEGOTIATE_IDENTITY_LEVEL_TOKEN", "0"},
		[2]string{"NEGOTIATE_EXTENDED_SESSION_SECURITY", "0"},
		[2]string{"NEGOTIATE_R6_UNUSED", "0"},
		[2]string{"NEGOTIATE_TARGET_TYPE_SERVER", "0"},
		[2]string{"NEGOTIATE_TARGET_TYPE_DOMAIN", "0"},
		[2]string{"NEGOTIATE_ALWAYS_SIGN", "0"},
		[2]string{"NEGOTIATE_R7_UNUSED", "0"},
		[2]string{"NEGOTIATE_OEM_WORKSTATION_SUPPLIED", "0"},
		[2]string{"NEGOTIATE_OEM_DOMAIN_SUPPLIED", "0"},
		[2]string{"NEGOTIATE_ANONYMOUS", "0"},
		[2]string{"NEGOTIATE_R8_UNUSED", "0"},
		[2]string{"NEGOTIATE_NTLM", "0"},
		[2]string{"NEGOTIATE_R9_UNUSED", "0"},
		[2]string{"NEGOTIATE_LM_SESSION_KEY", "0"},
		[2]string{"NEGOTIATE_DATAGRAM_CONNECTIONLESS", "0"},
		[2]string{"NEGOTIATE_SEAL", "0"},
		[2]string{"NEGOTIATE_SIGN", "0"},
		[2]string{"NEGOTIATE_R10_UNUSED", "0"},
		[2]string{"NEGOTIATE_REQUEST_TARGET_NAME", "0"},
		[2]string{"NEGOTIATE_OEM_CHARSET", "0"},
		[2]string{"NEGOTIATE_UNICODE_CHARSET", "0"},
	}

	nf := *(*[4]byte)(unsafe.Pointer(&ui))
	// little endian
	nf[0], nf[1], nf[2], nf[3] = nf[3], nf[2], nf[1], nf[0]
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			if (nf[i]>>(7-j))&1 == 1 {
				flags[i*8+j][1] = "1"
			}
		}
	}
	return &flags
}

func DisplayNegotiateFlags(ui uint32) {
	flags := ParseNegotiateFlags(ui)

	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			set := "Not set"
			if flags[i*8+j][1] == "1" {
				set = "Set"
			}

			fmt.Printf("%s  %s: %s\n",
				displayBits(i*8+j, flags[i*8+j][1] == "1"),
				flags[i*8+j][0], set)
		}
	}
}
