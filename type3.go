package ntlmssp

import (
	"crypto/rand"
	"fmt"
	"math/bits"
	"unsafe"
)

type AuthenticateMsg struct {
	Signature   [8]byte
	MessageType uint32

	LmChallengeResponseLen          uint16
	LmChallengeResponseMaxLen       uint16
	LmChallengeResponseBufferOffset uint32

	NtChallengeResponseLen          uint16
	NtChallengeResponseMaxLen       uint16
	NtChallengeResponseBufferOffset uint32

	DomainNameLen          uint16
	DomainNameMaxLen       uint16
	DomainNameBufferOffset uint32

	UserNameLen          uint16
	UserNameMaxLen       uint16
	UserNameBufferOffset uint32

	WorkstationLen          uint16
	WorkstationMaxLen       uint16
	WorkstationBufferOffset uint32

	EncryptedRandomSessionKeyLen          uint16
	EncryptedRandomSessionKeyMaxLen       uint16
	EncryptedRandomSessionKeyBufferOffset uint32

	NegotiateFlags uint32
	// Version is variable
	// Version        [8]byte

	// The MIC field is omitted in Windows NT, Windows 2000, Windows XP, and Windows Server 2003.
	// MIC     [16]byte
	Payload []byte

	offset uint32
	ptr    uint32
}

func (am AuthenticateMsg) Display() {
	fmt.Println("Authenticate Message (type3)")
	fmt.Printf("Signature: %v (%s)\n", am.Signature[:], am.Signature[:])
	fmt.Printf("MessageType: %x\n", am.MessageType)

	fmt.Printf("Response Version: ")
	if am.NtChallengeResponseLen <= 24 {
		if am.NegotiateFlags&NEGOTIATE_EXTENDED_SESSION_SECURITY != 0 {
			fmt.Println("NTLMv2 Session")
		} else {
			fmt.Println("NTLMv1")
		}
	} else {
		fmt.Println("NTLMv2")
	}

	fmt.Printf("LmChallengeResponse: %x\n", am.LmChallengeResponse())
	fmt.Printf("    (Len: %d  Offset: %d)\n", am.LmChallengeResponseLen, am.LmChallengeResponseBufferOffset)

	ntresp := am.NtChallengeResponse()
	if ntv2, ok := ntresp.(*NTLMv2Response); ok {
		fmt.Printf("NtChallengeResponse: %x\n", am.NtChallengeResponseBytes())
		fmt.Printf("    (Len: %d  offset: %d)\n",
			am.NtChallengeResponseLen, am.NtChallengeResponseBufferOffset)
		fmt.Printf("    Response: %x\n", ntv2.Response)
		fmt.Printf("    NTLMv2ClientChallenge: \n")
		fmt.Printf("      ChallengeFromClient: %x\n", ntv2.ClientChallenge.ChallengeFromClient)
		fmt.Printf("      RespType: %d\n", ntv2.ClientChallenge.RespType)
		fmt.Printf("      HiRespType: %d\n", ntv2.ClientChallenge.HiRespType)
		fmt.Printf("      TimeStamp: %d\n", ntv2.ClientChallenge.TimeStamp)
		fmt.Printf("      AVPair: \n")
		for k, v := range ntv2.ClientChallenge.AVPair {
			fmt.Printf("        %s: %v\n", k, v)
		}
	} else {
		fmt.Printf("NtChallengeResponse: %x\n", ntresp.(*NTLMResponse).Response)
		fmt.Printf("    (Len: %d  Offset: %d)\n", am.NtChallengeResponseLen, am.NtChallengeResponseBufferOffset)
	}

	fmt.Printf("DomainName: %s\n", am.DomainName())
	fmt.Printf("    (Len: %d  Offset: %d)\n", am.DomainNameLen, am.DomainNameBufferOffset)

	fmt.Printf("UserName: %s\n", am.UserName())
	fmt.Printf("    (Len: %d  Offset: %d)\n", am.UserNameLen, am.UserNameBufferOffset)

	fmt.Printf("Workstation: %s\n", am.Workstation())
	fmt.Printf("    (Len: %d  Offset: %d)\n", am.WorkstationLen, am.WorkstationBufferOffset)

	fmt.Printf("EncryptedRandomSessionKey: %v\n", am.EncryptedRandomSessionKey())
	fmt.Printf("    (Len: %d  Offset: %d)\n", am.EncryptedRandomSessionKeyLen, am.EncryptedRandomSessionKeyBufferOffset)
	DisplayNegotiateFlags(am.NegotiateFlags)
	fmt.Println()
}

func (am *AuthenticateMsg) UnMarshal(bs []byte) {
	copy(am.Signature[:], bs[:8])
	am.MessageType = uint32(bytes2Uint(bs[8:12], '<'))

	am.LmChallengeResponseLen = uint16(bytes2Uint(bs[12:14], '<'))
	am.LmChallengeResponseMaxLen = uint16(bytes2Uint(bs[14:16], '<'))
	am.LmChallengeResponseBufferOffset = uint32(bytes2Uint(bs[16:20], '<'))

	am.NtChallengeResponseLen = uint16(bytes2Uint(bs[20:22], '<'))
	am.NtChallengeResponseMaxLen = uint16(bytes2Uint(bs[22:24], '<'))
	am.NtChallengeResponseBufferOffset = uint32(bytes2Uint(bs[24:28], '<'))

	am.DomainNameLen = uint16(bytes2Uint(bs[28:30], '<'))
	am.DomainNameMaxLen = uint16(bytes2Uint(bs[30:32], '<'))
	am.DomainNameBufferOffset = uint32(bytes2Uint(bs[32:36], '<'))

	am.UserNameLen = uint16(bytes2Uint(bs[36:38], '<'))
	am.UserNameMaxLen = uint16(bytes2Uint(bs[38:40], '<'))
	am.UserNameBufferOffset = uint32(bytes2Uint(bs[40:44], '<'))

	am.WorkstationLen = uint16(bytes2Uint(bs[44:46], '<'))
	am.WorkstationMaxLen = uint16(bytes2Uint(bs[46:48], '<'))
	am.WorkstationBufferOffset = uint32(bytes2Uint(bs[48:52], '<'))

	am.EncryptedRandomSessionKeyLen = uint16(bytes2Uint(bs[52:54], '<'))
	am.EncryptedRandomSessionKeyMaxLen = uint16(bytes2Uint(bs[54:56], '<'))
	am.EncryptedRandomSessionKeyBufferOffset = uint32(bytes2Uint(bs[56:60], '<'))

	am.NegotiateFlags = uint32(bytes2Uint(bs[60:64], '<'))
	am.offset = 64
	am.ptr = 64

	plen := 0
	if am.LmChallengeResponseBufferOffset != 0 && am.LmChallengeResponseLen != 0 {
		plen += int(am.LmChallengeResponseLen)
	}
	if am.NtChallengeResponseBufferOffset != 0 && am.NtChallengeResponseLen != 0 {
		plen += int(am.NtChallengeResponseLen)
	}
	if am.DomainNameBufferOffset != 0 && am.DomainNameLen != 0 {
		plen += int(am.DomainNameLen)
	}
	if am.UserNameBufferOffset != 0 && am.UserNameLen != 0 {
		plen += int(am.UserNameLen)
	}
	if am.WorkstationBufferOffset != 0 && am.WorkstationLen != 0 {
		plen += int(am.WorkstationLen)
	}
	if am.EncryptedRandomSessionKeyBufferOffset != 0 && am.EncryptedRandomSessionKeyLen != 0 {
		plen += int(am.EncryptedRandomSessionKeyLen)
	}

	if am.NegotiateFlags&NEGOTIATE_VERSION != 0 {
		plen += 8

		// Detect if there is MIC field
		if am.LmChallengeResponseBufferOffset > 72 &&
			am.NtChallengeResponseBufferOffset > 72 &&
			am.UserNameBufferOffset > 72 &&
			am.EncryptedRandomSessionKeyBufferOffset > 72 &&
			am.DomainNameBufferOffset > 72 &&
			am.WorkstationBufferOffset > 72 {
			plen += 16
		}
	} else {
		if am.LmChallengeResponseBufferOffset > 64 &&
			am.NtChallengeResponseBufferOffset > 64 &&
			am.UserNameBufferOffset > 64 &&
			am.EncryptedRandomSessionKeyBufferOffset > 64 &&
			am.DomainNameBufferOffset > 64 &&
			am.WorkstationBufferOffset > 64 {
			plen += 16
		}
	}

	am.Payload = make([]byte, plen)
	copy(am.Payload, bs[am.offset:am.offset+uint32(plen)])
}

func (am AuthenticateMsg) Marshal(endian byte) []byte {
	bs := []byte{}
	if endian == '>' {
		am.MessageType = bits.ReverseBytes32(am.MessageType)
		am.NegotiateFlags = bits.ReverseBytes32(am.NegotiateFlags)

		am.LmChallengeResponseLen = bits.ReverseBytes16(am.LmChallengeResponseLen)
		am.LmChallengeResponseMaxLen = bits.ReverseBytes16(am.LmChallengeResponseMaxLen)
		am.LmChallengeResponseBufferOffset = bits.ReverseBytes32(am.LmChallengeResponseBufferOffset)

		am.NtChallengeResponseLen = bits.ReverseBytes16(am.NtChallengeResponseLen)
		am.NtChallengeResponseMaxLen = bits.ReverseBytes16(am.NtChallengeResponseMaxLen)
		am.NtChallengeResponseBufferOffset = bits.ReverseBytes32(am.NtChallengeResponseBufferOffset)

		am.DomainNameLen = bits.ReverseBytes16(am.DomainNameLen)
		am.DomainNameMaxLen = bits.ReverseBytes16(am.DomainNameMaxLen)
		am.DomainNameBufferOffset = bits.ReverseBytes32(am.DomainNameBufferOffset)

		am.UserNameLen = bits.ReverseBytes16(am.UserNameLen)
		am.UserNameMaxLen = bits.ReverseBytes16(am.UserNameMaxLen)
		am.UserNameBufferOffset = bits.ReverseBytes32(am.UserNameBufferOffset)

		am.WorkstationLen = bits.ReverseBytes16(am.WorkstationLen)
		am.WorkstationMaxLen = bits.ReverseBytes16(am.WorkstationMaxLen)
		am.WorkstationBufferOffset = bits.ReverseBytes32(am.WorkstationBufferOffset)

		am.EncryptedRandomSessionKeyLen = bits.ReverseBytes16(am.EncryptedRandomSessionKeyLen)
		am.EncryptedRandomSessionKeyMaxLen = bits.ReverseBytes16(am.EncryptedRandomSessionKeyMaxLen)
		am.EncryptedRandomSessionKeyBufferOffset = bits.ReverseBytes32(am.EncryptedRandomSessionKeyBufferOffset)
	}

	bs = append(bs, am.Signature[:]...)

	bs = append(bs, (*(*[4]byte)(unsafe.Pointer(&am.MessageType)))[:]...)

	bs = append(bs, (*(*[2]byte)(unsafe.Pointer(&am.LmChallengeResponseLen)))[:]...)
	bs = append(bs, (*(*[2]byte)(unsafe.Pointer(&am.LmChallengeResponseMaxLen)))[:]...)
	bs = append(bs, (*(*[4]byte)(unsafe.Pointer(&am.LmChallengeResponseBufferOffset)))[:]...)

	bs = append(bs, (*(*[2]byte)(unsafe.Pointer(&am.NtChallengeResponseLen)))[:]...)
	bs = append(bs, (*(*[2]byte)(unsafe.Pointer(&am.NtChallengeResponseMaxLen)))[:]...)
	bs = append(bs, (*(*[4]byte)(unsafe.Pointer(&am.NtChallengeResponseBufferOffset)))[:]...)

	bs = append(bs, (*(*[2]byte)(unsafe.Pointer(&am.DomainNameLen)))[:]...)
	bs = append(bs, (*(*[2]byte)(unsafe.Pointer(&am.DomainNameMaxLen)))[:]...)
	bs = append(bs, (*(*[4]byte)(unsafe.Pointer(&am.DomainNameBufferOffset)))[:]...)

	bs = append(bs, (*(*[2]byte)(unsafe.Pointer(&am.UserNameLen)))[:]...)
	bs = append(bs, (*(*[2]byte)(unsafe.Pointer(&am.UserNameMaxLen)))[:]...)
	bs = append(bs, (*(*[4]byte)(unsafe.Pointer(&am.UserNameBufferOffset)))[:]...)

	bs = append(bs, (*(*[2]byte)(unsafe.Pointer(&am.WorkstationLen)))[:]...)
	bs = append(bs, (*(*[2]byte)(unsafe.Pointer(&am.WorkstationMaxLen)))[:]...)
	bs = append(bs, (*(*[4]byte)(unsafe.Pointer(&am.WorkstationBufferOffset)))[:]...)

	bs = append(bs, (*(*[2]byte)(unsafe.Pointer(&am.EncryptedRandomSessionKeyLen)))[:]...)
	bs = append(bs, (*(*[2]byte)(unsafe.Pointer(&am.EncryptedRandomSessionKeyMaxLen)))[:]...)
	bs = append(bs, (*(*[4]byte)(unsafe.Pointer(&am.EncryptedRandomSessionKeyBufferOffset)))[:]...)

	bs = append(bs, (*(*[4]byte)(unsafe.Pointer(&am.NegotiateFlags)))[:]...)
	bs = append(bs, am.Payload...)

	return bs
}

func NewAuthenticateMsg(bs []byte) *AuthenticateMsg {
	am := AuthenticateMsg{}
	if bs == nil {
		am.Signature = [8]byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}
		am.MessageType = 0x03
		am.offset = 64
		am.ptr = 64
	} else {
		am.UnMarshal(bs)
	}
	return &am
}

func (am AuthenticateMsg) LmChallengeResponse() []byte {
	if am.LmChallengeResponseLen == 0 {
		return nil
	}

	bs := am.Payload[am.LmChallengeResponseBufferOffset-am.offset : am.LmChallengeResponseBufferOffset-am.offset+uint32(am.LmChallengeResponseLen)]
	return bs
}

func (am AuthenticateMsg) NtChallengeResponse() interface{} {
	if am.NtChallengeResponseLen == 0 {
		return nil
	}

	bs := am.Payload[am.NtChallengeResponseBufferOffset-am.offset : am.NtChallengeResponseBufferOffset-am.offset+uint32(am.NtChallengeResponseLen)]

	var resp interface{}
	if len(bs) > 24 {
		// NTLMv2
		resp = ParseNTLMv2Response(bs)
	} else {
		arr := [24]byte{}
		copy(arr[:], bs[:24])
		resp = &NTLMResponse{
			Response: arr,
		}
	}
	return resp
}

func (am AuthenticateMsg) NtChallengeResponseBytes() []byte {
	if am.NtChallengeResponseLen == 0 {
		return nil
	}

	return am.Payload[am.NtChallengeResponseBufferOffset-am.offset : am.NtChallengeResponseBufferOffset-am.offset+uint32(am.NtChallengeResponseLen)]

}

func (am AuthenticateMsg) DomainName() string {
	if am.DomainNameLen == 0 {
		return ""
	}

	domain := am.Payload[am.DomainNameBufferOffset-am.offset : am.DomainNameBufferOffset-am.offset+uint32(am.DomainNameLen)]
	if am.NegotiateFlags&1 == 1 {
		return bytes2StringUTF16(domain)
	}
	return string(domain)
}

func (am AuthenticateMsg) DomainNameBytes() []byte {
	if am.DomainNameLen == 0 {
		return nil
	}

	return am.Payload[am.DomainNameBufferOffset-am.offset : am.DomainNameBufferOffset-am.offset+uint32(am.DomainNameLen)]
}

func (am AuthenticateMsg) UserName() string {
	if am.UserNameLen == 0 {
		return ""
	}
	uname := am.Payload[am.UserNameBufferOffset-am.offset : am.UserNameBufferOffset-am.offset+uint32(am.UserNameLen)]

	if am.NegotiateFlags&1 == 1 {
		return bytes2StringUTF16(uname)
	}
	return string(uname)
}

func (am AuthenticateMsg) UserNameBytes() []byte {
	if am.UserNameLen == 0 {
		return nil
	}
	return am.Payload[am.UserNameBufferOffset-am.offset : am.UserNameBufferOffset-am.offset+uint32(am.UserNameLen)]
}

func (am AuthenticateMsg) Workstation() string {
	if am.WorkstationLen == 0 {
		return ""
	}
	ws := am.Payload[am.WorkstationBufferOffset-am.offset : am.WorkstationBufferOffset-am.offset+uint32(am.WorkstationMaxLen)]

	if am.NegotiateFlags&1 == 1 {
		return bytes2StringUTF16(ws)
	}
	return string(ws)
}

func (am AuthenticateMsg) WorkstationBytes() []byte {
	if am.WorkstationLen == 0 {
		return nil
	}
	return am.Payload[am.WorkstationBufferOffset-am.offset : am.WorkstationBufferOffset-am.offset+uint32(am.WorkstationMaxLen)]

}

func (am AuthenticateMsg) EncryptedRandomSessionKey() []byte {
	if am.EncryptedRandomSessionKeyLen == 0 {
		return nil
	}
	return am.Payload[am.EncryptedRandomSessionKeyBufferOffset-am.offset : am.EncryptedRandomSessionKeyBufferOffset-am.offset+uint32(am.EncryptedRandomSessionKeyLen)]
}

func (am AuthenticateMsg) Version() []byte {
	if am.NegotiateFlags&NEGOTIATE_VERSION != 0 {
		return am.Payload[:8]
	} else {
		return nil
	}
}

func (am *AuthenticateMsg) SetUserName(uname []byte) {
	if am.UserNameLen != 0 {
		panic("Can't set UserName field repeatedly")
	}

	if am.NegotiateFlags&NEGOTIATE_UNICODE_CHARSET != 0 {
		am.UserNameLen = uint16(2 * len(uname))
		am.UserNameMaxLen = am.UserNameLen
		am.UserNameBufferOffset = am.ptr
		am.Payload = append(am.Payload, encodeUTF16LE(uname)...)
	} else {
		am.UserNameLen = uint16(len(uname))
		am.UserNameMaxLen = am.UserNameLen
		am.UserNameBufferOffset = am.ptr
		am.Payload = append(am.Payload, uname...)
	}

	am.ptr += uint32(am.UserNameLen)
}

func (am *AuthenticateMsg) SetDomainName(dname []byte) {
	if am.DomainNameLen != 0 {
		panic("Can't set DomainName field repeatedly")
	}

	if am.NegotiateFlags&NEGOTIATE_UNICODE_CHARSET != 0 {
		am.DomainNameLen = uint16(2 * len(dname))
		am.DomainNameMaxLen = am.DomainNameLen
		am.DomainNameBufferOffset = am.ptr
		am.Payload = append(am.Payload, encodeUTF16LE(dname)...)
	} else {
		am.DomainNameLen = uint16(len(dname))
		am.DomainNameMaxLen = am.DomainNameLen
		am.DomainNameBufferOffset = am.ptr
		am.Payload = append(am.Payload, dname...)
	}

	am.ptr += uint32(am.DomainNameLen)
}

func (am *AuthenticateMsg) SetWorkstation(ws []byte) {
	if am.WorkstationLen != 0 {
		panic("Can't set Workstation field repeatedly")
	}

	if am.NegotiateFlags&NEGOTIATE_UNICODE_CHARSET != 0 {
		am.WorkstationLen = uint16(2 * len(ws))
		am.WorkstationMaxLen = am.WorkstationLen
		am.WorkstationBufferOffset = am.ptr
		am.Payload = append(am.Payload, encodeUTF16LE(ws)...)
	} else {
		am.WorkstationLen = uint16(len(ws))
		am.WorkstationMaxLen = am.WorkstationLen
		am.WorkstationBufferOffset = am.ptr
		am.Payload = append(am.Payload, ws...)
	}

	am.ptr += uint32(am.WorkstationLen)
}

func (am *AuthenticateMsg) SetLmResponse(version int, challenge []byte, pwd []byte) {
	if am.LmChallengeResponseLen != 0 {
		panic("Can't set LmResponse field repeatedly")
	}

	var lmresp []byte
	if version == 1 {
		lmresp = ComputeLMResponse(challenge, LmHash(pwd))
	} else if version == 2 {
		usernameWithDomainOrServer := am.UserNameBytes()
		domain := am.DomainNameBytes()
		if len(domain) != 0 {
			usernameWithDomainOrServer = append(usernameWithDomainOrServer, domain...)
		} else {
			workstation := am.WorkstationBytes()
			if len(workstation) != 0 {
				usernameWithDomainOrServer = append(usernameWithDomainOrServer, workstation...)
			}
		}

		lmresp = ComputeLMv2Response(challenge, usernameWithDomainOrServer, NtHash(pwd), nil)
	}

	am.LmChallengeResponseLen = uint16(len(lmresp))
	am.LmChallengeResponseMaxLen = am.LmChallengeResponseLen
	am.LmChallengeResponseBufferOffset = am.ptr
	am.Payload = append(am.Payload, lmresp...)
	am.ptr += uint32(am.LmChallengeResponseLen)
}

func (am *AuthenticateMsg) SetNtResponse(version int, challenge []byte, pwd []byte) {
	if am.NtChallengeResponseLen != 0 {
		panic("Can't set NtResponse field repeatedly")
	}

	var ntresp []byte
	if version == 1 {
		ntresp = ComputeNTLMv1Response(challenge, NtHash(pwd))
	} else if version == 2 {
		usernameWithDomainOrServer := am.UserNameBytes()
		domain := am.DomainNameBytes()
		if len(domain) != 0 {
			usernameWithDomainOrServer = append(usernameWithDomainOrServer, domain...)
		} else {
			workstation := am.WorkstationBytes()
			if len(workstation) != 0 {
				usernameWithDomainOrServer = append(usernameWithDomainOrServer, workstation...)
			}
		}

		ntresp = ComputeNTLMv2Response(challenge, usernameWithDomainOrServer, NtHash(pwd), nil)
	}

	am.NtChallengeResponseLen = uint16(len(ntresp))
	am.NtChallengeResponseMaxLen = am.NtChallengeResponseLen
	am.NtChallengeResponseBufferOffset = am.ptr
	am.Payload = append(am.Payload, ntresp...)
	am.ptr += uint32(am.NtChallengeResponseLen)
}

func (am *AuthenticateMsg) SetNTLMResponse(version int, challenge []byte, pwd []byte) {
	if version == 1 && am.NegotiateFlags&NEGOTIATE_EXTENDED_SESSION_SECURITY != 0 {
		nonce := [24]byte{}
		rand.Read(nonce[:8])
		am.LmChallengeResponseLen = 24
		am.LmChallengeResponseMaxLen = 24
		am.LmChallengeResponseBufferOffset = am.ptr
		am.Payload = append(am.Payload, nonce[:]...)
		am.ptr += uint32(am.LmChallengeResponseLen)

		ntsresp := ComputeNTLMv2SessionResponse(challenge, nonce[:8], NtHash([]byte(pwd)))
		am.NtChallengeResponseLen = uint16(len(ntsresp))
		am.NtChallengeResponseMaxLen = am.NtChallengeResponseLen
		am.NtChallengeResponseBufferOffset = am.ptr
		am.Payload = append(am.Payload, ntsresp...)
		am.ptr += uint32(am.NtChallengeResponseLen)

	} else {
		am.SetLmResponse(version, challenge, pwd)
		am.SetNtResponse(version, challenge, pwd)
	}
}
