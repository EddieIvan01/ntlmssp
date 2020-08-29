package ntlmssp

import (
	"fmt"
	"math/bits"
	"unsafe"
)

const NegotiateMsgPayloadOffset = 32

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/
type NegotiateMsg struct {
	Signature      [8]byte
	MessageType    uint32
	NegotiateFlags uint32

	DomainNameLen          uint16
	DomainNameMaxLen       uint16
	DomainNameBufferOffset uint32

	WorkstationLen          uint16
	WorkstationMaxLen       uint16
	WorkstationBufferOffset uint32

	// Version is variable, saved in Payload field
	// Version [8]byte
	Payload []byte

	offset uint32
}

func (nm NegotiateMsg) Display() {
	fmt.Println("Negotiate Message (type1)")
	fmt.Printf("Signature: %v (%s)\n", nm.Signature[:], nm.Signature[:])
	fmt.Printf("MessageType: %x\n", nm.MessageType)
	fmt.Printf("NegotiateFlags: %x\n", nm.NegotiateFlags)
	fmt.Println("NegotiateFlags Details:")
	DisplayNegotiateFlags(nm.NegotiateFlags)
	fmt.Printf("DomainName: %s\n", nm.DomainName())
	fmt.Printf("    (Len: %d  Offset: %d)\n", nm.DomainNameLen, nm.DomainNameBufferOffset)
	fmt.Printf("Workstation: %s\n", nm.Workstation())
	fmt.Printf("    (Len: %d  Offset: %d)\n\n", nm.WorkstationLen, nm.WorkstationBufferOffset)
}

func (nm NegotiateMsg) Marshal(endian byte) []byte {
	bs := []byte{}

	// NTLMSSP is little endian
	if endian == '>' {
		nm.MessageType = bits.ReverseBytes32(nm.MessageType)
		nm.NegotiateFlags = bits.ReverseBytes32(nm.NegotiateFlags)

		nm.DomainNameLen = bits.ReverseBytes16(nm.DomainNameLen)
		nm.DomainNameMaxLen = bits.ReverseBytes16(nm.DomainNameMaxLen)
		nm.DomainNameBufferOffset = bits.ReverseBytes32(nm.DomainNameBufferOffset)

		nm.WorkstationLen = bits.ReverseBytes16(nm.WorkstationLen)
		nm.WorkstationMaxLen = bits.ReverseBytes16(nm.WorkstationMaxLen)
		nm.WorkstationBufferOffset = bits.ReverseBytes32(nm.WorkstationBufferOffset)
	}

	bs = append(bs, nm.Signature[:]...)

	bs = append(bs, (*(*[4]byte)(unsafe.Pointer(&nm.MessageType)))[:]...)
	bs = append(bs, (*(*[4]byte)(unsafe.Pointer(&nm.NegotiateFlags)))[:]...)

	bs = append(bs, (*(*[2]byte)(unsafe.Pointer(&nm.DomainNameLen)))[:]...)
	bs = append(bs, (*(*[2]byte)(unsafe.Pointer(&nm.DomainNameMaxLen)))[:]...)
	bs = append(bs, (*(*[4]byte)(unsafe.Pointer(&nm.DomainNameBufferOffset)))[:]...)

	bs = append(bs, (*(*[2]byte)(unsafe.Pointer(&nm.WorkstationLen)))[:]...)
	bs = append(bs, (*(*[2]byte)(unsafe.Pointer(&nm.WorkstationMaxLen)))[:]...)
	bs = append(bs, (*(*[4]byte)(unsafe.Pointer(&nm.WorkstationBufferOffset)))[:]...)
	bs = append(bs, nm.Payload...)

	return bs
}

func (nm *NegotiateMsg) UnMarshal(bs []byte) {
	copy(nm.Signature[:], bs[:8])
	nm.MessageType = uint32(bytes2Uint(bs[8:12], '<'))
	nm.NegotiateFlags = uint32(bytes2Uint(bs[12:16], '<'))

	nm.DomainNameLen = uint16(bytes2Uint(bs[16:18], '<'))
	nm.DomainNameMaxLen = uint16(bytes2Uint(bs[18:20], '<'))
	nm.DomainNameBufferOffset = uint32(bytes2Uint(bs[20:24], '<'))

	nm.WorkstationLen = uint16(bytes2Uint(bs[24:26], '<'))
	nm.WorkstationMaxLen = uint16(bytes2Uint(bs[26:28], '<'))
	nm.WorkstationBufferOffset = uint32(bytes2Uint(bs[28:32], '<'))

	nm.offset = NegotiateMsgPayloadOffset

	plen := 0
	if nm.DomainNameBufferOffset != 0 && nm.DomainNameLen != 0 {
		plen += int(nm.DomainNameLen)
	}
	if nm.WorkstationBufferOffset != 0 && nm.WorkstationLen != 0 {
		plen += int(nm.WorkstationLen)
	}

	if nm.NegotiateFlags&NEGOTIATE_VERSION != 0 {
		plen += 8
	}

	nm.Payload = make([]byte, plen)
	copy(nm.Payload, bs[NegotiateMsgPayloadOffset:NegotiateMsgPayloadOffset+uint32(plen)])
}

func NewNegotiateMsg(bs []byte) *NegotiateMsg {
	nm := NegotiateMsg{}
	if bs == nil {
		nm.Signature = [8]byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}
		nm.MessageType = 0x01
		nm.offset = NegotiateMsgPayloadOffset
	} else {
		nm.UnMarshal(bs)
	}
	return &nm
}

// Must be OEM charset
func (nm NegotiateMsg) DomainName() string {
	if nm.DomainNameLen == 0 {
		return ""
	}
	return string(nm.Payload[nm.DomainNameBufferOffset-NegotiateMsgPayloadOffset : nm.DomainNameBufferOffset-NegotiateMsgPayloadOffset+uint32(nm.DomainNameLen)])
}

// Must be OEM charset
func (nm NegotiateMsg) Workstation() string {
	if nm.WorkstationLen == 0 {
		return ""
	}
	return string(nm.Payload[nm.WorkstationBufferOffset-NegotiateMsgPayloadOffset : nm.WorkstationBufferOffset-NegotiateMsgPayloadOffset+uint32(nm.WorkstationLen)])
}

func (nm *NegotiateMsg) SetDomainName(dname []byte) {
	if nm.DomainNameLen != 0 {
		panic("Can't set DomainName field repeatedly")
	}

	nm.NegotiateFlags |= NEGOTIATE_OEM_DOMAIN_SUPPLIED

	nm.DomainNameLen = uint16(len(dname))
	nm.DomainNameMaxLen = nm.DomainNameLen
	nm.DomainNameBufferOffset = nm.offset
	nm.Payload = append(nm.Payload, dname...)
	nm.offset += uint32(nm.DomainNameLen)
}

func (nm *NegotiateMsg) SetWorkstation(ws []byte) {
	if nm.WorkstationLen != 0 {
		panic("Can't set Workstation field repeatedly")
	}

	nm.NegotiateFlags |= NEGOTIATE_OEM_WORKSTATION_SUPPLIED

	nm.WorkstationLen = uint16(len(ws))
	nm.WorkstationMaxLen = nm.WorkstationLen
	nm.WorkstationBufferOffset = nm.offset
	nm.Payload = append(nm.Payload, ws...)
	nm.offset += uint32(nm.WorkstationLen)
}

func (nm NegotiateMsg) Version() []byte {
	if nm.NegotiateFlags&NEGOTIATE_VERSION != 0 {
		return nm.Payload[:8]
	} else {
		return nil
	}
}

func (nm *NegotiateMsg) Reset() {
	nm.Payload = nil
	nm.offset = NegotiateMsgPayloadOffset
}
