package ntlmssp

import (
	"crypto/rand"
	"fmt"
	"math/bits"
	"unsafe"
)

type ChallengeMsg struct {
	Signature   [8]byte
	MessageType uint32

	TargetNameLen          uint16
	TargetNameMaxLen       uint16
	TargetNameBufferOffset uint32

	NegotiateFlags  uint32
	ServerChallenge [8]byte
	Reserved        [8]byte

	TargetInfoLen          uint16
	TargetInfoMaxLen       uint16
	TargetInfoBufferOffset uint32

	// Version is variable
	// Version [8]byte
	Payload []byte

	offset uint32
	ptr    uint32
}

func (cm ChallengeMsg) Display() {
	fmt.Println("Challenge Message (type2)")
	fmt.Printf("Signature: %v (%s)\n", cm.Signature[:], cm.Signature[:])
	fmt.Printf("MessageType: %x\n", cm.MessageType)
	fmt.Printf("TargetName: %s\n", cm.TargetName())
	fmt.Printf("    (Len: %d  Offset: %d)\n", cm.TargetNameLen, cm.TargetNameBufferOffset)

	fmt.Printf("NegotiateFlags: %x\n", cm.NegotiateFlags)
	fmt.Println("NegotiateFlags Details:")
	DisplayNegotiateFlags(cm.NegotiateFlags)

	fmt.Printf("ServerChallenge: %x\n", cm.ServerChallenge)

	tinfo := ParseAVPair(cm.TargetInfo())
	fmt.Printf("TargetInfo: (Len: %d  Offset: %d)\n", cm.TargetInfoLen, cm.TargetInfoBufferOffset)
	for k, v := range tinfo {
		fmt.Printf("    %s: %v\n", k, v)
	}
	fmt.Println()
}

func (cm ChallengeMsg) Marshal(endian byte) []byte {
	bs := []byte{}
	if endian == '>' {
		cm.MessageType = bits.ReverseBytes32(cm.MessageType)
		cm.NegotiateFlags = bits.ReverseBytes32(cm.NegotiateFlags)

		cm.TargetNameLen = bits.ReverseBytes16(cm.TargetNameLen)
		cm.TargetNameMaxLen = bits.ReverseBytes16(cm.TargetNameMaxLen)
		cm.TargetNameBufferOffset = bits.ReverseBytes32(cm.TargetNameBufferOffset)

		cm.TargetInfoLen = bits.ReverseBytes16(cm.TargetInfoLen)
		cm.TargetInfoMaxLen = bits.ReverseBytes16(cm.TargetInfoMaxLen)
		cm.TargetInfoBufferOffset = bits.ReverseBytes32(cm.TargetInfoBufferOffset)
	}

	bs = append(bs, cm.Signature[:]...)

	bs = append(bs, (*(*[4]byte)(unsafe.Pointer(&cm.MessageType)))[:]...)

	bs = append(bs, (*(*[2]byte)(unsafe.Pointer(&cm.TargetNameLen)))[:]...)
	bs = append(bs, (*(*[2]byte)(unsafe.Pointer(&cm.TargetNameMaxLen)))[:]...)
	bs = append(bs, (*(*[4]byte)(unsafe.Pointer(&cm.TargetNameBufferOffset)))[:]...)

	bs = append(bs, (*(*[4]byte)(unsafe.Pointer(&cm.NegotiateFlags)))[:]...)
	bs = append(bs, cm.ServerChallenge[:]...)
	bs = append(bs, cm.Reserved[:]...)

	bs = append(bs, (*(*[2]byte)(unsafe.Pointer(&cm.TargetInfoLen)))[:]...)
	bs = append(bs, (*(*[2]byte)(unsafe.Pointer(&cm.TargetInfoMaxLen)))[:]...)
	bs = append(bs, (*(*[4]byte)(unsafe.Pointer(&cm.TargetInfoBufferOffset)))[:]...)
	bs = append(bs, cm.Payload...)

	return bs
}

func (cm *ChallengeMsg) UnMarshal(bs []byte) {
	copy(cm.Signature[:], bs[:8])
	cm.MessageType = uint32(bytes2Uint(bs[8:12], '<'))

	cm.TargetNameLen = uint16(bytes2Uint(bs[12:14], '<'))
	cm.TargetNameMaxLen = uint16(bytes2Uint(bs[14:16], '<'))
	cm.TargetNameBufferOffset = uint32(bytes2Uint(bs[16:20], '<'))

	cm.NegotiateFlags = uint32(bytes2Uint(bs[20:24], '<'))
	copy(cm.ServerChallenge[:], bs[24:32])
	copy(cm.Reserved[:], bs[32:40])

	cm.TargetInfoLen = uint16(bytes2Uint(bs[40:42], '<'))
	cm.TargetInfoMaxLen = uint16(bytes2Uint(bs[42:44], '<'))
	cm.TargetInfoBufferOffset = uint32(bytes2Uint(bs[44:48], '<'))
	cm.offset = 48
	cm.ptr = 48

	plen := 0
	if cm.TargetNameBufferOffset != 0 && cm.TargetNameLen != 0 {
		plen += int(cm.TargetNameLen)
	}
	if cm.TargetInfoBufferOffset != 0 && cm.TargetInfoLen != 0 {
		plen += int(cm.TargetInfoLen)
	}

	if (cm.NegotiateFlags&NEGOTIATE_VERSION)>>25 == 1 {
		plen += 8
	}

	cm.Payload = make([]byte, plen)
	copy(cm.Payload, bs[cm.offset:cm.offset+uint32(plen)])
}

func NewChallengeMsg(bs []byte) *ChallengeMsg {
	cm := ChallengeMsg{}
	if bs == nil {
		cm.Signature = [8]byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}
		cm.MessageType = 0x02
		cm.offset = 48
		cm.ptr = 48
	} else {
		cm.UnMarshal(bs)
	}
	return &cm
}

func (cm ChallengeMsg) TargetName() string {
	if cm.TargetNameLen == 0 {
		return ""
	}
	tname := cm.Payload[cm.TargetNameBufferOffset-cm.offset : cm.TargetNameBufferOffset-cm.offset+uint32(cm.TargetNameLen)]

	if cm.NegotiateFlags&1 == 1 {
		return bytes2StringUTF16(tname)
	}
	return string(tname)
}

func (cm *ChallengeMsg) SetTargetName(tname []byte) {
	if cm.TargetNameLen != 0 {
		panic("Can't set TargetName field repeatedly")
	}

	if cm.NegotiateFlags&NEGOTIATE_UNICODE_CHARSET != 0 {
		cm.TargetNameLen = uint16(2 * len(tname))
		cm.TargetNameMaxLen = cm.TargetNameLen
		cm.TargetNameBufferOffset = cm.ptr
		cm.Payload = append(cm.Payload, encodeUTF16LE(tname)...)
	} else {
		cm.TargetNameLen = uint16(len(tname))
		cm.TargetNameMaxLen = cm.TargetNameLen
		cm.TargetNameBufferOffset = cm.ptr
		cm.Payload = append(cm.Payload, tname...)
	}

	cm.ptr += uint32(cm.TargetNameLen)
}

func (cm ChallengeMsg) TargetInfo() []byte {
	if cm.TargetInfoLen == 0 {
		return nil
	}
	return cm.Payload[cm.TargetInfoBufferOffset-cm.offset : cm.TargetInfoBufferOffset-cm.offset+uint32(cm.TargetInfoLen)]
}

func (cm *ChallengeMsg) SetTargetInfo(tinfo map[string]interface{}) {
	if cm.TargetInfoLen != 0 {
		panic("Can't set TargetInfo field repeatedly")
	}

	cm.NegotiateFlags |= NEGOTIATE_TARGET_INFO

	bs := []byte{}
	for k, v := range tinfo {
		if avIdsRev[k] == 0 {
			continue
		}
		bs = append(bs, avIdsRev[k], 0)

		if avIdsRev[k] != 6 && avIdsRev[k] != 7 && avIdsRev[k] != 8 && avIdsRev[k] != 10 {
			length := len(v.(string)) * 2
			bs = append(bs, byte(length&0xff), byte((length&0xff00)>>8))
			bs = append(bs, encodeUTF16LE([]byte(v.(string)))...)
		} else {
			length := len(v.([]byte))
			bs = append(bs, byte(length&0xff), byte((length&0xff00)>>8))
			bs = append(bs, v.([]byte)...)
		}
	}
	bs = append(bs, []byte{0, 0, 0, 0}...)

	cm.TargetInfoLen = uint16(len(bs))
	cm.TargetInfoMaxLen = cm.TargetInfoLen
	cm.TargetInfoBufferOffset = cm.ptr
	cm.Payload = append(cm.Payload, bs...)
	cm.ptr += uint32(cm.TargetInfoLen)
}

func (cm ChallengeMsg) Version() []byte {
	if cm.NegotiateFlags&NEGOTIATE_VERSION != 0 {
		return cm.Payload[:8]
	} else {
		return nil
	}
}

func (cm *ChallengeMsg) SetServerChallenge(challenge []byte) {
	if challenge == nil {
		rand.Read(cm.ServerChallenge[:])
	} else {
		copy(cm.ServerChallenge[:], challenge)
	}
}
