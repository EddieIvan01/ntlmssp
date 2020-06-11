package ntlmssp

import "unsafe"

type LMResponse struct {
	Response [24]byte
}

type LMv2Response struct {
	Response            [16]byte
	ChallengeFromClient [8]byte
}

type NTLMResponse struct {
	Response [24]byte
}

type NTLMv2Response struct {
	Response        [16]byte
	ClientChallenge NTLMv2ClientChallenge
}

type NTLMv2ClientChallenge struct {
	RespType            byte
	HiRespType          byte
	Reserved1           uint16
	Reserved2           uint32
	TimeStamp           uint64
	ChallengeFromClient [8]byte
	Reserved3           uint32
	AVPair              map[string]interface{}
}

type NTLMv2SessionResponse struct {
	Response [24]byte
}

type AnonymousResponse struct {
}

func (cc NTLMv2ClientChallenge) Marshal() []byte {
	output := []byte{cc.RespType, cc.HiRespType}
	output = append(output, []byte{0, 0}...)
	output = append(output, []byte{0, 0, 0, 0}...)
	output = append(output, (*(*[8]byte)(unsafe.Pointer(&cc.TimeStamp)))[:]...)
	output = append(output, cc.ChallengeFromClient[:]...)
	output = append(output, []byte{0, 0, 0, 0}...)

	for k, v := range cc.AVPair {
		if avIdsRev[k] == 0 {
			continue
		}
		output = append(output, avIdsRev[k], 0)

		if avIdsRev[k] != 6 && avIdsRev[k] != 7 && avIdsRev[k] != 8 && avIdsRev[k] != 10 {
			length := len(v.(string)) * 2
			output = append(output, byte(length&0xff), byte((length&0xff00)>>8))
			output = append(output, encodeUTF16LE([]byte(v.(string)))...)
		} else {
			length := len(v.([]byte))
			output = append(output, byte(length&0xff), byte((length&0xff00)>>8))
			output = append(output, v.([]byte)...)
		}
	}
	output = append(output, []byte{0, 0, 0, 0}...)
	return output
}

func ParseNTLMv2Response(bs []byte) *NTLMv2Response {
	ntv2r := NTLMv2Response{}
	copy(ntv2r.Response[:], bs[:16])

	ntv2r.ClientChallenge.RespType = bs[16]
	ntv2r.ClientChallenge.HiRespType = bs[17]
	// skip 6
	ntv2r.ClientChallenge.TimeStamp = bytes2Uint(bs[24:32], '<')
	copy(ntv2r.ClientChallenge.ChallengeFromClient[:], bs[32:40])
	// skip 4
	ntv2r.ClientChallenge.AVPair = ParseAVPair(bs[44:])

	return &ntv2r
}
