package ntlmssp

import (
	"bytes"
	"crypto/rand"
	"time"
)

func ComputeLMResponse(challenge []byte, lmhash []byte) []byte {
	lmhash = append(lmhash, []byte{0, 0, 0, 0, 0}...)

	output := append(desEnc(padding(lmhash[:7]), challenge), desEnc(padding(lmhash[7:14]), challenge)...)
	output = append(output, desEnc(padding(lmhash[14:]), challenge)...)
	return output
}

func ComputeLMv2Response(challenge []byte, usernameWithDomainOrServer []byte, nthash []byte, clientNonce []byte) []byte {
	if clientNonce == nil {
		clientNonce = make([]byte, 8)
		rand.Read(clientNonce)
	}
	hsh := hmacMd5(nthash, bytes.ToUpper(usernameWithDomainOrServer))
	return append(hmacMd5(hsh, append(challenge, clientNonce...)), clientNonce...)
}

func ComputeNTLMv1Response(challenge []byte, nthash []byte) []byte {
	return ComputeLMResponse(challenge, nthash)
}

func ComputeNTLMv2Response(challenge []byte, usernameWithDomainOrServer []byte, nthash []byte, clientChallenge []byte) []byte {
	if clientChallenge == nil {
		nonce := [8]byte{}
		rand.Read(nonce[:])
		cc := NTLMv2ClientChallenge{
			RespType:            1,
			HiRespType:          1,
			Reserved1:           0,
			Reserved2:           0,
			TimeStamp:           (uint64(time.Now().UnixNano()) / 100) + 116444736000000000,
			ChallengeFromClient: nonce,
			Reserved3:           0,
			AVPair:              nil,
		}
		clientChallenge = cc.Marshal()
	}
	return ComputeLMv2Response(challenge, usernameWithDomainOrServer, nthash, clientChallenge)
}

func ComputeNTLMv2SessionResponse(challenge []byte, clientNonce []byte, nthash []byte) []byte {
	if clientNonce == nil {
		clientNonce = make([]byte, 8)
		rand.Read(clientNonce)
	}

	sessionHash := md5Hash(append(challenge, clientNonce...))[:8]
	nthash = append(nthash, []byte{0, 0, 0, 0, 0}...)
	output := append(desEnc(padding(nthash[:7]), sessionHash), desEnc(padding(nthash[7:14]), sessionHash)...)
	return append(output, desEnc(padding(nthash[14:21]), sessionHash)...)
}
