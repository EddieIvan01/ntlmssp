package main

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"ntlmssp"
)

var challenge = []byte("\x00\x11\x22\x33\x44\x55\x66\x77")
var pwd = []byte("p4ssw0rd")

func handler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.WriteHeader(401)
		return
	}

	bs, err := base64.StdEncoding.DecodeString(auth[5:])
	if err != nil {
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.WriteHeader(401)
		w.Write([]byte("Malformed base64"))
		return
	}

	switch bs[8] {
	case 1:
		type1 := ntlmssp.NewNegotiateMsg(bs)
		type2 := ntlmssp.NewChallengeMsg(nil)

		type2.NegotiateFlags = type1.NegotiateFlags
		type2.NegotiateFlags &^= ntlmssp.NEGOTIATE_VERSION
		type2.NegotiateFlags |= ntlmssp.NEGOTIATE_EXTENDED_SESSION_SECURITY | ntlmssp.NEGOTIATE_TARGET_TYPE_DOMAIN
		type2.SetServerChallenge(challenge)
		type2.SetTargetName([]byte("XYZ.LAB"))

		type2.SetTargetInfo(map[string]interface{}{
			"MsvAvNbComputerName":  "WIN-123456",
			"MsvAvNbDomainName":    "XYZ.LAB",
			"MsvAvDnsComputerName": "DC$",
			"MsvAvDnsDomainName":   "XYZ.LAB",
		})

		w.Header().Set("WWW-Authenticate", "NTLM "+base64.StdEncoding.EncodeToString(type2.Marshal('<')))
		w.WriteHeader(401)
	case 3:
		type3 := ntlmssp.NewAuthenticateMsg(bs)
		ok := false
		if type3.NtChallengeResponseLen <= 24 {
			// NTLMv2 session
			if type3.NegotiateFlags&ntlmssp.NEGOTIATE_EXTENDED_SESSION_SECURITY != 0 {
				ntsResp := ntlmssp.ComputeNTLMv2SessionResponse(
					challenge,
					type3.LmChallengeResponse()[:8],
					ntlmssp.NtHash(pwd))
				if bytes.Equal(ntsResp, type3.NtChallengeResponseBytes()) {
					ok = true
				}
			} else {
				// NTLM
				ntResp := ntlmssp.ComputeNTLMv1Response(challenge, ntlmssp.NtHash(pwd))
				if bytes.Equal(ntResp, type3.NtChallengeResponseBytes()) {
					ok = true
				}
			}
		} else {
			// NTLMv2
			userNameWithDomainOrServer := type3.UserNameBytes()
			if type3.DomainNameLen != 0 {
				userNameWithDomainOrServer = append(userNameWithDomainOrServer, type3.DomainNameBytes()...)
			} else if type3.WorkstationLen != 0 {
				userNameWithDomainOrServer = append(userNameWithDomainOrServer, type3.WorkstationBytes()...)
			}

			ntResp := ntlmssp.ComputeNTLMv2Response(
				challenge,
				userNameWithDomainOrServer,
				ntlmssp.NtHash(pwd),
				type3.NtChallengeResponseBytes()[16:],
			)
			if bytes.Equal(ntResp, type3.NtChallengeResponseBytes()) {
				ok = true
			}
		}

		if ok {
			w.Write([]byte("OK"))
		} else {
			w.Write([]byte("Auth fail"))
		}
	default:
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.WriteHeader(401)
		w.Write([]byte("Malformed NTLMSSP"))
		return
	}
}

func server() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":80", nil)
}
