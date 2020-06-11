package main

import (
	"encoding/base64"
	"fmt"
	"ntlmssp"

	"github.com/eddieivan01/nic"
)

var url = "http://127.0.0.1"

func client() {
	resp, err := nic.Post(url, nil)
	if err != nil || resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") != "NTLM" {
		fmt.Println("type1 error")
		return
	}

	type1 := ntlmssp.NewNegotiateMsg(nil)
	type1.NegotiateFlags |= ntlmssp.NEGOTIATE_OEM_DOMAIN_SUPPLIED |
		ntlmssp.NEGOTIATE_OEM_WORKSTATION_SUPPLIED |
		ntlmssp.NEGOTIATE_128BIT_SESSION_KEY |
		ntlmssp.NEGOTIATE_56BIT_ENCRYPTION |
		ntlmssp.NEGOTIATE_UNICODE_CHARSET |
		ntlmssp.NEGOTIATE_REQUEST_TARGET_NAME
	type1.SetDomainName([]byte("CC.LAB"))
	type1.SetWorkstation([]byte("WIN-123456"))
	type1.Display()

	resp, err = nic.Post(url, nic.H{
		Headers: nic.KV{
			"Authorization": "NTLM " + base64.StdEncoding.EncodeToString(type1.Marshal('<')),
		},
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	// trip "NTLM "
	bs, err := base64.StdEncoding.DecodeString(resp.Header.Get("WWW-Authenticate")[5:])
	if err != nil {
		fmt.Println("type2 error")
		return
	}
	type2 := ntlmssp.NewChallengeMsg(bs)
	type2.Display()

	type3 := ntlmssp.NewAuthenticateMsg(nil)
	type3.NegotiateFlags = type2.NegotiateFlags
	// type3.NegotiateFlags &^= ntlmssp.NEGOTIATE_EXTENDED_SESSION_SECURITY

	type3.SetUserName([]byte("admin"))
	type3.SetDomainName([]byte("LAB"))
	type3.SetNTLMResponse(2, type2.ServerChallenge[:], pwd)
	type3.Display()

	resp, err = nic.Post(url, nic.H{
		Headers: nic.KV{
			"Authorization": "NTLM " + base64.StdEncoding.EncodeToString(type3.Marshal('<')),
		},
	})

	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(resp.Text)
}
