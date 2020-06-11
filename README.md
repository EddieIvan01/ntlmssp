# NTLMSSP

Windows NTLMSSP library written in Go.

This library has very few wrapper and error handling. Read source code and make sure you understand the Windows NTLM before using this library.

## Usage

### Parse binary

```go
bs, _ := base64.StdEncoding.DecodeString("TlRMTVNTUAADAAAAGAAYAFAAAAAwADAAaAAAAAYABgBKAAAACgAKAEAAAAAAAAAAAAAAAAAAAAAAAAAABTCJoGEAZABtAGkAbgBMAEEAQgDKWtAQahWyLGUi6N0I3Y89TQ//e2QL4SPYLBXpg00OEIk5edtauBUdAQEAAAAAAAArN+A/oD/WAQRU5zwV4quKAAAAAAAAAAA=")
type3 := ntlmssp.NewAuthenticateMsg(bs)
type3.Display()
```

OUTPUT:

```
Authenticate Message (type3)
Signature: [78 84 76 77 83 83 80 0] (NTLMSSP)
MessageType: 3
Response Version: NTLMv2
LmChallengeResponse: ca5ad0106a15b22c6522e8dd08dd8f3d4d0fff7b640be123
    (Len: 24  Offset: 80)
NtChallengeResponse: d82c15e9834d0e10893979db5ab8151d01010000000000002b37e03fa03fd6010454e73c15e2ab8a0000000000000000
    (Len: 48  offset: 104)
    Response: d82c15e9834d0e10893979db5ab8151d
    NTLMv2ClientChallenge:
      ChallengeFromClient: 0454e73c15e2ab8a
      RespType: 1
      HiRespType: 1
      TimeStamp: 132363196552984363
      AVPair:
DomainName: LAB
    (Len: 6  Offset: 74)
UserName: admin
    (Len: 10  Offset: 64)
Workstation:
    (Len: 0  Offset: 0)
EncryptedRandomSessionKey: []
    (Len: 0  Offset: 0)
1... .... .... .... .... .... .... ....   NEGOTIATE_56BIT_ENCRYPTION: Set
.0.. .... .... .... .... .... .... ....   NEGOTIATE_EXPLICIT_KEY_EXCHANGE: Not set
..1. .... .... .... .... .... .... ....   NEGOTIATE_128BIT_SESSION_KEY: Set
...0 .... .... .... .... .... .... ....   NEGOTIATE_R1_UNUSED: Not set
.... 0... .... .... .... .... .... ....   NEGOTIATE_R2_UNUSED: Not set
.... .0.. .... .... .... .... .... ....   NEGOTIATE_R3_UNUSED: Not set
.... ..0. .... .... .... .... .... ....   NEGOTIATE_VERSION: Not set
.... ...0 .... .... .... .... .... ....   NEGOTIATE_R4_UNUSED: Not set
.... .... 1... .... .... .... .... ....   NEGOTIATE_REQUEST_TARGET_INFO: Set
.... .... .0.. .... .... .... .... ....   NEGOTIATE_REQUEST_NON_NT_SESSION_KEY: Not set
.... .... ..0. .... .... .... .... ....   NEGOTIATE_R5_UNUSED: Not set
.... .... ...0 .... .... .... .... ....   NEGOTIATE_IDENTITY_LEVEL_TOKEN: Not set
.... .... .... 1... .... .... .... ....   NEGOTIATE_EXTENDED_SESSION_SECURITY: Set
.... .... .... .0.. .... .... .... ....   NEGOTIATE_R6_UNUSED: Not set
.... .... .... ..0. .... .... .... ....   NEGOTIATE_TARGET_TYPE_SERVER: Not set
.... .... .... ...1 .... .... .... ....   NEGOTIATE_TARGET_TYPE_DOMAIN: Set
.... .... .... .... 0... .... .... ....   NEGOTIATE_ALWAYS_SIGN: Not set
.... .... .... .... .0.. .... .... ....   NEGOTIATE_R7_UNUSED: Not set
.... .... .... .... ..1. .... .... ....   NEGOTIATE_OEM_WORKSTATION_SUPPLIED: Set
.... .... .... .... ...1 .... .... ....   NEGOTIATE_OEM_DOMAIN_SUPPLIED: Set
.... .... .... .... .... 0... .... ....   NEGOTIATE_ANONYMOUS: Not set
.... .... .... .... .... .0.. .... ....   NEGOTIATE_R8_UNUSED: Not set
.... .... .... .... .... ..0. .... ....   NEGOTIATE_NTLM: Not set
.... .... .... .... .... ...0 .... ....   NEGOTIATE_R9_UNUSED: Not set
.... .... .... .... .... .... 0... ....   NEGOTIATE_LM_SESSION_KEY: Not set
.... .... .... .... .... .... .0.. ....   NEGOTIATE_DATAGRAM_CONNECTIONLESS: Not set
.... .... .... .... .... .... ..0. ....   NEGOTIATE_SEAL: Not set
.... .... .... .... .... .... ...0 ....   NEGOTIATE_SIGN: Not set
.... .... .... .... .... .... .... 0...   NEGOTIATE_R10_UNUSED: Not set
.... .... .... .... .... .... .... .1..   NEGOTIATE_REQUEST_TARGET_NAME: Set
.... .... .... .... .... .... .... ..0.   NEGOTIATE_OEM_CHARSET: Not set
.... .... .... .... .... .... .... ...1   NEGOTIATE_UNICODE_CHARSET: Set
```

### Generate NTLM message

```go
type2 := ntlmssp.NewChallengeMsg(nil)
type2.NegotiateFlags |= ntlmssp.NEGOTIATE_56BIT_ENCRYPTION |
    ntlmssp.NEGOTIATE_128BIT_SESSION_KEY |
    ntlmssp.NEGOTIATE_EXTENDED_SESSION_SECURITY |
    ntlmssp.NEGOTIATE_UNICODE_CHARSET
type2.SetTargetName([]byte("SMB"))
type2.SetServerChallenge([]byte("\x00\x11\x22\x33\x44\x55\x66\x77"))
type2.SetTargetInfo(map[string]interface{}{
    "MsvAvNbComputerName":  "WIN-123456",
    "MsvAvNbDomainName":    "XYZ.LAB",
    "MsvAvDnsComputerName": "DC$",
    "MsvAvDnsDomainName":   "XYZ.LAB",
})
fmt.Println(type2.Marshal('<'))
```

OUTPUT:

```go
[78 84 76 77 83 83 80 0 2 0 0 0 6 0 6 0 48 0 0 0 1 0 136 160 0 17 34 51 68 85 102 119 0 0 0 0 0 0 0 0 74 0 74 0 54 0 0 0 83 0 77 0 66 0 1 0 20 0 87 0 73 0 78 0 45 0 49 0 50 0 51 0 52 0 53 0 54 0 2 0 14 0 88 0 89 0 90 0 46 0 76 0 65 0 66 0 3 0 6 0 68 0 67 0 36 0 4 0 14 0 88 0 89 0 90 0 46 0 76 0 65 0 66 0 0 0 0 0]
```

## Example

+ [Local NTLM Negotiate](example/local_negotiate.go)
+ [Embed into HTTP protocol (server)](example/server.go)
+ [Embed into HTTP protocol (client)](example/client.go)

## Reference documents

+ https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/
+ http://davenport.sourceforge.net/ntlm.html
