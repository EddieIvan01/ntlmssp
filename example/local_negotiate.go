package main

import (
	"fmt"
	"ntlmssp"
	"syscall"
	"unsafe"
)

var (
	username   = []byte("iv4n")
	password   = []byte("password")
	servername = []byte("PC")
)

var (
	security                  = syscall.NewLazyDLL("security.dll")
	acquireCredentialsHandleA = security.NewProc("AcquireCredentialsHandleA")
	acceptSecurityContext     = security.NewProc("AcceptSecurityContext")
)

const (
	SEC_E_OK              = 0x00
	SEC_I_CONTINUE_NEEDED = 0x90312
	SEC_E_LOGON_DENIED    = 0x8009030c
	SEC_E_INVALID_TOKEN   = 0x80090308

	SECPKG_CRED_INBOUND = 0x01

	SECBUFFER_TOKEN   = 2
	SECBUFFER_VERSION = 0

	ASC_REQ_ALLOCATE_MEMORY = 0x100
	ASC_REQ_CONNECTION      = 0x800

	SECURITY_NATIVE_DREP = 0x10
)

type (
	secHandle struct {
		dwLower uint64
		dwUpper uint64
	}
	credHandle secHandle
	ctxtHandle secHandle

	timeStamp struct {
		LowPart  uint32
		HighPart uint32
	}

	secBuffer struct {
		cbBuffer   uint32 // Size of the buffer, in bytes
		BufferType uint32 // Type of the buffer (below)

		pvBuffer uintptr // Pointer to the buffer
	}

	secBufferDesc struct {
		ulVersion uint32 // Version number
		cBuffers  uint32 // Number of buffers

		pBuffers *secBuffer // Pointer to array of buffers
	}
)

func localNegotiate() {
	lpPackageName := []byte("Negotiate")
	hCredential := credHandle{}
	time := timeStamp{}

	ret, _, err := acquireCredentialsHandleA.Call(
		0,
		(uintptr)(unsafe.Pointer(&lpPackageName[0])),
		SECPKG_CRED_INBOUND,
		0, 0, 0, 0,
		(uintptr)(unsafe.Pointer(&hCredential)),
		(uintptr)(unsafe.Pointer(&time)),
	)
	if ret != SEC_E_OK {
		fmt.Println(err)
		return
	}

	hContext := ctxtHandle{}
	secBufClient := secBuffer{}
	secBufDescClient := secBufferDesc{}
	initTokenContextBuffer(&secBufDescClient, &secBufClient)

	type1 := ntlmssp.NewNegotiateMsg(nil)
	type1.NegotiateFlags |= ntlmssp.NEGOTIATE_128BIT_SESSION_KEY |
		ntlmssp.NEGOTIATE_56BIT_ENCRYPTION |
		ntlmssp.NEGOTIATE_UNICODE_CHARSET |
		ntlmssp.NEGOTIATE_EXTENDED_SESSION_SECURITY

	bs := type1.Marshal('<')
	secBufClient.cbBuffer = uint32(len(bs))
	secBufClient.pvBuffer = (uintptr)(unsafe.Pointer(&bs[0]))

	secBufServer := secBuffer{}
	secBufDescServer := secBufferDesc{}
	initTokenContextBuffer(&secBufDescServer, &secBufServer)

	var fContextAttr uint32
	var tsExpiry timeStamp

	ret, _, err = acceptSecurityContext.Call(
		(uintptr)(unsafe.Pointer(&hCredential)),
		0,
		(uintptr)(unsafe.Pointer(&secBufDescClient)),
		ASC_REQ_ALLOCATE_MEMORY|ASC_REQ_CONNECTION,
		SECURITY_NATIVE_DREP,
		(uintptr)(unsafe.Pointer(&hContext)),
		(uintptr)(unsafe.Pointer(&secBufDescServer)),
		(uintptr)(unsafe.Pointer(&fContextAttr)),
		(uintptr)(unsafe.Pointer(&tsExpiry)),
	)
	if ret != SEC_I_CONTINUE_NEEDED {
		fmt.Println(err)
		return
	}
	type2 := ntlmssp.NewChallengeMsg(loadByteArray(secBufServer.pvBuffer, secBufServer.cbBuffer))
	type2.Display()

	type3 := ntlmssp.NewAuthenticateMsg(nil)
	type3.NegotiateFlags = type2.NegotiateFlags
	// type3.NegotiateFlags &^= ntlmssp.NEGOTIATE_EXTENDED_SESSION_SECURITY
	type3.SetUserName(username)
	type3.SetWorkstation(servername)
	type3.SetNTLMResponse(1, type2.ServerChallenge[:], password)
	type3.Display()
	bs = type3.Marshal('<')

	initTokenContextBuffer(&secBufDescClient, &secBufClient)
	secBufClient.pvBuffer = (uintptr)(unsafe.Pointer(&bs[0]))
	secBufClient.cbBuffer = uint32(len(bs))
	initTokenContextBuffer(&secBufDescServer, &secBufServer)

	ret, _, err = acceptSecurityContext.Call(
		(uintptr)(unsafe.Pointer(&hCredential)),
		(uintptr)(unsafe.Pointer(&hContext)),
		(uintptr)(unsafe.Pointer(&secBufDescClient)),
		ASC_REQ_ALLOCATE_MEMORY|ASC_REQ_CONNECTION,
		SECURITY_NATIVE_DREP,
		(uintptr)(unsafe.Pointer(&hContext)),
		(uintptr)(unsafe.Pointer(&secBufDescServer)),
		(uintptr)(unsafe.Pointer(&fContextAttr)),
		(uintptr)(unsafe.Pointer(&tsExpiry)),
	)

	if ret == SEC_E_INVALID_TOKEN {
		fmt.Println("NTLM auth error,", err)
	}

	if ret == SEC_E_LOGON_DENIED {
		fmt.Println("Username or password wrong,", err)
		return
	}

	if ret == SEC_E_OK {
		fmt.Println("Auth ok,", err)
	}
}

func initTokenContextBuffer(bufDesc *secBufferDesc, buf *secBuffer) {
	buf.BufferType = SECBUFFER_TOKEN
	buf.cbBuffer = 0
	buf.pvBuffer = 0

	bufDesc.ulVersion = SECBUFFER_VERSION
	bufDesc.cBuffers = 1
	bufDesc.pBuffers = buf
}

func loadByteArray(addr uintptr, length uint32) []byte {
	// I don't know the length while compiling
	output := (*[512]byte)(unsafe.Pointer(addr))
	return (*output)[:length]
}
