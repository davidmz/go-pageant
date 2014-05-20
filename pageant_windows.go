/*
Package pageant is a small package for sending queries and receiving answers
to/from PyTTY pageant.exe utility.

This package is windows-only.
*/
package pageant

// see https://github.com/Yasushi/putty/blob/master/windows/winpgntc.c#L155
// see https://github.com/paramiko/paramiko/blob/master/paramiko/win_pageant.py

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	. "syscall"
	. "unsafe"
)

var (
	ErrPageantNotFound = errors.New("Pageant process not found")
	ErrMessageTooLong  = errors.New("Message too long")
	ErrSendMessage     = errors.New("Error sending message")
)

const (
	// Maximum size of the message can be sent to pageant
	MaxMessageLen = 8192 - 4
)

// IsActive returns true if Pageant process is active and can be queried.
func IsActive() bool {
	return 0 == getPageantWindow()
}

// Query sends message msg to Pageant and returns response or error.
func Query(msg []byte) ([]byte, error) {
	if len(msg) > MaxMessageLen {
		return nil, ErrMessageTooLong
	}

	paWin := getPageantWindow()
	if paWin == 0 {
		return nil, ErrPageantNotFound
	}

	thId, _, _ := MustLoadDLL("kernel32.dll").MustFindProc("GetCurrentThreadId").Call()
	mapName := fmt.Sprintf("PageantRequest%08x", thId)
	pMapName, _ := UTF16PtrFromString(mapName)

	mmap, err := CreateFileMapping(InvalidHandle, nil, PAGE_READWRITE, 0, MaxMessageLen+4, pMapName)
	if err != nil {
		return nil, err
	}
	defer CloseHandle(mmap)

	ptr, err := MapViewOfFile(mmap, FILE_MAP_WRITE, 0, 0, 0)
	if err != nil {
		return nil, err
	}

	mmSlice := (*(*[MaxMessageLen]byte)(Pointer(ptr)))[:]

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, uint32(len(msg)))
	binary.Write(buf, binary.BigEndian, msg)

	copy(mmSlice, buf.Bytes())

	cds := copyData{
		dwData: agentCopydataID,
		cbData: uint32(len(mapName) + 1),
		lpData: Pointer(&([]byte(mapName))[0]),
	}

	resp, _, _ := MustLoadDLL("user32.dll").MustFindProc("SendMessageW").Call(
		paWin,
		wmCopydata,
		0,
		uintptr(Pointer(&cds)),
	)
	if resp == 0 {
		return nil, ErrSendMessage
	}

	respLen := binary.BigEndian.Uint32(mmSlice[:4])
	respData := mmSlice[4 : respLen+4]

	return respData, nil
}

/////// Internals ////////

const (
	agentCopydataID = 0x804e50ba
	wmCopydata      = 74
)

type copyData struct {
	dwData uintptr
	cbData uint32
	lpData Pointer
}

func getPageantWindow() uintptr {
	nameP, _ := UTF16PtrFromString("Pageant")
	win, _, _ := MustLoadDLL("user32.dll").MustFindProc("FindWindowW").Call(
		uintptr(Pointer(nameP)),
		uintptr(Pointer(nameP)),
	)
	return win
}
