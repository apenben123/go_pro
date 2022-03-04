package playtoken

/*
#cgo CFLAGS: -Icpp
#cgo LDFLAGS: -Llib -lplaytoken
#include <stdlib.h>
#include "play_token.h"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func BentchCppTest(loops int64) {
	var i int64
	for i = 0; i < loops; i++ {
		CppTest(false)
	}
}

func CppTest(dbg bool) {
	//cplaytoken := C.CString("")
	cfilename := C.CString("test")
	cipaddr := C.CString("192.168.49.210")

	defer C.free(unsafe.Pointer(cfilename))
	defer C.free(unsafe.Pointer(cipaddr))
	cplaytoken := C.get_video_play_token_ver1(cipaddr, cfilename, 10, 1, 0)
	defer C.free(unsafe.Pointer(cplaytoken))
	s := C.GoString(cplaytoken)
	if dbg {
		fmt.Printf("cplaytoken addr = %v\n", &cplaytoken)
		fmt.Printf("cfilename addr = %v\n", &cfilename)
		fmt.Printf("cipaddr addr = %v\n", &cipaddr)
		fmt.Printf("s=%v\n", s)
	}
}
