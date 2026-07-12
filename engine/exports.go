package main

import (
	"C"
	"fmt"
)

//export StartXrayC
func StartXrayC(configPath *C.char) int {
	err := startXrayInternal(C.GoString(configPath))
	if err != nil {
		fmt.Println("StartXrayC Error:", err)
		return 1
	}
	return 0
}

//export StopXrayC
func StopXrayC() {
	stopXrayInternal()
}

//export StartSingBoxC
func StartSingBoxC(configPath *C.char) int {
	err := startSingBoxInternal(C.GoString(configPath))
	if err != nil {
		return 1
	}
	return 0
}

//export StopSingBoxC
func StopSingBoxC() {
	stopSingBoxInternal()
}

//export StartSNIC
func StartSNIC(configPath *C.char) int {
	err := startSNIInternal(C.GoString(configPath))
	if err != nil {
		return 1
	}
	return 0
}

//export StopSNIC
func StopSNIC() {
	stopSNIInternal()
}

//export StartMHRVC
func StartMHRVC(port C.int, ids *C.char) int {
	err := startMHRVInternal(int(port), C.GoString(ids))
	if err != nil {
		return 1
	}
	return 0
}

//export StopMHRVC
func StopMHRVC() {
	stopMHRVInternal()
}
