package main

import (
	"C"
	"fmt"
	"strings"
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

//export StartNeighborC
func StartNeighborC(listenPort C.int, targetPort C.int) int {
	err := startNeighborInternal(int(listenPort), int(targetPort))
	if err != nil {
		fmt.Println("StartNeighborC Error:", err)
		return 1
	}
	return 0
}

//export StopNeighborC
func StopNeighborC() {
	stopNeighborInternal()
}

//export ScanIPsC
func ScanIPsC(ipsC *C.char, port C.int, concurrency C.int, timeoutMs C.int) *C.char {
	ipsStr := C.GoString(ipsC)
	if ipsStr == "" {
		return C.CString("")
	}
	ips := strings.Split(ipsStr, ",")
	res := scanIPsInternal(ips, int(port), int(concurrency), int(timeoutMs))
	return C.CString(res)
}


