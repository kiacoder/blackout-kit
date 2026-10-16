package main

import (
	"C"
	"fmt"
	"strings"
)

//export StartXrayC
func StartXrayC(configPath *C.char) int {
	err := safeCall("StartXrayC", func() error {
		return startXrayInternal(C.GoString(configPath))
	})
	if err != nil {
		fmt.Println("StartXrayC Error:", err)
		return 1
	}
	return 0
}

//export StopXrayC
func StopXrayC() {
	if err := safeCall("StopXrayC", func() error {
		stopXrayInternal()
		return nil
	}); err != nil {
		fmt.Println("StopXrayC Error:", err)
	}
}

//export StartSingBoxC
func StartSingBoxC(configInput *C.char) int {
	err := safeCall("StartSingBoxC", func() error {
		value := C.GoString(configInput)
		if strings.HasPrefix(strings.TrimSpace(value), "{") {
			return startSingBoxConfig([]byte(value))
		}
		return startSingBoxInternal(value)
	})
	if err != nil {
		return 1
	}
	return 0
}

//export StopSingBoxC
func StopSingBoxC() {
	if err := safeCall("StopSingBoxC", func() error {
		stopSingBoxInternal()
		return nil
	}); err != nil {
		fmt.Println("StopSingBoxC Error:", err)
	}
}

//export StartGDPIC
func StartGDPIC() C.int {
	if err := safeCall("StartGDPIC", startGDPIInternal); err != nil {
		return 1
	}
	return 0
}

//export StopGDPIC
func StopGDPIC() {
	if err := safeCall("StopGDPIC", func() error {
		stopGDPIInternal()
		return nil
	}); err != nil {
		fmt.Println("StopGDPIC Error:", err)
	}
}

//export IsGDPIRunningC
func IsGDPIRunningC() C.int {
	running := false
	if err := safeCall("IsGDPIRunningC", func() error {
		running = isGDPIRunningInternal()
		return nil
	}); err != nil {
		return 0
	}
	if running {
		return 1
	}
	return 0
}

//export StartSNIC
func StartSNIC(configPath *C.char) int {
	err := safeCall("StartSNIC", func() error {
		return startSNIInternal(C.GoString(configPath))
	})
	if err != nil {
		return 1
	}
	return 0
}

//export StopSNIC
func StopSNIC() {
	if err := safeCall("StopSNIC", func() error {
		stopSNIInternal()
		return nil
	}); err != nil {
		fmt.Println("StopSNIC Error:", err)
	}
}

//export StartMHRVC
func StartMHRVC(port C.int, ids *C.char) int {
	err := safeCall("StartMHRVC", func() error {
		return startMHRVInternal(int(port), C.GoString(ids))
	})
	if err != nil {
		return 1
	}
	return 0
}

//export StopMHRVC
func StopMHRVC() {
	if err := safeCall("StopMHRVC", func() error {
		stopMHRVInternal()
		return nil
	}); err != nil {
		fmt.Println("StopMHRVC Error:", err)
	}
}

//export StartNeighborC
func StartNeighborC(listenPort C.int, targetPort C.int, bindLan C.int) int {
	err := safeCall("StartNeighborC", func() error {
		return startNeighborInternal(int(listenPort), int(targetPort), bindLan != 0)
	})
	if err != nil {
		fmt.Println("StartNeighborC Error:", err)
		return 1
	}
	return 0
}

//export StopNeighborC
func StopNeighborC() {
	if err := safeCall("StopNeighborC", func() error {
		stopNeighborInternal()
		return nil
	}); err != nil {
		fmt.Println("StopNeighborC Error:", err)
	}
}

//export ScanIPsC
func ScanIPsC(ipsC *C.char, port C.int, concurrency C.int, timeoutMs C.int) *C.char {
	var result string
	if err := safeCall("ScanIPsC", func() error {
		ipsStr := C.GoString(ipsC)
		if ipsStr == "" {
			result = ""
			return nil
		}
		ips := strings.Split(ipsStr, ",")
		result = scanIPsInternal(ips, int(port), int(concurrency), int(timeoutMs))
		return nil
	}); err != nil {
		return C.CString("")
	}
	return C.CString(result)
}
