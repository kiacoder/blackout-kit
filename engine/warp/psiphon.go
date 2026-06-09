package main

import "C"

import (
	"context"
	"fmt"
	"os"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

var psiphonController *psiphon.Controller
var psiphonCtx context.Context
var psiphonCancel context.CancelFunc

func startPsiphonInternal(configPath string) error {
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read psiphon config: %w", err)
	}

	config, err := psiphon.LoadConfig(configBytes)
	if err != nil {
		return fmt.Errorf("failed to parse psiphon config: %w", err)
	}

	controller, err := psiphon.NewController(config)
	if err != nil {
		return fmt.Errorf("failed to initialize psiphon controller: %w", err)
	}

	psiphonController = controller
	psiphonCtx, psiphonCancel = context.WithCancel(context.Background())
	
	go psiphonController.Run(psiphonCtx)

	fmt.Println("Psiphon tunnel core started successfully natively")
	return nil
}

func stopPsiphonInternal() {
	if psiphonCancel != nil {
		psiphonCancel()
		psiphonCancel = nil
	}
	if psiphonController != nil {
		psiphonController = nil
		fmt.Println("Psiphon tunnel core stopped")
	}
}

//export StartPsiphonC
func StartPsiphonC(configPath *C.char) C.int {
	path := C.GoString(configPath)
	if err := startPsiphonInternal(path); err != nil {
		fmt.Printf("StartPsiphonC error: %v\n", err)
		return 1
	}
	return 0
}

//export StopPsiphonC
func StopPsiphonC() {
	stopPsiphonInternal()
}
