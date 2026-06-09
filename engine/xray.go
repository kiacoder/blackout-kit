package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
)

var xrayServer *core.Instance

func startXrayInternal(configPath string) error {
	configFile, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	defer configFile.Close()

	config, err := core.LoadConfig("json", configFile)
	if err != nil {
		return fmt.Errorf("failed to parse config JSON: %w", err)
	}

	server, err := core.New(config)
	if err != nil {
		return fmt.Errorf("failed to initialize xray server: %w", err)
	}

	if err := server.Start(); err != nil {
		return fmt.Errorf("failed to start xray server: %w", err)
	}

	xrayServer = server
	fmt.Println("Xray-core library started successfully.")
	return nil
}

func stopXrayInternal() {
	if xrayServer != nil {
		xrayServer.Close()
		xrayServer = nil
		fmt.Println("Xray-core stopped")
	}
}

// RunXray starts xray-core using the config file at path and blocks
func RunXray(configPath string) error {
	if err := startXrayInternal(configPath); err != nil {
		return err
	}
	
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	fmt.Println("Received shutdown signal")
	stopXrayInternal()
	return nil
}
