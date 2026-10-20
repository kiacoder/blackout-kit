package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
)

var singboxInstance *box.Box
var singboxCancel context.CancelFunc

func startSingBoxConfig(configJSON []byte) error {
	engineMu.Lock()
	defer engineMu.Unlock()
	if singboxInstance != nil {
		return fmt.Errorf("sing-box is already running")
	}
	var options option.Options
	if err := json.Unmarshal(configJSON, &options); err != nil {
		return fmt.Errorf("failed to parse config JSON: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	singboxCancel = cancel

	instance, err := box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		// Without this the cancel stayed in the global: a later Stop closed
		// a context that was never started, and the cancel leaked.
		cancel()
		return fmt.Errorf("failed to create sing-box instance: %w", err)
	}

	if err := instance.Start(); err != nil {
		cancel()
		instance.Close()
		return fmt.Errorf("failed to start sing-box instance: %w", err)
	}

	singboxInstance = instance
	fmt.Println("Sing-box library started successfully.")
	return nil
}

func startSingBoxInternal(configPath string) error {
	configJSON, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	return startSingBoxConfig(configJSON)
}

func stopSingBoxInternal() {
	engineMu.Lock()
	defer engineMu.Unlock()
	if singboxCancel != nil {
		singboxCancel()
		singboxCancel = nil
	}
	if singboxInstance != nil {
		singboxInstance.Close()
		singboxInstance = nil
		fmt.Println("Sing-box stopped")
	}
}

func RunSingBox(configPath string) error {
	if err := startSingBoxInternal(configPath); err != nil {
		return err
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	fmt.Println("Received shutdown signal")
	stopSingBoxInternal()
	return nil
}
