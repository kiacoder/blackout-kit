package main

import (
	"context"
	"fmt"
	"os"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
)

// RunSingBox starts sing-box using the config file at path and blocks
func RunSingBox(configPath string) error {
	configJSON, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var options option.Options
	if err := options.UnmarshalJSON(configJSON); err != nil {
		return fmt.Errorf("failed to parse config JSON: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	instance, err := box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		return fmt.Errorf("failed to create sing-box instance: %w", err)
	}

	if err := instance.Start(); err != nil {
		return fmt.Errorf("failed to start sing-box instance: %w", err)
	}

	fmt.Println("Sing-box library started successfully inside process.")

	// Block forever (or until signal)
	select {}
}
