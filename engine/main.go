package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]
	switch subcommand {
	case "xray":
		xrayCmd := flag.NewFlagSet("xray", flag.ExitOnError)
		configPath := xrayCmd.String("config", "xray_config.json", "Path to xray config JSON")
		xrayCmd.Parse(os.Args[2:])

		fmt.Printf("Starting embedded Xray-core with config: %s\n", *configPath)
		if err := RunXray(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error running Xray: %v\n", err)
			os.Exit(1)
		}

	case "sing-box":
		sbCmd := flag.NewFlagSet("sing-box", flag.ExitOnError)
		configPath := sbCmd.String("config", "config.json", "Path to sing-box config JSON")
		sbCmd.Parse(os.Args[2:])

		fmt.Printf("Starting embedded Sing-box with config: %s\n", *configPath)
		if err := RunSingBox(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error running Sing-box: %v\n", err)
			os.Exit(1)
		}

	case "sni":
		sniCmd := flag.NewFlagSet("sni", flag.ExitOnError)
		configPath := sniCmd.String("config", "config.json", "Path to SNI config JSON")
		sniCmd.Parse(os.Args[2:])

		fmt.Printf("Starting embedded SNI Spoofer with config: %s\n", *configPath)
		if err := RunSNI(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error running SNI spoofer: %v\n", err)
			os.Exit(1)
		}

	case "mhrv":
		mhrvCmd := flag.NewFlagSet("mhrv", flag.ExitOnError)
		port := mhrvCmd.Int("port", 8087, "SOCKS/HTTP proxy port")
		ids := mhrvCmd.String("ids", "", "Comma-separated list of Google Apps Script IDs")
		mhrvCmd.Parse(os.Args[2:])

		if *ids == "" {
			fmt.Fprintln(os.Stderr, "Error: --ids argument is required for mhrv")
			os.Exit(1)
		}

		fmt.Printf("Starting embedded MHRV (GAS proxy) on port %d\n", *port)
		if err := RunMHRV(*port, *ids); err != nil {
			fmt.Fprintf(os.Stderr, "Error running MHRV: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: blackout-engine <subcommand> [args]")
	fmt.Println("Available subcommands:")
	fmt.Println("  xray      --config <path>")
	fmt.Println("  sing-box  --config <path>")
	fmt.Println("  sni       --config <path>")
	fmt.Println("  mhrv      --port <port> --ids <gas-ids-comma-separated>")
}
