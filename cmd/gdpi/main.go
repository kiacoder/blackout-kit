package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/imgk/divert-go"
)

const gdpiChunkSize = 10

func processPacket(handle *divert.Handle, packetBytes []byte, addr *divert.Address) error {
	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.Default)

	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			ipv4 := ipv4Layer.(*layers.IPv4)
			tcp := tcpLayer.(*layers.TCP)
			payload := tcp.Payload
			if len(payload) > gdpiChunkSize {
				opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
				seqOffset := uint32(0)
				fragmentIndex := 0
				for i := 0; i < len(payload); i += gdpiChunkSize {
					end := i + gdpiChunkSize
					if end > len(payload) {
						end = len(payload)
					}
					ipv4Frag := *ipv4
					tcpFrag := *tcp
					tcpFrag.Payload = payload[i:end]
					tcpFrag.Seq += seqOffset
					tcpFrag.SetNetworkLayerForChecksum(&ipv4Frag)
					bufFrag := gopacket.NewSerializeBuffer()
					if err := gopacket.SerializeLayers(bufFrag, opts, &ipv4Frag, &tcpFrag, gopacket.Payload(tcpFrag.Payload)); err != nil {
						return fmt.Errorf("serialize ipv4 fragment %d: %w", fragmentIndex, err)
					}
					if _, err := handle.Send(bufFrag.Bytes(), addr); err != nil {
						return fmt.Errorf("send ipv4 fragment %d: %w", fragmentIndex, err)
					}
					seqOffset += uint32(end - i)
					fragmentIndex++
				}
				return nil
			}
		}
	}

	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			ipv6 := ipv6Layer.(*layers.IPv6)
			tcp := tcpLayer.(*layers.TCP)
			payload := tcp.Payload
			if len(payload) > gdpiChunkSize {
				opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
				seqOffset := uint32(0)
				fragmentIndex := 0
				for i := 0; i < len(payload); i += gdpiChunkSize {
					end := i + gdpiChunkSize
					if end > len(payload) {
						end = len(payload)
					}
					ipv6Frag := *ipv6
					tcpFrag := *tcp
					tcpFrag.Payload = payload[i:end]
					tcpFrag.Seq += seqOffset
					tcpFrag.SetNetworkLayerForChecksum(&ipv6Frag)
					bufFrag := gopacket.NewSerializeBuffer()
					if err := gopacket.SerializeLayers(bufFrag, opts, &ipv6Frag, &tcpFrag, gopacket.Payload(tcpFrag.Payload)); err != nil {
						return fmt.Errorf("serialize ipv6 fragment %d: %w", fragmentIndex, err)
					}
					if _, err := handle.Send(bufFrag.Bytes(), addr); err != nil {
						return fmt.Errorf("send ipv6 fragment %d: %w", fragmentIndex, err)
					}
					seqOffset += uint32(end - i)
					fragmentIndex++
				}
				return nil
			}
		}
	}

	if _, err := handle.Send(packetBytes, addr); err != nil {
		return fmt.Errorf("send passthrough packet: %w", err)
	}
	return nil
}

func main() {
	fmt.Println("Go-GDPI dev harness")
	fmt.Println("Opening WinDivert and processing outbound TCP traffic...")

	filter := "outbound and tcp and (tcp.PayloadLength > 0) and (tcp.DstPort == 80 or tcp.DstPort == 443)"
	handle, err := divert.Open(filter, divert.LayerNetwork, 0, 0)
	if err != nil {
		fmt.Printf("Failed to open WinDivert handle. Are you running as Administrator?\nError: %v\n", err)
		os.Exit(1)
	}
	defer handle.Close()

	fmt.Println("WinDivert started successfully. Press Ctrl+C to stop.")

	go func() {
		buf := make([]byte, 65535)
		addr := new(divert.Address)
		for {
			n, err := handle.Recv(buf, addr)
			if err != nil {
				fmt.Printf("Recv error: %v\n", err)
				break
			}
			if err := processPacket(handle, buf[:n], addr); err != nil {
				fmt.Printf("Packet processing error: %v\n", err)
				break
			}
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	fmt.Println("Stopping Go-GDPI...")
}
