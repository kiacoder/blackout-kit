package main

import (
	"fmt"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/imgk/divert-go"
)

var gdpiHandle *divert.Handle
var gdpiRunning atomic.Bool

const gdpiChunkSize = 10

func processGDPIPacket(handle *divert.Handle, packetBytes []byte, addr *divert.Address) error {
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

func startGDPIInternal() error {
	if gdpiHandle != nil {
		gdpiRunning.Store(true)
		return nil
	}

	filter := "outbound and tcp and (tcp.PayloadLength > 0) and (tcp.DstPort == 80 or tcp.DstPort == 443)"
	handle, err := divert.Open(filter, divert.LayerNetwork, 0, 0)
	if err != nil {
		gdpiRunning.Store(false)
		return err
	}
	gdpiHandle = handle
	gdpiRunning.Store(true)

	go func() {
		buf := make([]byte, 65535)
		addr := new(divert.Address)
		defer gdpiRunning.Store(false)
		for {
			n, err := handle.Recv(buf, addr)
			if err != nil {
				return
			}
			if err := processGDPIPacket(handle, buf[:n], addr); err != nil {
				gdpiRunning.Store(false)
				return
			}
		}
	}()
	return nil
}

func stopGDPIInternal() {
	gdpiRunning.Store(false)
	if gdpiHandle != nil {
		gdpiHandle.Close()
		gdpiHandle = nil
	}
}

func isGDPIRunningInternal() bool {
	return gdpiHandle != nil && gdpiRunning.Load()
}
