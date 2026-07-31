package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type scanResult struct {
	IP      string
	Latency float64
}

// scanIPsInternal performs the highly concurrent TCP dial tests in Go
func scanIPsInternal(ips []string, port int, concurrency int, timeoutMs int) string {
	to := time.Duration(timeoutMs) * time.Millisecond
	
	var wg sync.WaitGroup
	results := make(chan scanResult, len(ips))
	sem := make(chan struct{}, concurrency)
	
	for _, ip := range ips {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			
			addr := net.JoinHostPort(targetIP, strconv.Itoa(port))
			start := time.Now()
			
			dialer := net.Dialer{Timeout: to}
			conn, err := dialer.Dial("tcp", addr)
			if err == nil {
				conn.Close()
				latency := float64(time.Since(start).Milliseconds())
				results <- scanResult{IP: targetIP, Latency: latency}
			}
		}(ip)
	}
	
	wg.Wait()
	close(results)
	
	var valid []scanResult
	for r := range results {
		valid = append(valid, r)
	}
	
	sort.Slice(valid, func(i, j int) bool {
		return valid[i].Latency < valid[j].Latency
	})
	
	var out []string
	for _, v := range valid {
		out = append(out, fmt.Sprintf("%s|%.1f", v.IP, v.Latency))
	}
	
	return strings.Join(out, ",")
}
