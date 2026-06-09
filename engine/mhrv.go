package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
	"os"
	"os/signal"
	"syscall"
)

type GASRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type GASResponse struct {
	Status  int                 `json:"status"`
	Headers map[string]interface{} `json:"headers"`
	Body    string              `json:"body"`
}

type GASProxy struct {
	gasIDs     []string
	currentIdx int
	lock       sync.Mutex
	client     *http.Client
}

func NewGASProxy(ids []string) *GASProxy {
	return &GASProxy{
		gasIDs: ids,
		client: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

func (p *GASProxy) nextID() string {
	p.lock.Lock()
	defer p.lock.Unlock()
	if len(p.gasIDs) == 0 {
		return ""
	}
	id := p.gasIDs[p.currentIdx%len(p.gasIDs)]
	p.currentIdx++
	return id
}

func (p *GASProxy) relayRequest(gasID string, req *http.Request) (*GASResponse, error) {
	// Read request body
	var reqBody []byte
	if req.Body != nil {
		var err error
		reqBody, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
	}

	// Build headers map, filtering out proxy headers
	headers := make(map[string]string)
	for k, vv := range req.Header {
		kl := strings.ToLower(k)
		if kl == "host" || kl == "proxy-connection" || kl == "proxy-authorization" || kl == "connection" {
			continue
		}
		if len(vv) > 0 {
			headers[k] = strings.Join(vv, ", ")
		}
	}

	targetURL := req.URL.String()
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + req.Host + req.URL.Path
	}

	gasPayload := GASRequest{
		URL:     targetURL,
		Method:  req.Method,
		Headers: headers,
		Body:    base64.StdEncoding.EncodeToString(reqBody),
	}

	payloadBytes, err := json.Marshal(gasPayload)
	if err != nil {
		return nil, err
	}

	gasURL := fmt.Sprintf("https://script.google.com/macros/s/%s/exec", gasID)
	httpReq, err := http.NewRequest("POST", gasURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var gasResp GASResponse
	if err := json.Unmarshal(respBytes, &gasResp); err != nil {
		return nil, fmt.Errorf("invalid json response (err: %v): %s", err, string(respBytes))
	}

	return &gasResp, nil
}

func (p *GASProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "CONNECT" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("CONNECT (HTTPS tunneling) is not supported by the GAS relay engine.\nUse the SNI or XRay engine for HTTPS browsing.\nThe GAS engine handles HTTP traffic only.\n"))
		return
	}

	// Try a few times with different IDs
	var gasResp *GASResponse
	var err error
	maxTries := 3
	if len(p.gasIDs) < maxTries {
		maxTries = len(p.gasIDs)
	}

	// Read request body once
	var reqBody []byte
	if r.Body != nil {
		reqBody, _ = io.ReadAll(r.Body)
		r.Body.Close()
	}

	for i := 0; i < maxTries; i++ {
		id := p.nextID()
		// Re-assign body reader for retries
		if len(reqBody) > 0 {
			r.Body = io.NopCloser(bytes.NewReader(reqBody))
		}
		gasResp, err = p.relayRequest(id, r)
		if err == nil {
			break
		}
		// Print a warning to stdout/stderr so the user/logs show which ID failed
		safeID := id
		if len(safeID) > 15 {
			safeID = safeID[:15] + "..."
		}
		fmt.Printf("Warning: Google Apps Script relay failed for ID %s: %v\n", safeID, err)
	}

	if gasResp == nil {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(fmt.Sprintf("GAS relay failed — all endpoints unreachable: %v", err)))
		return
	}

	// Write response headers
	for k, v := range gasResp.Headers {
		kl := strings.ToLower(k)
		if kl == "transfer-encoding" || kl == "connection" {
			continue
		}
		if arr, ok := v.([]interface{}); ok {
			for _, item := range arr {
				if s, ok := item.(string); ok {
					w.Header().Add(k, s)
				}
			}
		} else if s, ok := v.(string); ok {
			w.Header().Set(k, s)
		}
	}

	// Write status
	status := gasResp.Status
	if status == 0 {
		status = 200
	}
	w.WriteHeader(status)

	// Decode and write body
	bodyBytes, err := base64.StdEncoding.DecodeString(gasResp.Body)
	if err != nil {
		// Fallback to raw string if not base64
		bodyBytes = []byte(gasResp.Body)
	}
	w.Write(bodyBytes)
}

var mhrvServer *http.Server

func startMHRVInternal(port int, idsComma string) error {
	ids := strings.Split(idsComma, ",")
	if len(ids) == 0 || (len(ids) == 1 && ids[0] == "") {
		return fmt.Errorf("no GAS IDs provided")
	}

	// Shuffle ids for load balancing
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(ids), func(i, j int) { ids[i], ids[j] = ids[j], ids[i] })

	proxy := NewGASProxy(ids)
	mhrvServer = &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", port),
		Handler: proxy,
	}

	fmt.Printf("MHRV (Google Apps Script HTTP Relay) running at 127.0.0.1:%d\n", port)
	
	go func() {
		if err := mhrvServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("MHRV Server error: %v\n", err)
		}
	}()
	return nil
}

func stopMHRVInternal() {
	if mhrvServer != nil {
		mhrvServer.Close()
		mhrvServer = nil
		fmt.Println("MHRV stopped")
	}
}

func RunMHRV(port int, idsComma string) error {
	if err := startMHRVInternal(port, idsComma); err != nil {
		return err
	}
	
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
	fmt.Println("Received shutdown signal")
	stopMHRVInternal()
	return nil
}
