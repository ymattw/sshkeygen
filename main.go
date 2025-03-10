package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	ignoreCase bool
	numWorkers int
)

func main() {
	flag.BoolVar(&ignoreCase, "i", false, "Ignore case when comparing the suffix")
	flag.IntVar(&numWorkers, "n", 1, "Number of workers to utilize")
	flag.Parse()
	log.SetFlags(0)

	suffixes := flag.Args()
	if len(suffixes) == 0 {
		log.Fatalf("Usage: %s [flags] <suffix>...", os.Args[0])
	}
	if numWorkers < 1 {
		log.Fatal("Number of workers must be at least 1")
	}
	log.Printf("Searching with %d worker(s), case %ssensitive",
		numWorkers, map[bool]string{true: "in", false: ""}[ignoreCase])

	var (
		counter int64
		found   int64
		wg      sync.WaitGroup
		start   = time.Now()
	)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				privateKeyPEM, publicKeyBytes, base64Data, err := generateKeys()
				if err != nil {
					log.Printf("Error generating keys: %v", err)
					continue
				}
				atomic.AddInt64(&counter, 1)

				if hasSuffix(base64Data, suffixes) {
					atomic.AddInt64(&found, 1)
					keyFile := fmt.Sprintf("%d.key", time.Now().UnixNano())
					pubFile := keyFile + ".pub"

					if err := os.WriteFile(keyFile, privateKeyPEM, 0600); err != nil {
						log.Printf("Failed to write private key: %v", err)
						continue
					}
					if err := os.WriteFile(pubFile, publicKeyBytes, 0644); err != nil {
						log.Printf("Failed to write public key: %v", err)
						continue
					}
					log.Printf("Found %s -> %s", string(publicKeyBytes), pubFile)
				}
			}
		}()
	}

	// Report progress every 10 seconds
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			hits := atomic.LoadInt64(&found)
			log.Printf("Searched %.1fM key pairs (%.f pairs/sec), hit %d",
				float64(counter)/1_000_000, float64(counter)/time.Since(start).Seconds(), hits)
		}
	}()

	wg.Wait()
}

func generateKeys() ([]byte, []byte, string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, "", err
	}

	// Fixed PEM encoding
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, nil, "", err
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	publicKeyBytes := ssh.MarshalAuthorizedKey(signer.PublicKey())
	publicKeyStr := strings.TrimSpace(string(publicKeyBytes))
	parts := strings.Split(publicKeyStr, " ")
	if len(parts) < 2 {
		return nil, nil, "", fmt.Errorf("invalid public key format: %s", publicKeyStr)
	}
	base64Data := parts[1]

	return pemBytes, publicKeyBytes, base64Data, nil
}

func hasSuffix(s string, suffixes []string) bool {
	if ignoreCase {
		s = strings.ToLower(s)
	}
	for _, suffix := range suffixes {
		if ignoreCase {
			suffix = strings.ToLower(suffix)
		}
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
}
