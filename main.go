package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/ssh"
)

var (
	ignoreCase bool
	numWorkers int
)

// Per-worker random source
type worker struct {
	rng io.Reader
}

func newWorker() (*worker, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, err
	}

	return &worker{
		rng: &chacha20Reader{cipher: cipher},
	}, nil
}

type chacha20Reader struct {
	cipher *chacha20.Cipher
}

func (r *chacha20Reader) Read(p []byte) (int, error) {
	// Generate keystream by XORing with zero-filled buffer
	zeros := make([]byte, len(p))
	r.cipher.XORKeyStream(p, zeros)
	return len(p), nil
}

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

	passphrase := []byte(os.Getenv("PASSPHRASE"))
	log.Printf("Searching with %d worker(s), case %ssensitive, private key will %s passphrase protected",
		numWorkers, map[bool]string{true: "in", false: ""}[ignoreCase],
		map[bool]string{true: "be", false: "NOT be"}[len(passphrase) > 0])

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

			w, err := newWorker()
			if err != nil {
				log.Printf("Failed to initialize worker: %v", err)
				return
			}

			for {
				pub, priv, err := ed25519.GenerateKey(w.rng)
				if err != nil {
					log.Printf("Error generating keys: %v", err)
					continue
				}
				atomic.AddInt64(&counter, 1)

				pubKey := publicKeyString(pub)
				if !hasSuffix(pubKey, suffixes) {
					continue
				}

				atomic.AddInt64(&found, 1)
				privKey := privateKeyPEM(priv, passphrase)

				keyFile := fmt.Sprintf("%d.key", time.Now().UnixNano())
				pubFile := keyFile + ".pub"

				if err := os.WriteFile(keyFile, privKey, 0600); err != nil {
					log.Printf("Failed to write private key: %v", err)
					continue
				}
				if err := os.WriteFile(pubFile, []byte(pubKey+"\n"), 0644); err != nil {
					log.Printf("Failed to write public key: %v", err)
					continue
				}
				// Clear the current line and move cursor back to the start
				log.Printf("\r\x1b[KFound %s -> %s*", pubKey, keyFile)
			}
		}()
	}

	// Report progress every 10 seconds
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			elapsed := time.Since(start)
			hits := atomic.LoadInt64(&found)
			// Clear the current line and move cursor back to the start
			fmt.Printf("\r\x1b[KSearched %.1fM key pairs in %s (%.fK pairs/sec), hit %d",
				float64(counter)/1_000_000, elapsed.Round(time.Second), float64(counter)/1000/elapsed.Seconds(), hits)
		}
	}()

	wg.Wait()
}

func publicKeyString(pub ed25519.PublicKey) string {
	sshPubKey, _ := ssh.NewPublicKey(pub)
	return fmt.Sprintf("%s %s", sshPubKey.Type(), base64.StdEncoding.EncodeToString(sshPubKey.Marshal()))
}

func privateKeyPEM(priv ed25519.PrivateKey, passphrase []byte) []byte {
	var block *pem.Block
	if len(passphrase) > 0 {
		block, _ = ssh.MarshalPrivateKeyWithPassphrase(priv, "" /*comment*/, passphrase)
	} else {
		block, _ = ssh.MarshalPrivateKey(priv, "" /*comment*/)
	}
	return pem.EncodeToMemory(block)
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
