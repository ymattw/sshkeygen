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
	"time"

	"golang.org/x/crypto/ssh"
)

var ignoreCase bool

func main() {
	flag.BoolVar(&ignoreCase, "i", false, "Ignore case when comparing the suffix")
	flag.Parse()
	log.SetFlags(0)
	suffixes := flag.Args()
	if len(suffixes) == 0 {
		log.Fatalf("Usage: %s <suffix>...", os.Args[0])
	}

	startTime := time.Now()
	i := 0
	found := 0
	for {
		i++
		if i%1_000_000 == 0 {
			log.Printf("Generated %dM key pairs (%.f pairs/sec), hit %d", i/1_000_000, float64(i)/time.Since(startTime).Seconds(), found)
		}

		privateKeyPEM, publicKeyBytes, base64Data, err := generateKeys()
		if err != nil {
			log.Printf("Error generating keys: %v", err)
			continue
		}

		if hasSuffix(base64Data, suffixes) {
			found++
			keyFile := fmt.Sprintf("%d.key", time.Now().UnixNano())
			pubFile := keyFile + ".pub"

			if err := os.WriteFile(keyFile, privateKeyPEM, 0600); err != nil {
				log.Printf("Failed to write private key: %v", err)
				continue
			}
			if err := os.WriteFile(pubFile, publicKeyBytes, 0644); err != nil {
				log.Printf("Failed to write public key: %v", err)
				os.Remove(keyFile)
				continue
			}
			log.Printf("Found %s, saved to %s", string(publicKeyBytes), pubFile)
		}
	}
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
