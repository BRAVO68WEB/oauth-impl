package oidc

import (
	"log"
	"time"
)

// StartRotation retires signing keys on a fixed interval. A zero interval does nothing.
func StartRotation(ks *KeySet, interval, retain time.Duration) {
	if ks == nil || interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if err := ks.Rotate(retain); err != nil {
				log.Printf("signing key rotation: %v", err)
			}
		}
	}()
}
