package trustchainstate

import (
	"crypto/rand"
	"encoding/hex"
)

func randomTemporaryName(prefix string) (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", ErrUnavailable
	}
	return prefix + hex.EncodeToString(random[:]) + ".tmp", nil
}
