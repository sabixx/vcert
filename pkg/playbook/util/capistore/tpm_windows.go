//go:build windows

/*
 * Copyright Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package capistore

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/google/certtostore"
	"go.uber.org/zap"

	"github.com/Venafi/vcert/v5/pkg/certificate"
)

// TPMCertStore wraps certtostore for TPM-backed CAPI operations
type TPMCertStore struct {
	store     *certtostore.WinCertStore
	container string
}

// NewTPMCertStore creates a new TPM-backed certificate store
// container is a unique name for the key container (typically based on CommonName)
// currentUser determines whether to use CurrentUser or LocalMachine store
func NewTPMCertStore(container string, currentUser bool) (*TPMCertStore, error) {
	opts := certtostore.WinCertStoreOptions{
		Provider:    certtostore.ProviderMSPlatform, // Microsoft Platform Crypto Provider (TPM)
		Container:   container,
		CurrentUser: currentUser,
	}

	store, err := certtostore.OpenWinCertStoreWithOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM cert store: %w", err)
	}

	zap.L().Debug("opened TPM-backed certificate store",
		zap.String("container", container),
		zap.Bool("currentUser", currentUser))

	return &TPMCertStore{
		store:     store,
		container: container,
	}, nil
}

// NewTPMCertStoreWithFallback tries to create a TPM-backed store, falling back to software if unavailable
// Returns the store and a boolean indicating if TPM is being used
func NewTPMCertStoreWithFallback(container string, currentUser bool) (*TPMCertStore, bool, error) {
	// Try TPM first
	store, err := NewTPMCertStore(container, currentUser)
	if err == nil {
		return store, true, nil
	}

	zap.L().Warn("TPM not available, falling back to software key storage",
		zap.Error(err))

	// Fall back to software provider
	opts := certtostore.WinCertStoreOptions{
		Provider:    certtostore.ProviderMSSoftware, // Microsoft Software Key Storage Provider
		Container:   container,
		CurrentUser: currentUser,
	}

	winStore, err := certtostore.OpenWinCertStoreWithOptions(opts)
	if err != nil {
		return nil, false, fmt.Errorf("failed to open software cert store: %w", err)
	}

	zap.L().Info("using software key storage (TPM fallback)",
		zap.String("container", container))

	return &TPMCertStore{
		store:     winStore,
		container: container,
	}, false, nil
}

// GenerateKey creates a key in the TPM (or software store if fallback)
// legacyKeySize allows fallback to 2048-bit RSA if the TPM doesn't support the requested size
func (t *TPMCertStore) GenerateKey(keyType certificate.KeyType, keySize int, legacyKeySize bool) (crypto.Signer, int, error) {
	var algo certtostore.Algorithm
	var size int

	switch keyType {
	case certificate.KeyTypeRSA:
		algo = certtostore.RSA
		size = keySize
		if size == 0 {
			size = 2048 // Default
		}
	case certificate.KeyTypeECDSA:
		algo = certtostore.EC
		// For EC, size represents the curve
		switch keySize {
		case 256, 0:
			size = 256 // P-256
		case 384:
			size = 384 // P-384
		default:
			return nil, 0, fmt.Errorf("TPM supports ECDSA curves P-256 and P-384, requested size %d", keySize)
		}
	case certificate.KeyTypeED25519:
		// ED25519 is not supported by TPM 2.0 - no fallback
		return nil, 0, fmt.Errorf("ED25519 key type is not supported by TPM 2.0")
	default:
		return nil, 0, fmt.Errorf("key type %s not supported for TPM", keyType.String())
	}

	zap.L().Debug("generating TPM-backed key",
		zap.String("algorithm", string(algo)),
		zap.Int("size", size))

	// Try to generate the key with the requested size
	signer, err := t.store.Generate(certtostore.GenerateOpts{
		Algorithm: algo,
		Size:      size,
	})

	// If generation succeeded, return the key
	if err == nil {
		return signer, size, nil
	}

	// Generation failed - check if we can fall back for RSA keys with size > 2048
	if keyType == certificate.KeyTypeRSA && size > 2048 {
		if !legacyKeySize {
			// No fallback allowed - return error with helpful message
			return nil, 0, fmt.Errorf("this TPM does not support RSA %d-bit keys. Try 2048 bits or set request.tpmConfig.legacyKeySize: true to automatically fall back", size)
		}

		// Try fallback to 2048 bits
		zap.L().Warn("TPM does not support requested RSA key size, falling back to 2048 bits",
			zap.Int("requestedSize", size),
			zap.Int("fallbackSize", 2048),
			zap.Error(err))

		signer, err = t.store.Generate(certtostore.GenerateOpts{
			Algorithm: algo,
			Size:      2048,
		})
		if err != nil {
			return nil, 0, fmt.Errorf("failed to generate RSA 2048-bit key in TPM: %w", err)
		}

		zap.L().Info("successfully generated TPM-backed key with fallback size",
			zap.String("algorithm", string(algo)),
			zap.Int("requestedSize", size),
			zap.Int("actualSize", 2048))
		return signer, 2048, nil
	}

	// For ECDSA or RSA <= 2048, just return the error
	return nil, 0, fmt.Errorf("failed to generate key in TPM: %w", err)
}

// StoreCertificate installs the certificate associated with the TPM-backed key
func (t *TPMCertStore) StoreCertificate(cert *x509.Certificate, intermediate *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate cannot be nil")
	}

	zap.L().Debug("storing certificate with TPM-backed key",
		zap.String("subject", cert.Subject.CommonName),
		zap.String("container", t.container))

	err := t.store.Store(cert, intermediate)
	if err != nil {
		return fmt.Errorf("failed to store certificate: %w", err)
	}

	return nil
}

// Close releases resources associated with the store
func (t *TPMCertStore) Close() error {
	if t.store != nil {
		return t.store.Close()
	}
	return nil
}

// GenerateContainerName creates a unique container name from the common name
func GenerateContainerName(commonName string) string {
	// Replace invalid characters and create a unique container name
	name := strings.ReplaceAll(commonName, " ", "_")
	name = strings.ReplaceAll(name, ".", "_")
	name = strings.ReplaceAll(name, "*", "wildcard")

	// Prefix with vcert to identify our containers
	return fmt.Sprintf("vcert_%s", name)
}

// ParseCAPILocation parses a CAPI location string and returns the store location details
// Format: "StoreLocation\StoreName" (e.g., "LocalMachine\My" or "CurrentUser\My")
func ParseCAPILocation(location string) (currentUser bool, storeName string, err error) {
	parts := strings.SplitN(location, "\\", 2)
	if len(parts) != 2 {
		return false, "", fmt.Errorf("invalid CAPI location format: %s (expected StoreLocation\\StoreName)", location)
	}

	storeLocation := strings.ToLower(parts[0])
	storeName = parts[1]

	switch storeLocation {
	case "currentuser":
		currentUser = true
	case "localmachine":
		currentUser = false
	default:
		return false, "", fmt.Errorf("invalid store location: %s (expected CurrentUser or LocalMachine)", parts[0])
	}

	return currentUser, storeName, nil
}
