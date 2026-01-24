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

// Package tpmstore provides Linux TPM 2.0 operations.
// On Windows, use the capistore package instead for TPM-backed certificates.
package tpmstore

import (
	"crypto"
	"fmt"

	"github.com/Venafi/vcert/v5/pkg/certificate"
)

// ErrUseCapistore is returned when Linux TPM store is attempted on Windows
var ErrUseCapistore = fmt.Errorf("on Windows, use capistore package for TPM-backed certificates")

// LinuxTPMStore is not available on Windows - use capistore instead
type LinuxTPMStore struct{}

// TPMKey is not available on Windows - use capistore instead
type TPMKey struct{}

// NewLinuxTPMStore returns an error on Windows - use capistore instead
func NewLinuxTPMStore() (*LinuxTPMStore, error) {
	return nil, ErrUseCapistore
}

// NewLinuxTPMStoreWithFallback returns an error on Windows - use capistore instead
func NewLinuxTPMStoreWithFallback() (*LinuxTPMStore, bool, error) {
	return nil, false, ErrUseCapistore
}

// GenerateKey returns an error on Windows
func (s *LinuxTPMStore) GenerateKey(keyType certificate.KeyType, keySize int, legacyKeySize bool) (*TPMKey, int, error) {
	return nil, 0, ErrUseCapistore
}

// Close is a no-op on Windows
func (s *LinuxTPMStore) Close() error {
	return nil
}

// Signer returns nil on Windows
func (k *TPMKey) Signer() crypto.Signer {
	return nil
}

// TSS2PEM returns an error on Windows
func (k *TPMKey) TSS2PEM() ([]byte, error) {
	return nil, ErrUseCapistore
}

// RawBlob returns nil on Windows
func (k *TPMKey) RawBlob() []byte {
	return nil
}

// Close is a no-op on Windows
func (k *TPMKey) Close() error {
	return nil
}

// IsTPMAvailable returns false on Windows - use capistore for TPM detection
func IsTPMAvailable() bool {
	return false
}
