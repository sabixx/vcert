//go:build !linux && !windows

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

package tpmstore

import (
	"crypto"
	"fmt"

	"github.com/Venafi/vcert/v5/pkg/certificate"
)

// ErrTPMNotSupported is returned when TPM operations are attempted on unsupported platforms
var ErrTPMNotSupported = fmt.Errorf("TPM-backed certificates are only supported on Windows (CAPI) and Linux (PEM)")

// LinuxTPMStore is a stub for unsupported platforms
type LinuxTPMStore struct{}

// TPMKey is a stub for unsupported platforms
type TPMKey struct{}

// NewLinuxTPMStore returns an error on unsupported platforms
func NewLinuxTPMStore() (*LinuxTPMStore, error) {
	return nil, ErrTPMNotSupported
}

// NewLinuxTPMStoreWithFallback returns nil on unsupported platforms (will use software keys)
func NewLinuxTPMStoreWithFallback() (*LinuxTPMStore, bool, error) {
	return nil, false, nil
}

// GenerateKey returns an error on unsupported platforms
func (s *LinuxTPMStore) GenerateKey(keyType certificate.KeyType, keySize int, legacyKeySize bool) (*TPMKey, int, error) {
	return nil, 0, ErrTPMNotSupported
}

// Close is a no-op on unsupported platforms
func (s *LinuxTPMStore) Close() error {
	return nil
}

// Signer returns nil on unsupported platforms
func (k *TPMKey) Signer() crypto.Signer {
	return nil
}

// TSS2PEM returns an error on unsupported platforms
func (k *TPMKey) TSS2PEM() ([]byte, error) {
	return nil, ErrTPMNotSupported
}

// RawBlob returns nil on unsupported platforms
func (k *TPMKey) RawBlob() []byte {
	return nil
}

// Close is a no-op on unsupported platforms
func (k *TPMKey) Close() error {
	return nil
}

// IsTPMAvailable always returns false on unsupported platforms
func IsTPMAvailable() bool {
	return false
}
