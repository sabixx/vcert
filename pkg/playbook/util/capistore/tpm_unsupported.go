//go:build !windows

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

	"github.com/Venafi/vcert/v5/pkg/certificate"
)

// ErrTPMNotSupportedOnPlatform is returned when TPM operations are attempted on non-Windows platforms
var ErrTPMNotSupportedOnPlatform = fmt.Errorf("TPM-backed certificates are only supported on Windows with CAPI installation")

// TPMCertStore is a stub for non-Windows platforms
type TPMCertStore struct{}

// NewTPMCertStore returns an error on non-Windows platforms
func NewTPMCertStore(container string, currentUser bool) (*TPMCertStore, error) {
	return nil, ErrTPMNotSupportedOnPlatform
}

// NewTPMCertStoreWithFallback returns an error on non-Windows platforms
func NewTPMCertStoreWithFallback(container string, currentUser bool) (*TPMCertStore, bool, error) {
	return nil, false, ErrTPMNotSupportedOnPlatform
}

// GenerateKey returns an error on non-Windows platforms
// legacyKeySize is ignored on non-Windows platforms
func (t *TPMCertStore) GenerateKey(keyType certificate.KeyType, keySize int, legacyKeySize bool) (crypto.Signer, int, error) {
	return nil, 0, ErrTPMNotSupportedOnPlatform
}

// StoreCertificate returns an error on non-Windows platforms
func (t *TPMCertStore) StoreCertificate(cert *x509.Certificate, intermediate *x509.Certificate) error {
	return ErrTPMNotSupportedOnPlatform
}

// Close is a no-op on non-Windows platforms
func (t *TPMCertStore) Close() error {
	return nil
}

// GenerateContainerName creates a container name (works on all platforms for validation)
func GenerateContainerName(commonName string) string {
	return fmt.Sprintf("vcert_%s", commonName)
}

// ParseCAPILocation parses a CAPI location string
func ParseCAPILocation(location string) (currentUser bool, storeName string, err error) {
	return false, "", ErrTPMNotSupportedOnPlatform
}

// InstallationConfig holds configuration for CAPI certificate installation (stub for non-Windows)
type InstallationConfig struct {
	PFX             []byte
	FriendlyName    string
	IsNonExportable bool
	Password        string
	StoreLocation   string
	StoreName       string
}

// PowerShell is a stub for non-Windows platforms
type PowerShell struct{}

// NewPowerShell returns a stub PowerShell instance on non-Windows platforms
func NewPowerShell() *PowerShell {
	return &PowerShell{}
}

// SetCertificateFriendlyName is a no-op on non-Windows platforms
func (ps PowerShell) SetCertificateFriendlyName(config InstallationConfig, thumbprint string) error {
	return ErrTPMNotSupportedOnPlatform
}
