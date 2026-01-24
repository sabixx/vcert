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

package domain

import (
	"errors"
	"fmt"

	"github.com/Venafi/vcert/v5/pkg/certificate"
)

// CertificateTask represents a task to be run:
// A certificate to be requested/renewed and installed in one (or more) location(s)
type CertificateTask struct {
	Name          string          `yaml:"name,omitempty"`
	Request       PlaybookRequest `yaml:"request,omitempty"`
	Installations Installations   `yaml:"installations,omitempty"`
	RenewBefore   string          `yaml:"renewBefore,omitempty"`
	SetEnvVars    []string        `yaml:"setEnvVars,omitempty"`
}

// CertificateTasks is a slice of CertificateTask
type CertificateTasks []CertificateTask

// IsValid returns true if the CertificateTask has the minimum required fields to be run
func (task CertificateTask) IsValid() (bool, error) {
	var rErr error = nil
	rValid := true

	// Each certificate request needs a zone, required field
	if task.Request.Zone == "" {
		rValid = false
		rErr = errors.Join(rErr, fmt.Errorf("\t\t%w", ErrNoRequestZone))
	}

	if task.Request.Subject.CommonName == "" {
		rValid = false
		rErr = errors.Join(rErr, fmt.Errorf("\t\t%w", ErrNoRequestCN))
	}

	// This task has no installations defined
	if len(task.Installations) < 1 {
		rValid = false
		rErr = errors.Join(rErr, fmt.Errorf("\t\t%w", ErrNoInstallations))
	}

	// Validate each installation
	for i, installation := range task.Installations {
		_, err := installation.IsValid()
		if err != nil {
			rErr = errors.Join(rErr, fmt.Errorf("\t\tinstallations[%d]:\n%w", i, err))
			rValid = false
		}
	}

	// Validate TPM-specific requirements
	if err := task.validateTPMRequirements(); err != nil {
		rErr = errors.Join(rErr, fmt.Errorf("\t\t%w", err))
		rValid = false
	}

	return rValid, rErr
}

// validateTPMRequirements validates TPM-specific requirements for the task
func (task CertificateTask) validateTPMRequirements() error {
	csrOrigin := certificate.ParseCSROrigin(task.Request.CsrOrigin)

	// Only validate for TPM CSR origins
	if csrOrigin != certificate.TPMGeneratedCSR && csrOrigin != certificate.TPMOptionalGeneratedCSR {
		return nil
	}

	// Check for incompatible formats (PKCS12/JKS) - these can NEVER work with TPM
	// because TPM-backed private keys cannot be exported.
	// This applies to both 'tpm' and 'tpm_optional' since the behavior would be
	// inconsistent (TPM on one machine, software on another with same playbook).
	for _, inst := range task.Installations {
		if inst.Type == FormatPKCS12 || inst.Type == FormatJKS {
			return ErrTPMIncompatibleFormat
		}
	}

	// TPM requires platform-specific installation formats:
	// - Windows: CAPI
	// - Linux: PEM
	// Note: Platform check happens at runtime in the enrollment flow
	hasCAPI := false
	hasPEM := false
	for _, inst := range task.Installations {
		if inst.Type == FormatCAPI {
			hasCAPI = true
		}
		if inst.Type == FormatPEM {
			hasPEM = true
		}
	}

	hasCompatibleFormat := hasCAPI || hasPEM
	if !hasCompatibleFormat {
		// For tpm_optional, this is not an error - it will fall back to software at runtime
		if csrOrigin == certificate.TPMOptionalGeneratedCSR {
			return nil
		}
		// For mandatory tpm, we need either CAPI (Windows) or PEM (Linux)
		return ErrTPMUnsupportedPlatform
	}

	// Validate key type - ED25519 is not supported by TPM 2.0
	if task.Request.KeyType == certificate.KeyTypeED25519 {
		return ErrTPMKeyTypeNotSupported
	}

	// Validate TPM config
	if err := task.Request.TPMConfig.Validate(); err != nil {
		return err
	}

	return nil
}
