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

package service

import (
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/playbook/app/domain"
	"github.com/Venafi/vcert/v5/pkg/playbook/app/installer"
	"github.com/Venafi/vcert/v5/pkg/playbook/app/vcertutil"
	"github.com/Venafi/vcert/v5/pkg/playbook/util/capistore"
	"github.com/Venafi/vcert/v5/pkg/venafi"
)

// DefaultRenew represents the duration before certificate expiration in which renewal should be attempted
const (
	DefaultRenew = "10%"

	envVarThumbprint = "thumbprint"
	envVarSerial     = "serial"
	envVarBase64     = "base64"
)

// Execute takes the task and requests the certificate specified,
// then it installs it in the locations defined by the installers.
//
// Config is used to make the connection to the CyberArk platform for the certificate request.
func Execute(config domain.Config, task domain.CertificateTask) []error {
	// Check if certificate needs action
	changed, err := isCertificateChanged(config, task)
	if err != nil {
		zap.L().Error("error checking certificate in task", zap.String("task", task.Name), zap.Error(err))
		return []error{err}
	}

	// Config has not changed. Do nothing
	if !changed {
		zap.L().Info("certificate in good health. No actions needed",
			zap.String("certificate", task.Request.Subject.CommonName))
		return nil
	}
	zap.L().Info("certificate needs action", zap.String("certificate", task.Request.Subject.CommonName))

	// Check if this is a TPM enrollment with CAPI installation
	csrOrigin := certificate.ParseCSROrigin(task.Request.CsrOrigin)
	if shouldUseTPMEnrollment(csrOrigin, task.Installations) {
		return executeWithTPM(config, task)
	}

	// Ensure there is a keyPassword in the request when origin is service
	if csrOrigin == certificate.ServiceGeneratedCSR {
		zap.L().Info("csr option is 'service'. Generating random password for certificate request")
		task.Request.KeyPassword = vcertutil.GeneratePassword()
	}

	// Config changed or certificate needs renewal. Do request
	pcc, certRequest, err := vcertutil.EnrollCertificate(config, task.Request)
	if err != nil {
		return []error{fmt.Errorf("error requesting certificate %s: %w", task.Name, err)}
	}
	zap.L().Info("successfully enrolled certificate", zap.String("certificate", task.Request.Subject.CommonName))

	// Private Key should not be decrypted when csrOrigin is service and Platform is Firefly.
	// Firefly does not support encryption of private keys
	decryptPK := true
	if config.Connection.Platform == venafi.Firefly && csrOrigin == certificate.ServiceGeneratedCSR {
		decryptPK = false
	}

	// This function will add the private key to the PCC when csrOrigin is local.
	// It will also decrypt the Private Key if it is encrypted
	x509Certificate, prepedPcc, err := installer.CreateX509Cert(pcc, certRequest, decryptPK)
	if err != nil {
		e := "error preparing certificate for installation"
		zap.L().Error(e, zap.Error(err))
		return []error{fmt.Errorf("%s: %w", e, err)}
	}
	zap.L().Info("successfully prepared certificate for installation")

	// Set certificate to environment variables
	if task.SetEnvVars != nil {
		zap.L().Debug("setting environment variables")
		setEnvVars(task, x509Certificate, prepedPcc)
	}

	// Install certificate on locations
	errorList := make([]error, 0)
	for _, installation := range task.Installations {
		e := runInstaller(installation, prepedPcc)
		if e != nil {
			errorList = append(errorList, e)
		}
	}
	return errorList

}

// shouldUseTPMEnrollment checks if the task should use TPM enrollment
// TPM enrollment requires a TPM CSR origin and at least one CAPI installation
func shouldUseTPMEnrollment(csrOrigin certificate.CSrOriginOption, installations domain.Installations) bool {
	// Only for TPM CSR origins
	if csrOrigin != certificate.TPMGeneratedCSR && csrOrigin != certificate.TPMOptionalGeneratedCSR {
		return false
	}

	// Check if there's a CAPI installation
	for _, inst := range installations {
		if inst.Type == domain.FormatCAPI {
			return true
		}
	}

	return false
}

// executeWithTPM handles certificate enrollment using TPM-backed keys for CAPI installations
func executeWithTPM(config domain.Config, task domain.CertificateTask) []error {
	zap.L().Info("using TPM-backed certificate enrollment",
		zap.String("certificate", task.Request.Subject.CommonName))

	// Find the CAPI installation to use for TPM enrollment
	var capiInstallation *domain.Installation
	var otherInstallations []domain.Installation

	for i := range task.Installations {
		if task.Installations[i].Type == domain.FormatCAPI {
			if capiInstallation == nil {
				capiInstallation = &task.Installations[i]
			} else {
				// Additional CAPI installations - will need to be handled separately
				otherInstallations = append(otherInstallations, task.Installations[i])
			}
		} else {
			// Non-CAPI installations cannot use TPM-backed keys (keys are non-exportable)
			zap.L().Warn("skipping non-CAPI installation for TPM enrollment (TPM keys are non-exportable)",
				zap.String("format", task.Installations[i].Type.String()),
				zap.String("file", task.Installations[i].File))
		}
	}

	if capiInstallation == nil {
		return []error{fmt.Errorf("TPM enrollment requires CAPI installation format")}
	}

	// Get CAPI location
	capiLocation := capiInstallation.CAPILocation
	if capiLocation == "" {
		capiLocation = capiInstallation.Location //nolint:staticcheck
	}

	// Determine if TPM is optional (tpm_optional allows fallback to software)
	csrOrigin := certificate.ParseCSROrigin(task.Request.CsrOrigin)
	isOptional := csrOrigin == certificate.TPMOptionalGeneratedCSR

	// Enroll certificate with TPM (or software fallback if isOptional and TPM unavailable)
	cert, err := vcertutil.EnrollCertificateWithTPM(config, task.Request, capiLocation, isOptional)
	if err != nil {
		return []error{fmt.Errorf("error enrolling certificate with TPM %s: %w", task.Name, err)}
	}

	zap.L().Info("successfully enrolled certificate with TPM-backed key",
		zap.String("certificate", task.Request.Subject.CommonName),
		zap.String("capiLocation", capiLocation))

	// Set FriendlyName on the certificate so Check() can find it later
	// certtostore doesn't support setting FriendlyName, so we do it via PowerShell
	friendlyName := capiInstallation.CAPIFriendlyName
	if friendlyName == "" {
		friendlyName = task.Request.Subject.CommonName
	}

	tpmCert, err := installer.CreateCertificateFromX509(cert)
	if err != nil {
		zap.L().Warn("failed to get certificate thumbprint for FriendlyName", zap.Error(err))
	} else {
		// Parse CAPI location to get store details
		storeLocation := "LocalMachine"
		storeName := "My"
		parts := strings.Split(capiLocation, "\\")
		if len(parts) == 2 {
			storeLocation = parts[0]
			storeName = parts[1]
		}

		instConfig := capistore.InstallationConfig{
			FriendlyName:  friendlyName,
			StoreName:     storeName,
			StoreLocation: storeLocation,
		}

		ps := capistore.NewPowerShell()
		if err := ps.SetCertificateFriendlyName(instConfig, strings.ToUpper(tpmCert.Thumbprint)); err != nil {
			zap.L().Warn("failed to set certificate FriendlyName - Check() may not find the certificate",
				zap.String("friendlyName", friendlyName),
				zap.Error(err))
		} else {
			zap.L().Info("successfully set certificate FriendlyName",
				zap.String("friendlyName", friendlyName))
		}
	}

	// Run after-install actions for the CAPI installation if configured
	if capiInstallation.AfterAction != "" {
		instlr := installer.GetInstaller(*capiInstallation)
		result, err := instlr.AfterInstallActions()
		if err != nil {
			zap.L().Error("error running after-install actions",
				zap.String("location", capiLocation),
				zap.Error(err))
		} else if strings.TrimSpace(result) == "1" {
			zap.L().Warn("after-install actions returned failure status")
		} else {
			zap.L().Info("successfully executed after-install actions")
		}
	}

	// Run install validation if configured
	if capiInstallation.InstallValidation != "" {
		instlr := installer.GetInstaller(*capiInstallation)
		result, err := instlr.InstallValidationActions()
		if err != nil {
			zap.L().Error("error running installation validation",
				zap.String("location", capiLocation),
				zap.Error(err))
		} else if strings.TrimSpace(result) == "1" {
			zap.L().Warn("installation validation returned failure status")
		} else {
			zap.L().Info("successfully executed installation validation")
		}
	}

	// Handle additional CAPI installations (if any)
	// Note: These would need a different approach as the key is bound to the first store
	if len(otherInstallations) > 0 {
		zap.L().Warn("additional CAPI installations detected but TPM-backed key can only be stored once",
			zap.Int("additionalInstallations", len(otherInstallations)))
	}

	// Set environment variables if requested
	if task.SetEnvVars != nil {
		zap.L().Debug("setting environment variables for TPM-backed certificate")
		// For TPM-backed certs, we create a Certificate struct with the cert and thumbprint
		tpmCert, err := installer.CreateCertificateFromX509(cert)
		if err != nil {
			zap.L().Warn("failed to create certificate struct for environment variables", zap.Error(err))
		} else {
			// Create minimal PEMCollection for base64 env var (will be empty for TPM certs)
			pcc := &certificate.PEMCollection{}
			setEnvVars(task, tpmCert, pcc)
		}
	}

	return nil
}

func isCertificateChanged(config domain.Config, task domain.CertificateTask) (bool, error) {
	//If forceRenew is set, then no need to check the certificate status
	if config.ForceRenew {
		zap.L().Info("Flag [force-renew] is set. All certificates will be requested/renewed regardless of status")
		return true, nil
	}
	renewBefore := DefaultRenew
	if task.RenewBefore != "" {
		renewBefore = task.RenewBefore
	}

	changed := false
	// check if any installs have changed
	for _, install := range task.Installations {
		isChanged, err := installer.GetInstaller(install).Check(renewBefore, task.Request)
		if err != nil {
			return false, fmt.Errorf("error checking for certificate %s: %w", task.Name, err)
		}
		if isChanged {
			changed = true
		}
	}

	return changed, nil
}

func runInstaller(installation domain.Installation, prepedPcc *certificate.PEMCollection) error {
	location := getInstallationLocationString(installation)

	instlr := installer.GetInstaller(installation)
	zap.L().Info("running Installer", zap.String("installer", installation.Type.String()),
		zap.String("location", location))

	var err error

	if installation.BackupFiles {
		zap.L().Info("backing up certificate for Installer", zap.String("installer", installation.Type.String()),
			zap.String("location", location))
		err = instlr.Backup()
		if err != nil {
			e := "error backing up certificate"
			zap.L().Error(e, zap.String("location", location), zap.Error(err))
			return fmt.Errorf("%s at location %s: %w", e, location, err)
		}
	}

	err = instlr.Install(*prepedPcc)
	if err != nil {
		e := "error installing certificate"
		zap.L().Error(e, zap.String("location", location), zap.Error(err))
		return fmt.Errorf("%s at location %s: %w", e, location, err)
	}
	zap.L().Info("successfully installed certificate", zap.String("location", location))

	if installation.AfterAction == "" {
		return nil
	}

	result, err := instlr.AfterInstallActions()
	if err != nil {
		e := "error running after-install actions"
		zap.L().Error(e, zap.String("location", location), zap.Error(err))
		return fmt.Errorf("%s at location %s: %w", e, location, err)
	} else if strings.TrimSpace(result) == "1" {
		zap.L().Info("after-install actions failed")
	}
	zap.L().Info("successfully executed after-install actions")

	if installation.InstallValidation == "" {
		return nil
	}

	validationResults, err := instlr.InstallValidationActions()

	if err != nil {
		e := "error running installation validation actions"
		zap.L().Error(e, zap.String("location", location), zap.Error(err))
		return fmt.Errorf("%s at location %s: %w", e, location, err)
	} else if strings.TrimSpace(validationResults) == "1" {
		zap.L().Info("installation validation actions failed")
	}
	zap.L().Info("successfully executed installation validation actions")

	return nil
}

func setEnvVars(task domain.CertificateTask, cert *installer.Certificate, prepedPcc *certificate.PEMCollection) {
	//todo case sensitivity. upper the name
	for _, envVar := range task.SetEnvVars {
		varName := ""
		varValue := ""
		switch strings.ToLower(envVar) {
		case envVarThumbprint:
			varName = fmt.Sprintf("VCERT_%s_THUMBPRINT", strings.ToUpper(task.Name))
			varValue = cert.Thumbprint
		case envVarSerial:
			varName = fmt.Sprintf("VCERT_%s_SERIAL", strings.ToUpper(task.Name))
			varValue = cert.X509cert.SerialNumber.String()
		case envVarBase64:
			varName = fmt.Sprintf("VCERT_%s_BASE64", strings.ToUpper(task.Name))
			varValue = prepedPcc.Certificate
		default:
			zap.L().Error("environment variable not supported", zap.String("envVar", envVar))
			continue
		}

		if varValue == "" {
			zap.L().Error("environment variable value not found", zap.String("envVar", varName))
			continue
		}

		err := os.Setenv(varName, varValue)
		if err != nil {
			zap.L().Error("failed to set environment variable", zap.String("envVar", varName), zap.Error(err))
		}
	}
}

func getInstallationLocationString(installation domain.Installation) string {
	if installation.Type != domain.FormatCAPI {
		return installation.File
	}

	if installation.CAPILocation != "" {
		return installation.CAPILocation
	}
	return installation.Location //nolint:staticcheck
}
