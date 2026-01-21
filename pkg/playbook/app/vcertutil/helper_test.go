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

package vcertutil

import (
	"testing"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/playbook/app/domain"
)

func TestSetCSR_Local(t *testing.T) {
	playbookRequest := domain.PlaybookRequest{
		CsrOrigin: "local",
	}
	vcertRequest := &certificate.Request{}

	err := setCSR(playbookRequest, vcertRequest)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if vcertRequest.CsrOrigin != certificate.LocalGeneratedCSR {
		t.Errorf("expected LocalGeneratedCSR, got %v", vcertRequest.CsrOrigin)
	}
}

func TestSetCSR_Service(t *testing.T) {
	playbookRequest := domain.PlaybookRequest{
		CsrOrigin: "service",
	}
	vcertRequest := &certificate.Request{}

	err := setCSR(playbookRequest, vcertRequest)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if vcertRequest.CsrOrigin != certificate.ServiceGeneratedCSR {
		t.Errorf("expected ServiceGeneratedCSR, got %v", vcertRequest.CsrOrigin)
	}
}

func TestSetCSR_TPMOptional_FallsBackToLocal(t *testing.T) {
	// On systems without TPM (like macOS), tpm_optional should fall back to local
	playbookRequest := domain.PlaybookRequest{
		CsrOrigin: "tpm_optional",
		KeyType:   certificate.KeyTypeRSA,
		KeyLength: 2048,
	}
	vcertRequest := &certificate.Request{
		KeyType:   certificate.KeyTypeRSA,
		KeyLength: 2048,
	}

	err := setCSR(playbookRequest, vcertRequest)

	// Should not error - just fall back
	if err != nil {
		t.Errorf("unexpected error for tpm_optional: %v", err)
	}
	// Should fall back to LocalGeneratedCSR on systems without TPM
	if vcertRequest.CsrOrigin != certificate.LocalGeneratedCSR {
		t.Errorf("expected LocalGeneratedCSR (fallback), got %v", vcertRequest.CsrOrigin)
	}
}

func TestSetCSR_TPMMandatory_ReturnsError(t *testing.T) {
	// On systems without TPM, tpm (mandatory) should return an error
	playbookRequest := domain.PlaybookRequest{
		CsrOrigin: "tpm",
		KeyType:   certificate.KeyTypeRSA,
		KeyLength: 2048,
	}
	vcertRequest := &certificate.Request{
		KeyType:   certificate.KeyTypeRSA,
		KeyLength: 2048,
	}

	err := setCSR(playbookRequest, vcertRequest)

	// On systems without TPM, this should return an error
	if err == nil {
		t.Error("expected error for mandatory TPM on system without TPM, got nil")
	}
}

func TestSetCSR_EmptyDefaultsToLocal(t *testing.T) {
	playbookRequest := domain.PlaybookRequest{
		CsrOrigin: "",
	}
	vcertRequest := &certificate.Request{}

	err := setCSR(playbookRequest, vcertRequest)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if vcertRequest.CsrOrigin != certificate.LocalGeneratedCSR {
		t.Errorf("expected LocalGeneratedCSR for empty string, got %v", vcertRequest.CsrOrigin)
	}
}

func TestSetCSR_UnknownDefaultsToLocal(t *testing.T) {
	playbookRequest := domain.PlaybookRequest{
		CsrOrigin: "invalid_option",
	}
	vcertRequest := &certificate.Request{}

	err := setCSR(playbookRequest, vcertRequest)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if vcertRequest.CsrOrigin != certificate.LocalGeneratedCSR {
		t.Errorf("expected LocalGeneratedCSR for unknown option, got %v", vcertRequest.CsrOrigin)
	}
}

func TestSetKeyType_RSA(t *testing.T) {
	playbookRequest := domain.PlaybookRequest{
		KeyType:   certificate.KeyTypeRSA,
		KeyLength: 4096,
	}
	vcertRequest := &certificate.Request{}

	setKeyType(playbookRequest, vcertRequest)

	if vcertRequest.KeyType != certificate.KeyTypeRSA {
		t.Errorf("expected KeyTypeRSA, got %v", vcertRequest.KeyType)
	}
	if vcertRequest.KeyLength != 4096 {
		t.Errorf("expected key length 4096, got %d", vcertRequest.KeyLength)
	}
}

func TestSetKeyType_RSA_DefaultLength(t *testing.T) {
	playbookRequest := domain.PlaybookRequest{
		KeyType:   certificate.KeyTypeRSA,
		KeyLength: 0, // Should default to 2048
	}
	vcertRequest := &certificate.Request{}

	setKeyType(playbookRequest, vcertRequest)

	if vcertRequest.KeyType != certificate.KeyTypeRSA {
		t.Errorf("expected KeyTypeRSA, got %v", vcertRequest.KeyType)
	}
	if vcertRequest.KeyLength != DefaultRSALength {
		t.Errorf("expected default key length %d, got %d", DefaultRSALength, vcertRequest.KeyLength)
	}
}

func TestSetKeyType_ECDSA(t *testing.T) {
	playbookRequest := domain.PlaybookRequest{
		KeyType:  certificate.KeyTypeECDSA,
		KeyCurve: certificate.EllipticCurveP384,
	}
	vcertRequest := &certificate.Request{}

	setKeyType(playbookRequest, vcertRequest)

	if vcertRequest.KeyType != certificate.KeyTypeECDSA {
		t.Errorf("expected KeyTypeECDSA, got %v", vcertRequest.KeyType)
	}
	if vcertRequest.KeyCurve != certificate.EllipticCurveP384 {
		t.Errorf("expected P384 curve, got %v", vcertRequest.KeyCurve)
	}
}

func TestSetKeyType_ED25519(t *testing.T) {
	playbookRequest := domain.PlaybookRequest{
		KeyType: certificate.KeyTypeED25519,
	}
	vcertRequest := &certificate.Request{}

	setKeyType(playbookRequest, vcertRequest)

	if vcertRequest.KeyType != certificate.KeyTypeED25519 {
		t.Errorf("expected KeyTypeED25519, got %v", vcertRequest.KeyType)
	}
	if vcertRequest.KeyCurve != certificate.EllipticCurveED25519 {
		t.Errorf("expected ED25519 curve, got %v", vcertRequest.KeyCurve)
	}
}

func TestSetKeyType_Default(t *testing.T) {
	playbookRequest := domain.PlaybookRequest{
		KeyType: certificate.KeyType(999), // Unknown key type
	}
	vcertRequest := &certificate.Request{}

	setKeyType(playbookRequest, vcertRequest)

	// Should default to RSA 2048
	if vcertRequest.KeyType != certificate.KeyTypeRSA {
		t.Errorf("expected default KeyTypeRSA, got %v", vcertRequest.KeyType)
	}
	if vcertRequest.KeyLength != DefaultRSALength {
		t.Errorf("expected default key length %d, got %d", DefaultRSALength, vcertRequest.KeyLength)
	}
}
