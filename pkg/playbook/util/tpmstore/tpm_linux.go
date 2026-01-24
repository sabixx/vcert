//go:build linux

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"go.uber.org/zap"

	"github.com/Venafi/vcert/v5/pkg/certificate"
)

const (
	// DefaultTPMDevice is the default TPM resource manager device on Linux
	DefaultTPMDevice = "/dev/tpmrm0"
	// FallbackTPMDevice is the fallback TPM device if resource manager is not available
	FallbackTPMDevice = "/dev/tpm0"
)

// LinuxTPMStore provides TPM 2.0 key operations on Linux
type LinuxTPMStore struct {
	tpm           transport.TPMCloser
	primaryHandle tpm2.TPMHandle
}

// TPMKey represents a TPM-backed key with its wrapped blob for persistence
type TPMKey struct {
	signer     crypto.Signer
	publicBlob []byte
	privateBlob []byte
	parentHandle tpm2.TPMHandle
	keyHandle   tpm2.TPMHandle
	store       *LinuxTPMStore
}

// tss2PrivateKey represents the ASN.1 structure for TSS2 PRIVATE KEY PEM format
// This is compatible with tpm2-tss-engine and OpenSSL TPM2 provider
type tss2PrivateKey struct {
	Type       asn1.ObjectIdentifier
	EmptyAuth  bool
	Parent     int
	PublicKey  []byte
	PrivateKey []byte
}

// TSS2 OID for TPM 2.0 keys: 2.23.133.10.1.3
var oidTSS2 = asn1.ObjectIdentifier{2, 23, 133, 10, 1, 3}

// NewLinuxTPMStore opens a connection to the TPM device
func NewLinuxTPMStore() (*LinuxTPMStore, error) {
	// Try the resource manager first
	tpm, err := transport.OpenTPM(DefaultTPMDevice)
	if err != nil {
		zap.L().Debug("failed to open TPM resource manager, trying direct device",
			zap.String("device", DefaultTPMDevice),
			zap.Error(err))

		// Try the direct TPM device
		tpm, err = transport.OpenTPM(FallbackTPMDevice)
		if err != nil {
			return nil, fmt.Errorf("failed to open TPM device: %w", err)
		}
	}

	store := &LinuxTPMStore{
		tpm: tpm,
	}

	// Create a primary key under the owner hierarchy for key creation
	primaryHandle, err := store.createPrimaryKey()
	if err != nil {
		tpm.Close()
		return nil, fmt.Errorf("failed to create TPM primary key: %w", err)
	}
	store.primaryHandle = primaryHandle

	zap.L().Debug("opened Linux TPM store")
	return store, nil
}

// NewLinuxTPMStoreWithFallback tries to create a TPM store, returning nil if TPM is unavailable
// The boolean return value indicates whether TPM is being used
func NewLinuxTPMStoreWithFallback() (*LinuxTPMStore, bool, error) {
	store, err := NewLinuxTPMStore()
	if err != nil {
		zap.L().Warn("TPM not available, will use software key generation",
			zap.Error(err))
		return nil, false, nil
	}
	return store, true, nil
}

// createPrimaryKey creates a primary key under the owner hierarchy
func (s *LinuxTPMStore) createPrimaryKey() (tpm2.TPMHandle, error) {
	// Create an RSA primary key template for the storage hierarchy
	primaryTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Decrypt:             true,
			Restricted:          true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				KeyBits: 2048,
			},
		),
	}

	createPrimaryCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(primaryTemplate),
	}

	rsp, err := createPrimaryCmd.Execute(s.tpm)
	if err != nil {
		return 0, fmt.Errorf("CreatePrimary failed: %w", err)
	}

	return rsp.ObjectHandle, nil
}

// GenerateKey creates a new key in the TPM
// Returns a crypto.Signer for the key and the actual key size used
func (s *LinuxTPMStore) GenerateKey(keyType certificate.KeyType, keySize int, legacyKeySize bool) (*TPMKey, int, error) {
	switch keyType {
	case certificate.KeyTypeRSA:
		return s.generateRSAKey(keySize, legacyKeySize)
	case certificate.KeyTypeECDSA:
		return s.generateECDSAKey(keySize)
	case certificate.KeyTypeED25519:
		return nil, 0, fmt.Errorf("ED25519 key type is not supported by TPM 2.0")
	default:
		return nil, 0, fmt.Errorf("key type %s not supported for TPM", keyType.String())
	}
}

// generateRSAKey creates an RSA key in the TPM
func (s *LinuxTPMStore) generateRSAKey(keySize int, legacyKeySize bool) (*TPMKey, int, error) {
	if keySize == 0 {
		keySize = 2048
	}

	// Try requested size first
	key, err := s.createRSAKey(keySize)
	if err == nil {
		return key, keySize, nil
	}

	// If requested size > 2048 and failed, try fallback
	if keySize > 2048 && legacyKeySize {
		zap.L().Warn("TPM does not support requested RSA key size, falling back to 2048 bits",
			zap.Int("requestedSize", keySize),
			zap.Int("fallbackSize", 2048),
			zap.Error(err))

		key, err = s.createRSAKey(2048)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to generate RSA 2048-bit key in TPM: %w", err)
		}
		return key, 2048, nil
	}

	if keySize > 2048 {
		return nil, 0, fmt.Errorf("this TPM does not support RSA %d-bit keys. Try 2048 bits or set request.tpmConfig.legacyKeySize: true", keySize)
	}

	return nil, 0, fmt.Errorf("failed to generate RSA key in TPM: %w", err)
}

// createRSAKey creates an RSA signing key under the primary
func (s *LinuxTPMStore) createRSAKey(keySize int) (*TPMKey, error) {
	rsaTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: tpm2.TPMKeyBits(keySize),
			},
		),
	}

	createCmd := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: s.primaryHandle,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(rsaTemplate),
	}

	rsp, err := createCmd.Execute(s.tpm)
	if err != nil {
		return nil, fmt.Errorf("Create RSA key failed: %w", err)
	}

	// Load the key
	loadCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: s.primaryHandle,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:  rsp.OutPublic,
		InPrivate: rsp.OutPrivate,
	}

	loadRsp, err := loadCmd.Execute(s.tpm)
	if err != nil {
		return nil, fmt.Errorf("Load RSA key failed: %w", err)
	}

	// Get the public key for the Signer interface
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key contents: %w", err)
	}

	rsaDetail, err := pub.Parameters.RSADetail()
	if err != nil {
		return nil, fmt.Errorf("failed to get RSA parameters: %w", err)
	}

	rsaUnique, err := pub.Unique.RSA()
	if err != nil {
		return nil, fmt.Errorf("failed to get RSA unique: %w", err)
	}

	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(rsaUnique.Buffer),
		E: int(rsaDetail.Exponent),
	}
	if pubKey.E == 0 {
		pubKey.E = 65537 // Default RSA exponent
	}

	return &TPMKey{
		signer:       &tpmRSASigner{store: s, handle: loadRsp.ObjectHandle, pubKey: pubKey},
		publicBlob:   rsp.OutPublic.Bytes(),
		privateBlob:  rsp.OutPrivate.Buffer,
		parentHandle: s.primaryHandle,
		keyHandle:    loadRsp.ObjectHandle,
		store:        s,
	}, nil
}

// generateECDSAKey creates an ECDSA key in the TPM
func (s *LinuxTPMStore) generateECDSAKey(keySize int) (*TPMKey, int, error) {
	var curve tpm2.TPMECCCurve
	var goCurve elliptic.Curve

	switch keySize {
	case 256, 0:
		curve = tpm2.TPMECCNistP256
		goCurve = elliptic.P256()
		keySize = 256
	case 384:
		curve = tpm2.TPMECCNistP384
		goCurve = elliptic.P384()
	default:
		return nil, 0, fmt.Errorf("TPM supports ECDSA curves P-256 and P-384, requested size %d", keySize)
	}

	ecTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				CurveID: curve,
			},
		),
	}

	createCmd := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: s.primaryHandle,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(ecTemplate),
	}

	rsp, err := createCmd.Execute(s.tpm)
	if err != nil {
		return nil, 0, fmt.Errorf("Create ECDSA key failed: %w", err)
	}

	// Load the key
	loadCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: s.primaryHandle,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:  rsp.OutPublic,
		InPrivate: rsp.OutPrivate,
	}

	loadRsp, err := loadCmd.Execute(s.tpm)
	if err != nil {
		return nil, 0, fmt.Errorf("Load ECDSA key failed: %w", err)
	}

	// Get the public key for the Signer interface
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get public key contents: %w", err)
	}

	ecUnique, err := pub.Unique.ECC()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get ECC unique: %w", err)
	}

	pubKey := &ecdsa.PublicKey{
		Curve: goCurve,
		X:     new(big.Int).SetBytes(ecUnique.X.Buffer),
		Y:     new(big.Int).SetBytes(ecUnique.Y.Buffer),
	}

	return &TPMKey{
		signer:       &tpmECDSASigner{store: s, handle: loadRsp.ObjectHandle, pubKey: pubKey},
		publicBlob:   rsp.OutPublic.Bytes(),
		privateBlob:  rsp.OutPrivate.Buffer,
		parentHandle: s.primaryHandle,
		keyHandle:    loadRsp.ObjectHandle,
		store:        s,
	}, keySize, nil
}

// Close releases TPM resources
func (s *LinuxTPMStore) Close() error {
	if s.primaryHandle != 0 {
		flushCmd := tpm2.FlushContext{FlushHandle: s.primaryHandle}
		flushCmd.Execute(s.tpm)
	}
	if s.tpm != nil {
		return s.tpm.Close()
	}
	return nil
}

// Signer returns the crypto.Signer interface for this key
func (k *TPMKey) Signer() crypto.Signer {
	return k.signer
}

// TSS2PEM returns the key in TSS2 PRIVATE KEY PEM format
// This format is compatible with OpenSSL TPM2 provider and tpm2-tss-engine
func (k *TPMKey) TSS2PEM() ([]byte, error) {
	// Parent is the owner hierarchy handle (0x40000001)
	tss2Key := tss2PrivateKey{
		Type:       oidTSS2,
		EmptyAuth:  true,
		Parent:     0x40000001, // TPM_RH_OWNER
		PublicKey:  k.publicBlob,
		PrivateKey: k.privateBlob,
	}

	der, err := asn1.Marshal(tss2Key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TSS2 key: %w", err)
	}

	block := &pem.Block{
		Type:  "TSS2 PRIVATE KEY",
		Bytes: der,
	}

	return pem.EncodeToMemory(block), nil
}

// RawBlob returns the raw TPM key blobs (public + private) for storage
func (k *TPMKey) RawBlob() []byte {
	// Combine public and private blobs with length prefixes
	// Format: [4-byte pubLen][publicBlob][4-byte privLen][privateBlob]
	pubLen := len(k.publicBlob)
	privLen := len(k.privateBlob)
	blob := make([]byte, 4+pubLen+4+privLen)

	blob[0] = byte(pubLen >> 24)
	blob[1] = byte(pubLen >> 16)
	blob[2] = byte(pubLen >> 8)
	blob[3] = byte(pubLen)
	copy(blob[4:], k.publicBlob)

	offset := 4 + pubLen
	blob[offset] = byte(privLen >> 24)
	blob[offset+1] = byte(privLen >> 16)
	blob[offset+2] = byte(privLen >> 8)
	blob[offset+3] = byte(privLen)
	copy(blob[offset+4:], k.privateBlob)

	return blob
}

// Close releases the TPM key handle
func (k *TPMKey) Close() error {
	if k.keyHandle != 0 && k.store != nil {
		flushCmd := tpm2.FlushContext{FlushHandle: k.keyHandle}
		flushCmd.Execute(k.store.tpm)
	}
	return nil
}

// tpmRSASigner implements crypto.Signer for RSA keys stored in TPM
type tpmRSASigner struct {
	store  *LinuxTPMStore
	handle tpm2.TPMHandle
	pubKey *rsa.PublicKey
}

func (s *tpmRSASigner) Public() crypto.PublicKey {
	return s.pubKey
}

func (s *tpmRSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashAlg := tpm2.TPMAlgSHA256
	if opts != nil {
		switch opts.HashFunc() {
		case crypto.SHA256:
			hashAlg = tpm2.TPMAlgSHA256
		case crypto.SHA384:
			hashAlg = tpm2.TPMAlgSHA384
		case crypto.SHA512:
			hashAlg = tpm2.TPMAlgSHA512
		default:
			return nil, fmt.Errorf("unsupported hash function: %v", opts.HashFunc())
		}
	}

	signCmd := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: s.handle,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digest: tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSchemeHash{HashAlg: hashAlg},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	rsp, err := signCmd.Execute(s.store.tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM Sign failed: %w", err)
	}

	rsaSig, err := rsp.Signature.Signature.RSASSA()
	if err != nil {
		return nil, fmt.Errorf("failed to get RSA signature: %w", err)
	}

	return rsaSig.Sig.Buffer, nil
}

// tpmECDSASigner implements crypto.Signer for ECDSA keys stored in TPM
type tpmECDSASigner struct {
	store  *LinuxTPMStore
	handle tpm2.TPMHandle
	pubKey *ecdsa.PublicKey
}

func (s *tpmECDSASigner) Public() crypto.PublicKey {
	return s.pubKey
}

func (s *tpmECDSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashAlg := tpm2.TPMAlgSHA256
	if opts != nil {
		switch opts.HashFunc() {
		case crypto.SHA256:
			hashAlg = tpm2.TPMAlgSHA256
		case crypto.SHA384:
			hashAlg = tpm2.TPMAlgSHA384
		default:
			return nil, fmt.Errorf("unsupported hash function for ECDSA: %v", opts.HashFunc())
		}
	}

	signCmd := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: s.handle,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digest: tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{HashAlg: hashAlg},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	rsp, err := signCmd.Execute(s.store.tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM Sign failed: %w", err)
	}

	ecdsaSig, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("failed to get ECDSA signature: %w", err)
	}

	// Convert TPM ECDSA signature to ASN.1 DER format
	r := new(big.Int).SetBytes(ecdsaSig.SignatureR.Buffer)
	sigS := new(big.Int).SetBytes(ecdsaSig.SignatureS.Buffer)

	return asn1.Marshal(struct {
		R, S *big.Int
	}{r, sigS})
}

// IsTPMAvailable checks if a TPM device is accessible
func IsTPMAvailable() bool {
	tpm, err := transport.OpenTPM(DefaultTPMDevice)
	if err != nil {
		tpm, err = transport.OpenTPM(FallbackTPMDevice)
		if err != nil {
			return false
		}
	}
	tpm.Close()
	return true
}
