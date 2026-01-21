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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/playbook/app/domain"
	"github.com/Venafi/vcert/v5/pkg/playbook/util/capistore"
	"github.com/Venafi/vcert/v5/pkg/util"
	"github.com/Venafi/vcert/v5/pkg/venafi/tpp"
	"github.com/Venafi/vcert/v5/pkg/verror"
)

// EnrollCertificate takes a Request object and requests a certificate to the Venafi platform defined by config.
//
// Then it retrieves the certificate and returns it along with the certificate chain and the private key used.
func EnrollCertificate(config domain.Config, request domain.PlaybookRequest) (*certificate.PEMCollection, *certificate.Request, error) {
	client, err := buildClient(config, request.Zone, request.Timeout)
	if err != nil {
		return nil, nil, err
	}

	vRequest, err := buildRequest(request)
	if err != nil {
		return nil, nil, err
	}

	zoneCfg, err := client.ReadZoneConfiguration()
	if err != nil {
		return nil, nil, err
	}
	zap.L().Debug("successfully read zone config", zap.String("zone", request.Zone))

	err = client.GenerateRequest(zoneCfg, &vRequest)
	if err != nil {
		return nil, nil, err
	}
	zap.L().Debug("successfully updated Request with zone config values")

	var pcc *certificate.PEMCollection

	if client.SupportSynchronousRequestCertificate() {
		pcc, err = client.SynchronousRequestCertificate(&vRequest)
	} else {
		reqID, reqErr := client.RequestCertificate(&vRequest)
		if reqErr != nil {
			return nil, nil, reqErr
		}
		zap.L().Debug("successfully requested certificate", zap.String("requestID", reqID))

		vRequest.PickupID = reqID

		pcc, err = client.RetrieveCertificate(&vRequest)
	}

	if err != nil {
		return nil, nil, err
	}
	zap.L().Debug("successfully retrieved certificate", zap.String("certificate", request.Subject.CommonName))

	return pcc, &vRequest, nil
}

func buildClient(config domain.Config, zone string, timeout int) (endpoint.Connector, error) {
	var netTransport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(timeout) * time.Second,
			KeepAlive: time.Duration(timeout) * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	vcertConfig := &vcert.Config{
		ConnectorType:   config.Connection.GetConnectorType(),
		BaseUrl:         config.Connection.URL,
		Zone:            zone,
		ConnectionTrust: loadTrustBundle(config.Connection.TrustBundlePath),
		LogVerbose:      false,
	}

	vcertConfig.Client = &http.Client{
		Timeout:   time.Duration(DefaultTimeout) * time.Second,
		Transport: netTransport,
	}
	if timeout > 0 {
		vcertConfig.Client.Timeout = time.Duration(timeout) * time.Second
	}
	var connectionTrustBundle *x509.CertPool

	if vcertConfig.ConnectionTrust != "" {
		zap.L().Debug("Using trust bundle in custom http client")
		connectionTrustBundle = x509.NewCertPool()
		if !connectionTrustBundle.AppendCertsFromPEM([]byte(vcertConfig.ConnectionTrust)) {
			return nil, fmt.Errorf("%w: failed to parse PEM trust bundle", verror.UserDataError)
		}
		netTransport.TLSClientConfig = &tls.Config{
			RootCAs:    connectionTrustBundle,
			MinVersion: tls.VersionTLS12,
		}

		vcertConfig.Client.Transport = netTransport
	}

	// build Authentication object
	vcertAuth, err := buildVCertAuthentication(config.Connection.Credentials)
	if err != nil {
		return nil, err
	}
	vcertConfig.Credentials = vcertAuth

	client, err := vcert.NewClient(vcertConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func buildVCertAuthentication(playbookAuth domain.Authentication) (*endpoint.Authentication, error) {
	attrPrefix := "config.connection.credentials.%s"

	vcertAuth := &endpoint.Authentication{}

	// CyberArk Certificate Manager, SaaS API key
	apiKey, err := getAttributeValue(fmt.Sprintf(attrPrefix, "apiKey"), playbookAuth.APIKey)
	if err != nil {
		return nil, err
	}
	vcertAuth.APIKey = apiKey

	// CyberArk Certificate Manager, SaaS service account
	jwt, err := getAttributeValue(fmt.Sprintf(attrPrefix, "externalJWT"), playbookAuth.ExternalJWT)
	if err != nil {
		return nil, err
	}
	vcertAuth.ExternalJWT = jwt

	tokenURL, err := getAttributeValue(fmt.Sprintf(attrPrefix, "tokenURL"), playbookAuth.TokenURL)
	if err != nil {
		return nil, err
	}
	vcertAuth.TokenURL = tokenURL

	// CyberArk Certificate Manager, Self-Hosted/Certificate Manager, SaaS/Workload Identity Manager Access token
	accessToken, err := getAttributeValue(fmt.Sprintf(attrPrefix, "accessToken"), playbookAuth.AccessToken)
	if err != nil {
		return nil, err
	}
	vcertAuth.AccessToken = accessToken

	// Scope
	scope, err := getAttributeValue(fmt.Sprintf(attrPrefix, "scope"), playbookAuth.Scope)
	if err != nil {
		return nil, err
	}
	vcertAuth.Scope = scope

	// Client ID
	clientID, err := getAttributeValue(fmt.Sprintf(attrPrefix, "clientId"), playbookAuth.ClientId)
	if err != nil {
		return nil, err
	}
	vcertAuth.ClientId = clientID

	// Client secret
	clientSecret, err := getAttributeValue(fmt.Sprintf(attrPrefix, "clientSecret"), playbookAuth.ClientSecret)
	if err != nil {
		return nil, err
	}
	vcertAuth.ClientSecret = clientSecret

	// Return here as Identity provider is nil
	if playbookAuth.IdentityProvider == nil {
		return vcertAuth, nil
	}

	idp := &endpoint.OAuthProvider{}

	// OAuth provider token url
	idpTokenURL, err := getAttributeValue(fmt.Sprintf(attrPrefix, "idP.tokenURL"), playbookAuth.IdentityProvider.TokenURL)
	if err != nil {
		return nil, err
	}
	idp.TokenURL = idpTokenURL

	// OAuth provider audience
	audience, err := getAttributeValue(fmt.Sprintf(attrPrefix, "idP.audience"), playbookAuth.IdentityProvider.Audience)
	if err != nil {
		return nil, err
	}
	idp.Audience = audience

	vcertAuth.IdentityProvider = idp

	return vcertAuth, nil
}

func getAttributeValue(attrName string, attrValue string) (string, error) {
	offset := len(filePrefix)
	attrValue = strings.TrimSpace(attrValue)

	// No file prefix, return value as is
	if !strings.HasPrefix(attrValue, filePrefix) {
		return attrValue, nil
	}

	data, err := readFile(attrValue[offset:])
	if err != nil {
		return "", fmt.Errorf("failed to read value [%s] from authentication object: %w", attrName, err)
	}
	fileValue := strings.TrimSpace(string(data))

	return fileValue, nil
}

func buildRequest(request domain.PlaybookRequest) (certificate.Request, error) {

	vcertRequest := certificate.Request{
		CADN: request.CADN,
		Subject: pkix.Name{
			CommonName:         request.Subject.CommonName,
			Country:            []string{request.Subject.Country},
			Organization:       []string{request.Subject.Organization},
			OrganizationalUnit: request.Subject.OrgUnits,
			Locality:           []string{request.Subject.Locality},
			Province:           []string{request.Subject.Province},
		},
		DNSNames:       request.DNSNames,
		OmitSANs:       request.OmitSANs,
		EmailAddresses: request.EmailAddresses,
		IPAddresses:    getIPAddresses(request.IPAddresses),
		URIs:           getURIs(request.URIs),
		UPNs:           request.UPNs,
		FriendlyName:   request.FriendlyName,
		ChainOption:    request.ChainOption,
		KeyPassword:    request.KeyPassword,
		CustomFields:   request.CustomFields,
		ExtKeyUsages:   request.ExtKeyUsages,
	}

	// Set timeout for cert retrieval
	setTimeout(request, &vcertRequest)
	//Set Location
	setLocationWorkload(request, &vcertRequest)
	//Set KeyType
	setKeyType(request, &vcertRequest)
	//Set Origin
	setOrigin(request, &vcertRequest)
	//Set Validity
	setValidity(request, &vcertRequest)
	//Set CSR
	if err := setCSR(request, &vcertRequest); err != nil {
		return certificate.Request{}, err
	}

	return vcertRequest, nil
}

// DecryptPrivateKey takes an encrypted private key and decrypts it using the given password.
//
// The private key must be in PKCS8 format.
func DecryptPrivateKey(privateKey string, password string) (string, error) {
	privateKey, err := util.DecryptPkcs8PrivateKey(privateKey, password)
	return privateKey, err
}

// EncryptPrivateKeyPKCS1 takes a decrypted PKCS8 private key and encrypts it back in PKCS1 format
func EncryptPrivateKeyPKCS1(privateKey string, password string) (string, error) {
	privateKey, err := util.EncryptPkcs1PrivateKey(privateKey, password)
	return privateKey, err
}

// IsValidAccessToken checks that the accessToken in config is not expired.
func IsValidAccessToken(config domain.Config) (bool, error) {
	// No access token provided. Use refresh token to get new access token right away
	if config.Connection.Credentials.AccessToken == "" {
		return false, fmt.Errorf("an access token was not provided for connection to TPP")
	}

	vConfig := &vcert.Config{
		ConnectorType: config.Connection.GetConnectorType(),
		BaseUrl:       config.Connection.URL,
		Credentials: &endpoint.Authentication{
			Scope:       config.Connection.Credentials.Scope,
			ClientId:    config.Connection.Credentials.ClientId,
			AccessToken: config.Connection.Credentials.AccessToken,
		},
		ConnectionTrust: loadTrustBundle(config.Connection.TrustBundlePath),
		LogVerbose:      false,
	}

	client, err := vcert.NewClient(vConfig, false)
	if err != nil {
		return false, err
	}

	_, err = client.(*tpp.Connector).VerifyAccessToken(vConfig.Credentials)

	return err == nil, err
}

// RefreshTPPTokens uses the refreshToken in config to request a new pair of tokens
func RefreshTPPTokens(config domain.Config) (string, string, error) {
	vConfig := &vcert.Config{
		ConnectorType: config.Connection.GetConnectorType(),
		BaseUrl:       config.Connection.URL,
		Credentials: &endpoint.Authentication{
			Scope:    config.Connection.Credentials.Scope,
			ClientId: config.Connection.Credentials.ClientId,
		},
		ConnectionTrust: loadTrustBundle(config.Connection.TrustBundlePath),
		LogVerbose:      false,
	}

	//Creating an empty client
	client, err := vcert.NewClient(vConfig, false)
	if err != nil {
		return "", "", err
	}

	auth := endpoint.Authentication{
		RefreshToken: config.Connection.Credentials.RefreshToken,
		ClientPKCS12: config.Connection.Credentials.P12Task != "",
		Scope:        config.Connection.Credentials.Scope,
		ClientId:     config.Connection.Credentials.ClientId,
	}

	if auth.RefreshToken != "" {
		resp, err := client.(*tpp.Connector).RefreshAccessToken(&auth)
		if err != nil {
			if auth.ClientPKCS12 {
				resp, err2 := client.(*tpp.Connector).GetRefreshToken(&auth)
				if err2 != nil {
					return "", "", errors.Join(err2, err)
				}
				return resp.Access_token, resp.Refresh_token, nil
			}
			return "", "", err
		}
		return resp.Access_token, resp.Refresh_token, nil
	} else if auth.ClientPKCS12 {
		auth.RefreshToken = ""
		resp, err := client.(*tpp.Connector).GetRefreshToken(&auth)
		if err != nil {
			return "", "", err
		}
		return resp.Access_token, resp.Refresh_token, nil
	}

	return "", "", fmt.Errorf("no refresh token or certificate available to refresh access token")
}

func GeneratePassword() string {
	letterRunes := "abcdefghijklmnopqrstuvwxyz"

	b := make([]byte, 4)
	_, _ = rand.Read(b)

	for i, v := range b {
		b[i] = letterRunes[v%byte(len(letterRunes))]
	}

	randString := string(b)

	return fmt.Sprintf("t%d-%s.temp.pwd", time.Now().Unix(), randString)
}

// EnrollCertificateWithTPM handles TPM-backed certificate enrollment for CAPI installations.
// The key is generated in the TPM, CSR is created and submitted to Venafi, and the
// resulting certificate is stored in Windows CAPI with the TPM-backed key.
//
// Parameters:
//   - config: The playbook configuration for connection
//   - request: The certificate request parameters
//   - capiLocation: The CAPI store location (e.g., "LocalMachine\\My" or "CurrentUser\\My")
//   - isOptional: If true, falls back to software key generation when TPM is unavailable
//
// Returns:
//   - The enrolled x509 certificate
//   - Error if enrollment fails
func EnrollCertificateWithTPM(config domain.Config, request domain.PlaybookRequest, capiLocation string, isOptional bool) (*x509.Certificate, error) {
	// Parse CAPI location to get store settings
	currentUser, _, err := capistore.ParseCAPILocation(capiLocation)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CAPI location: %w", err)
	}

	// Generate a unique container name for the TPM key based on common name
	container := capistore.GenerateContainerName(request.Subject.CommonName)

	zap.L().Info("initializing TPM-backed certificate enrollment",
		zap.String("commonName", request.Subject.CommonName),
		zap.String("container", container),
		zap.String("capiLocation", capiLocation),
		zap.Bool("tpmOptional", isOptional))

	// Open TPM-backed cert store (with fallback to software if isOptional)
	var tpmStore *capistore.TPMCertStore
	var usingTPM bool

	if isOptional {
		// Use fallback function - will use software key storage if TPM unavailable
		tpmStore, usingTPM, err = capistore.NewTPMCertStoreWithFallback(container, currentUser)
		if err != nil {
			return nil, fmt.Errorf("failed to open cert store: %w", err)
		}
		if !usingTPM {
			zap.L().Info("TPM not available, using software key storage (tpm_optional fallback)")
		}
	} else {
		// TPM is mandatory - fail if unavailable
		tpmStore, err = capistore.NewTPMCertStore(container, currentUser)
		if err != nil {
			return nil, fmt.Errorf("failed to open TPM cert store: %w", err)
		}
		usingTPM = true
	}
	defer tpmStore.Close()

	// Determine key type and size
	keyType := request.KeyType
	if keyType == 0 {
		keyType = certificate.KeyTypeRSA // Default to RSA
	}
	keySize := request.KeyLength
	if keySize == 0 {
		keySize = 2048 // Default RSA key size
	}

	// Generate TPM-backed key (with legacy key size fallback if configured)
	signer, actualKeySize, err := tpmStore.GenerateKey(keyType, keySize, request.TPMConfig.LegacyKeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TPM key: %w", err)
	}

	// Log if key size was adjusted due to legacy fallback
	if actualKeySize != keySize {
		zap.L().Warn("TPM key size adjusted due to tpmConfig.legacyKeySize setting",
			zap.Int("requestedSize", keySize),
			zap.Int("actualSize", actualKeySize))
	}

	keyStorageType := "TPM-backed"
	if !usingTPM {
		keyStorageType = "software"
	}
	zap.L().Info("successfully generated key",
		zap.String("storageType", keyStorageType),
		zap.String("keyType", keyType.String()),
		zap.Int("keySize", actualKeySize))

	// Build CSR template from request
	csrTemplate := buildCSRTemplate(request)

	// Create CSR signed by TPM-backed key
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR with TPM key: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	zap.L().Debug("created CSR with TPM-backed key")

	// Build Venafi client
	client, err := buildClient(config, request.Zone, request.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to build Venafi client: %w", err)
	}

	// Build the certificate request for Venafi
	vRequest := certificate.Request{
		CsrOrigin: certificate.UserProvidedCSR, // We're providing the CSR
	}
	if err := vRequest.SetCSR(csrPEM); err != nil {
		return nil, fmt.Errorf("failed to set CSR: %w", err)
	}

	// Set timeout and other options
	setTimeout(request, &vRequest)
	vRequest.ChainOption = request.ChainOption
	vRequest.CustomFields = request.CustomFields
	vRequest.FriendlyName = request.FriendlyName

	// Read zone configuration
	zoneCfg, err := client.ReadZoneConfiguration()
	if err != nil {
		return nil, fmt.Errorf("failed to read zone configuration: %w", err)
	}
	zap.L().Debug("successfully read zone config", zap.String("zone", request.Zone))

	// Generate request with zone config (this updates the request with zone settings)
	if err := client.GenerateRequest(zoneCfg, &vRequest); err != nil {
		return nil, fmt.Errorf("failed to generate request with zone config: %w", err)
	}

	// Request certificate from Venafi
	var pcc *certificate.PEMCollection
	if client.SupportSynchronousRequestCertificate() {
		pcc, err = client.SynchronousRequestCertificate(&vRequest)
	} else {
		reqID, reqErr := client.RequestCertificate(&vRequest)
		if reqErr != nil {
			return nil, fmt.Errorf("failed to request certificate: %w", reqErr)
		}
		zap.L().Debug("successfully requested certificate", zap.String("requestID", reqID))

		vRequest.PickupID = reqID
		pcc, err = client.RetrieveCertificate(&vRequest)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve certificate: %w", err)
	}

	zap.L().Info("successfully retrieved certificate from Venafi",
		zap.String("commonName", request.Subject.CommonName))

	// Parse the certificate
	certBlock, _ := pem.Decode([]byte(pcc.Certificate))
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Parse intermediate certificate if present
	var intermediate *x509.Certificate
	if len(pcc.Chain) > 0 {
		chainBlock, _ := pem.Decode([]byte(pcc.Chain[0]))
		if chainBlock != nil {
			intermediate, _ = x509.ParseCertificate(chainBlock.Bytes)
		}
	}

	// Store the certificate with the TPM-backed key
	if err := tpmStore.StoreCertificate(cert, intermediate); err != nil {
		return nil, fmt.Errorf("failed to store certificate in CAPI with TPM key: %w", err)
	}

	zap.L().Info("successfully stored certificate in Windows CAPI",
		zap.String("commonName", request.Subject.CommonName),
		zap.String("capiLocation", capiLocation),
		zap.String("keyStorage", keyStorageType))

	return cert, nil
}

// buildCSRTemplate creates an x509.CertificateRequest template from the playbook request
func buildCSRTemplate(request domain.PlaybookRequest) x509.CertificateRequest {
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         request.Subject.CommonName,
			Country:            []string{request.Subject.Country},
			Organization:       []string{request.Subject.Organization},
			OrganizationalUnit: request.Subject.OrgUnits,
			Locality:           []string{request.Subject.Locality},
			Province:           []string{request.Subject.Province},
		},
		DNSNames:       request.DNSNames,
		EmailAddresses: request.EmailAddresses,
	}

	// Add IP addresses
	for _, ipStr := range request.IPAddresses {
		if ip := net.ParseIP(ipStr); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	// Add URIs
	template.URIs = getURIs(request.URIs)

	return template
}
