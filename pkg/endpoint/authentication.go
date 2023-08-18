/*
 * Copyright 2023 Venafi, Inc.
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

package endpoint

// Authentication provides a struct for authentication data. Either specify User and Password for Trust Protection Platform
// or Firefly or ClientId and ClientSecret for Firefly or specify an APIKey for TLS Protect Cloud.
type Authentication struct {
	User         string `yaml:"user,omitempty"`
	Password     string `yaml:"password,omitempty"`
	APIKey       string `yaml:"apiKey,omitempty"`
	RefreshToken string `yaml:"refreshToken,omitempty"`
	Scope        string `yaml:"scope,omitempty"`
	ClientId     string `yaml:"clientId,omitempty"`
	ClientSecret string `yaml:"clientSecret,omitempty"`
	AccessToken  string `yaml:"accessToken,omitempty"`
	ClientPKCS12 bool   `yaml:"-"`
	// IdentityProvider specify the OAuth 2.0 which VCert will be working for authorization purposes
	IdentityProvider *OAuthProvider `yaml:"idP,omitempty"`
}

// OAuthProvider provides a struct for the OAuth 2.0 providers information
type OAuthProvider struct {
	DeviceURL string `yaml:"-"`
	TokenURL  string `yaml:"tokenURL,omitempty"`
	Audience  string `yaml:"audience,omitempty"`
}
