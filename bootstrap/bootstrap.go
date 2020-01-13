/*
 * Copyright 2017-2019 Kopano and its licensors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package bootstrap

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
	"stash.kopano.io/kgol/rndm"

	"stash.kopano.io/kc/konnect/config"
	"stash.kopano.io/kc/konnect/encryption"
	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/managers"
	oidcProvider "stash.kopano.io/kc/konnect/oidc/provider"
	"stash.kopano.io/kc/konnect/utils"
)

// Identity managers.
const (
	identityManagerNameCookie = "cookie"
	identityManagerNameDummy  = "dummy"
	identityManagerNameKC     = "kc"
	identityManagerNameLDAP   = "ldap"
)

// API types.
const (
	apiTypeKonnect = "konnect"
	apiTypeSignin  = "signin"
)

// Defaults.
const (
	DefaultIdentifierClientPath = "./identifier-webapp"
	DefaultSigningKeyID         = "default"
	DefaultSigningKeyBits       = 2048
)

//Stringly typed application config, represents the user accessible config params
type Config struct {
	ISS                            string
	IdentityManager                string
	URIBasePath                    string
	SignInUri                      string
	SignedOutUri                   string
	AuthorizationEndpointURI       string
	EndsessionEndpointURI          string
	Insecure                       bool
	TrustedProxy                   []string
	AllowScope                     []string
	AllowClientGuests              bool
	AllowDynamicClientRegistration bool
	EncryptionSecretFile           string
	Listen                         string
	IdentifierClientPath           string
	IdentifierRegistrationConf     string
	IdentifierScopesConf           string
	SigningKid                     string
	SigningMethod                  string
	SigningPrivateKeyFiles         []string
	ValidationKeysPath             string
	CookieBackendUri               string
	CookieNames                    []string
}

// Bootstrap is a data structure to hold configuration required to start
// konnectd.
type bootstrap struct {
	signInFormURI            *url.URL
	signedOutURI             *url.URL
	authorizationEndpointURI *url.URL
	endSessionEndpointURI    *url.URL

	tlsClientConfig *tls.Config

	issuerIdentifierURI        *url.URL
	identifierClientPath       string
	identifierRegistrationConf string
	identifierAuthoritiesConf  string
	identifierScopesConf       string

	encryptionSecret []byte
	signingMethod    jwt.SigningMethod
	signingKeyID     string
	signers          map[string]crypto.Signer
	validators       map[string]crypto.PublicKey

	accessTokenDurationSeconds uint64
	uriBasePath                string

	Cfg      *config.Config
	Managers *managers.Managers
}

func Boot(ctx context.Context, bsConf *Config, serverConf *config.Config) (*bootstrap, error) {
	// NOTE(longsleep): Ensure to use same salt length as the hash size.
	// See https://www.ietf.org/mail-archive/web/jose/current/msg02901.html for
	// reference and https://github.com/dgrijalva/jwt-go/issues/285 for
	// the issue in upstream jwt-go.
	for _, alg := range []string{jwt.SigningMethodPS256.Name, jwt.SigningMethodPS384.Name, jwt.SigningMethodPS512.Name} {
		sm := jwt.GetSigningMethod(alg)
		if signingMethodRSAPSS, ok := sm.(*jwt.SigningMethodRSAPSS); ok {
			signingMethodRSAPSS.Options.SaltLength = rsa.PSSSaltLengthEqualsHash
		}
	}

	bs := &bootstrap{
		Cfg: serverConf,
	}

	err := bs.initialize(bsConf)
	if err != nil {
		return nil, err
	}

	err = bs.setup(ctx, bsConf)
	if err != nil {
		return nil, err
	}

	return bs, nil
}

// initialize, parsed parameters from commandline with validation and adds them
// to the associated Bootstrap data.
func (bs *bootstrap) initialize(cfg *Config) error {
	logger := bs.Cfg.Logger
	var err error

	if cfg.IdentityManager == "" {
		return fmt.Errorf("identity-manager argument missing, use one of kc, ldap, cookie, dummy")
	}

	bs.issuerIdentifierURI, err = url.Parse(cfg.ISS)
	if err != nil {
		return fmt.Errorf("invalid iss value, iss is not a valid URL), %v", err)
	} else if cfg.ISS == "" {
		return fmt.Errorf("missing iss value, did you provide the --iss parameter?")
	} else if bs.issuerIdentifierURI.Scheme != "https" {
		return fmt.Errorf("invalid iss value, URL must start with https://")
	} else if bs.issuerIdentifierURI.Host == "" {
		return fmt.Errorf("invalid iss value, URL must have a host")
	}

	bs.uriBasePath = cfg.URIBasePath

	bs.signInFormURI, err = url.Parse(cfg.SignInUri)
	if err != nil {
		return fmt.Errorf("invalid sign-in URI, %v", err)
	}

	bs.signedOutURI, err = url.Parse(cfg.SignedOutUri)
	if err != nil {
		return fmt.Errorf("invalid signed-out URI, %v", err)
	}

	bs.authorizationEndpointURI, err = url.Parse(cfg.AuthorizationEndpointURI)
	if err != nil {
		return fmt.Errorf("invalid authorization-endpoint-uri, %v", err)
	}

	bs.endSessionEndpointURI, err = url.Parse(cfg.EndsessionEndpointURI)
	if err != nil {
		return fmt.Errorf("invalid endsession-endpoint-uri, %v", err)
	}

	if cfg.Insecure {
		// NOTE(longsleep): This disable http2 client support. See https://github.com/golang/go/issues/14275 for reasons.
		bs.tlsClientConfig = utils.InsecureSkipVerifyTLSConfig()
		logger.Warnln("insecure mode, TLS client connections are susceptible to man-in-the-middle attacks")
	} else {
		bs.tlsClientConfig = utils.DefaultTLSConfig()
	}

	for _, trustedProxy := range cfg.TrustedProxy {
		if ip := net.ParseIP(trustedProxy); ip != nil {
			bs.Cfg.TrustedProxyIPs = append(bs.Cfg.TrustedProxyIPs, &ip)
			continue
		}
		if _, ipNet, errParseCIDR := net.ParseCIDR(trustedProxy); errParseCIDR == nil {
			bs.Cfg.TrustedProxyNets = append(bs.Cfg.TrustedProxyNets, ipNet)
			continue
		}
	}
	if len(bs.Cfg.TrustedProxyIPs) > 0 {
		logger.Infoln("trusted proxy IPs", bs.Cfg.TrustedProxyIPs)
	}
	if len(bs.Cfg.TrustedProxyNets) > 0 {
		logger.Infoln("trusted proxy networks", bs.Cfg.TrustedProxyNets)
	}

	if len(cfg.AllowScope) > 0 {
		bs.Cfg.AllowedScopes = cfg.AllowScope
		logger.Infoln("using custom allowed OAuth 2 scopes", bs.Cfg.AllowedScopes)
	}

	bs.Cfg.AllowClientGuests = cfg.AllowClientGuests
	if bs.Cfg.AllowClientGuests {
		logger.Infoln("client controlled guests are enabled")
	}

	bs.Cfg.AllowDynamicClientRegistration = cfg.AllowDynamicClientRegistration
	if bs.Cfg.AllowDynamicClientRegistration {
		logger.Infoln("dynamic client registration is enabled")
	}

	encryptionSecretFn := cfg.EncryptionSecretFile

	if encryptionSecretFn != "" {
		logger.WithField("file", encryptionSecretFn).Infoln("loading encryption secret from file")
		bs.encryptionSecret, err = ioutil.ReadFile(encryptionSecretFn)
		if err != nil {
			return fmt.Errorf("failed to load encryption secret from file: %v", err)
		}
		if len(bs.encryptionSecret) != encryption.KeySize {
			return fmt.Errorf("invalid encryption secret size - must be %d bytes", encryption.KeySize)
		}
	} else {
		logger.Warnf("missing --encryption-secret parameter, using random encyption secret with %d bytes", encryption.KeySize)
		bs.encryptionSecret = rndm.GenerateRandomBytes(encryption.KeySize)
	}

	bs.Cfg.ListenAddr = cfg.Listen

	bs.identifierClientPath = cfg.IdentifierClientPath

	bs.identifierRegistrationConf = cfg.IdentifierRegistrationConf
	if bs.identifierRegistrationConf != "" {
		bs.identifierRegistrationConf, _ = filepath.Abs(bs.identifierRegistrationConf)
		if _, errStat := os.Stat(bs.identifierRegistrationConf); errStat != nil {
			return fmt.Errorf("identifier-registration-conf file not found or unable to access: %v", errStat)
		}
		bs.identifierAuthoritiesConf = bs.identifierRegistrationConf
	}

	bs.identifierScopesConf = cfg.IdentifierScopesConf
	if bs.identifierScopesConf != "" {
		bs.identifierScopesConf, _ = filepath.Abs(bs.identifierScopesConf)
		if _, errStat := os.Stat(bs.identifierScopesConf); errStat != nil {
			return fmt.Errorf("identifier-scopes-conf file not found or unable to access: %v", errStat)
		}
	}

	bs.signingKeyID = cfg.SigningKid
	bs.signers = make(map[string]crypto.Signer)
	bs.validators = make(map[string]crypto.PublicKey)

	signingMethodString := cfg.SigningMethod
	bs.signingMethod = jwt.GetSigningMethod(signingMethodString)
	if bs.signingMethod == nil {
		return fmt.Errorf("unknown signing method: %s", signingMethodString)
	}

	signingKeyFns := cfg.SigningPrivateKeyFiles
	if len(signingKeyFns) > 0 {
		first := true
		for _, signingKeyFn := range signingKeyFns {
			logger.WithField("path", signingKeyFn).Infoln("loading signing key")
			err = AddSignerWithIDFromFile(signingKeyFn, "", bs)
			if err != nil {
				return err
			}
			if first {
				// Also add key under the provided id.
				first = false
				err = AddSignerWithIDFromFile(signingKeyFn, bs.signingKeyID, bs)
				if err != nil {
					return err
				}
			}
		}
	} else {
		//NOTE(longsleep): remove me - create keypair a random key pair.
		sm := jwt.SigningMethodPS256
		bs.signingMethod = sm
		logger.WithField("alg", sm.Name).Warnf("missing --signing-private-key parameter, using random %d bit signing key", DefaultSigningKeyBits)
		signer, _ := rsa.GenerateKey(rand.Reader, DefaultSigningKeyBits)
		bs.signers[bs.signingKeyID] = signer
	}

	// Ensure we have a signer for the things we need.
	err = ValidateSigners(bs)
	if err != nil {
		return err
	}

	validationKeysPath := cfg.ValidationKeysPath
	if validationKeysPath != "" {
		logger.WithField("path", validationKeysPath).Infoln("loading validation keys")
		err = AddValidatorsFromPath(validationKeysPath, bs)
		if err != nil {
			return err
		}
	}

	bs.Cfg.HTTPTransport = utils.HTTPTransportWithTLSClientConfig(bs.tlsClientConfig)
	bs.accessTokenDurationSeconds = 10 * 60 // 10 Minutes.

	return nil
}

// setup takes care of setting up the managers based on the associated
// Bootstrap's data.
func (bs *bootstrap) setup(ctx context.Context, cfg *Config) error {
	managers, err := NewManagers(ctx, bs)
	if err != nil {
		return err
	}

	identityManager, err := bs.setupIdentity(ctx, cfg)
	if err != nil {
		return err
	}
	managers.Set("identity", identityManager)

	guestManager, err := bs.setupGuest(ctx, identityManager)
	if err != nil {
		return err
	}
	managers.Set("guest", guestManager)

	oidcProvider, err := bs.setupOIDCProvider(ctx)
	if err != nil {
		return err
	}
	managers.Set("oidc", oidcProvider)
	managers.Set("handler", oidcProvider) // Use OIDC provider as default HTTP handler.

	err = managers.Apply()
	if err != nil {
		return fmt.Errorf("failed to apply managers: %v", err)
	}

	// Final steps
	err = oidcProvider.InitializeMetadata()
	if err != nil {
		return fmt.Errorf("failed to initialize provider metadata: %v", err)
	}

	bs.Managers = managers
	return nil
}

func (bs *bootstrap) makeURIPath(api string, subpath string) string {
	subpath = strings.TrimPrefix(subpath, "/")

	switch api {
	case apiTypeKonnect:
		return fmt.Sprintf("%s/konnect/v1/%s", strings.TrimSuffix(bs.uriBasePath, "/"), subpath)
	case apiTypeSignin:
		return fmt.Sprintf("%s/signin/v1/%s", strings.TrimSuffix(bs.uriBasePath, "/"), subpath)
	default:
		panic("unknown api type")
	}
}

func (bs *bootstrap) setupIdentity(ctx context.Context, cfg *Config) (identity.Manager, error) {
	var err error
	logger := bs.Cfg.Logger

	if cfg.IdentityManager == "" {
		return nil, fmt.Errorf("identity-manager argument missing")
	}

	identityManagerName := cfg.IdentityManager

	// Identity manager.
	var identityManager identity.Manager
	switch identityManagerName {
	case identityManagerNameCookie:
		identityManager, err = newCookieIdentityManager(bs, cfg)

	case identityManagerNameKC:
		identityManager, err = newKCIdentityManager(bs)

	case identityManagerNameLDAP:
		identityManager, err = newLDAPIdentityManager(bs)

	case identityManagerNameDummy:
		identityManager, err = newDummyIdentityManager(bs)

	default:
		err = fmt.Errorf("unknown identity manager %v", identityManagerName)
	}
	if err != nil {
		return nil, err
	}
	logger.WithFields(logrus.Fields{
		"name":   identityManagerName,
		"scopes": identityManager.ScopesSupported(nil),
		"claims": identityManager.ClaimsSupported(nil),
	}).Infoln("identity manager set up")

	return identityManager, nil
}

func (bs *bootstrap) setupGuest(ctx context.Context, identityManager identity.Manager) (identity.Manager, error) {
	if !bs.Cfg.AllowClientGuests {
		return nil, nil
	}

	var err error
	logger := bs.Cfg.Logger

	guestManager, err := newGuestIdentityManager(bs)
	if err != nil {
		return nil, err
	}

	if guestManager != nil {
		logger.Infoln("identity guest manager set up")
	}
	return guestManager, nil
}

func (bs *bootstrap) setupOIDCProvider(ctx context.Context) (*oidcProvider.Provider, error) {
	var err error
	logger := bs.Cfg.Logger

	sessionCookiePath, err := getCommonURLPathPrefix(bs.authorizationEndpointURI.EscapedPath(), bs.endSessionEndpointURI.EscapedPath())
	if err != nil {
		return nil, fmt.Errorf("failed to find common URL prefix for authorize and endsession: %v", err)
	}

	var registrationPath = ""
	if bs.Cfg.AllowDynamicClientRegistration {
		registrationPath = bs.makeURIPath(apiTypeKonnect, "/register")
	}

	provider, err := oidcProvider.NewProvider(&oidcProvider.Config{
		Config: bs.Cfg,

		IssuerIdentifier:       bs.issuerIdentifierURI.String(),
		WellKnownPath:          "/.well-known/openid-configuration",
		JwksPath:               bs.makeURIPath(apiTypeKonnect, "/jwks.json"),
		AuthorizationPath:      bs.authorizationEndpointURI.EscapedPath(),
		TokenPath:              bs.makeURIPath(apiTypeKonnect, "/token"),
		UserInfoPath:           bs.makeURIPath(apiTypeKonnect, "/userinfo"),
		EndSessionPath:         bs.endSessionEndpointURI.EscapedPath(),
		CheckSessionIframePath: bs.makeURIPath(apiTypeKonnect, "/session/check-session.html"),
		RegistrationPath:       registrationPath,

		BrowserStateCookiePath: bs.makeURIPath(apiTypeKonnect, "/session/"),
		BrowserStateCookieName: "__Secure-KKBS", // Kopano-Konnect-Browser-State

		SessionCookiePath: sessionCookiePath,
		SessionCookieName: "__Secure-KKCS", // Kopano-Konnect-Client-Session

		AccessTokenDuration:  time.Duration(bs.accessTokenDurationSeconds) * time.Second,
		IDTokenDuration:      1 * time.Hour,            // 1 Hour, must be consumed by then.
		RefreshTokenDuration: 24 * 365 * 3 * time.Hour, // 3 Years.
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create provider: %v", err)
	}
	if bs.signingMethod != nil {
		err = provider.SetSigningMethod(bs.signingMethod)
		if err != nil {
			return nil, fmt.Errorf("failed to set provider signing method: %v", err)
		}
	}

	// All add signers.
	for id, signer := range bs.signers {
		if id == bs.signingKeyID {
			err = provider.SetSigningKey(id, signer)
			// Always set default key.
			if id != DefaultSigningKeyID {
				provider.SetValidationKey(DefaultSigningKeyID, signer.Public())
			}
		} else {
			// Set non default signers as well.
			err = provider.SetSigningKey(id, signer)
		}
		if err != nil {
			return nil, err
		}
	}
	// Add all validators.
	for id, publicKey := range bs.validators {
		err = provider.SetValidationKey(id, publicKey)
		if err != nil {
			return nil, err
		}
	}

	sk, ok := provider.GetSigningKey(bs.signingMethod)
	if !ok {
		return nil, fmt.Errorf("no signing key for selected signing method")
	}
	if bs.signingKeyID == "" {
		// Ensure that there is a default signing Key ID even if none was set.
		provider.SetValidationKey(DefaultSigningKeyID, sk.PrivateKey.Public())
	}
	logger.WithFields(logrus.Fields{
		"id":     sk.ID,
		"method": fmt.Sprintf("%T", sk.SigningMethod),
		"alg":    sk.SigningMethod.Alg(),
	}).Infoln("oidc token signing default set up")

	return provider, nil
}
