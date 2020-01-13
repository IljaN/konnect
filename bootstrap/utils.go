package bootstrap

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"stash.kopano.io/kc/konnect/signing"
	"strings"
)

func parseJSONWebKey(jsonBytes []byte) (*jose.JSONWebKey, error) {
	k := &jose.JSONWebKey{}
	if err := k.UnmarshalJSON(jsonBytes); err != nil {
		return nil, err
	}
	return k, nil
}

func LoadSignerFromFile(fn string) (string, crypto.Signer, error) {
	readBytes, errRead := ioutil.ReadFile(fn)
	if errRead != nil {
		return "", nil, fmt.Errorf("failed to parse key file: %v", errRead)
	}

	ext := filepath.Ext(fn)
	switch ext {
	case ".json":
		k, err := parseJSONWebKey(readBytes)
		if err != nil {
			return "", nil, fmt.Errorf("failed to parse key file as JWK: %v", err)
		}
		if !k.Valid() {
			return "", nil, fmt.Errorf("json file is not a valid JWK")
		}
		if k.IsPublic() {
			return "", nil, fmt.Errorf("JWK is a public key, private key required to use as signer")
		}
		signer, ok := k.Key.(crypto.Signer)
		if !ok {
			return "", nil, fmt.Errorf("JWS key type %T is not a signer", k.Key)
		}

		return k.KeyID, signer, nil

	case ".pem":
		fallthrough
	default:
		// Try PEM if not otherwise detected.
		signer, err := parsePEMSigner(readBytes)
		return "", signer, err
	}
}

func parsePEMSigner(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	var signer crypto.Signer
	for {
		pkcs1Key, errParse1 := x509.ParsePKCS1PrivateKey(block.Bytes)
		if errParse1 == nil {
			signer = pkcs1Key
			break
		}

		pkcs8Key, errParse2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if errParse2 == nil {
			signerSigner, ok := pkcs8Key.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("failed to use key as crypto signer")
			}
			signer = signerSigner
			break
		}

		ecKey, errParse3 := x509.ParseECPrivateKey(block.Bytes)
		if errParse3 == nil {
			signer = ecKey
			break
		}

		return nil, fmt.Errorf("failed to parse signer key - valid PKCS#1, PKCS#8 ...? %v, %v, %v", errParse1, errParse2, errParse3)
	}

	return signer, nil
}

func LoadValidatorFromFile(fn string) (string, crypto.PublicKey, error) {
	readBytes, errRead := ioutil.ReadFile(fn)
	if errRead != nil {
		return "", nil, fmt.Errorf("failed to parse key file: %v", errRead)
	}

	ext := filepath.Ext(fn)
	switch ext {
	case ".json":
		k, err := parseJSONWebKey(readBytes)
		if err != nil {
			return "", nil, fmt.Errorf("failed to parse key file as JWK: %v", err)
		}
		if !k.Valid() {
			return "", nil, fmt.Errorf("json file is not a valid JWK")
		}
		if !k.IsPublic() {
			public := k.Public()
			k = &public
		}
		return k.KeyID, k.Key, nil

	case ".pem":
		fallthrough
	default:
		// Try PEM if not otherwise detected.
		validator, err := parsePEMValidator(readBytes)
		return "", validator, err
	}
}

func parsePEMValidator(pemBytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	var validator crypto.PublicKey
	for {
		pkixPubKey, errParse0 := x509.ParsePKIXPublicKey(block.Bytes)
		if errParse0 == nil {
			validator = pkixPubKey
			break
		}

		pkcs1PubKey, errParse1 := x509.ParsePKCS1PublicKey(block.Bytes)
		if errParse1 == nil {
			validator = pkcs1PubKey
			break
		}

		pkcs1PrivKey, errParse2 := x509.ParsePKCS1PrivateKey(block.Bytes)
		if errParse2 == nil {
			validator = pkcs1PrivKey.Public()
			break
		}

		pkcs8Key, errParse3 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if errParse3 == nil {
			signerSigner, ok := pkcs8Key.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("failed to use key as crypto signer")
			}
			validator = signerSigner.Public()
			break
		}

		ecKey, errParse4 := x509.ParseECPrivateKey(block.Bytes)
		if errParse4 == nil {
			validator = ecKey.Public()
			break
		}

		return nil, fmt.Errorf("failed to parse validator key - valid PKCS#1, PKCS#8 ...? %v, %v, %v, %v, %v", errParse0, errParse1, errParse2, errParse3, errParse4)
	}

	return validator, nil
}

func AddSignerWithIDFromFile(fn string, kid string, bs *bootstrap) error {
	fi, err := os.Lstat(fn)
	if err != nil {
		return fmt.Errorf("failed load load signer key: %v", err)
	}

	mode := fi.Mode()
	switch {
	case mode.IsDir():
		return fmt.Errorf("signer key must be a file")
	}

	// Load file.
	signerKid, signer, err := LoadSignerFromFile(fn)
	if err != nil {
		return err
	}
	if kid == "" {
		kid = signerKid
	}
	if kid == "" {
		// Get ID from file, following symbolic link.
		var real string
		if mode&os.ModeSymlink != 0 {
			real, err = os.Readlink(fn)
			if err != nil {
				return err
			}
			_, real = filepath.Split(real)
		} else {
			real = fi.Name()
		}

		kid = getKeyIDFromFilename(real)
	}

	if _, ok := bs.signers[kid]; ok {
		bs.Cfg.Logger.WithFields(logrus.Fields{
			"path": fn,
			"kid":  kid,
		}).Warnln("skipped as signer with same kid already loaded")
		return nil
	} else {
		bs.Cfg.Logger.WithFields(logrus.Fields{
			"path": fn,
			"kid":  kid,
		}).Debugln("loaded signer key")
	}

	bs.signers[kid] = signer
	return nil
}

func ValidateSigners(bs *bootstrap) error {
	haveRSA := false
	haveECDSA := false
	haveEd25519 := false
	for _, signer := range bs.signers {
		switch s := signer.(type) {
		case *rsa.PrivateKey:
			// Ensure the private key is not vulnerable with PKCS-1.5 signatures. See
			// https://paragonie.com/blog/2018/04/protecting-rsa-based-protocols-against-adaptive-chosen-ciphertext-attacks#rsa-anti-bb98
			// for details.
			if s.PublicKey.E < 65537 {
				return fmt.Errorf("RSA signing key with public exponent < 65537")
			}
			haveRSA = true
		case *ecdsa.PrivateKey:
			haveECDSA = true
		case ed25519.PrivateKey:
			haveEd25519 = true
		default:
			return fmt.Errorf("unsupported signer type: %v", s)
		}
	}

	// Validate signing method
	switch bs.signingMethod.(type) {
	case *jwt.SigningMethodRSA:
		if !haveRSA {
			return fmt.Errorf("no private key for signing method: %s", bs.signingMethod.Alg())
		}
	case *jwt.SigningMethodRSAPSS:
		if !haveRSA {
			return fmt.Errorf("no private key for signing method: %s", bs.signingMethod.Alg())
		}
	case *jwt.SigningMethodECDSA:
		if !haveECDSA {
			return fmt.Errorf("no private key for signing method: %s", bs.signingMethod.Alg())
		}
	case *signing.SigningMethodEdwardsCurve:
		if !haveEd25519 {
			return fmt.Errorf("no private key for signing method: %s", bs.signingMethod.Alg())
		}
	default:
		return fmt.Errorf("unsupported signing method: %s", bs.signingMethod.Alg())
	}

	if !haveRSA {
		bs.Cfg.Logger.Warnln("no RSA signing private key, some clients might not be compatible")
	}

	return nil
}

func AddValidatorsFromPath(pn string, bs *bootstrap) error {
	fi, err := os.Lstat(pn)
	if err != nil {
		return fmt.Errorf("failed load load validator keys: %v", err)
	}

	switch mode := fi.Mode(); {
	case mode.IsDir():
		// OK.
	default:
		return fmt.Errorf("validator path must be a directory")
	}

	// Load all files.
	files := []string{}
	if pemFiles, err := filepath.Glob(filepath.Join(pn, "*.pem")); err != nil {
		return fmt.Errorf("validator path err: %v", err)
	} else {
		files = append(files, pemFiles...)
	}
	if jsonFiles, err := filepath.Glob(filepath.Join(pn, "*.json")); err != nil {
		return fmt.Errorf("validator path err: %v", err)
	} else {
		files = append(files, jsonFiles...)
	}

	for _, file := range files {
		kid, validator, err := LoadValidatorFromFile(file)
		if err != nil {
			bs.Cfg.Logger.WithError(err).WithField("path", file).Warnln("failed to load validator key")
			continue
		}

		// Get ID from file, without following symbolic links.
		if kid == "" {
			_, fn := filepath.Split(file)
			kid = getKeyIDFromFilename(fn)
		}
		if _, ok := bs.validators[kid]; ok {
			bs.Cfg.Logger.WithFields(logrus.Fields{
				"path": file,
				"kid":  kid,
			}).Warnln("skipped as validator with same kid already loaded")
			continue
		} else {
			bs.Cfg.Logger.WithFields(logrus.Fields{
				"path": file,
				"kid":  kid,
			}).Debugln("loaded validator key")
		}
		bs.validators[kid] = validator
	}

	return nil
}

func withSchemeAndHost(u, base *url.URL) *url.URL {
	if u.Host != "" && u.Scheme != "" {
		return u
	}

	r, _ := url.Parse(u.String())
	r.Scheme = base.Scheme
	r.Host = base.Host

	return r
}

func getKeyIDFromFilename(fn string) string {
	ext := filepath.Ext(fn)
	return strings.TrimSuffix(fn, ext)
}

func getCommonURLPathPrefix(p1, p2 string) (string, error) {
	parts1 := strings.Split(p1, "/")
	parts2 := strings.Split(p2, "/")

	common := make([]string, 0)
	for idx, p := range parts1 {
		if idx >= len(parts2) {
			break
		}
		if p != parts2[idx] {
			break
		}
		common = append(common, p)
	}
	if len(common) == 0 {
		return "", errors.New("no common path prefix")
	}

	return strings.Join(common, "/"), nil
}