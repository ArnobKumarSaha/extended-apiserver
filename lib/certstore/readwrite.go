package certstore

import (
	"crypto/rsa"
	"crypto/x509"
	"github.com/pkg/errors"
	"github.com/spf13/afero"
	certutil "k8s.io/client-go/util/cert"
)

func (s *CertStore) Write(name string, crt *x509.Certificate, key *rsa.PrivateKey) error {
	// certutil.EncodeCertPEM converts the certificate into Byte slice
	// then afero.WriteFile() actually write these Bytes into specific file location
	if err := afero.WriteFile(s.fs, s.CertFile(name), certutil.EncodeCertPEM(crt), 0644); err != nil {
		return errors.Wrapf(err, "failed to write `%s`", s.CertFile(name))
	}
	if err := afero.WriteFile(s.fs, s.KeyFile(name), certutil.EncodePrivateKeyPEM(key), 0600); err != nil {
		return errors.Wrapf(err, "failed to write `%s`", s.KeyFile(name))
	}
	return nil
}

func (s *CertStore) Read(name string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Reading the certificate
	crtBytes, err := afero.ReadFile(s.fs, s.CertFile(name))
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to read certificate `%s`", s.CertFile(name))
	}
	crt, err := certutil.ParseCertsPEM(crtBytes)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to parse certificate `%s`", s.CertFile(name))
	}

	// Reading the Private key
	keyBytes, err := afero.ReadFile(s.fs, s.KeyFile(name))
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to read private key `%s`", s.KeyFile(name))
	}
	key, err := certutil.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to parse private key `%s`", s.KeyFile(name))
	}
	return crt[0], key.(*rsa.PrivateKey), nil
}
