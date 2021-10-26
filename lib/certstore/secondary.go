package certstore

import (
	"crypto/rsa"
	"github.com/pkg/errors"
	"github.com/spf13/afero"
	"k8s.io/client-go/util/cert"
	"os"
)

func (s *CertStore) InitCA(prefix ...string) error {
	err := s.LoadCA(prefix...)
	if err == nil {
		return nil
	}
	return s.NewCA(prefix...)
}


func (s *CertStore) LoadCA(prefix ...string) error {
	if err := s.prep(prefix...); err != nil {
		return err
	}

	if s.PairExists(s.ca, prefix...) {
		var err error
		s.caCert, s.caKey, err = s.Read(s.ca)
		return err
	}


	if _, err := s.fs.Stat(s.KeyFile(s.ca)); err == nil {  //only ca key found
		// So, read the private key
		keyBytes, err := afero.ReadFile(s.fs, s.KeyFile(s.ca))
		if err != nil {
			return errors.Wrapf(err, "failed to read private key `%s`", s.KeyFile(s.ca))
		}
		key, err := cert.ParsePrivateKeyPEM(keyBytes)
		if err != nil {
			return errors.Wrapf(err, "failed to parse private key `%s`", s.KeyFile(s.ca))
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return errors.Errorf("private key `%s` is not a rsa private key", s.KeyFile(s.ca))
		}
		// & make a CA cert from it.
		return s.createCAFromKey(rsaKey)
	}

	return os.ErrNotExist
}

// PairExists Just checks if the cert & key file exists with filename prefix-name
func (s *CertStore) PairExists(name string, prefix ...string) bool {
	if err := s.prep(prefix...); err != nil {
		panic(err)
	}

	if _, err := s.fs.Stat(s.CertFile(name)); err == nil {
		if _, err := s.fs.Stat(s.KeyFile(name)); err == nil {
			return true
		}
	}
	return false
}

/*
func (s *CertStore) CACertBytes() []byte {
	return cert.EncodeCertPEM(s.caCert)
}*/