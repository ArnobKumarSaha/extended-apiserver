package certstore

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/afero"
	certutil "k8s.io/client-go/util/cert"
)

type CertStore struct {
	fs           afero.Fs
	dir          string
	organization []string
	prefix       string
	ca           string
	caKey        *rsa.PrivateKey
	caCert       *x509.Certificate
}

// NewCertStore Creates an object of CertStore struct
func NewCertStore(fs afero.Fs, dir string, organization ...string) (*CertStore, error) {
	err := fs.MkdirAll(dir, 0755)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create dir `%s`", dir)
	}
	return &CertStore{
		fs: fs,
		dir: dir,
		ca: "ca",
		organization: append([]string(nil), organization...),
	}, nil
}

// NewCA calls prep() , certutil.NewPrivateKey(), createCAFromKey().
// caKey, caCert & prefix field will be filled up after calling NewCA()
func (s *CertStore) NewCA(prefix ...string) error {
	if err := s.prep(prefix...); err != nil {
		return err
	}

	key, err := certutil.NewPrivateKey()
	if err != nil {
		return errors.Wrap(err, "failed to generate private key")
	}
	return s.createCAFromKey(key)
}

// Set the 'prefix' field of certStore
func (s *CertStore) prep(prefix ...string) error {
	switch len(prefix) {
	case 0:
		s.prefix = ""
	case 1:
		s.prefix = strings.ToLower(strings.Trim(strings.TrimSpace(prefix[0]), "-")) + "-"
	default:
		return fmt.Errorf("multiple ca prefix given: %v", prefix)
	}
	return nil
}

// Generate a self-signed certificate for CA from a given privateJey
func (s *CertStore) createCAFromKey(key *rsa.PrivateKey) error {
	var err error

	cfg := certutil.Config{
		CommonName:   s.ca,
		Organization: s.organization,
		AltNames: certutil.AltNames{
			DNSNames: []string{s.ca},
			IPs:      []net.IP{net.ParseIP("127.0.0.1")},
		},
	}
	crt, err := certutil.NewSelfSignedCACert(cfg, key)
	if err != nil {
		return errors.Wrap(err, "failed to generate self-signed certificate")
	}
	err = s.Write(s.ca, crt, key)
	if err != nil {
		return err
	}

	s.caCert = crt
	s.caKey = key
	return nil
}










// AltNames contains the domain names and IP addresses that will be added to the API Server's x509 certificate SubAltNames field.
// It return a signed certificate (by our CA) & private key for server.
func (s *CertStore) NewServerCertPair(sans certutil.AltNames) (*x509.Certificate, *rsa.PrivateKey, error) {
	cfg := certutil.Config{
		CommonName:   getCN(sans),
		Organization: s.organization,
		AltNames:     sans,
		Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	key, err := certutil.NewPrivateKey()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate private key")
	}

	// Our CA is signing a config, and making a certificate
	crt, err := certutil.NewSignedCert(cfg, key, s.caCert, s.caKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate server certificate")
	}
	return crt, key, nil
}

// NewClientCertPair is almost similar to NewServerCertPair, except
// client can specify the organization here, which was by default the org of CA
func (s *CertStore) NewClientCertPair(sans certutil.AltNames, organization ...string) (*x509.Certificate, *rsa.PrivateKey, error) {
	cfg := certutil.Config{
		CommonName:   getCN(sans),
		Organization: organization,
		AltNames:     sans,
		Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	key, err := certutil.NewPrivateKey()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate private key")
	}
	crt, err := certutil.NewSignedCert(cfg, key, s.caCert, s.caKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate client certificate")
	}
	return crt, key, nil
}

// making a string looks like,  /s.dir/s.prefix/name.crt
func (s *CertStore) CertFile(name string) string {
	filename := strings.ToLower(name) + ".crt"
	if s.prefix != "" {
		filename = s.prefix + filename
	}
	return filepath.Join(s.dir, filename)
}

// making a string looks like,  /s.dir/s.prefix/name.key
func (s *CertStore) KeyFile(name string) string {
	filename := strings.ToLower(name) + ".key"
	if s.prefix != "" {
		filename = s.prefix + filename
	}
	return filepath.Join(s.dir, filename)
}


// If DNS is given , that will be the common name, otherwise the ip will be the common name
func getCN(sans certutil.AltNames) string {
	if len(sans.DNSNames) > 0 {
		return sans.DNSNames[0]
	}
	if len(sans.IPs) > 0 {
		return sans.IPs[0].String()
	}
	return ""
}






// *********************************************************************************************

/*
func (s *CertStore) SetCA(crtBytes, keyBytes []byte) error {
	crt, err := cert.ParseCertsPEM(crtBytes)
	if err != nil {
		return errors.Wrap(err, "failed to parse ca certificate")
	}

	key, err := cert.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		return errors.Wrap(err, "failed to parse ca private key")
	}

	s.caCert = crt[0]
	s.caKey = key.(*rsa.PrivateKey)
	return s.Write(s.ca, s.caCert, s.caKey)
}


func (s *CertStore) Location() string {
	return s.dir
}

func (s *CertStore) CAName() string {
	return s.ca
}

func (s *CertStore) CACert() *x509.Certificate {
	return s.caCert
}

func (s *CertStore) CAKey() *rsa.PrivateKey {
	return s.caKey
}

func (s *CertStore) CAKeyBytes() []byte {
	return cert.EncodePrivateKeyPEM(s.caKey)
}
func (s *CertStore) IsExists(name string, prefix ...string) bool {
	if err := s.prep(prefix...); err != nil {
		panic(err)
	}

	if _, err := s.fs.Stat(s.CertFile(name)); err == nil {
		return true
	}
	if _, err := s.fs.Stat(s.KeyFile(name)); err == nil {
		return true
	}
	return false
}

*/
