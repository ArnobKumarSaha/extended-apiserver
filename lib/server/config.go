package server

type Config struct {
	Address     string  // Address to listen
	CACertFiles []string // CA's certificates
	CertFile    string // Server's certificate (tls)
	KeyFile     string // Server's private key (tls)
}
