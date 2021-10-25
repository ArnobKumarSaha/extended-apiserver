package main

import (
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/Arnobkumarsaha/extended-api/lib/certstore"
	"github.com/Arnobkumarsaha/extended-api/lib/server"
	"github.com/gorilla/mux"
	"github.com/spf13/afero"
	"k8s.io/client-go/util/cert"
)

func okHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "OK")
}

func makeCertificates() *certstore.CertStore {
	fs := afero.NewOsFs()
	// CA setup
	store, err := certstore.NewCertStore(fs, "/tmp/k8s-extended-apiserver")
	if err != nil {
		log.Fatalln(err)
	}
	err = store.NewCA("apiserver")
	if err != nil {
		log.Fatalln(err)
	}

	// server-side setup
	serverCert, serverKey, err := store.NewServerCertPair(cert.AltNames{
		IPs: []net.IP{net.ParseIP("127.0.0.1")},
	})
	if err != nil {
		log.Fatalln(err)
	}
	err = store.Write("tls", serverCert, serverKey)
	if err != nil {
		log.Fatalln(err)
	}

	// client-side setup
	clientCert, clientKey, err := store.NewClientCertPair(cert.AltNames{
		DNSNames: []string{"arnob"},
	})
	if err != nil {
		log.Fatalln(err)
	}
	err = store.Write("arnob", clientCert, clientKey)
	if err != nil {
		log.Fatalln(err)
	}
	return store
}

func main() {
	store := makeCertificates()
	// make the server
	cfg := server.Config{
		Address: "127.0.0.1:8443",
		CACertFiles: []string{
			store.CertFile("ca"),
		},
		CertFile: store.CertFile("tls"),
		KeyFile:  store.KeyFile("tls"),
	}
	srv := server.NewGenericServer(cfg)


	// http request handlers
	r := mux.NewRouter()
	r.HandleFunc("/core/{resource}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r) // Get the route variables , a map[string]string
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Resource: %v\n", vars["resource"])
	})
	r.HandleFunc("/", okHandler)
	srv.ListenAndServe(r)
}
