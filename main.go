package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/Arnobkumarsaha/extended-api/lib/certstore"
	"github.com/Arnobkumarsaha/extended-api/lib/server"
	"github.com/gorilla/mux"
	"github.com/spf13/afero"
	"k8s.io/client-go/util/cert"
)

func okHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "OK from APIserver")
}

func makeCertificates(fs afero.Fs) *certstore.CertStore {
	// CA setup
	store, err := certstore.NewCertStore(fs, "/tmp/k8s-extended-apiserver")
	if err != nil {
		log.Fatalln(err)
	}
	err = store.InitCA("apiserver")
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
		DNSNames: []string{"arnobkumarsaha"},
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

func getTLSCertificateOfNewCA(fs afero.Fs) tls.Certificate{
	// Making the 'requestheader' CA
	rhStore, err := certstore.NewCertStore(fs, "/tmp/k8s-extended-apiserver")
	if err != nil {
		log.Fatalln(err)
	}
	err = rhStore.InitCA("requestheader")
	if err != nil {
		log.Fatalln(err)
	}

	// Client-side setup
	rhClientCert, rhClientKey, err := rhStore.NewClientCertPair(cert.AltNames{
		// because apiserver is making the calls to database eas(extended-api-server), apiserver itself is the client
		DNSNames: []string{"requestheaderapiserver"},
	})
	if err != nil {
		log.Fatalln(err)
	}
	err = rhStore.Write("apiserver", rhClientCert, rhClientKey)
	if err != nil {
		log.Fatalln(err)
	}

	// rhClientCert is x509 certificate, But http.Transport{} wants a tls certificate.
	// So make this required conversion

	rhCert, err := tls.LoadX509KeyPair(rhStore.CertFile("apiserver"), rhStore.KeyFile("apiserver"))
	if err != nil {
		log.Fatalln(err)
	}
	return rhCert
}

func main() {
	fs := afero.NewOsFs()
	store := makeCertificates(fs)
	var proxy = false
	flag.BoolVar(&proxy, "send-proxy-request", proxy, "forward requests to database extended apiserver")
	flag.Parse()
	rhCert := getTLSCertificateOfNewCA(fs)

	// ----------------------------List PEM-encoded certs , where it will forward-------------------------------------------------
	easCACertPool := x509.NewCertPool()
	// It contains a set of certificates , where is supports to make proxy
	if proxy {
		easStore, err := certstore.NewCertStore(fs, "/tmp/k8s-extended-apiserver")
		if err != nil {
			log.Fatalln(err)
		}
		err = easStore.LoadCA("database")
		if err != nil {
			log.Fatalln(err)
		}
		easCACertPool.AppendCertsFromPEM(easStore.CACertBytes())
	}
	// -----------------------------------------------------------------------------
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
	// -----------------------------------------------------------------------------
	if proxy {
		r.HandleFunc("/database/{resource}", func(w http.ResponseWriter, r *http.Request) {
			tr := &http.Transport{
				MaxIdleConnsPerHost: 10,
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{rhCert},
					RootCAs:      easCACertPool,
				},
			}
			client := http.Client{
				Transport: tr,
				Timeout:   time.Duration(30 * time.Second),
			}

			// Construct the new URL to make internal request
			u := *r.URL
			u.Scheme = "https"
			u.Host = "127.0.0.2:8443"
			fmt.Printf("forwarding request to %v\n", u.String())

			// Now construct the Request and DO the request to server
			req, _ := http.NewRequest(r.Method, u.String(), nil)
			if len(r.TLS.PeerCertificates) > 0 {
				req.Header.Set("X-Remote-User", r.TLS.PeerCertificates[0].Subject.CommonName)
			}
			resp, err := client.Do(req)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "error: %v\n", err.Error())
				return
			}
			defer resp.Body.Close()

			w.WriteHeader(http.StatusOK)
			io.Copy(w, resp.Body)
		})
	}
	// -----------------------------------------------------------------------------
	r.HandleFunc("/", okHandler)
	srv.ListenAndServe(r)
}
