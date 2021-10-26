
## What have been done in main.go ::

**makeCertificates()** creates a self-signed CA , CA-certified tls server & a CA-certified client. namely,
apiserver-ca.crt , apiserver-ca.key,
apiserver-tls.crt , apiserver-tls.key
apiserver-arnob.crt , apiserver-arnob.key

**getTLSCertificateOfNewCA()** creates another self-signed CA & a CA-certified client. namely,
requestheader-ca.crt, requestheader-ca.crt
requestheader-apiserver.crt, requestheader-apiserver.crt
Look, apiserver is the client now . It will request to the database-server

**main()** makes a temporary CertStore to load the database-ca (to append that into CertPool ) which is generated in database-apiserver/main.go
Create a Generic Server with apiserver-tls (which was signed with apiserver-ca).
Makes a http.Transport where in TLSClientConfig Certificates used, to present to the other side of the connection (in this case , database-server),
and RootCAs to verify the server-certificates


![alt text](https://github.com/Arnobkumarsaha/extended-apiserver/blob/main/pictures/generated-keys-and-certs.png?raw=true)


## What have been done in database-apiserver/main.go ::

**makeCertificates()** creates a self-signed CA , CA-certified tls server & a CA-certified client. namely,
database-ca.crt , database-ca.key,
database-tls.crt , database-tls.key
database-jane.crt , database-jane.key

**main()** makes two temporary CertStore . One to load the apiserver-ca . Another to load requestheader CA (to append that into CertPool ) which is generated 
in apiserver/main.go
It creates a Generic Server . If proxy is On, It appned both requestheader CA and api-server CA as CACertFiles in the cofiguration of Generic server.

It also has a http handler function with path '..../database/{something}' If client certificate is used,  that will be verified using request-header CA as the 
rootCA. 
Direct access with certificate, to the db server is not possible, bcz we didn't add databse CA in the CACertFiles of server.Config



![alt text](https://github.com/Arnobkumarsaha/extended-apiserver/blob/main/pictures/http-calls-using-curl.png?raw=true)


ONE = 127.0.0.1:8443/database/postgres
TWO = 127.0.0.2:8443/database/postgres
## --cacert apiserver-ca.crt --cert apiserver-arnob.crt --key apiserver-arnob.key
Req to ONE --> says call from apiserver (X_REMOTE_USER), TLS.PeerCertificate : requestheaderapiserver
Req to TWO --> says call came directly (Clinet-Cert_CN), TLS.PeerCertificate : arnob , ca

## --cacert database-ca.crt --cert apiserver-arnob.crt --key apiserver-arnob.key
Req to ONE --> says call from apiserver (X_REMOTE_USER), TLS.PeerCertificate : requestheaderapiserver
Req to TWO --> says call  came directly (Clinet-Cert_CN), TLS.PeerCertificate : arnob
