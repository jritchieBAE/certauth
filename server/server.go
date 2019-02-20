package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"../../mTLS/mtlsServer"
)

func main() {

	http.HandleFunc("/", certProvider)
	CheckServerCertificates()

	server := mtlsServer.NewUnsecureServer()
	server.Listen(":8080")
}

func certProvider(w http.ResponseWriter, r *http.Request) {

	var requesterDetails pkix.Name
	json.NewDecoder(r.Body).Decode(&requesterDetails)

	cert, key := GenerateClientCertificate(&requesterDetails)

	data := map[string]interface{}{
		"Certificate": cert,
		"Key":         key,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	// json.NewEncoder(w).Encode(data)
	body, _ := json.Marshal(data)

	w.Write(body)
}

func CheckServerCertificates() {
	_, err := tls.LoadX509KeyPair("./root.crt", "./root.key")
	if err != nil {
		log.Println(err)
		GenerateServerCertificates()
	}
}

func GenerateServerCertificates() {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization:       []string{"BAE Systems"},
			OrganizationalUnit: []string{"Applied Intelligence"},
			Country:            []string{"UK"},
			Province:           []string{"London"},
			CommonName:         "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey
	ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		log.Println("create ca failed", err)
		return
	}

	//public key
	certOut, err := os.Create("root.crt")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: ca_b})
	certOut.Close()
	log.Println("generated root certificate")

	//private key
	keyOut, err := os.OpenFile("root.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	log.Println("generated root key")
}

func GenerateClientCertificate(certDetails *pkix.Name) (string, string) {
	// load CA
	catls, err := tls.LoadX509KeyPair("root.crt", "root.key")
	if err != nil {
		panic(err)
	}
	ca, err := x509.ParseCertificate(catls.Certificate[0])
	if err != nil {
		panic(err)
	}

	log.Println("Creating certificate for", (certDetails.Organization))
	//Prepare certificate
	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(1653),
		Subject:               *certDetails,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 7),
		SubjectKeyId:          []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey

	//sign the certificate
	cert_b, err := x509.CreateCertificate(rand.Reader, cert, ca, pub, catls.PrivateKey)

	//public Key
	certOut, err := os.Create("cert.crt")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert_b})
	certOut.Close()

	//private key
	keyOut, err := os.Open
	File("cert.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	return readFile("cert.crt"), readFile("cert.key")
}

func readFile(fileName string) (content string) {
	file, _ := os.Open(fileName)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		content += scanner.Text() + "\n"
	}
	return
}
