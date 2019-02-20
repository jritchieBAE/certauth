package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"../../mTLS/mtlsClient"
)

func main() {
	client := mtlsClient.NewUnsecureClient()

	requesterDetails := map[string]interface{}{
		"Organization":     []string{"BAE Systems"},
		"OrganizationUnit": []string{"Applied Intelligence"},
		"Country":          []string{"UK"},
		"Province":         []string{"London"},
		"CommonName":       "localhost",
	}

	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(requesterDetails)

	req, err := http.NewRequest("POST", "http://localhost:8080", buf)
	if err != nil {
		log.Fatal(err)
	}

	r, err := client.Do(req)

	if err != nil {
		log.Println(err)
	} else {

		defer r.Body.Close()
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Fatal(err)
		}
		var resp interface{}
		json.Unmarshal(body, &resp)

		r := resp.(map[string]interface{})
		c := r["Certificate"].(string)
		k := r["Key"].(string)

		certOut, err := os.Create("cert.crt")
		certOut.Write([]byte(c))
		// pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: r["Certificate"]})
		certOut.Close()

		keyOut, err := os.Create("cert.key")
		keyOut.Write([]byte(k))
		// pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: r["Key"]})
		keyOut.Close()
	}

	_, err = tls.LoadX509KeyPair("cert.crt", "cert.key")
	if err != nil {
		log.Println(err)
	}
}
