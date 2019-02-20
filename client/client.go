package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"../../mTLS/mtlsClient"
)

func main() {
	client := mtlsClient.NewUnsecureClient()

	r, err := client.Get("http://localhost:8080")

	if err != nil {
		fmt.Println(err)
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
		log.Println("cert or key invalid")
		log.Println(err)
	}
}
