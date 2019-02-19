package main

import (
	"io"
	"net/http"

	"../mTLS/mtlsServer"
)

func main() {

	http.HandleFunc("/", certProvider)
	CheckServerCertificates()

	server := mtlsServer.NewUnsecureServer()
	server.Listen(":8080")
}

func certProvider(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "Hello world!\n")
}
