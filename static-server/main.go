package main

import (
    "log"
    "net/http"
)

func main() {
    fs := http.FileServer(http.Dir("../static"))
    log.Println("Serving static files on https://localhost:8443")
    err := http.ListenAndServeTLS(":8443", "../cert.pem", "../key.pem", fs)
    if err != nil {
        log.Fatalf("Failed to start HTTPS static server: %v", err)
    }
}
