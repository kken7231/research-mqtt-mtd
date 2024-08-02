package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

// OID for Common Name
var oidCommonName = []int{2, 5, 4, 3}

func main() {
	// Path to the certificate file
	certFile := "./sample.crt"

	// Read the certificate file
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		log.Fatalf("Failed to read certificate file: %v", err)
	}

	// Decode the PEM encoded certificate
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatalf("Failed to decode PEM block containing the certificate")
	}

	// Parse the X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}

	// Print certificate information
	printCertificateInfo(cert)
}

func printCertificateInfo(cert *x509.Certificate) {
	fmt.Println(cert)
	fmt.Printf("Subject: %s\n", cert.Subject)
	fmt.Printf("Issuer: %s\n", cert.Issuer)
	fmt.Printf("Not Before: %s\n", cert.NotBefore)
	fmt.Printf("Not After: %s\n", cert.NotAfter)

	// Extract and print CN from Subject
	for _, attr := range cert.Subject.Names {
		if attr.Type.Equal(oidCommonName) {
			fmt.Printf("Common Name (CN) from Subject: %s\n", attr.Value)
		}
	}

	// Print DNS names from SAN
	fmt.Printf("DNS Names: %v\n", cert.DNSNames)

	// Print IP addresses from SAN
	for _, ip := range cert.IPAddresses {
		fmt.Printf("IP Address: %s\n", ip)
	}

	// Print email addresses from SAN
	fmt.Printf("Email Addresses: %v\n", cert.EmailAddresses)

	// Print URIs from SAN
	for _, uri := range cert.URIs {
		fmt.Printf("URI: %s\n", uri)
	}
}
