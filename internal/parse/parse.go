package parse

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// CertificateData struct contains base64 pem data
type CertificateData struct {
	SecretName    string
	Namespace     string
	Certificate   string
	CaCertificate string
}

// ParsedCertificateData struct contains decoded x509 certificates
type ParsedCertificateData struct {
	SecretName    string
	Namespace     string
	Certificate   *x509.Certificate
	CaCertificate *x509.Certificate
}

// NewCertificateData takes secret data and extracts base64 pem strings
func NewCertificateData(ns, secretName string, data map[string]interface{}, secretKey string) (*CertificateData, error) {
	certsMap := data["data"].(map[string]interface{})

	certData := CertificateData{
		SecretName: secretName,
		Namespace:  ns,
	}

	// TODO: Check if certsMap is nil ?

	if secretKey != "" {
		if val, ok := certsMap[secretKey]; ok {
			certData.Certificate = fmt.Sprintf("%v", val)
		}

		return &certData, nil
	}

	secretType := fmt.Sprintf("%v", data["type"])

	if secretType == "kubernetes.io/tls" { // nolint gosec
		if val, ok := certsMap["tls.crt"]; ok {
			certData.Certificate = fmt.Sprintf("%v", val)
		}

		if val, ok := certsMap["ca.crt"]; ok {
			certData.CaCertificate = fmt.Sprintf("%v", val)
		}

		return &certData, nil
	}

	return nil, fmt.Errorf("unsupported secret type %s", secretType)
}

// ParseCertificates method parses each base64 pem strings and creates x509 certificates
func (c *CertificateData) ParseCertificates() (*ParsedCertificateData, error) {
	var cert *x509.Certificate
	var err error

	if c.Certificate != "" {
		cert, err = parse(c.Certificate)
		if err != nil {
			return nil, fmt.Errorf("unable to parse certificate %w", err)
		}
	}

	var caCert *x509.Certificate
	if c.CaCertificate != "" {
		caCert, err = parse(c.CaCertificate)
		if err != nil {
			return nil, fmt.Errorf("unable to parse ca certificate %w", err)
		}
	}

	result := ParsedCertificateData{
		SecretName:    c.SecretName,
		Namespace:     c.Namespace,
		Certificate:   cert,
		CaCertificate: caCert,
	}

	return &result, nil
}

func parse(base64Pem string) (*x509.Certificate, error) {
	decodedPemCertificate, err := base64.StdEncoding.DecodeString(base64Pem)
	if err != nil {
		return nil, fmt.Errorf("unable to base64 decode %w", err)
	}

	block, _ := pem.Decode(decodedPemCertificate)
	if block == nil {
		return nil, fmt.Errorf("no pem block found")
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate error %w", err)
	}

	return certificate, nil
}
