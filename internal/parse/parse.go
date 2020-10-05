package parse

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
	"k8s.io/klog"
)

type CertificateData struct {
	SecretName    string
	Certificate   string
	CaCertificate string
}

type ParsedCertificateData struct {
	SecretName    string
	Certificate   *x509.Certificate
	CaCertificate *x509.Certificate
}

func (p *ParsedCertificateData) Output() {

	klog.Info(p.SecretName)

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Issuer", "Subject", "SerialNumber", "Expired"})

	table.Append([]string{p.Certificate.Issuer.String(), p.Certificate.Subject.String(), p.Certificate.SerialNumber.String(), p.Certificate.NotAfter.String()})
	table.Append([]string{p.CaCertificate.Issuer.String(), p.CaCertificate.Subject.String(), p.CaCertificate.SerialNumber.String(), p.CaCertificate.NotAfter.String()})

	table.Render() // Send output
}

func NewCertificateData(secretName string, data map[string]interface{}) (*CertificateData, error) {
	secretType := fmt.Sprintf("%v", data["type"])

	if secretType == "kubernetes.io/tls" {

		certsMap := data["data"].(map[string]interface{})

		certData := CertificateData{
			SecretName:    secretName,
			Certificate:   fmt.Sprintf("%v", certsMap["tls.crt"]),
			CaCertificate: fmt.Sprintf("%v", certsMap["ca.crt"]),
		}

		return &certData, nil

	} else {
		return nil, fmt.Errorf("unsupported secret type %s", secretType)
	}
}

func (c *CertificateData) ParseCertificates() (*ParsedCertificateData, error) {
	cert, err := parse(c.Certificate)
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate %w", err)
	}

	caCert, err := parse(c.CaCertificate)
	if err != nil {
		return nil, fmt.Errorf("unable to parse ca certificate %w", err)
	}

	result := ParsedCertificateData{
		SecretName:    c.SecretName,
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
