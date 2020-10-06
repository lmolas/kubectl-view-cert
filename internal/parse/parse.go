package parse

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/jedib0t/go-pretty/table"
	"k8s.io/klog"
)

type CertificateData struct {
	SecretName    string
	Namespace     string
	Certificate   string
	CaCertificate string
}

type ParsedCertificateData struct {
	SecretName    string
	Namespace     string
	Certificate   *x509.Certificate
	CaCertificate *x509.Certificate
}

func (p *ParsedCertificateData) Output(date *time.Time) {
	if p.CaCertificate == nil && p.Certificate == nil {
		return
	}

	var certRow, caCertRow table.Row

	if p.Certificate != nil {
		if (date != nil && date.After(p.Certificate.NotAfter)) || date == nil {
			certRow = []interface{}{fmt.Sprintf("%s/%s", p.Namespace, p.SecretName), "Cert", p.Certificate.Issuer.String(), p.Certificate.Subject.String(), p.Certificate.NotAfter.String()}
		}
	}
	if p.CaCertificate != nil {
		if (date != nil && date.After(p.CaCertificate.NotAfter)) || date == nil {
			caCertRow = []interface{}{fmt.Sprintf("%s/%s", p.Namespace, p.SecretName), "CaCert", p.CaCertificate.Issuer.String(), p.CaCertificate.Subject.String(), p.CaCertificate.NotAfter.String()}
		}
	}

	if len(certRow) == 0 && len(caCertRow) == 0 {
		return
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Secret", "Type", "Issuer", "Subject", "Not After"})

	if len(certRow) > 0 {
		t.AppendRow(certRow)
	}

	if len(caCertRow) > 0 {
		t.AppendRow(caCertRow)
	}

	t.SetStyle(table.StyleColoredBlackOnYellowWhite)
	t.Render()

	fmt.Println("")
}

func NewCertificateData(ns, secretName string, data map[string]interface{}) (*CertificateData, error) {
	secretType := fmt.Sprintf("%v", data["type"])

	if secretType == "kubernetes.io/tls" {

		certsMap := data["data"].(map[string]interface{})

		certData := CertificateData{
			SecretName: secretName,
			Namespace:  ns,
		}

		if val, ok := certsMap["tls.crt"]; ok {
			certData.Certificate = fmt.Sprintf("%v", val)
		}

		if val, ok := certsMap["ca.crt"]; ok {
			certData.CaCertificate = fmt.Sprintf("%v", val)
		}

		klog.V(1).Infof("Cert %s", certData.Certificate)
		klog.V(1).Infof("CaCert %s", certData.CaCertificate)

		return &certData, nil

	} else {
		return nil, fmt.Errorf("unsupported secret type %s", secretType)
	}
}

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
