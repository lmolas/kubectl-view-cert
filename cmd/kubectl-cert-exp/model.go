package main

import (
	"time"
)

// Certificate struct contains all certificate fields used for display
type Certificate struct {
	IsCa         bool
	SecretName   string
	Namespace    string
	SerialNumber string
	Issuer       string
	Subject      string
	Validity     CertificateValidity
}

// CertificateValidity struct contains certificate date fields
type CertificateValidity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

func filter(datas []*Certificate, date time.Time, filterFunc func(*Certificate, time.Time) bool) []*Certificate {
	filteredDatas := make([]*Certificate, 0)
	for _, data := range datas {
		if filterFunc(data, date) {
			filteredDatas = append(filteredDatas, data)
		}
	}
	return filteredDatas
}

func dateAfterFilter(data *Certificate, date time.Time) bool {
	return data.Validity.NotAfter.Before(date)
}
