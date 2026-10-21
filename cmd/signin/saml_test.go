package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestSAMLCertificateKeepsPublicKeyAndHidesEngineSubject(t *testing.T) {
	issuer, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	original := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ZITADEL SP", Organization: []string{"ZITADEL"}}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, original, original, &sp.PublicKey, sp)
	if err != nil {
		t.Fatal(err)
	}
	brander := &certificateBranding{key: issuer, cache: map[[32]byte]string{}}
	encoded, err := brander.certificate(base64.StdEncoding.EncodeToString(der))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(cert.Subject.String()+cert.Issuer.String()), "zitadel") {
		t.Fatal("engine subject leaked")
	}
	if !cert.PublicKey.(*rsa.PublicKey).Equal(&sp.PublicKey) {
		t.Fatal("SP trust key changed")
	}
	clear(brander.cache)
	again, err := brander.certificate(base64.StdEncoding.EncodeToString(der))
	if err != nil || again != encoded {
		t.Fatal("certificate changed across cache/restart")
	}
	if err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err == nil {
		t.Fatal("leaf must be issued by branding authority, not the SP")
	}
	if err = (&x509.Certificate{PublicKey: &issuer.PublicKey}).CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Fatal(err)
	}
}
