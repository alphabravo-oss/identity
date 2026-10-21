package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// SAML trusts the SP public key in exchanged metadata. Reissue only its X.509
// envelope with our issuer/subject. The public key and all signed XML bytes remain
// unchanged: KeyInfo is outside SignedInfo and excluded by the enveloped transform.
// A persisted RSA issuer makes this envelope deterministic across replicas/restarts.
type certificateBranding struct {
	key   *rsa.PrivateKey
	mu    sync.Mutex
	cache map[[32]byte]string
}

var samlBranding *certificateBranding
var certificateElement = regexp.MustCompile(`(?s)(<(?:[A-Za-z_][A-Za-z0-9_.-]*:)?X509Certificate\b[^>]*>)([^<]+)(</(?:[A-Za-z_][A-Za-z0-9_.-]*:)?X509Certificate>)`)
var callbackPath = regexp.MustCompile(`^/idps/(callback|[A-Za-z0-9_-]{1,200}/saml/(metadata|acs|slo))$`)

func initSAMLBranding() {
	b, err := os.ReadFile("/runtime/saml-branding-key")
	if err != nil {
		log.Fatal("SAML branding credential unavailable")
	}
	block, _ := pem.Decode(b)
	if block == nil {
		log.Fatal("invalid SAML branding credential")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal("invalid SAML branding credential")
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		log.Fatal("RSA SAML branding credential required")
	}
	samlBranding = &certificateBranding{key: rsaKey, cache: map[[32]byte]string{}}
}
func (b *certificateBranding) certificate(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(encoded), ""))
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(raw)
	b.mu.Lock()
	defer b.mu.Unlock()
	if value, ok := b.cache[hash]; ok {
		return value, nil
	}
	original, err := x509.ParseCertificate(raw)
	if err != nil {
		return "", err
	}
	subject := pkix.Name{Organization: []string{"AlphaBravo"}, CommonName: "AlphaBravo Identity"}
	parent := &x509.Certificate{Subject: pkix.Name{Organization: []string{"AlphaBravo"}, CommonName: "AlphaBravo Identity Certificate Authority"}, PublicKey: &b.key.PublicKey, IsCA: true, BasicConstraintsValid: true}
	template := &x509.Certificate{SerialNumber: new(big.Int).SetBytes(hash[:16]), Subject: subject, NotBefore: original.NotBefore, NotAfter: original.NotAfter, KeyUsage: original.KeyUsage, ExtKeyUsage: original.ExtKeyUsage, SignatureAlgorithm: x509.SHA256WithRSA, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, original.PublicKey, b.key)
	if err != nil {
		return "", err
	}
	value := base64.StdEncoding.EncodeToString(der)
	if len(b.cache) >= 32 {
		clear(b.cache)
	}
	b.cache[hash] = value
	return value, nil
}
func (b *certificateBranding) xml(raw []byte) ([]byte, error) {
	var first error
	out := certificateElement.ReplaceAllStringFunc(string(raw), func(element string) string {
		parts := certificateElement.FindStringSubmatch(element)
		certificate, err := b.certificate(parts[2])
		if err != nil {
			first = err
			return ""
		}
		return parts[1] + certificate + parts[3]
	})
	if first != nil {
		return nil, first
	}
	return []byte(out), nil
}
func normalizeSAMLForm(fields map[string]string) error {
	encoded := fields["SAMLRequest"]
	if encoded == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	raw, err = samlBranding.xml(raw)
	if err != nil {
		return err
	}
	fields["SAMLRequest"] = base64.StdEncoding.EncodeToString(raw)
	return nil
}
func idpCallbacks() http.Handler {
	target, err := url.Parse(api)
	if err != nil {
		log.Fatal("invalid internal API address")
	}
	host := apiHost
	if host == "" {
		host = target.Host
	}
	proxy := &httputil.ReverseProxy{Rewrite: func(request *httputil.ProxyRequest) {
		request.SetURL(target)
		request.Out.Host = host
		request.SetXForwarded()
		request.Out.Header.Set("X-Forwarded-Host", host)
		request.Out.Header.Set("X-Forwarded-Proto", "https")
		request.Out.Header.Set("Accept-Encoding", "identity")
	}}
	proxy.ModifyResponse = func(res *http.Response) error {
		if !strings.HasSuffix(res.Request.URL.Path, "/saml/metadata") || res.StatusCode != http.StatusOK {
			return nil
		}
		originalBody := res.Body
		defer func() { _ = originalBody.Close() }()
		raw, err := io.ReadAll(io.LimitReader(originalBody, 2<<20))
		if err != nil {
			return err
		}
		raw, err = samlBranding.xml(raw)
		if err != nil {
			return err
		}
		res.Body = io.NopCloser(strings.NewReader(string(raw)))
		res.ContentLength = int64(len(raw))
		res.Header.Set("Content-Length", strconv.Itoa(len(raw)))
		res.Header.Del("ETag")
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "Identity callback unavailable", http.StatusBadGateway)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !callbackPath.MatchString(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
		proxy.ServeHTTP(w, r)
	})
}
