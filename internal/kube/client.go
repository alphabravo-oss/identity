// Package kube implements the small Secret API subset needed by bootstrap.
package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type Client struct {
	URL, Namespace, Token string
	HTTP                  *http.Client
}

func InCluster() (*Client, error) {
	root := "/var/run/secrets/kubernetes.io/serviceaccount/"
	token, err := os.ReadFile(root + "token")
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(root + "ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("invalid cluster CA")
	}
	ns, err := os.ReadFile(root + "namespace")
	if err != nil {
		return nil, err
	}
	return &Client{URL: "https://" + os.Getenv("KUBERNETES_SERVICE_HOST") + ":" + os.Getenv("KUBERNETES_SERVICE_PORT"), Namespace: string(ns), Token: string(token), HTTP: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}}, nil
}

type Secret struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name            string            `json:"name"`
		ResourceVersion string            `json:"resourceVersion,omitempty"`
		Labels          map[string]string `json:"labels,omitempty"`
	} `json:"metadata"`
	Data map[string][]byte `json:"data"`
}

func (c *Client) request(ctx context.Context, method, path string, in, out any) (int, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.URL+"/api/v1/namespaces/"+c.Namespace+"/secrets"+path, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode >= 300 {
		return res.StatusCode, fmt.Errorf("secret API: %d", res.StatusCode)
	}
	if out != nil {
		err = json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(out)
	}
	return res.StatusCode, err
}
func (c *Client) Get(ctx context.Context, name string) (Secret, error) {
	var s Secret
	_, err := c.request(ctx, "GET", "/"+name, nil, &s)
	return s, err
}
func (c *Client) Put(ctx context.Context, name string, data map[string][]byte) error {
	old, err := c.Get(ctx, name)
	method, path := "POST", ""
	if err == nil {
		method, path = "PUT", "/"+name
	} else {
		status, e := c.request(ctx, "GET", "/"+name, nil, nil)
		if status != 404 {
			return e
		}
	}
	s := Secret{APIVersion: "v1", Kind: "Secret", Data: data}
	s.Metadata.Name = name
	s.Metadata.ResourceVersion = old.Metadata.ResourceVersion
	s.Metadata.Labels = map[string]string{"app.kubernetes.io/managed-by": "identity"}
	_, err = c.request(ctx, method, path, s, nil)
	return err
}
