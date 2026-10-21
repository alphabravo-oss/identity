// Package registry defines the product registration contract shared by bootstrap and sign-in.
package registry

import (
	"fmt"
	"net/url"
	"regexp"
)

type Branding struct{ Product, Logo, Accent, AccentDark, PrivacyURL, TermsURL string }
type Product struct {
	Slug                string              `json:"slug"`
	DisplayName         string              `json:"displayName"`
	Branding            Branding            `json:"branding"`
	Roles               []string            `json:"roles"`
	RedirectURIs        []string            `json:"redirectURIs"`
	PostLogoutRedirects []string            `json:"postLogoutRedirects,omitempty"`
	GroupRoles          map[string][]string `json:"groupRoles,omitempty"`
}

var slug = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var color = regexp.MustCompile(`^#[a-fA-F0-9]{6}$`)

func (p Product) Validate() error {
	if !slug.MatchString(p.Slug) || p.DisplayName == "" {
		return fmt.Errorf("invalid product name or slug")
	}
	if !color.MatchString(p.Branding.Accent) || !color.MatchString(p.Branding.AccentDark) {
		return fmt.Errorf("%s: accents must be six-digit hex colors", p.Slug)
	}
	if len(p.RedirectURIs) == 0 {
		return fmt.Errorf("%s: redirects required", p.Slug)
	}
	for _, s := range append(append([]string{}, p.RedirectURIs...), p.PostLogoutRedirects...) {
		u, e := url.Parse(s)
		if e != nil || u.Host == "" || u.Fragment != "" || (u.Scheme != "https" && (u.Scheme != "http" || u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1")) {
			return fmt.Errorf("%s: invalid redirect", p.Slug)
		}
	}
	for _, rs := range p.GroupRoles {
		for _, r := range rs {
			found := false
			for _, defined := range p.Roles {
				found = found || r == defined
			}
			if !found {
				return fmt.Errorf("%s: undefined mapped role %s", p.Slug, r)
			}
		}
	}
	return nil
}

type Runtime struct {
	Brands   map[string]Branding `json:"brands"`
	GroupMap map[string][]string `json:"groupMap"`
	OrgID    string              `json:"orgId"`
	IDPs     map[string]string   `json:"idps"`
}
