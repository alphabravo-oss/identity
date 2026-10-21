// Command claims-hook is a Zitadel Actions v2 target for the preaccesstoken / preuserinfo functions.
// It appends one compact claim, alphabravo_roles = {"<project>": ["role", ...]}, built from the user's grants,
// so relying parties never parse Zitadel's urn:zitadel:iam:org:project:<id>:roles maps.
package claims

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type request struct {
	UserGrants []struct {
		ProjectID   string   `json:"project_id"`
		ProjectName string   `json:"project_name"`
		Roles       []string `json:"roles"`
	} `json:"user_grants"`
}

type claim struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

func Handler(key []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if len(key) == 0 || err != nil || !valid(key, r.Header.Get("ZITADEL-Signature"), body) {
			log.Printf("rejected: bad or missing ZITADEL-Signature")
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		var req request
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		roles := map[string][]string{}
		for _, g := range req.UserGrants {
			if len(g.Roles) == 0 {
				continue
			}
			name := g.ProjectName
			if name == "" {
				name = g.ProjectID
			}
			roles[name] = append(roles[name], g.Roles...)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string][]claim{"append_claims": {{Key: "alphabravo_roles", Value: roles}}})
	})
}

// valid checks Zitadel's "t=<unix>,v1=<hex hmac-sha256(t.body)>" header and a 5-minute replay window.
func valid(key []byte, header string, body []byte) bool {
	var ts string
	var sigs []string
	for _, kv := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sigs = append(sigs, v)
		}
	}
	t, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || time.Since(time.Unix(t, 0)).Abs() > 5*time.Minute {
		return false
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(ts + "."))
	m.Write(body)
	want := hex.EncodeToString(m.Sum(nil))
	for _, s := range sigs {
		if hmac.Equal([]byte(s), []byte(want)) {
			return true
		}
	}
	return false
}
