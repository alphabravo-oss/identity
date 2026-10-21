// Gosec's release dependency predates Go 1.27 export data. Pin a compatible analyzer.
module github.com/alphabravo-oss/identity/tools/security

go 1.27.3

require (
 github.com/securego/gosec/v2 v2.29.0
 golang.org/x/tools v0.52.0
)
