{{- define "identity.name" -}}
{{- printf "%s-identity" .Release.Name | trunc 45 | trimSuffix "-" -}}
{{- end -}}
{{- define "identity.image" -}}
{{- if .digest -}}{{ .repository }}@{{ .digest }}{{- else -}}{{ .repository }}:{{ .tag }}{{- end -}}
{{- end -}}
{{- define "identity.apiCIDRs" -}}
{{- $cidrs := .Values.networkPolicy.apiServerCIDRs -}}
{{- $api := lookup "v1" "Endpoints" "default" "kubernetes" -}}
{{- if $api -}}
{{- range $api.subsets -}}
{{- range .addresses -}}
{{- $suffix := "/32" -}}
{{- if contains ":" .ip -}}{{- $suffix = "/128" -}}{{- end -}}
{{- $cidrs = append $cidrs (printf "%s%s" .ip $suffix) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $cidrs | uniq | toJson -}}
{{- end -}}
