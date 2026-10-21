{{- define "identity.name" -}}
{{- printf "%s-identity" .Release.Name | trunc 45 | trimSuffix "-" -}}
{{- end -}}
{{- define "identity.image" -}}
{{- if .digest -}}{{ .repository }}@{{ .digest }}{{- else -}}{{ .repository }}:{{ .tag }}{{- end -}}
{{- end -}}
