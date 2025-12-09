{{- define "image" -}}
{{- if (kindIs "string" $) -}}
{{- $ }}
{{- else -}}
{{- if hasPrefix "sha256:" (required "$.tag is required" $.tag) -}}
{{- required "$.repository is required" $.repository }}@{{ $.tag }}
{{- else }}
{{- required "$.repository is required" $.repository }}:{{ $.tag }}
{{- end }}
{{- end -}}
{{- end -}}
