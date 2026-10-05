{{- define "ddns-updater.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "ddns-updater.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "ddns-updater.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "ddns-updater.labels" -}}
helm.sh/chart: {{ include "ddns-updater.chart" . }}
{{ include "ddns-updater.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "ddns-updater.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ddns-updater.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "ddns-updater.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ddns-updater.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "ddns-updater.secretName" -}}
{{- default (include "ddns-updater.fullname" .) .Values.credentials.existingSecret }}
{{- end }}

{{- define "ddns-updater.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}
{{- end }}

{{/*
Where the credentials Secret comes from: "existing" (credentials.existingSecret),
"external" (an ExternalSecret rendered by this chart) or "chart" (a Secret
rendered by this chart from credentials.username/password).
*/}}
{{- define "ddns-updater.credentialsSource" -}}
{{- if .Values.credentials.existingSecret }}existing
{{- else if .Values.externalSecret.enabled }}external
{{- else }}chart
{{- end }}
{{- end }}

{{- define "ddns-updater.validate" -}}
{{- if not .Values.hostnames }}
{{- fail "hostnames: at least one hostname is required" }}
{{- end }}
{{- $source := include "ddns-updater.credentialsSource" . }}
{{- if and .Values.credentials.existingSecret .Values.externalSecret.enabled }}
{{- fail "credentials.existingSecret and externalSecret.enabled are mutually exclusive" }}
{{- end }}
{{- if eq $source "external" }}
{{- with .Values.externalSecret }}
{{- if not .secretStoreRef.name }}
{{- fail "externalSecret.secretStoreRef.name is required" }}
{{- end }}
{{- if or (not .username.key) (not .password.key) }}
{{- fail "externalSecret: username.key and password.key are required" }}
{{- end }}
{{- end }}
{{- end }}
{{- if eq $source "chart" }}
{{- if or (not .Values.credentials.username) (not .Values.credentials.password) }}
{{- fail "credentials: set credentials.existingSecret, enable externalSecret, or set both credentials.username and credentials.password" }}
{{- end }}
{{- end }}
{{- if not (or .Values.ipv4.enabled .Values.ipv6.enabled) }}
{{- fail "at least one of ipv4.enabled or ipv6.enabled must be true" }}
{{- end }}
{{- end }}
