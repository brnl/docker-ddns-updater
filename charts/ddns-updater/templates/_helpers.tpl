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

{{/* Secret name of an extra account: (dict "root" $ "account" .) */}}
{{- define "ddns-updater.accountSecretName" -}}
{{- with .account }}
{{- default (printf "%s-%s" (include "ddns-updater.fullname" $.root) .name | trunc 63 | trimSuffix "-") .existingSecret }}
{{- end }}
{{- end }}

{{/* Environment variable prefix of an extra account. */}}
{{- define "ddns-updater.accountEnvPrefix" -}}
{{- printf "DDNS_ACCOUNT_%s_" (.name | upper | replace "-" "_") }}
{{- end }}

{{/*
An ExternalSecret. Takes a dict with root, name (resource and target Secret
name), store, refreshInterval, annotations, username, password, usernameKey
and passwordKey.
*/}}
{{- define "ddns-updater.externalSecretResource" -}}
apiVersion: {{ .root.Values.externalSecret.apiVersion }}
kind: ExternalSecret
metadata:
  name: {{ .name }}
  labels:
    {{- include "ddns-updater.labels" .root | nindent 4 }}
  {{- with .annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  refreshInterval: {{ .refreshInterval | quote }}
  secretStoreRef:
    kind: {{ .store.kind | default "ClusterSecretStore" }}
    name: {{ .store.name }}
  target:
    name: {{ .name }}
    creationPolicy: Owner
  data:
    {{- range $field, $ref := dict "username" .username "password" .password }}
    - secretKey: {{ get $ (printf "%sKey" $field) }}
      remoteRef:
        key: {{ $ref.key | quote }}
        {{- with $ref.property }}
        property: {{ . | quote }}
        {{- end }}
        {{- with $ref.version }}
        version: {{ . | quote }}
        {{- end }}
    {{- end }}
{{- end }}

{{- define "ddns-updater.validate" -}}
{{- if not (or .Values.hostnames .Values.accounts) }}
{{- fail "configure hostnames (the default account) and/or accounts" }}
{{- end }}
{{- /*
Secret names the chart creates (itself or via an ExternalSecret) must not be
used by any other account, whatever the order: otherwise two accounts would
read each other's credentials.
*/}}
{{- $generated := dict }}
{{- if and .Values.hostnames (ne (include "ddns-updater.credentialsSource" .) "existing") }}
{{- $_ := set $generated (include "ddns-updater.secretName" .) "default" }}
{{- end }}
{{- range .Values.accounts }}
{{- if not .existingSecret }}
{{- $secretName := include "ddns-updater.accountSecretName" (dict "root" $ "account" .) }}
{{- if hasKey $generated $secretName }}
{{- fail (printf "accounts[%s]: Secret name %q clashes with account %q (names are truncated to 63 characters); use shorter account names or fullnameOverride" .name $secretName (get $generated $secretName)) }}
{{- end }}
{{- $_ := set $generated $secretName .name }}
{{- end }}
{{- end }}
{{- if and .Values.hostnames .Values.credentials.existingSecret (hasKey $generated .Values.credentials.existingSecret) }}
{{- fail (printf "credentials.existingSecret %q is the Secret the chart creates for account %q" .Values.credentials.existingSecret (get $generated .Values.credentials.existingSecret)) }}
{{- end }}
{{- $names := dict }}
{{- range .Values.accounts }}
{{- if or (eq .name "default") (hasKey $names .name) }}
{{- fail (printf "accounts: account name %q must be unique and not \"default\"" .name) }}
{{- end }}
{{- $_ := set $names .name true }}
{{- if and .existingSecret (hasKey $generated .existingSecret) }}
{{- fail (printf "accounts[%s]: existingSecret %q is the Secret the chart creates for account %q" .name .existingSecret (get $generated .existingSecret)) }}
{{- end }}
{{- $es := and .externalSecret .externalSecret.enabled }}
{{- $sources := 0 }}
{{- if .existingSecret }}{{ $sources = add1 $sources }}{{ end }}
{{- if $es }}{{ $sources = add1 $sources }}{{ end }}
{{- if or .username .password }}{{ $sources = add1 $sources }}{{ end }}
{{- if ne (int $sources) 1 }}
{{- fail (printf "accounts[%s]: set exactly one of existingSecret, externalSecret.enabled, or username+password" .name) }}
{{- end }}
{{- if and (or .username .password) (not (and .username .password)) }}
{{- fail (printf "accounts[%s]: set both username and password" .name) }}
{{- end }}
{{- if $es }}
{{- if not (or (and .externalSecret.secretStoreRef .externalSecret.secretStoreRef.name) $.Values.externalSecret.secretStoreRef.name) }}
{{- fail (printf "accounts[%s].externalSecret: set secretStoreRef.name (here or in externalSecret.secretStoreRef)" .name) }}
{{- end }}
{{- if not (and .externalSecret.username .externalSecret.username.key .externalSecret.password .externalSecret.password.key) }}
{{- fail (printf "accounts[%s].externalSecret: username.key and password.key are required" .name) }}
{{- end }}
{{- end }}
{{- end }}
{{- if .Values.hostnames }}
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
{{- end }}
{{- with .Values.metrics }}
{{- if and (or .serviceMonitor.enabled .prometheusRule.enabled) (not .enabled) }}
{{- fail "metrics.serviceMonitor and metrics.prometheusRule require metrics.enabled" }}
{{- end }}
{{- end }}
{{- if and .Values.metrics.serviceMonitor.enabled (not .Values.service.enabled) }}
{{- fail "metrics.serviceMonitor.enabled requires service.enabled" }}
{{- end }}
{{- if .Values.httpRoute.enabled }}
{{- if not .Values.service.enabled }}
{{- fail "httpRoute.enabled requires service.enabled" }}
{{- end }}
{{- if not .Values.httpRoute.parentRefs }}
{{- fail "httpRoute.parentRefs is required when httpRoute.enabled" }}
{{- end }}
{{- end }}
{{- if not (or .Values.ipv4.enabled .Values.ipv6.enabled) }}
{{- fail "at least one of ipv4.enabled or ipv6.enabled must be true" }}
{{- end }}
{{- end }}
