{{- define "stack-engine.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "stack-engine.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "stack-engine.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "stack-engine.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "stack-engine.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "stack-engine.selector" -}}
app.kubernetes.io/name: {{ include "stack-engine.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* image reference: a digest wins over a tag */}}
{{- define "stack-engine.image" -}}
{{- $repo := printf "%s/%s" .root.Values.image.registry .name -}}
{{- if .root.Values.image.digest -}}
{{- printf "%s@%s" $repo .root.Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" $repo (default .root.Chart.AppVersion .root.Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "stack-engine.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "stack-engine.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* the secret every pod mounts: required, never created here */}}
{{- define "stack-engine.secretName" -}}
{{- required "secrets.existingSecret is required: the Secret that holds the install's keys (see values.yaml)" .Values.secrets.existingSecret -}}
{{- end -}}

{{/* the settings the API, the worker and the migration Job share */}}
{{- define "stack-engine.env" -}}
- { name: NODE_ENV, value: production }
- { name: STACK_DEPLOYMENT, value: self_managed }
- { name: STACK_API_BASE_URL, value: {{ required "publicUrl is required (an https origin)" .Values.publicUrl | quote }} }
{{- with .Values.dashboardUrl }}
- { name: DASHBOARD_URL, value: {{ . | quote }} }
{{- end }}
{{- with .Values.mcpPublicUrl }}
- { name: STACK_MCP_BASE_URL, value: {{ . | quote }} }
{{- end }}
{{- with .Values.issuer }}
- { name: STACK_ISSUER, value: {{ . | quote }} }
{{- end }}
{{- with .Values.securityContact }}
- { name: STACK_SECURITY_CONTACT, value: {{ . | quote }} }
{{- end }}
- { name: DATABASE_URL_FILE, value: /run/secrets/database-url }
- { name: REDIS_URL_FILE, value: /run/secrets/redis-url }
- { name: API_KEY_PEPPER_FILE, value: /run/secrets/api-key-pepper }
- { name: STACK_KEY_FILE, value: /run/secrets/stack-kek }
- { name: SESSION_SIGNING_KEY_FILE, value: /run/secrets/session-signing-key }
- { name: MCP_ELICITATION_ATTESTATION_KEY_FILE, value: /run/secrets/mcp-attestation-key }
- { name: AUDIT_ARCHIVE_BUCKET, value: {{ .Values.archive.bucket | quote }} }
{{- with .Values.archive.endpoint }}
- { name: AUDIT_ARCHIVE_ENDPOINT, value: {{ . | quote }} }
{{- end }}
- { name: AUDIT_ARCHIVE_REGION, value: {{ .Values.archive.region | quote }} }
- { name: AWS_ACCESS_KEY_ID_FILE, value: /run/secrets/archive-access-key }
- { name: AWS_SECRET_ACCESS_KEY_FILE, value: /run/secrets/archive-secret-key }
- { name: STACK_EMAIL_TRANSPORT, value: {{ .Values.email.transport | quote }} }
{{- with .Values.email.from }}
- { name: EMAIL_FROM, value: {{ . | quote }} }
{{- end }}
- name: SMTP_URL
  valueFrom: { secretKeyRef: { name: {{ include "stack-engine.secretName" . }}, key: smtp-url, optional: true } }
- name: STACK_LICENCE_KEY
  valueFrom: { secretKeyRef: { name: {{ include "stack-engine.secretName" . }}, key: licence-key, optional: true } }
{{- with .Values.network.url }}
- { name: STACK_NETWORK_URL, value: {{ . | quote }} }
- { name: STACK_NETWORK_RULES, value: {{ $.Values.network.rules | quote }} }
- { name: STACK_NETWORK_CLASSIFIER, value: {{ $.Values.network.classifier | quote }} }
- name: STACK_NETWORK_KEY
  valueFrom: { secretKeyRef: { name: {{ include "stack-engine.secretName" $ }}, key: network-key } }
{{- end }}
{{- if and .Values.intentModel.url .Values.intentModel.name }}
- { name: STACK_INTENT_MODEL_URL, value: {{ .Values.intentModel.url | quote }} }
- { name: STACK_INTENT_MODEL_NAME, value: {{ .Values.intentModel.name | quote }} }
- name: STACK_INTENT_MODEL_KEY
  valueFrom: { secretKeyRef: { name: {{ include "stack-engine.secretName" . }}, key: intent-model-key, optional: true } }
{{- end }}
{{- with .Values.siem.syslogUrl }}
- { name: STACK_SIEM_SYSLOG_URL, value: {{ . | quote }} }
{{- end }}
{{- with .Values.siem.httpUrl }}
- { name: STACK_SIEM_HTTP_URL, value: {{ . | quote }} }
{{- end }}
{{- if or .Values.siem.syslogUrl .Values.siem.httpUrl }}
- { name: STACK_SIEM_STREAMS, value: {{ .Values.siem.streams | quote }} }
{{- end }}
- { name: OAUTH_ENABLED, value: {{ .Values.oauth.enabled | quote }} }
- { name: OAUTH_SCOPE_ENFORCEMENT, value: {{ .Values.oauth.enabled | quote }} }
{{- with .Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "stack-engine.secretVolume" -}}
- name: secrets
  secret:
    secretName: {{ include "stack-engine.secretName" . }}
    defaultMode: 0440
{{- end -}}
