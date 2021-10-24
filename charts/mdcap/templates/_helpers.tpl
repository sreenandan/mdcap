{{/*
Copyright (C) 2021 Robin.io All Rights Reserved.
*/}}
{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "mdcap.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Expand the name of the chart.
*/}}
{{- define "mdcap.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}



{{/*
Create a fully qualified engine name.
*/}}

{{- define "engine.fullname" -}}
{{- if .Values.engine.fullnameOverride -}}
{{- .Values.engine.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- printf "%s-%s" .Release.Name .Values.engine.name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s-%s" .Release.Name $name .Values.engine.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "grafana.fullname" -}}
{{- if .Values.grafana.fullnameOverride -}}
{{- .Values.grafana.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- printf "%s-%s" .Release.Name .Values.grafana.name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s-%s" .Release.Name $name .Values.grafana.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "vmetrics.fullname" -}}
{{- if .Values.vmetrics.fullnameOverride -}}
{{- .Values.vmetrics.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- printf "%s-%s" .Release.Name .Values.vmetrics.name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s-%s" .Release.Name $name .Values.vmetrics.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "artifactory.fullname" -}}
{{- if .Values.artifactory.fullnameOverride -}}
{{- .Values.artifactory.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- printf "%s-%s" .Release.Name .Values.artifactory.name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s-%s" .Release.Name $name .Values.artifactory.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "logstore.fullname" -}}
{{- if .Values.logstore.fullnameOverride -}}
{{- .Values.logstore.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- printf "%s-%s" .Release.Name .Values.logstore.name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s-%s" .Release.Name $name .Values.logstore.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "dashboard.fullname" -}}
{{- if .Values.dashboard.fullnameOverride -}}
{{- .Values.dashboard.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- printf "%s-%s" .Release.Name .Values.dashboard.name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s-%s" .Release.Name $name .Values.dashboard.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "nginx.fullname" -}}
{{- if .Values.nginx.fullnameOverride -}}
{{- .Values.nginx.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- printf "%s-%s" .Release.Name .Values.nginx.name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s-%s" .Release.Name $name .Values.nginx.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "eventserver.fullname" -}}
{{- if .Values.eventserver.fullnameOverride -}}
{{- .Values.eventserver.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- printf "%s-%s" .Release.Name .Values.eventserver.name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s-%s" .Release.Name $name .Values.eventserver.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "playground.fullname" -}}
{{- if .Values.playground.fullnameOverride -}}
{{- .Values.playground.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- printf "%s-%s" .Release.Name .Values.playground.name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s-%s" .Release.Name $name .Values.playground.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "engine.storageclass.name" -}}
{{- if .Values.storageClassNameOverride -}}
{{- printf "%s" .Values.storageClassNameOverride -}}
{{- else -}}
{{- printf "%s" .Values.engine.persistentVolume.storageClass -}}
{{- end -}}
{{- end -}}

{{- define "artifactory.storageclass.name" -}}
{{- if .Values.storageClassNameOverride -}}
{{- printf "%s" .Values.storageClassNameOverride -}}
{{- else -}}
{{- printf "%s" .Values.artifactory.persistentVolume.storageClass -}}
{{- end -}}
{{- end -}}

{{- define "logstore.storageclass.name" -}}
{{- if .Values.storageClassNameOverride -}}
{{- printf "%s" .Values.storageClassNameOverride -}}
{{- else -}}
{{- printf "%s" .Values.logstore.persistentVolume.storageClass -}}
{{- end -}}
{{- end -}}

{{- define "playground.storageclass.name" -}}
{{- if .Values.storageClassNameOverride -}}
{{- printf "%s" .Values.storageClassNameOverride -}}
{{- else -}}
{{- printf "%s" .Values.playground.persistentVolume.storageClass -}}
{{- end -}}
{{- end -}}

{{- define "nginx.storageclass.name" -}}
{{- if .Values.storageClassNameOverride -}}
{{- printf "%s" .Values.storageClassNameOverride -}}
{{- else -}}
{{- printf "%s" .Values.nginx.persistentVolume.storageClass -}}
{{- end -}}
{{- end -}}

{{- define "eventserver.storageclass.name" -}}
{{- if .Values.storageClassNameOverride -}}
{{- printf "%s" .Values.storageClassNameOverride -}}
{{- else -}}
{{- printf "%s" .Values.eventserver.persistentVolume.storageClass -}}
{{- end -}}
{{- end -}}

{{- define "vmetrics.storageclass.name" -}}
{{- if .Values.storageClassNameOverride -}}
{{- printf "%s" .Values.storageClassNameOverride -}}
{{- else -}}
{{- printf "%s" .Values.vmetrics.persistentVolume.storageClass -}}
{{- end -}}
{{- end -}}

{{- define "grafana.storageclass.name" -}}
{{- if .Values.storageClassNameOverride -}}
{{- printf "%s" .Values.storageClassNameOverride -}}
{{- else -}}
{{- printf "%s" .Values.grafana.persistentVolume.storageClass -}}
{{- end -}}
{{- end -}}

{{- define "imagePullSecret" }}
{{- with .Values.imageCredentials }}
{{- printf "{\"auths\":{\"%s\":{\"username\":\"%s\",\"password\":\"%s\",\"email\":\"%s\",\"auth\":\"%s\"}}}" .registry .username .password .email (printf "%s:%s" .username .password | b64enc) | b64enc }}
{{- end }}
{{- end }}


{{- define "mdcap.add.imagePullSecret" }}
{{ if .Values.imageCredentials.registry }}
imagePullSecrets:
  - name:  {{ .Release.Name }}-imagepull-secret
{{- end }}
{{- end }}

{{- define "versionValidateK8s" -}}
{{- printf "%s" .Capabilities.KubeVersion.Version -}}
{{- if .Capabilities.KubeVersion.Version | trimPrefix "v" | semverCompare "<1.19" -}}
{{ required "Robin Version less than 5.3.5 does not support RWX volume access mode. vmetrics can not run without RXW support. Please use --set vmetrics.enabled=false to disable metrics." .value }}
{{- end -}}
{{- end -}}

{{- define "annotationsToStr" -}}
{{- $annstr := "" -}}
{{- range $k, $v := .Values.taskrunner.annotations -}}
{{- $annstr := list $k ":" $v "," | join ""  -}}
{{- printf "%s" $annstr -}}
{{- end -}}
{{- end -}}

# Robin 5.3.5 is K8s 1.20
# robin 5.3.3 is K8s 1.18 
{{- define "robinVersion533" -}}
{{- if .Capabilities.KubeVersion.Version | trimPrefix "v" | semverCompare "<1.19" -}}
{{- printf "%s" "true"  -}}
{{- else -}}
{{- printf "%s" "false"  -}}
{{- end -}}
{{- end -}}
