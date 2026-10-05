#!/usr/bin/env bash
# Prints the release version from charts/ddns-updater/Chart.yaml, the single
# source of truth for the chart version, the app version and the git tag.
# Fails if the version is not semver or if appVersion differs from version.
set -euo pipefail

chart="$(dirname "$0")/../charts/ddns-updater/Chart.yaml"
field() { sed -n "s/^$1:[[:space:]]*//p" "$chart" | tr -d "\"'[:space:]"; }

version=$(field version)
app_version=$(field appVersion)

semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'
if [[ ! $version =~ $semver ]]; then
  echo "Chart.yaml: version '$version' is not a semantic version" >&2
  exit 1
fi
if [[ $app_version != "$version" ]]; then
  echo "Chart.yaml: appVersion '$app_version' must equal version '$version'" >&2
  exit 1
fi
echo "$version"
