#!/usr/bin/env bash
# Convenience launcher for development / published binary next to this script.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="${HOME}/.dotnet:${PATH}"
export DOTNET_ROOT="${DOTNET_ROOT:-${HOME}/.dotnet}"

if [[ -x "${ROOT}/bin/publish/NetworkSentinel" ]]; then
  exec "${ROOT}/bin/publish/NetworkSentinel" "$@"
fi
if [[ -x "${ROOT}/bin/Release/net8.0/NetworkSentinel" ]]; then
  exec "${ROOT}/bin/Release/net8.0/NetworkSentinel" "$@"
fi
exec dotnet run --project "${ROOT}/NetworkSentinel.csproj" -c Release -- "$@"
