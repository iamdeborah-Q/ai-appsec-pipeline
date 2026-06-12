#!/usr/bin/env bash
# Build the golden image and fail if any FIXABLE HIGH/CRITICAL CVE is present.
set -e

echo "==> Building golden image..."
docker build -t golden-python-base golden-image/

echo "==> Scanning (only fixable vulnerabilities)..."
trivy image --ignore-unfixed --severity HIGH,CRITICAL --exit-code 1 golden-python-base

echo "✅ Golden image is clean of fixable HIGH/CRITICAL vulnerabilities."