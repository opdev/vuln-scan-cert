#!/bin/bash
set -euo pipefail

echo "Scanning image: ${IMAGE}"
echo "ROX Central endpoint: ${ROX_ENDPOINT}"
echo "API Token file: ${ROX_API_TOKEN_FILE}"

# Create results directory
mkdir -p "${RESULTS_PATH}"

# Generate unique filename based on image name
# Convert image name to safe filename: remove registry, replace special chars with hyphens
IMAGE_SAFE=$(echo "${IMAGE}" | sed 's|.*/||; s|[^a-zA-Z0-9._-]|-|g' | sed 's|--*|-|g; s|^-||; s|-$||')
echo "Image safe name: ${IMAGE_SAFE}"

# Download roxctl binary from the working URL
echo "Downloading roxctl binary..."
ROXCTL_URL="https://mirror.openshift.com/pub/rhacs/assets/4.4.2/bin/Linux/roxctl"

if curl -sL -f -o /tmp/roxctl "$ROXCTL_URL"; then
    chmod +x /tmp/roxctl
    if /tmp/roxctl version &>/dev/null; then
        ROXCTL_CMD="/tmp/roxctl"
        echo "Successfully downloaded roxctl from $ROXCTL_URL"
        /tmp/roxctl version
    else
        echo "ERROR: Downloaded file is not a valid roxctl binary"
        exit 1
    fi
else
    echo "ERROR: Failed to download roxctl from $ROXCTL_URL"
    exit 1
fi

# Perform the image scan and save results to JSON file with unique name
JSON_OUTPUT="${RESULTS_PATH}/scan-results-${IMAGE_SAFE}.json"

echo "ROX API Token file: ${ROX_API_TOKEN_FILE}"
if [ ! -f "${ROX_API_TOKEN_FILE}" ]; then
    echo "ERROR: ROX API token file not found at ${ROX_API_TOKEN_FILE}"
    echo "Available files in /workspace:"
    find /workspace -name "*token*" -o -name "rox*" 2>/dev/null || echo "No token files found"
    exit 1
fi

echo "Running scan command..."
# Run the scan with JSON output
$ROXCTL_CMD image scan \
  --insecure-skip-tls-verify=${INSECURE} \
  --output=json \
  --image="${IMAGE}" > "${JSON_OUTPUT}"

echo "Scan completed successfully"
echo "JSON results saved to: ${JSON_OUTPUT}"

# Show first few lines of results for verification
echo "Sample of scan results:"
head -10 "${JSON_OUTPUT}"
