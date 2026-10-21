#!/bin/bash
set -euo pipefail

echo "Scanning image: ${IMAGE}"
echo "ROX Central endpoint: ${ROX_ENDPOINT}"

# Create results directory
mkdir -p "${RESULTS_PATH}"

# Split image into name and tag
if [[ "${IMAGE}" == *":"* ]]; then
    IMAGE_NAME="${IMAGE%:*}"
    IMAGE_TAG="${IMAGE##*:}"
else
    IMAGE_NAME="${IMAGE}"
    IMAGE_TAG="latest"
fi

# Remove registry prefix from image name
IMAGE_NAME="${IMAGE_NAME##*/}"

# Sanitize image name and tag for filename
IMAGE_NAME_SAFE=$(echo "${IMAGE_NAME}" | sed 's|[^a-zA-Z0-9._-]|-|g' | sed 's|--*|-|g; s|^-||; s|-$||')
IMAGE_TAG_SAFE=$(echo "${IMAGE_TAG}" | sed 's|[^a-zA-Z0-9._-]|-|g' | sed 's|--*|-|g; s|^-||; s|-$||')

echo "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo "Safe filename: ${PARTNER_NAME}_${SCANNER_NAME}_${SCANNER_VERSION}_${IMAGE_NAME_SAFE}_${IMAGE_TAG_SAFE}"

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

# Perform the image scan and save results to JSON file with new naming format
JSON_OUTPUT="${RESULTS_PATH}/${PARTNER_NAME}_${SCANNER_NAME}_${SCANNER_VERSION}_${IMAGE_NAME_SAFE}_${IMAGE_TAG_SAFE}.json"

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
