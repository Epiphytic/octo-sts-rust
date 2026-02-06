#!/usr/bin/env bash
# Deploy octo-sts-gcp to Cloud Run
# Usage: ./deploy.sh [--project PROJECT_ID]
#
# Prerequisites:
#   gcloud auth login
#   gcloud auth configure-docker
#
# Required secrets (set via gcloud secrets or env vars):
#   GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY, GITHUB_WEBHOOK_SECRET, DOMAIN

set -euo pipefail

PROJECT="${1:-backstage-np-mly9n}"
REGION="us-central1"
SERVICE_NAME="octo-sts"
IMAGE="gcr.io/${PROJECT}/${SERVICE_NAME}"

echo "Deploying to project: ${PROJECT}"
echo "Region: ${REGION}"
echo "Image: ${IMAGE}"

# Build from workspace root (Dockerfile expects workspace layout)
cd "$(dirname "$0")/.."

# Build and push container
echo "Building container..."
docker build -f gcp/Dockerfile -t "${IMAGE}" .

echo "Pushing to GCR..."
docker push "${IMAGE}"

# Deploy to Cloud Run
echo "Deploying to Cloud Run..."
gcloud run deploy "${SERVICE_NAME}" \
	--project="${PROJECT}" \
	--region="${REGION}" \
	--image="${IMAGE}" \
	--platform=managed \
	--port=8080 \
	--memory=256Mi \
	--cpu=1 \
	--min-instances=0 \
	--max-instances=3 \
	--set-env-vars="GCP_PROJECT=${PROJECT}" \
	--allow-unauthenticated

echo ""
echo "Deployed! Get the service URL with:"
echo "  gcloud run services describe ${SERVICE_NAME} --project=${PROJECT} --region=${REGION} --format='value(status.url)'"
