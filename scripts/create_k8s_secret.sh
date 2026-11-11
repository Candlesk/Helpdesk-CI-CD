#!/usr/bin/env bash
# Create the database Secret without committing any value to git.
# The password is generated locally and only lives in the cluster Secret.
set -euo pipefail

NAMESPACE="${NAMESPACE:-helpdesk}"
PASSWORD="$(openssl rand -hex 24)"

kubectl -n "$NAMESPACE" create secret generic helpdesk-db \
  --from-literal=POSTGRES_USER=helpdesk \
  --from-literal=POSTGRES_DB=helpdesk \
  --from-literal=POSTGRES_PASSWORD="$PASSWORD" \
  --from-literal=DATABASE_URL="postgresql://helpdesk:${PASSWORD}@helpdesk-db:5432/helpdesk" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Secret helpdesk-db created/updated in namespace $NAMESPACE."
echo "The generated password was not written to disk."
