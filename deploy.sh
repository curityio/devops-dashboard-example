#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"

#
# Set URLs
#
export ADMIN_BASE_URL='https://localhost:6749'
export RUNTIME_BASE_URL='https://localhost:8443'

#
# Clear cached database volumes on disk if required
#
rm -rf data 2>/dev/null

#
# This is used by Curity developers to prevent checkins of license files
#
cp ./hooks/pre-commit ./.git/hooks

#
# Deploy the system
#
docker compose --project-name dashboard up --force-recreate
