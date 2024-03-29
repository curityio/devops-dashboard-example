#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"

#
# Use HTTP development URLs for simplicity
#
export ADMIN_BASE_URL='http://localhost:6749'
export RUNTIME_BASE_URL='http://localhost:8443'

#
# Check there is a license file
#
if [ ! -f './license.json' ]; then
  echo 'Please copy a valid license file for the Curity Identity Server into the root folder before deploying'
  exit
fi

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
