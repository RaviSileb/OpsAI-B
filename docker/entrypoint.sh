#!/bin/sh
# Container entrypoint: optional DB auto-migrate flag, then exec the command.
set -eu
exec "$@"
