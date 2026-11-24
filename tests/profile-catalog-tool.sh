#!/bin/sh
# Metadata-format fixture only: no sampling or benchmark result is simulated.
set -eu
if [ "$1" = buildid-list ]; then cat "${3%/*}/catalog"; fi
