#!/bin/sh

set -e

. ./set-env.sh

python -m pytest
