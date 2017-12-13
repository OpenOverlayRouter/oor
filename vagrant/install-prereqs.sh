#!/bin/bash
set -e
set -o pipefail

export DEBIAN_FRONTEND=noninteractive

# Update packages
apt-get -qq update
apt-get -qq upgrade
# Install build depndencies
apt-get -y -q install gengetopt libconfuse-dev libzmq3-dev libxml2-dev
# Install the Clang compiler to be able to test build with that too
apt-get -y -q install clang
