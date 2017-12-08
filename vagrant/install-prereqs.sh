#!/bin/bash
set -e
set -o pipefail

export DEBIAN_FRONTEND=noninteractive

# Update packages
sudo apt-get -qq update
sudo apt-get -qq upgrade
# Install build depndencies
sudo apt-get -y -q install gengetopt libconfuse-dev libzmq3-dev libxml2-dev
# Install the Clang compiler to be able to test build with that too
sudo apt-get -y -q install clang
