#!/bin/bash
set -e
set -o pipefail

export DEBIAN_FRONTEND=noninteractive

echo "Upgrading existing packages and installing OOR build prerequisites ..."
# Update packages
apt-get -y -q update
apt-get -y -q -o Dpkg::Options::="--force-confnew" upgrade
# Install build depndencies
apt-get -y -q install gengetopt libconfuse-dev libzmq3-dev libxml2-dev
# Install the Clang compiler to be able to test build with that too
apt-get -y -q install clang
echo "Prerequisites installed."
