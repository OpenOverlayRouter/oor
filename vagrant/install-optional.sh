#!/bin/bash
#
# This script expects the non-privileged username as the first argument

set -e
set -o pipefail

export DEBIAN_FRONTEND=noninteractive

# Install various utilities
apt-get -y -q install htop tmux unzip
# Install TShark for network packet analysis
export DEBCONF_DB_FALLBACK=/vagrant/vagrant/wireshark-common_config.dat
apt-get -y -q install tshark
groupadd wireshark || true
usermod -a -G wireshark $1
chgrp wireshark /usr/bin/dumpcap
chmod 4750 /usr/bin/dumpcap
