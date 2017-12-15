#!/bin/bash
set -e
set -o pipefail

export DEBIAN_FRONTEND=noninteractive

echo "Adding WebUpd8 PPA for Oracle Java 8 ..."
add-apt-repository -y ppa:webupd8team/java 2>/dev/null
echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | /usr/bin/debconf-set-selections
apt-get -y -q update
echo "Downloading and installing Oracle Java 8 ..."
apt-get -y install oracle-java8-installer >/dev/null
echo "Installing Oracle Java 8 done."
