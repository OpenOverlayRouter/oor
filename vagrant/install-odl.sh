#!/bin/bash
set -e
set -o pipefail

# If the ODL release is changed (e.g., Nitrogen -> Oxygen) links in the
# README.md file should be updated too. Search for
# 'http://docs.opendaylight.org/en/stable-nitrogen/' and update accordingly
KARAF_VERSION=0.7.1
KARAF=karaf-$KARAF_VERSION
ODL=OpenDaylight-Nitrogen-SR1

echo "Installing OpenDaylight ..."
if [ ! -s "/tmp/vagrant-cache/$ODL.tar.gz" ]; then
	wget --no-verbose https://nexus.opendaylight.org/content/repositories/public/org/opendaylight/integration/karaf/$KARAF_VERSION/$KARAF.tar.gz -O /tmp/vagrant-cache/$ODL.tar.gz
fi
rm -rf $HOME/$ODL
tar xvf /tmp/vagrant-cache/$ODL.tar.gz -C $HOME >/dev/null
mv $HOME/$KARAF $HOME/$ODL
# Make lispflowmapping autostart in OpenDaylight
sed -i 's/featuresBoot =/featuresBoot = odl-lispflowmapping-mappingservice-shell,/g' $HOME/$ODL/etc/org.apache.karaf.features.cfg
mkdir $HOME/.karaf
cp /vagrant/karaf.history $HOME/.karaf
echo "client" >> $HOME/.bash_history
echo "" >> $HOME/.bashrc
echo "# Add OpenDaylight binaries to the PATH" >> $HOME/.bashrc
echo "export PATH=\$PATH:\$HOME/$ODL/bin" >> $HOME/.bashrc
echo "Installing OpenDaylight done. Starting as a daemon ..."
$HOME/$ODL/bin/start
