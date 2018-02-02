#!/bin/bash
set -e
set -o pipefail

echo "Installing lig from source..."
rm -rf $HOME/lig
git clone -q https://github.com/davidmeyer/lig.git $HOME/lig
cd $HOME/lig
make > /dev/null 2>&1
sudo cp lig /usr/local/bin
echo "Installing lig finished successfully."
