#!/bin/bash
set -e
set -o pipefail

cd $HOME/oor && make && sudo make install
cp vagrant/.bash_history $HOME
