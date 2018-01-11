#!/bin/bash
set -e
set -o pipefail

cd $HOME/oor && make clean && make && sudo make install
