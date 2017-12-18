#!/bin/bash

echo "Setting up dot files..."
cat /vagrant/bashrc_additions >> $HOME/.bashrc
cp /vagrant/.bash_history $HOME
cp /vagrant/.tmux.conf $HOME
