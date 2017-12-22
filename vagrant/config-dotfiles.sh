#!/bin/bash

echo "Setting up dot files..."
cat /vagrant/vagrant/bashrc_additions >> $HOME/.bashrc
cp /vagrant/vagrant/.bash_history $HOME
cp /vagrant/vagrant/.tmux.conf $HOME
