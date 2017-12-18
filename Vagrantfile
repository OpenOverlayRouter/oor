# -*- mode: ruby -*-
# vi: set ft=ruby ts=2 sw=2 sts=2 et :

# This Vagrantfile lives in the top-level directory, since then it makes all
# source code available in the /vagrant shared folder. That means that build
# artifacts are also available for the host system.

Vagrant.configure(2) do |config|
  # vagrant-cachier caches apt/yum etc. to speed subsequent `vagrant up`
  # To enable, run `vagrant plugin install vagrant-cachier`
  if Vagrant.has_plugin?("vagrant-cachier")
    config.cache.scope = :box
    config.cache.synced_folder_opts = {
      owner: '_apt',
      group: '_apt',
      mount_options: ["dmode=777", "fmode=666"]
    }
  end
  config.vm.box = "ubuntu/artful64"
  config.vm.box_check_update = false
  config.vm.define "oor-dev"
  config.vm.hostname = "oor-dev"
  config.vm.provision "shell", path: "vagrant/install-prereqs.sh"
  config.vm.provider :virtualbox do |vb|
    vb.name = "oor-dev"
    vb.cpus = 2
    vb.memory = 512
    vb.customize [ "modifyvm", :id, "--description", "VM for Open Overlay Router development" ]
    # This disables generating a log file with boot messages. If you need to
    # debug the boot process, comment the following line.
    vb.customize [ "modifyvm", :id, "--uartmode1", "disconnected" ]
  end
end
