# -*- mode: ruby -*-
# vi: set ft=ruby ts=2 sw=2 sts=2 et :

# This Vagrantfile lives in the top-level directory, since then it makes all
# source code available in the /vagrant shared folder. That means that build
# artifacts are also available for the host system.

# Determine number of available CPU cores
def numcpus(default)
  host = RbConfig::CONFIG['host_os']
  if host =~ /darwin/
    cpus = `sysctl -n hw.ncpu`.to_i
  elsif host =~ /linux/
    cpus = `nproc`.to_i
  else
    cpus = default
  end
end

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
  # TODO need to figure out how to use #{config.ssh.username} instead of
  # "ubuntu" to be more general, if the box we use changes the user
  username = "vagrant"
  config.vm.provider :virtualbox do |vb|
    # This disables generating a log file with boot messages. If you need to
    # debug the boot process, comment the following line.
    vb.customize [ "modifyvm", :id, "--uartmode1", "disconnected" ]
  end

  # Main VM for OOR core development
  config.vm.define "oor-dev", primary: true do |main|
    main.vm.hostname = "oor-dev"
    main.vm.provision "shell", path: "vagrant/install-prereqs.sh"
    main.vm.provider :virtualbox do |vb|
      vb.name = "oor-dev"
      vb.cpus = 2
      vb.memory = 512
      vb.customize [ "modifyvm", :id, "--description", "VM for Open Overlay Router development" ]
    end
  end

  # Optional VM for Android builds
  # Does not install Android Studio, but installs Gradle and the Android SDK
  # and adds some files necessary to build an .apk from the command line
  config.vm.define "oor-dev-android", autostart: false do |android|
    android.vm.hostname = "oor-dev-android"
    android.vm.provision "shell", path: "vagrant/install-optional.sh", args: username
    android.vm.provision "shell", path: "vagrant/install-oracle-java8.sh"
    android.vm.provision "shell", path: "vagrant/config-dotfiles.sh", privileged: false
    android.vm.provision "shell", path: "vagrant/install-android-sdk.sh", privileged: false
    android.vm.provider :virtualbox do |vb|
      vb.name = "oor-dev-android"
      vb.cpus = numcpus(2)
      vb.memory = 4096
      vb.customize [ "modifyvm", :id, "--description", "VM for Open Overlay Router Android builds" ]
    end
  end
end
