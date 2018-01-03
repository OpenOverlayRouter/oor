#!/bin/bash
set -e

PLATFORM_VERSION=`grep compileSdkVersion /vagrant/android/app/build.gradle | awk '{ print $2 }'`
BUILD_TOOLS_VERSION=`grep buildToolsVersion /vagrant/android/app/build.gradle | awk '{ gsub(/\47/,"",$2); print $2 }'`
SDK_TOOLS_VERSION=3859397
SDK_PATH=/vagrant/android/sdk

if [ ! -s "/tmp/vagrant-cache/sdk-tools-linux.zip" ]; then
	echo "Downloading Android SDK Tools ..."
	wget https://dl.google.com/android/repository/sdk-tools-linux-${SDK_TOOLS_VERSION}.zip -O /tmp/vagrant-cache/sdk-tools-linux.zip
	echo "... done."
fi

if [ ! -d $SDK_PATH/tools ]; then
	echo "Extracting Android SDK Tools ..."
	mkdir -p $SDK_PATH/tmp
	cd $SDK_PATH
	unzip -q /tmp/vagrant-cache/sdk-tools-linux.zip
	echo "... done."
fi

# Silence a warning
mkdir -p $HOME/.android
touch $HOME/.android/repositories.cfg

# Make the SDK Manager use the host disk as temporary download space, so we
# don't run out disk space on the VM
export _JAVA_OPTIONS="-Djava.io.tmpdir=${SDK_PATH}/tmp"
echo "" >> $HOME/.bashrc
echo "export _JAVA_OPTIONS=\"-Djava.io.tmpdir=${SDK_PATH}/tmp\"" >> $HOME/.bashrc

#$SDK_PATH/tools/bin/sdkmanager --update
echo "Accepting licenses ..."
yes | $SDK_PATH/tools/bin/sdkmanager --licenses > /dev/null
#echo "Updating Android SDK Tools ..."
#$SDK_PATH/tools/bin/sdkmanager --update
echo "Downloading and installing NDK ..."
$SDK_PATH/tools/bin/sdkmanager "ndk-bundle"
echo "Downloading and installing Android SDK Platform ${PLATFORM_VERSION}"
$SDK_PATH/tools/bin/sdkmanager "platforms;android-${PLATFORM_VERSION}"
echo "Downloading and installing Android SDK Platform-Tools"
$SDK_PATH/tools/bin/sdkmanager "platform-tools"
echo "Downloading and installing Android SDK Build-Tools ${BUILD_TOOLS_VERSION}"
$SDK_PATH/tools/bin/sdkmanager "build-tools;${BUILD_TOOLS_VERSION}"

# Create local.properties with the right values
echo "ndk.dir=${SDK_PATH}/ndk-bundle" > /vagrant/android/local.properties
echo "sdk.dir=${SDK_PATH}" >> /vagrant/android/local.properties

# Add SDK Tools to the PATH
echo "" >> $HOME/.bashrc
echo "# Add Android SDK Tools binaries to the PATH" >> $HOME/.bashrc
echo "export PATH=\$PATH:${SDK_PATH}/tools/bin" >> $HOME/.bashrc

# Initialize Gradle
echo "Initializing Gradle Wrapper ..."
export GRADLE_USER_HOME=/vagrant/android/.gradle
cd /vagrant/android
./gradlew -q tasks

echo "./gradlew :app:assembleRelease" >> $HOME/.bash_history
echo "./gradlew :app:assembleDebug" >> $HOME/.bash_history
echo "cd /vagrant/android" >> $HOME/.bash_history
