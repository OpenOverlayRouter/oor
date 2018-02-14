#!/bin/bash
set -e

PLATFORM_VERSION=`grep compileSdkVersion /vagrant/android/app/build.gradle | awk '{ print $2 }'`
BUILD_TOOLS_VERSION=`grep buildToolsVersion /vagrant/android/app/build.gradle | awk '{ gsub(/\47/,"",$2); print $2 }'`
# SDK_TOOLS_VERSION can be determined at https://developer.android.com/studio/index.html#downloads
SDK_TOOLS_VERSION=3859397
EMU_API=27
EMU_TAG=google_apis_playstore
# Valid ABI options are x86, x86_64, armeabi-v7a, arm64-v8a, but not all API;TAG;ABI combinations are available
EMU_ABI=x86
# Use `sdkmanager --list --verbose` to see which system images are available
ANDROID_SYSTEM_IMAGE="system-images;android-${EMU_API};${EMU_TAG};${EMU_ABI}"
ANDROID_SDK_ROOT=/vagrant/android/sdk
#export ANDROID_EMULATOR_HOME=$ANDROID_SDK_ROOT/.android

if [ ! -s "/tmp/vagrant-cache/sdk-tools-linux.zip" ]; then
	echo "Downloading Android SDK Tools ..."
	wget --no-verbose https://dl.google.com/android/repository/sdk-tools-linux-${SDK_TOOLS_VERSION}.zip -O /tmp/vagrant-cache/sdk-tools-linux.zip
	echo "... done."
fi

if [ ! -d $ANDROID_SDK_ROOT/tools ]; then
	echo "Extracting Android SDK Tools ..."
	mkdir -p $ANDROID_SDK_ROOT/tmp
	cd $ANDROID_SDK_ROOT
	unzip -q /tmp/vagrant-cache/sdk-tools-linux.zip
	echo "... done."
fi

# Silence a warning
mkdir -p $HOME/.android
touch $HOME/.android/repositories.cfg
#mkdir -p $ANDROID_EMULATOR_HOME
#touch $ANDROID_EMULATOR_HOME/repositories.cfg

# Make the SDK Manager use the host disk as temporary download space, so we
# don't run out disk space on the VM
export _JAVA_OPTIONS="-Djava.io.tmpdir=${ANDROID_SDK_ROOT}/tmp"
echo "" >> $HOME/.bashrc
echo "export _JAVA_OPTIONS=\"-Djava.io.tmpdir=${ANDROID_SDK_ROOT}/tmp\"" >> $HOME/.bashrc

echo "Accepting licenses ..."
yes | $ANDROID_SDK_ROOT/tools/bin/sdkmanager --licenses > /dev/null
#echo "Updating Android SDK Tools ..."
# Commented out because the Tools after the update don't seem to have the `sdkmanager` binary anymore (!?)
#$ANDROID_SDK_ROOT/tools/bin/sdkmanager --update
echo "Downloading and installing NDK ..."
$ANDROID_SDK_ROOT/tools/bin/sdkmanager "ndk-bundle"
echo "Downloading and installing Android SDK Platform ${PLATFORM_VERSION}"
$ANDROID_SDK_ROOT/tools/bin/sdkmanager "platforms;android-${PLATFORM_VERSION}"
echo "Downloading and installing Android SDK Platform-Tools"
$ANDROID_SDK_ROOT/tools/bin/sdkmanager "platform-tools"
echo "Downloading and installing Android SDK Build-Tools ${BUILD_TOOLS_VERSION}"
$ANDROID_SDK_ROOT/tools/bin/sdkmanager "build-tools;${BUILD_TOOLS_VERSION}"
echo "Downloading and installing Google APIs System Image for ${EMU_ABI} ABI"
$ANDROID_SDK_ROOT/tools/bin/sdkmanager "${ANDROID_SYSTEM_IMAGE}"
echo "Creating Nexus 5X API ${EMU_API} ${EMU_ABI} Android Virtual Device (AVD)"
$ANDROID_SDK_ROOT/tools/bin/avdmanager create avd --tag "${EMU_TAG}" --package "${ANDROID_SYSTEM_IMAGE}" --name "Nexus_5X_API_${EMU_API}_${EMU_ABI}" --abi $EMU_ABI --device "Nexus 5X"

# Install Android Emulator dependencies
sudo apt-get -y -q install libpulse0 libglu1-mesa

# Create local.properties with the right values
echo "ndk.dir=${ANDROID_SDK_ROOT}/ndk-bundle" > /vagrant/android/local.properties
echo "sdk.dir=${ANDROID_SDK_ROOT}" >> /vagrant/android/local.properties

# Add SDK Tools to the PATH
echo "" >> $HOME/.bashrc
echo "# Add Android SDK Tools binaries to the PATH" >> $HOME/.bashrc
echo "export PATH=\$PATH:${ANDROID_SDK_ROOT}/tools/bin:${ANDROID_SDK_ROOT}/tools:${ANDROID_SDK_ROOT}/platform-tools:${ANDROID_SDK_ROOT}/emulator" >> $HOME/.bashrc

# Initialize Gradle
echo "Initializing Gradle Wrapper ..."
export GRADLE_USER_HOME=/vagrant/android/.gradle
cd /vagrant/android
./gradlew -q tasks

echo "./gradlew :app:assembleRelease" >> $HOME/.bash_history
echo "./gradlew :app:assembleDebug" >> $HOME/.bash_history
echo "cd /vagrant/android" >> $HOME/.bash_history
