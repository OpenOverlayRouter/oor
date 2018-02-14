#!/bin/bash
set -e
unset -v _JAVA_OPTIONS

# Build OOR Android .apk
echo "Building OOR Android .apk ..."
#export GRADLE_USER_HOME=/vagrant/android/.gradle
cd /vagrant/android
./gradlew --console=plain --quiet :app:assembleDebug
mv app/build/outputs/apk/debug/app-debug.apk $HOME/oor.apk
