#!/bin/bash
set -e
unset -v _JAVA_OPTIONS

# Run the Android Emulator with the AVD created in the SDK install script
cd $ANDROID_SDK_ROOT/tools
emulator -avd Nexus_5X_API_27_x86 -no-accel -no-audio -no-window -no-snapshot -netdelay none -netspeed full &
#while [ "`adb shell getprop init.svc.bootanim | tr -d '\r' `" != "stopped" ] ; do sleep 1; done
#adb shell getprop init.svc.bootanim
