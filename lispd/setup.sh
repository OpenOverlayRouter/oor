#!/bin/sh
adb root
sleep 5
adb shell mount -o rw,remount /system
#adb shell busybox ifconfig lo:1 153.16.21.33 netmask 255.255.255.255
#adb shell busybox ip route add 204.69.200.7/32 via 192.168.0.1
#adb shell busybox ip route del default
#adb shell busybox ip route add default via 192.168.0.1 dev eth0 src 153.16.21.33
