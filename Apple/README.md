# OpenOverlayRouter on Apple

OOR-APPLE is the OpenOverlayRouter version for Apple macOS and iOS. We are using the official OOR code as base https://github.com/OpenOverlayRouter/oor. iOS version is working in an early state, there are a lot of code improvements to do and things to implement. Mac OS version is not working.

## Requirements

Compiling and running OOR on iOS requires the following:

- Mac running  macOS High Sierra 10.13.1
- Xcode 9.2
- An iPhone running iOS 11.2.2. **Is not possible to run OOR on simulator.**
- An Apple Developer Account that belongs to Apple Developer Program (**paid account**).

*We can't guarantee that OOR-iOS works with versions other than those listed.*

## Compile and run

1. Clone this repo.
2. Open xcode project located at oor/Apple/oor-apple.xcodeproj
3. Setup the *Bundle Identifier* and *Team* for **oor-ios** and  **oorPacketTunnelProvider** targets.
4. Define the constant **tunnelBundleId** in *oor-ios/ViewController.swift*
5. Be sure that you select oor-ios and your iPhone device in "active scheme" dropdown.
6. Click build and run button.
7. Enjoy!

Here you can see how to build and run it:

https://www.youtube.com/watch?v=z1LiZ7MFJRk


