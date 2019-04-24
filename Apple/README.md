# OpenOverlayRouter on Apple iOS

Open Overlay Router includes support for Apple iOS devices operating as LISP mobile
nodes (LISP-MN). The application is limited to one single EID (IPv4 or IPv6) mapped to one
or more RLOC interfaces (IPv4). Even though several interfaces can be managed by Open Overlay
Router at the same time, they can only be used in an active-backup fashion (no more
than one interface used at once).
You can install the application from the Apple Store:
    https://itunes.apple.com/us/app/openoverlayrouter/id1454649703?mt=8

Or you can follow next steps to compile the application from source code.

## Requirements

Compiling and running OOR on iOS requires the following:

- Mac running  macOS High Sierra 10.13.5
- Xcode 9.4.1
- An iPhone running iOS 11.3.1. **Is not possible to run OOR on simulator.**
- An Apple Developer Account that belongs to Apple Developer Program (**paid account**).

*We can't guarantee that OOR-iOS works with versions other than those listed.*

## Compile and run

1. Clone this repo.
2. Open xcode project located at oor/Apple/oor-apple.xcodeproj
3. Setup the *Bundle Identifier* and *Team* for **oor-ios** and  **oorPacketTunnelProvider** targets.
4. Define the constant **tunnelBundleId** in *oor/Apple/oor-ios/ViewController.swift*
5. Be sure that you select oor-ios and your iPhone device in "active scheme" dropdown.
6. Click build and run button.
7. Enjoy!

Here you can see how to build and run it:

https://www.youtube.com/watch?v=z1LiZ7MFJRk


