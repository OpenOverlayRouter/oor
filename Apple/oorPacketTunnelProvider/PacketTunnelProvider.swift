/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

import NetworkExtension
import Foundation

class PacketTunnelProvider: NEPacketTunnelProvider{
    
    let defaults = UserDefaults(suiteName: "group.oor")
    
    // The completion handler to call when the tunnel is fully established.
    var completionHandler: ((Error?) -> Void)?
    
    // Socket to notify OOR that have packet to encapsulate
    let oor_notify = UDPClient(address: "127.0.0.1", port: 10001)
    
    //Fake VPN server IP address
    var tunSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "0.0.0.0")
    
    //Interface monitoring
    open var currentReachabilityStatus: Int?
    open var newReachabilityStatus: Int?
    var reachability: Reachability?
    
    var oor_callbacks:iOS_CLibCallbacks?
    
    // Start fake tunnel connection
    override func startTunnel(options: [String : NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {
        self.completionHandler = completionHandler
        // Struct defined in C with the call back functions implemented in swift
        oor_callbacks = iOS_CLibCallbacks(
            packetTunnelProviderPtr:UnsafeRawPointer(Unmanaged.passUnretained(self.packetFlow).toOpaque()),
            ptp_write_to_tun: {(buffer, length, afi, ptp_ptr) in
                autoreleasepool {
                    unowned let myself = Unmanaged<NEPacketTunnelFlow>.fromOpaque(ptp_ptr).takeUnretainedValue()
                    let packets = [Data(bytes: buffer, count: Int(length))]
                    let protos: [NSNumber] = [afi as NSNumber]
                    // Here is where the retension is produced
                    myself.writePackets(packets,withProtocols: protos)
                }
        }
        )
        NSLog("===============================================================0");
        //TUN IP address
        let eid = defaults?.string(forKey: "eid")
        if validateIPv4(ip: eid!) {
            tunSettings.ipv4Settings = NEIPv4Settings(addresses: [eid!], subnetMasks: ["255.255.255.255"])
            // Networks to be routed through TUN
            tunSettings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
        } else if validateIPv6(ip: eid!) {
            tunSettings.ipv6Settings = NEIPv6Settings(addresses: [eid!], networkPrefixLengths: [128 as NSNumber])
            // Networks to be routed through TUN, it appears that there is some bug with defualt IPv6 route ::/0, so we define 2 routes with 2 big networks.
            let route1 = NEIPv6Route(destinationAddress: "::", networkPrefixLength: 1)
            let route2 = NEIPv6Route(destinationAddress: "8000::", networkPrefixLength: 1)
            tunSettings.ipv6Settings?.includedRoutes = [route1, route2]
        }

        tunSettings.mtu = 1440
        
        tunSettings.dnsSettings = NEDNSSettings(servers: [(defaults?.string(forKey: "dnsServer"))!])
        
        // Apply settings and create TUN
        setTunnelNetworkSettings(tunSettings) { error in
            if error != nil {
                NSLog("PacketTunnelProvider.startTunnel.setTunnelNetworkSettingsError \(String(describing: error))")
                completionHandler(error)
            }
            // Tell to the system that the fake VPN is "up"
            completionHandler(nil)
        }

        // Start OOR
        let myThread = Thread(target: self, selector: #selector(self.startOOR), object: nil)
        myThread.start()
    }
    
    @objc func startOOR() {
        let fileManager = FileManager.default

        let logFileSharedURL = fileManager.containerURL(forSecurityApplicationGroupIdentifier: "group.oor")?.appendingPathComponent("oor.log")
        
        
        if 	let logFileSharedURLpath = logFileSharedURL?.path {
            setLogPath((logFileSharedURLpath as NSString).utf8String)
        }
        let configFileSharedURL = fileManager.containerURL(forSecurityApplicationGroupIdentifier: "group.oor")?.appendingPathComponent("oor.conf")
        
        if let configFileSharedPath = configFileSharedURL?.path {
            setConfPath((configFileSharedPath as NSString).utf8String)
        }
        
        oor_start()
        iOS_init_out_packet_buffer()
        iOS_init_semaphore()
        iOS_CLibCallbacks_setup(&oor_callbacks!)
        //Start monitoring network changes
        reach()
        
        // Start handling outgoing packets coming from the TUN
        startHandlingPackets()
        
        // Start main loop
        oor_loop()
    }
    
    /// Start handling outgoing packets coming from the TUN
    func startHandlingPackets() {
        // Read outgoing packets coming from the TUN
        self.packetFlow.readPackets { inPackets, inProtocols in
            self.handlePackets(inPackets, protocols: inProtocols)
        }
    }
    
    /// Handle outgoing packets coming from the TUN.
    func handlePackets(_ packets: [Data], protocols: [NSNumber]) {
        for packet in packets {
            let nsData = packet as NSData
            let rawPtr = nsData.bytes
            oor_ptp_read_from_tun(rawPtr,Int32(nsData.length))
            oor_notify.send(string: "1")
        }
        // Read more outgoing packets coming from the TUN
        self.packetFlow.readPackets { inPackets, inProtocols in
            self.handlePackets(inPackets, protocols: inProtocols)
        }
    }
    
    /// Handle incoming packets coming from the TUN.
    func newOORInPackets(packets: [Data]) {
        var protocolArray = [NSNumber]()
        for _ in packets { protocolArray.append(0x02) }
        // Write incoming packets coming from OOR to TUN
        self.packetFlow.writePackets(packets, withProtocols: protocolArray)
    }
    
    
    // Start monitoring network changes
    func reach() {
        let reachability: Reachability?

        reachability = Reachability()
   
        self.reachability = reachability
 
        NotificationCenter.default.addObserver(self, selector: #selector(reachabilityChanged(_:)), name: .reachabilityChanged, object: reachability)
        
        if reachability?.connection == .none {
            currentReachabilityStatus = 0
            NSLog("REACHABILITY: setup none")
        } else if reachability?.connection == .cellular {
            currentReachabilityStatus = 1
            NSLog("REACHABILITY: setup CELLULAR")
        } else if reachability?.connection == .wifi {
            currentReachabilityStatus = 2
            NSLog("REACHABILITY: setup WIFI")
        }
        do {
            try reachability?.startNotifier()
        } catch {
            NSLog("Unable to start notifier")
        }
        
    }
    
    @objc func reachabilityChanged(_ note: Notification) {
        let reachability = note.object as! Reachability
        
        if reachability.connection == .none {
            newReachabilityStatus = 0
            NSLog("REACHABILITY: none")
        } else if reachability.connection == .cellular {
            NSLog("REACHABILITY: CELLULAR")
            newReachabilityStatus = 1
        } else if reachability.connection == .wifi {
            newReachabilityStatus = 2
            NSLog("REACHABILITY: WIFI")
        }

        if (currentReachabilityStatus != newReachabilityStatus && newReachabilityStatus != 0 && self.reasserting == false){
            self.reasserting = true
            setTunnelNetworkSettings(tunSettings) { error in
                if error != nil {
                    NSLog("PacketTunnelProvider.reachabilityChanged.setTunnelNetworkSettingsError \(String(describing: error))")
                }
                // Tell to the system that the VPN is "up"
                self.completionHandler!(nil)
                self.reasserting = false
            }
        }
        currentReachabilityStatus = newReachabilityStatus
    }
    
    func validateIPv4(ip: String) -> Bool {
        var sin = sockaddr_in()
        if ip.withCString({ cstring in inet_pton(AF_INET, cstring, &sin.sin_addr) }) == 1 {
            // IPv4 peer.
            return true
        }
        return false
    }
    
    func validateIPv6(ip: String) -> Bool {
        var sin6 = sockaddr_in6()
        if ip.withCString({ cstring in inet_pton(AF_INET6, cstring, &sin6.sin6_addr) }) == 1 {
            // IPv6 peer.
            return true
        }
        return false
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        // Add code here to start the process of stopping the tunnel.
        oor_stop()
        iOS_end_semaphore()
        completionHandler()
    }
     
     func handleAppMessage(messageData: NSData, completionHandler: ((NSData?) -> Void)?) {
     // Add code here to handle the message.
     if let handler = completionHandler {
     handler(messageData)
     }
     }
     
     func sleepWithCompletionHandler(completionHandler: () -> Void) {
     // Add code here to get ready to sleep.
     completionHandler()
     }
     
     override func wake() {
     // Add code here to wake up.
     }
}
