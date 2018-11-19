//
//  PacketTunnelProvider.swift
//  PacketTunnelProvider
//
//  Created by Oriol Marí Marqués on 17/11/2016.
//  Copyright © 2016 Oriol Marí Marqués. All rights reserved.
//

import NetworkExtension
import Foundation

class PacketTunnelProvider: NEPacketTunnelProvider {
    
    let defaults = UserDefaults(suiteName: "group.oor")
    
    // The completion handler to call when the tunnel is fully established.
    var completionHandler: ((Error?) -> Void)?
    
    // Socket to handle outgoing packets from OOR, get packets from oor
    open var oorOut: NWUDPSession?
    
    //Socket to handle interface change
    open var oorNetm: NWUDPSession?
    
    //Fake VPN server IP address
    var tunSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "0.0.0.0")
    
    //Interface monitoring
    open var currentReachabilityStatus: Int?
    open var newReachabilityStatus: Int?
    var reachability: Reachability?
    
    // Start fake tunnel connection
    override func startTunnel(options: [String : NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {
                
        self.completionHandler = completionHandler

        //TUN IP address
        let eid = defaults?.string(forKey: "eid")
        if validateIPv4(ip: eid!) {
            tunSettings.iPv4Settings = NEIPv4Settings(addresses: [eid!], subnetMasks: ["255.255.255.255"])
            // Networks to be routed through TUN
            tunSettings.iPv4Settings?.includedRoutes = [NEIPv4Route.default()]
        } else if validateIPv6(ip: eid!) {
            tunSettings.iPv6Settings = NEIPv6Settings(addresses: [eid!], networkPrefixLengths: [128])
            // Networks to be routed through TUN, it appears that there is some bug with defualt IPv6 route ::/0, so we define 2 routes with 2 big networks.
            let route1 = NEIPv6Route(destinationAddress: "::", networkPrefixLength: 1)
            let route2 = NEIPv6Route(destinationAddress: "8000::", networkPrefixLength: 1)
            tunSettings.iPv6Settings?.includedRoutes = [route1, route2]
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
        
        //Start monitoring network changes
        reach()
        
        // Start handling outgoing packets coming from the TUN
        startHandlingPackets()
        
    }
    
    func startOOR() {
        let fileManager = FileManager.default

        let logFileSharedURL = fileManager.containerURL(forSecurityApplicationGroupIdentifier: "group.oor")?.appendingPathComponent("oor.log")
        
        setLogPath((logFileSharedURL?.path as! NSString).utf8String)
        
        let configFileSharedURL = fileManager.containerURL(forSecurityApplicationGroupIdentifier: "group.oor")?.appendingPathComponent("oor.conf")
        
        setConfPath((configFileSharedURL?.path as! NSString).utf8String)
        
        oor_start()
        
        var endpoint: NWEndpoint
        let packetTunnelProviderAddress = NWHostEndpoint(hostname: "127.0.0.1", port: "10001")
        
        // Connect to OOR Data output Socket
        endpoint = NWHostEndpoint(hostname: "127.0.0.1", port: "10000")
        oorOut = self.createUDPSession(to: endpoint, from: packetTunnelProviderAddress)
        
        // Start listeing incoming packets coming from OOR
        oorOut?.setReadHandler({dataArray, error in
            if error != nil {
                NSLog("PacketTunnelProvider.startOOR.oorOut.setReadhandler ERROR \(String(describing: error))")
            }
            self.newOORInPackets(packets: dataArray!)
        }, maxDatagrams: 1)
        
        oor_loop()
    }
    
    /// Start handling outgoing packets coming from the TUN
    func startHandlingPackets() {
        // Read outgoing packets coming from the TUN
        packetFlow.readPackets { inPackets, inProtocols in
            self.handlePackets(inPackets, protocols: inProtocols)
        }
    }
    
    /// Handle outgoing packets coming from the TUN.
    func handlePackets(_ packets: [Data], protocols: [NSNumber]) {
        for packet in packets {
            oorOut?.writeDatagram(packet) { error in
                if error != nil {
                    NSLog("handlePackets: oorOut.writeDatagram error: \(String(describing: error))")
                }
            }
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
        packetFlow.writePackets(packets, withProtocols: protocolArray)
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
        let client = UDPClient(address: "127.0.0.1", port: 10002)

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
        
        if currentReachabilityStatus != newReachabilityStatus {
            self.reasserting = true
            
            if newReachabilityStatus == 1 {
                client.send(string: "1")
            } else if newReachabilityStatus == 2 {
                client.send(string: "2")
            }
            setTunnelNetworkSettings(tunSettings) { error in
                if error != nil {
                    NSLog("PacketTunnelProvider.reachabilityChanged.setTunnelNetworkSettingsError \(String(describing: error))")
                }
                // Tell to the system that the VPN is "up"
                self.completionHandler!(nil)
            }
        self.reasserting = false        }
        client.close()
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
