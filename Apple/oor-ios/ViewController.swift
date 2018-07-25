//
//  ViewController.swift
//  oor-ios
//
//  Created by Oriol Marí Marqués on 30/06/2017.
//
//

import UIKit
import Foundation
import NetworkExtension

class ViewController: UIViewController {
    
    // Write here the Bundle Identifier of PacketTunnelProvider.
    let tunnelBundleId = "Replace with oorPacketTunnelProvider bundle identifier"
    
    let defaults = UserDefaults(suiteName: "group.oor")
    
    var vpnManager: NETunnelProviderManager = NETunnelProviderManager()
    
    @IBOutlet weak var connectButton: UIButton!
    
    @IBOutlet weak var statusText: UILabel!

    override func viewDidLoad() {
        super.viewDidLoad()
        initVPNTunnelProviderManager()
        NotificationCenter.default.addObserver(self, selector: #selector(ViewController.VPNStatusDidChange(_:)), name: NSNotification.Name.NEVPNStatusDidChange, object: nil)
    }
    
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        self.navigationController?.navigationBar.tintAdjustmentMode = .normal
        self.navigationController?.navigationBar.tintAdjustmentMode = .automatic
    }
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    
    
    private func initVPNTunnelProviderManager() {
        
        NETunnelProviderManager.loadAllFromPreferences { (savedManagers: [NETunnelProviderManager]?, error: Error?) in
            if let error = error {
                print(error)
            }
            if let savedManagers = savedManagers {
                if savedManagers.count > 0 {
                    self.vpnManager = savedManagers[0]
                }
            }
            
            self.vpnManager.loadFromPreferences(completionHandler: { (error:Error?) in
                if let error = error {
                    print(error)
                }
                
                let providerProtocol = NETunnelProviderProtocol()
                providerProtocol.providerBundleIdentifier = self.tunnelBundleId
                providerProtocol.serverAddress = ""
                self.vpnManager.protocolConfiguration = providerProtocol
                self.vpnManager.localizedDescription = "OpenOverlayRouter"
                self.vpnManager.isEnabled = true
                
                self.vpnManager.saveToPreferences(completionHandler: { (error:Error?) in
                    if let error = error {
                        print(error)
                    } else {
                        print("Save successfully")
                    }
                })
                
                self.VPNStatusDidChange(nil)
                
            })
        }
        if (!(defaults?.bool(forKey: "firstLaunch"))!) {
            performSegue(withIdentifier: "settingsSegue", sender: self)
        }

    }
    
    func VPNStatusDidChange(_ notification: Notification?) {
        print("VPN Status changed:")
        let status = self.vpnManager.connection.status
        switch status {
        case .connecting:
            print("Connecting...")
            connectButton.setTitle("DISCONNECT", for: .normal)
            statusText.text = "OOR is starting"
            statusText.textColor = UIColor.orange
            break
        case .connected:
            print("Connected...")
            connectButton.setTitle("DISCONNECT", for: .normal)
            statusText.text = "OOR is running"
            statusText.textColor = UIColor.green
            break
        case .disconnecting:
            print("Disconnecting...")
            break
        case .disconnected:
            print("Disconnected...")
            connectButton.setTitle("CONNECT", for: .normal)
            statusText.text = "OOR is NOT running"
            statusText.textColor = UIColor.red
            break
        case .invalid:
            print("Invalid")
            break
        case .reasserting:
            print("Reasserting...")
            break
        }
    }
    
    @IBAction func go(_ sender: UIButton, forEvent event: UIEvent) {        
        self.vpnManager.loadFromPreferences { (error:Error?) in
            if let error = error {
                print(error)
            }
            if (sender.title(for: .normal) == "CONNECT") {
                do {
                    try self.vpnManager.connection.startVPNTunnel()
                } catch {
                    print(error)
                }
            } else {
                self.vpnManager.connection.stopVPNTunnel()
            }
        }
    }

    @IBAction func oorWebButton(_ sender: Any) {
        if let url = NSURL(string: "https://www.openoverlayrouter.org") {
            UIApplication.shared.openURL(url as URL)
        }
    }
    
    @IBAction func getHelpButton(_ sender: Any) {
        if let url = NSURL(string: "https://github.com/OpenOverlayRouter/oor/wiki/Mailing-lists") {
            UIApplication.shared.openURL(url as URL)
        }
    }
    
    @IBAction func getAnEIDButton(_ sender: Any) {
        if let url = NSURL(string: "https://www.lisp4.net/beta-network/get-involved") {
            UIApplication.shared.openURL(url as URL)
        }
    }
}
