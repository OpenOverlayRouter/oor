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

import UIKit
import Foundation
import NetworkExtension

class ViewController: UIViewController {
    
    // Write here the Bundle Identifier of PacketTunnelProvider.
    let tunnelBundleId = "org.openoverlayrouter.ptp"
    
    let defaults = UserDefaults(suiteName: "group.oor")
    
    var vpnManager: NETunnelProviderManager = NETunnelProviderManager()
    
    @IBOutlet weak var connectButton: UIButton!
    
    @IBOutlet weak var statusText: UILabel!

    override func viewDidLoad() {
        super.viewDidLoad()
        initVPNTunnelProviderManager()
        NotificationCenter.default.addObserver(self, selector:#selector(ViewController.VPNStatusDidChange(_:)), name: NSNotification.Name.NEVPNStatusDidChange, object: nil)
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
    
    @objc func VPNStatusDidChange(_ notification: Notification?) {
        print("VPN Status changed:")
        let status = self.vpnManager.connection.status
        switch status {
        case .connecting:
            print("Connecting...")
            connectButton.setTitle("DISCONNECT", for: .normal)
            statusText.text = "Starting OOR"
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
            statusText.text = "Stopping OOR"
            statusText.textColor = UIColor.orange
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
            UIApplication.shared.open(url as URL, options: [:], completionHandler: nil)
        }
    }
    
    @IBAction func getHelpButton(_ sender: Any) {
        if let url = NSURL(string: "https://github.com/OpenOverlayRouter/oor/wiki/Mailing-lists") {
            UIApplication.shared.open(url as URL, options: [:], completionHandler: nil)
        }
    }
}
