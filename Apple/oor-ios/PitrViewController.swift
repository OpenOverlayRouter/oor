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
import SafariServices

class PitrViewController: UIViewController, UITextFieldDelegate	 {

    @IBOutlet weak var PiTR_Table: UITableView!
    @IBOutlet weak var PiTR_addr: UITextField!
    
    var PiTR_list: [String]?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        PiTR_Table.tableFooterView = UIView(frame: CGRect.zero)
        
    }
    
    

    @IBAction func addPitrPush(_ sender: Any) {
        insertNewPitr()
    }    
    
    func showAlert(message:String){
        var alert:UIAlertController? = nil;
        alert = UIAlertController(title: "Error:",message: message, preferredStyle: .alert)
        alert!.addAction(UIAlertAction(title: "Ok", style: .default, handler: nil))
        self.present(alert!, animated: true)
    }
    
    func insertNewPitr(){
        // Some validations
        if PiTR_addr.text!.isEmpty {
            showAlert(message: "Empty IP address")
            return
        }
        
        if !validateIpAddress(ip: PiTR_addr.text!){
            showAlert(message: "Wrong address format")
            return
        }
        
        if PiTR_list!.contains(PiTR_addr.text!){
            showAlert(message: "Address already in the list")
            return
        }
        
        PiTR_list!.append(PiTR_addr.text!)
        let indexPath = IndexPath(row: PiTR_list!.count - 1, section: 0)
        PiTR_Table.beginUpdates()
        PiTR_Table.insertRows(at: [indexPath], with: .automatic)
        PiTR_Table.endUpdates()
        
        PiTR_addr.text = ""
        view.endEditing(true)
    }
    

}

extension PitrViewController: UITableViewDelegate, UITableViewDataSource{
    func tableView(_ PiTR_Table: UITableView, numberOfRowsInSection section: Int) -> Int {
        return PiTR_list!.count
    }
    
    func tableView(_ PiTR_Table: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let pitrAddressStr = PiTR_list![indexPath.row]
        let cell = PiTR_Table.dequeueReusableCell(withIdentifier: "PitrCell") as! PitrCell
        cell.PitrAddress.text = pitrAddressStr
        return cell
    }
    
    func tableView(_ PiTR_Table: UITableView, canEditRowAt indexPath: IndexPath) -> Bool {
        return true
    }
    
    
    func tableView(_ PiTR_Table: UITableView, commit editingStyle: UITableViewCell.EditingStyle, forRowAt indexPath: IndexPath) {
        
        if editingStyle == .delete {
            PiTR_list!.remove(at: indexPath.row)
            
            PiTR_Table.beginUpdates()
            PiTR_Table.deleteRows(at: [indexPath], with: .automatic)
            PiTR_Table.endUpdates()
        }
    }
    
}

