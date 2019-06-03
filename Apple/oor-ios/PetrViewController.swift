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

class PetrViewController: UIViewController, UITextFieldDelegate {

    
    @IBOutlet weak var PeTR_Table: UITableView!
    @IBOutlet weak var PeTR_addr_edit: UITextField!
    
    var PeTR_list: [String]?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        PeTR_Table.tableFooterView = UIView(frame: CGRect.zero)
    }
    
    @IBAction func Add_PeTR_Push(_ sender: Any) {
        insertNewPetr()
    }
    
    func showAlert(message:String){
        var alert:UIAlertController? = nil;
        alert = UIAlertController(title: "Error:",message: message, preferredStyle: .alert)
        alert!.addAction(UIAlertAction(title: "Ok", style: .default, handler: nil))
        self.present(alert!, animated: true)
    }
    
    func insertNewPetr(){
        // Some validations
        if PeTR_addr_edit.text!.isEmpty {
            showAlert(message: "Empty IP address")
            return
        }
        
        if !validateIpAddress(ip: PeTR_addr_edit.text!){
            showAlert(message: "Wrong address format")
            return
        }
        
        if PeTR_list!.contains(PeTR_addr_edit.text!){
            showAlert(message: "Address already in the list")
            return
        }
        
        PeTR_list!.append(PeTR_addr_edit.text!)
        let indexPath1 = IndexPath(row: PeTR_list!.count - 1, section: 0)
        PeTR_Table.beginUpdates()
        PeTR_Table.insertRows(at: [indexPath1], with: .automatic)
        PeTR_Table.endUpdates()
        
        PeTR_addr_edit.text = ""
        view.endEditing(true)
    }
    
    
}

extension PetrViewController: UITableViewDelegate, UITableViewDataSource{
    func tableView(_ PeTR_Table: UITableView, numberOfRowsInSection section: Int) -> Int {
        return PeTR_list!.count
    }
    
    func tableView(_ PeTR_Table: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let petrAddressStr = PeTR_list![indexPath.row]
        let cell = PeTR_Table.dequeueReusableCell(withIdentifier: "PetrCell") as! PetrCell
        cell.PetrAddress.text = petrAddressStr
        return cell
    }
    
    func tableView(_ PeTR_Table: UITableView, canEditRowAt indexPath: IndexPath) -> Bool {
        return true
    }
    
    
    func tableView(_ PeTR_Table: UITableView, commit editingStyle: UITableViewCell.EditingStyle, forRowAt indexPath: IndexPath) {
        
        if editingStyle == .delete {
            PeTR_list!.remove(at: indexPath.row)
            
            PeTR_Table.beginUpdates()
            PeTR_Table.deleteRows(at: [indexPath], with: .automatic)
            PeTR_Table.endUpdates()
        }
    }
    
}


