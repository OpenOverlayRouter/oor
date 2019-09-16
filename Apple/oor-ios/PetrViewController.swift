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
    @IBOutlet weak var priority_edit: UITextField!
    
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
        var priority = 1
        // Some validations
        if PeTR_addr_edit.text!.isEmpty {
            showAlert(message: "Empty IP address")
            return
        }
        
        if !validateIpAddress(ip: PeTR_addr_edit.text!){
            showAlert(message: "Wrong address format")
            return
        }
        
        if !priority_edit.text!.isEmpty{
            priority = Int(priority_edit.text!)!
            if (priority < 1 || priority > 255){
                showAlert(message: "Wrong priority value")
                return
            }
        }
        let petr_info = "\(PeTR_addr_edit.text!),\(priority)"

        var aux_petr = String()
        for index in 0..<PeTR_list!.count {
            aux_petr = "\(PeTR_addr_edit.text!),"
            if (PeTR_list![index].hasPrefix(aux_petr)){
                PeTR_Table.beginUpdates()
                PeTR_list![index] = petr_info
                PeTR_Table.endUpdates()
                PeTR_addr_edit.text = ""
                priority_edit.text = "1"
                PeTR_Table.reloadData()
                view.endEditing(true)
                return
                
            }
        }
        
                PeTR_list!.append(petr_info)
        let indexPath1 = IndexPath(row: PeTR_list!.count - 1, section: 0)
        PeTR_Table.beginUpdates()
        PeTR_Table.insertRows(at: [indexPath1], with: .automatic)
        PeTR_Table.endUpdates()
        
        PeTR_addr_edit.text = ""
        priority_edit.text = "1"
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
        let camps = petrAddressStr.components(separatedBy: ",")
        var petr_info = String()
        if (camps.count == 2){
            petr_info = "\(camps[0])   p: \(camps[1])"
        }else{
            petr_info = "\(camps[0])   p: 1)"
        }
        cell.PetrAddress.text = petr_info
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
    
    func tableView(_ PeTR_Table: UITableView, didSelectRowAt indexPath: IndexPath) {
        let petrAddressStr = PeTR_list![indexPath.row]
        let camps = petrAddressStr.components(separatedBy: ",")
        PeTR_addr_edit.text = camps[0]
        if (camps.count == 2){
            priority_edit.text = camps[1]
        }else{
            priority_edit.text = "1"
        }
    }
    
}


