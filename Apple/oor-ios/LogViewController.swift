//
//  File.swift
//  oor-ios
//
//  Created by Oriol Marí Marqués on 24/07/2018.
//

import Foundation
import UIKit
import MessageUI

class LogViewController: UIViewController, MFMailComposeViewControllerDelegate {
    @IBOutlet weak var textView: UITextView!
    
    @IBAction func refreshButton(_ sender: Any) {
        printLog()
    }
    
    @IBAction func sendButton(_ sender: Any) {
        sendEmail()
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        printLog()
    }
    
    func sendEmail() {
        if MFMailComposeViewController.canSendMail() {
            let mail = MFMailComposeViewController()
            mail.mailComposeDelegate = self
            let file = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.oor")?.appendingPathComponent("oor.log")
            if let fileData = NSData(contentsOfFile: (file?.path)!) {
                print("ORIOOLL")
                mail.addAttachmentData(fileData as Data, mimeType: "text", fileName: "oor.log")
            }
            present(mail, animated: true)
        }
    }
    
    func mailComposeController(_ controller: MFMailComposeViewController, didFinishWith result: MFMailComposeResult, error: Error?) {
        controller.dismiss(animated: true)
    }
    
    func printLog() {
        let file = "oor.log" //this is the file. we will write to and read from it
        if let dir = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.oor") {
            let fileURL = dir.appendingPathComponent(file)
            //reading
            do {
                textView.text = try String(contentsOf: fileURL, encoding: .utf8)
            }
            catch {
                NSLog("ERROR \(error)")
            }
        }
        textView.scrollRangeToVisible(NSMakeRange(textView.text.count - 1, 1))
    }
    
}
