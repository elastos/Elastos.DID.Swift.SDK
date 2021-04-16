/*
* Copyright (c) 2021 Elastos Foundation
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

import Foundation

public class DIDResolveResponse: ResolveResponse {
    
    init(_ responseId: String, _ result: DIDBiography) {
        super.init(responseId, result)
    }
    
    override init(_ responseId: String, _ code: Int, _ message: String) {
        super.init(responseId, code, message)
    }
    
    class func parse(_ input: Data) throws -> DIDResolveResponse {
        let json: [String: Any] = try input.dataToDictionary()
        let id = "\(String(describing: json["id"]))"
        let result: [String: Any]? = json["result"] as? [String: Any]
        let err: [String: Any]? = json["error"] as? [String: Any]
        if let _ = result {
            let did = result!["did"] as! String
            var stau = DIDBiographyStatus.STATUS_VALID
            switch "\(String(describing: result!["status"]))" {
            case "0":
                stau = DIDBiographyStatus.STATUS_VALID
            case "1":
                stau = DIDBiographyStatus.STATUS_EXPIRED
            case "2":
                stau = DIDBiographyStatus.STATUS_DEACTIVATED
            case "3":
                stau = DIDBiographyStatus.STATUS_NOT_FOUND
            default:
                stau = DIDBiographyStatus.STATUS_NOT_FOUND
            }
            return DIDResolveResponse(id, DIDBiography(try DID(did), stau))
        }
        else {
            let code = "\(String(describing: err!["code"]))"
            let message = "\(String(describing: err!["message"]))"

            return DIDResolveResponse(id, try Int(value: code), message)
        }
    }
}
