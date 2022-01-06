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

public class CredentialList: ResolveResult {
    static let DID = "did"
    static let CREDENTIALS = "credentials"

    static let DEFAULT_SIZE = 128
    static let MAX_SIZE = 256

    private var _did: DID
    private var _credentialIds: [DIDURL] = [ ]
    
    init(_ did: DID) {
        self._did = did
    }
    
    public var did: DID {
        return _did
    }
    
    public var count: Int {
        return credentialIds.count
    }
    
    public func getCredentialId(_ index: Int) -> DIDURL {
        return credentialIds[index]
    }
    
    public var credentialIds: [DIDURL] {
        return _credentialIds
    }
    
    public func appendCredentialId(_ id: DIDURL) {
        _credentialIds.append(id)
    }
    
    override func sanitize() throws {
        
    }
    
    class func deserialize(_ json: [String: Any]) throws -> CredentialList {
        let didString = "\(json["did"]!)"
        let credentials = json["credentials"] != nil ? json["credentials"] as! [String] : [ ]
        let did = try ElastosDIDSDK.DID(didString)
        let cre = CredentialList(did)
        try credentials.forEach { did in
            try cre._credentialIds.append(DIDURL(did))
        }
        
        return cre
    }
}
