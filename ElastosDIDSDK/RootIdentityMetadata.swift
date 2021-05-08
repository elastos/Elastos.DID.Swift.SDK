/*
* Copyright (c) 2020 Elastos Foundation
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

public class RootIdentityMetadata: AbstractMetadata {
    private let TAG = NSStringFromClass(RootIdentity.self)
    public let DEFAULT_DID = "defaultDid"
    var id: String?
    
    init(_ id: String?, _ store: DIDStore) {
        self.id = id
        super.init(store)
    }
    
    init(_ id: String) {
        self.id = id
        super.init()
    }
    
    override init() {
        super.init()
    }
    
    func setId(_ id: String) {
        self.id = id
    }
    
    func setDefaultDid(_ did: DID) {
        put(DEFAULT_DID, did.toString())
    }
    
    /// Get the last transaction id.
    func getDefaultDid() throws -> DID? {
        return try DID.valueOf(get(DEFAULT_DID)!)
    }
    
    override func save() {
        if attachedStore {
            do {
                try store?.storeRootIdentityMetadata(id!, self)
            } catch {
                Log.e(TAG, "INTERNAL - error store metadata for DIDStore")
            }
        }
    }
    
    class func parse(_ path: String) throws -> RootIdentityMetadata {
        let data: Data = try path.forReading()
        let dic: [String: String] = try data.dataToDictionary()
        let metadata = RootIdentityMetadata()
        metadata._props = dic
        
        return metadata
    }
}
