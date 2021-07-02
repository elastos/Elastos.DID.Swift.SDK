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

/// The object contains the information about the VerifiableCredential object.
/// the information may include the credential transaction information and user
/// defined information.
@objc(CredentialMetadata)
public class CredentialMetadata: AbstractMetadata {
    private let TXID = "txid"
    private let PUBLISHED = "published"
    private let REVOKED = "revoked"
    var id: DIDURL?
    
    /// Default constructor.
    override init() {
        super.init()
    }
    
    /// Constructs a CredentialMetadata with given id.
    /// - Parameter id: a credential id
    init(_ id: DIDURL) {
        self.id = id
        super.init()
    }
    
    /// Constructs a CredentialMetadata with given id and attach with
    /// a DID store.
    /// - Parameters:
    ///   - id: a credential id
    ///   - store: a DIDStore object
    init(_ id: DIDURL, _ store: DIDStore) {
        self.id = id
        super.init(store)
    }

    /// Set the last transaction id of the credential that associated with
    /// this metadata object.
    /// - Parameter txid: a transaction id
    func setTransactionId(_ txid: String) {
        put(TXID, txid)
    }
    
    /// Get the last transaction id of the credential that kept in this metadata
    /// object.
    /// - Returns: the transaction id
    public func getTransactionId() -> String? {
       return get(TXID)
    }
    
    /// Set the publish time of the credential that associated with this
    /// metadata object.
    /// - Parameter timestamp: the publish time
    func setPublishTime(_ timestamp: Date) {
        put(PUBLISHED, timestamp)
    }
    
    /// Get the publish time of the credential that kept in this metadata
    /// object.
    /// - Returns: the published time
    public func getPublishTime() -> Date? {
       return getDate(PUBLISHED, nil)
    }
    
    /// Set the revocation status of the credential that associated with this
    /// metadata object.
    /// - Parameter revoked: the revocation status
    func setRevoked(_ revoked: Bool) {
        put(REVOKED, revoked)
    }
    
    /// Get the revocation status of the credential that kept in this metadata
    /// object.
    /// - Returns: true if credential is revoked, otherwise false
    public func isRevoked() -> Bool {
       return getBoolean(REVOKED, false)
    }
    
    /// Returns a shallow copy of this instance: the property names and values
    /// themselves are not cloned.
    /// - Returns: a shallow copy of this object
    public override func clone() throws -> CredentialMetadata {
        let metaData = CredentialMetadata()
        metaData._store = store
        metaData._props = properties

        return metaData
    }
    
    /// Save this metadata object to the attached store if this metadata
    /// attached with a store.
    override func save() {
        if attachedStore {
            try? store?.storeCredentialMetadata(id!, self)
        }
    }
    
    class func parse(_ path: String) throws -> CredentialMetadata {
        let data: Data = try path.forReading()
        let dic: [String: String] = try data.dataToDictionary()
        let metadata = CredentialMetadata()
        metadata._props = dic
        
        return metadata
    }
    
    class func deserialize(_ content: String) throws -> CredentialMetadata {
        let dic = content.toStringDictionary()
        let metadata = CredentialMetadata()
        metadata._props = dic
        
        return metadata
    }
}
