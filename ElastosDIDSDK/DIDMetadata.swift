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

/// The object contains the information about the DID object.
/// the information may include the DID transaction information and user defined information.
public class DIDMetadata: AbstractMetadata {
    private let TAG = NSStringFromClass(DIDMetadata.self)
    private let ROOT_IDENTITY = "rootIdentity"
    private let INDEX = "index"
    private let TXID = "txid"
    private let PREV_SIGNATURE = "prevSignature"
    private let SIGNATURE = "signature"
    private let PUBLISHED = "published"
    private let DEACTIVATED = "deactivated"
    
    private var did: DID?
    
    /// Default constructor.
    override init() {
        super.init()
    }
    
    /// Constructs a CredentialMetadata with given did.
    /// - Parameter did: a DID object
    init(_ did: DID) {
        self.did = did
        super.init()
    }
    
    /// Constructs a DIDMetadata with given did and attach with a DID store.
    /// - Parameters:
    ///   - did: a DID object
    ///   - store: a DIDStore object
    init(_ did: DID, _ store: DIDStore) {
        self.did = did
        super.init(store)
    }
    
    /// Set the DID of this metadata object.
    /// - Parameter did: a credential id
    func setDid(_ did: DID) {
        self.did = did
    }
    
    /// Set the root identity id that the DID derived from, if the DID
    /// is derived from a root identity.
    /// - Parameter id: a root identity id
    func setRootIdentityId(_ id: String) {
        put(ROOT_IDENTITY, id)
    }
    
    /// Get the root identity id that the DID derived from.
    /// nil if the DID is not derived from a root identity.
    /// - Returns: the root identity id
    func getRootIdentityId() -> String? {
        return get(ROOT_IDENTITY)
    }
    
    /// Set the derived index if the DID is derived from a root identity.
    /// - Parameter index: a derive index
    func setIndex(_ index: Int) {
        put(INDEX, index)
    }
    
    /// Get the derived index only if the DID is derived from a root identity.
    /// - Returns: a derive index
    func getIndex() -> Int {
        return getInteger(INDEX)!
    }
    
    /// Set the last transaction id of the DID that associated with
    /// this metadata object.
    /// - Parameter txid: a transaction id
    func setTransactionId(_ txid: String) {
        put(TXID, txid)
    }
    
    /// Get the last transaction id of the DID that kept in this metadata
    /// object.
    /// - Returns: the transaction id
    func getTransactionId() -> String {
        return get(TXID)!
    }
    
    /// Set the previous signature of the DID document that associated with this
    /// metadata object.
    /// - Parameter signature: the signature string
    func setPreviousSignature(_ signature: String) {
        put(PREV_SIGNATURE, signature)
    }
    
    /// Get the previous document signature from the previous transaction.
    /// - Returns: the signature string
    func getPreviousSignature() -> String {
        return get(PREV_SIGNATURE)!
    }
    
    /// Set the latest signature of the DID document that associated with this
    /// metadata object.
    /// - Parameter signature: the signature string
    func setSignature(_ signature: String) {
        put(SIGNATURE, signature)
    }
    
    /// Get the signature of the DID document that kept in this metadata object.
    /// - Returns: the signature string
    func getSignature() -> String {
        return get(SIGNATURE)!
    }
    
    /// Set the publish time of the DID that associated with this
    /// metadata object.
    /// - Parameter timestamp: the publish time
    func setPublishTime(_ timestamp: Date) {
        put(PUBLISHED, timestamp)
    }
    
    /// Get the publish time of the DID that kept in this metadata
    /// object.
    /// - Returns: the published time
    func getPublishTime() -> Date? {
        return getDate(PUBLISHED)
    }
    
    /// Set the deactivated status of the DID that associated with this
    /// metadata object.
    /// - Parameter deactivated: the deactivated status
    func setDeactivated(_ deactivated: Bool) {
        put(DEACTIVATED, deactivated)
    }
    
    /// Get the deactivated status of the DID that kept in this metadata
    /// object.
    /// true if DID is deactivated, otherwise false
    public var isDeactivated: Bool {
        return getBoolean(DEACTIVATED)
    }
    
    /// Returns a shallow copy of this instance: the property names and values
    /// themselves are not cloned.
    /// - Returns: a shallow copy of this object
    public override func clone() throws -> DIDMetadata {
        // TODO:
        return try super.clone()
    }
    
    /// Save this metadata object to the attached store if this metadata
    /// attached with a store.
    override func save() {
        if attachedStore {
            do {
                try store?.storeDidMetadata(did!, self)
            } catch {
                Log.e(TAG, "INTERNAL - error store metadata for DIDStore")
            }
        }
    }
}
