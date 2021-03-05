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

/// The class defines the implement of DID Metadata.
public class DIDMetadata: AbstractMetadata {
    private let ROOT_IDENTITY = "rootIdentity"
    private let INDEX = "index"
    private let TXID = "txid"
    private let PREV_SIGNATURE = "prevSignature"
    private let SIGNATURE = "signature"
    private let PUBLISHED = "published"
    private let DEACTIVATED = "deactivated"
    
    private var _did: DID?
    
    /// The default constructor for JSON deserialize creator.
    override init() { }
    
    /// Constructs the empty DIDMetadataImpl.
    init(_ did: DID) {
        self._did = did
    }
    
    /// Constructs the empty DIDMetadataImpl with the given store.
    /// - Parameters:
    ///   - store: the specified DIDStore
    init(_ did: DID, _ store: DIDStore) {
        self._did = did
        super.init(store)
    }
    
    var did: DID? {
        get {
            return _did
        }
        set{
            _did  = newValue
        }
    }
    
    var rootIdentityId: String? {
        get {
            return get(ROOT_IDENTITY)
        }
        set{
            put(ROOT_IDENTITY, newValue)
        }
    }
    
    var index: Int? {
        get {
            return getInteger(INDEX)
        }
        set{
            put(INDEX, newValue)
        }
    }
    
    /// Set transaction id into DIDMetadata.
    /// Get the last transaction id.
    var transactionId: String? {
        get {
            return get(TXID)
        }
        set{
            put(TXID, newValue)
        }
    }
    
    /// Set previous signature into DIDMetadata.
    /// Get the document signature from the previous transaction.
    var previousSignature: String? {
        get {
            return get(PREV_SIGNATURE)
        }
        set{
            put(PREV_SIGNATURE, newValue)
        }
    }
    
    /// Set signature into DIDMetadata.
    /// Get the document signature from the lastest transaction.
    var signature: String? {
        get {
            return get(SIGNATURE)
        }
        set{
            put(SIGNATURE, newValue)
        }
    }
    
    /// Set published time into DIDMetadata.
    /// Get the time of the lastest published transaction.
    var published: Date? {
        get {
            return getDate(PUBLISHED)
        }
        set{
            put(PUBLISHED, newValue)
        }
    }
    
    /// Set deactivate status into DIDMetadata.
    /// Get the DID deactivated status.
    var deactivated: Bool {
        get {
            return getBoolean(DEACTIVATED)
        }
        set{
            put(DEACTIVATED, newValue)
        }
    }
    
    public override func clone() {
    // TODO:
    }
    
    override func save() {
        // TODO:
    }
}

/*
@objc(DIDMetadata)
public class DIDMetadata: Metadata {
    private var _deactivated: Bool = false
    private var _transactionId: String?
    private var _aliasName: String?
    private var _prevSignature: String?
    private var _signature: String?
    private var _published: Int?
    private let TXID = RESERVED_PREFIX + "txid"
    private let PREV_SIGNATURE = RESERVED_PREFIX + "prevSignature"
    private let SIGNATURE = RESERVED_PREFIX + "signature"
    private let PUBLISHED = RESERVED_PREFIX + "published"
    private let ALIAS = RESERVED_PREFIX + "alias"
    private let DEACTIVATED = RESERVED_PREFIX + "deactivated"

    @objc
    public required init() {
        super.init()
    }

    /// The name of alias.
    @objc
    public var aliasName: String? {
        return self.get(key: ALIAS) as? String
    }

    /// Set alias for did.
    /// - Parameter alias: The ailas string.
    @objc
    public func setAlias(_ alias: String?) {
        put(key: ALIAS, value: alias as Any)
    }

    /// Get transactionId.
    @objc
    public var transactionId: String? {
        return self.get(key: TXID) as? String
    }

    /// Set transactionId.
    /// - Parameter newValue: The transactionId string.
    @objc
    public func setTransactionId(_ newValue: String?) {
        put(key: TXID, value: newValue as Any)
    }

    /// Get the time of previous signature for did.
    @objc
    public var previousSignature: String? {
       return self.get(key: PREV_SIGNATURE) as? String
    }

    /// Set the time of previous signature for did.
    /// - Parameter newValue: The time of previous signature.
    @objc
    public func setPreviousSignature(_ newValue: String?) {
         put(key: PREV_SIGNATURE, value: newValue as Any)
    }

    /// Get signature.
    @objc
    public var signature: String? {
        return self.get(key: SIGNATURE) as? String
    }

    /// Set signature.
    /// - Parameter newValue: The signature string.
    @objc
    public func setSignature(_ newValue: String?) {
        put(key: SIGNATURE, value: newValue as Any)
    }

    /// Get the time of transaction id for did.
    /// - Returns: The time of transaction.
    @objc
    public func getPublished() -> Date? {
        if let time = self.get(key: PUBLISHED) as? String {
           return DateFormatter.convertToUTCDateFromString(time)
        }

        return nil
    }

    /// Set the time of transaction id for did.
    /// - Parameter timestamp: The time of transaction.
    @objc
    public func setPublished(_ timestamp: Date) {
        let timestampDate = DateFormatter.convertToUTCStringFromDate(timestamp)
        put(key: PUBLISHED, value: timestampDate as Any)
    }

    /// Get did status, deactived or not.
    @objc
    public var isDeactivated: Bool {
        let v =  self.get(key: DEACTIVATED)
        if case Optional<Any>.none = v {
            return false
        }
        else {
            return v as! Bool
        }
    }

    /// Set  did status, deactived or not.
    /// - Parameter newValue: Did status.
    @objc
    public func setDeactivated(_ newValue: Bool) {
        put(key: DEACTIVATED, value: newValue as Any)
    }
}
*/
