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
import PromiseKit

public class RootIdentity: NSObject {
    private let TAG = NSStringFromClass(RootIdentity.self)
    var mnemonic: String?
    var rootPrivateKey: DIDHDKey?
    var preDerivedPublicKey: DIDHDKey
    var index: Int // todo:

    var id: String?
    var metadata: RootIdentityMetadata?
    
    init(_ mnemonic: String, _ passphrase: String) throws {
        self.mnemonic = mnemonic
        let lang = try Mnemonic.getLanguage(mnemonic)
        self.rootPrivateKey = DIDHDKey(mnemonic, passphrase, lang)
        self.preDerivedPublicKey = try rootPrivateKey!.derive(DIDHDKey.DID_PRE_DERIVED_PUBLICKEY_PATH)
        self.index = 0
    }
    
    init(_ rootPrivateKey: DIDHDKey) throws {
        self.rootPrivateKey = rootPrivateKey
        self.preDerivedPublicKey = try rootPrivateKey.derive(DIDHDKey.DID_PRE_DERIVED_PUBLICKEY_PATH)
        self.index = 0
    }
    
    init(_ preDerivedPublicKey: DIDHDKey, _ index: Int) throws {
        self.preDerivedPublicKey = preDerivedPublicKey
        self.index = index
    }
    
    /// Initialize private identity by mnemonic.
    /// - Parameters:
    ///   - mnemonic: the mnemonic string
    ///   - passphrase: the password for mnemonic to generate seed
    ///   - storePassword: the password for DIDStore
    public static func create(_ mnemonic: String, _ passphrase: String?, _ overwrite: Bool, _ store: DIDStore, _ storePassword: String) throws -> RootIdentity {
        try checkArgument(!mnemonic.isEmpty, "Invalid mnemonic")
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        let _passphrase = passphrase == nil ? "" : passphrase
        try checkArgument(Mnemonic.isValid(Mnemonic.getLanguage(mnemonic), mnemonic), "Invalid mnemonic.")
        
        let identity = try RootIdentity(mnemonic, _passphrase!)
        if try store.containsRootIdentity(identity.getId()) && !overwrite {
            throw DIDError.UncheckedError.IllegalStateError.RootIdentityAlreadyExistError(identity.id)
        }
        identity.metadata = RootIdentityMetadata(identity.id!, store)
        try store.storeRootIdentity(identity, storePassword)
        try identity.wipe()
        
        return identity
    }
    
    public static func create(_ mnemonic: String, _ passphrase: String?, _ store: DIDStore, _ storePassword: String) throws -> RootIdentity {
        return try create(mnemonic, passphrase, false, store, storePassword)
    }
    
    public static func create(_ extentedPrivateKey: String, _ overwrite: Bool, _ store: DIDStore, _ storePassword: String) throws -> RootIdentity {
        try checkArgument(!extentedPrivateKey.isEmpty, "Invalid extended private key")
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        let rootPrivateKey = DIDHDKey.deserializeBase58(extentedPrivateKey)
        let identity = try RootIdentity(rootPrivateKey)
        
        if try identity.id != nil && store.containsRootIdentity(identity.id!) && !overwrite {
            throw DIDError.UncheckedError.IllegalStateError.RootIdentityAlreadyExistError(identity.id)
        }
        identity.metadata = RootIdentityMetadata(identity.id, store)
        try! store.storeRootIdentity(identity, storePassword)
        try identity.wipe()
        
        return identity
    }
    
    public static func create(_ extentedPrivateKey: String, _ store: DIDStore, _ storePassword: String) throws -> RootIdentity {
        return try create(extentedPrivateKey, false, store, storePassword)
    }
    
    public static func create(_ preDerivedPublicKey: String, _ index: Int) throws -> RootIdentity {
        let key = DIDHDKey.deserializeBase58(preDerivedPublicKey)
        return try RootIdentity(key, index)
    }
    
    public func wipe() throws {
        rootPrivateKey?.wipe()
        mnemonic = nil
        rootPrivateKey = nil
    }
    
    var store: DIDStore? {
        return metadata?.store
    }
    
    func setMetadata(_ metadata: RootIdentityMetadata) {
        self.metadata = metadata
    }
    
    static func getId(_ key: [UInt8]) -> String {
        let md5 = MD5Helper()
        var _key = key
        md5.update(&_key)
        let result = md5.finalize()
        let hex = result.hexString
        
        return hex
    }
    
    func getId() throws -> String {
        if id == nil {
            id = RootIdentity.getId(try preDerivedPublicKey.serializePublicKey())
        }

        return id!
    }
    
    public var alias: String? {
        set{
            metadata?.setAlias(newValue!)
        }
        get{
            metadata?.getAlias()
        }
    }
    
    public func defaultDid() throws -> DID {
        return try metadata!.getDefaultDid()!
    }
    
    public func setAsDefault() throws {
        try store!.setDefaultRootIdentity(self)
    }
    
    public func setDefaultDid(_ did: DID) throws {
        metadata!.setDefaultDid(did)
    }
    
    public func setDefaultDid(_ did: String) throws {
        try metadata!.setDefaultDid(DID.valueOf(did)!)
    }
    
    public func setDefaultDid(_ index: Int) throws {
        try metadata!.setDefaultDid(getDid(index))
    }
    
    public func setIndex(_ idx: Int) throws {
        index = idx
        try store!.storeRootIdentity(self)
    }
    
    public func incrementIndex() throws -> Int {
        index = index + 1
        try store!.storeRootIdentity(self)
        
        return index
    }
    
    /// Get DID with specified index.
    /// - Parameter index: the index
    /// - Returns: the DID object
    public func getDid(_ index: Int) throws -> DID {
        
        let key = try preDerivedPublicKey.derive("0/\(index)")
        let did = DID(DID.METHOD, key.getAddress())
        
        return did
    }
    
    public static func lazyCreateDidPrivateKey(_ id: DIDURL, _ store: DIDStore, _ storePassword: String) throws -> Data? {
        let  doc = try store.loadDid(id.did!)
        guard let _ = doc else {
            throw DIDError.CheckedError.DIDStoreError.MissingDocumentError("Missing document for DID: \(String(describing: id.did))")
        }
        let identity = doc?.getMetadata().rootIdentityId
        guard let _ = identity else {
            return nil
        }
        let key: DIDHDKey? = try store.derive(identity!, DIDHDKey.DID_DERIVE_PATH_PREFIX + (doc?.getMetadata().index)!, storePassword)
        let pk = try doc?.publicKey(ofId: id)
        guard let _ = key else {
            throw DIDError.CheckedError.DIDStoreError.InvalidPublickeyError("Invalid public key: \(id)")
        }
        guard key!.getPublicKeyBase58() == pk?.publicKeyBase58 else {
            throw DIDError.CheckedError.DIDStoreError.InvalidDIDMetadataError("Invalid DID metadata: \(String(describing: id.did))")
        }
        try store.storePrivateKey(for: id, privateKey: key!.serialize(), using: storePassword)
        let sk = try key!.serialize()
        key!.wipe()
        
        return sk
    }
    
    /// Create a new DID with specified index and get this DID's Document content.
    /// - Parameters:
    ///   - index: the index to create new did.
    ///   - storePassword: the password for DIDStore
    /// - Returns: the DIDDocument content related to the new DID
    public func newDid(_ index: Int, _ overwrite: Bool, _ storePassword: String) throws -> DIDDocument {
        try checkArgument(index >= 0, "Invalid index")
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        let did = try getDid(index)
        var doc = try store?.loadDid(did)
        if doc != nil  {
            guard !doc!.isDeactivated else {
                throw DIDError.UncheckedError.IllegalStateError.DIDDeactivatedError(did.toString())
            }
            guard overwrite else {
                throw DIDError.UncheckedError.IllegalStateError.DIDAlreadyExistError("DID already exists in the store.")
            }
        }
        
        doc = try did.resolve()
        if doc != nil  {
            guard !doc!.isDeactivated else {
                throw DIDError.UncheckedError.IllegalStateError.DIDDeactivatedError(did.toString())
            }
        }
        Log.d(TAG, "Creating new DID ", did.toString(), " at index ", index)
        
        let key = try store!.derive(getId(), DIDHDKey.DID_DERIVE_PATH_PREFIX + index, storePassword)
        
        let id = try DIDURL(did, "#primary")
        try store?.storePrivateKey(for: id, privateKey: try key.serialize(), using: storePassword)
        let db = DIDDocumentBuilder(did, store!)
        _ = try db.appendAuthenticationKey(with: id, keyBase58: key.getPublicKeyBase58())
        doc = try db.sealed(using: storePassword)
        try store?.storeDid(using: doc!)
        
        return doc!
    }
    
    public func newDid(_ index: Int, _ storePassword: String) throws -> DIDDocument {
        
        return try newDid(index, false, storePassword)
    }
    
    /// Create a new DID without alias and get this DID's Document content.
    /// - Parameters:
    ///   - storePassword: the password for DIDStore
    /// - Returns: the DIDDocument content related to the new DID
    public func newDid(_ overwrite: Bool, _ storePassword: String) throws -> DIDDocument {
        
        let doc = try newDid(index, overwrite, storePassword)
        _ = try incrementIndex()
        
        return doc
    }
    
    public func newDid(_ storePassword: String) throws -> DIDDocument {
        
        return try newDid(false, storePassword)
    }
    
    public func hasMnemonic() throws -> Bool {
        return try store!.containsRootIdentityMnemonic(getId())
    }
    
    /// Export mnemonic from DIDStore
    /// - Parameter storePassword: the password for DIDStore
    /// - Returns: the mnemonic string
    public func exportMnemonic(_ storePassword: String) throws -> String {
        return try store!.exportRootIdentityMnemonic(getId(), storePassword)!
    }
    
    public func synchronize(_ index: Int, _ handle: ConflictHandler?) throws -> Bool {
        try checkArgument(index >= 0, "Invalid index")
        var h = handle
        if h == nil {
            h = DIDStore.defaultConflictHandle
        }
        let did = try getDid(index)
        Log.i(TAG, "Synchronize ", did.toString(), "/", index, "...")
        let resolvedDoc = try did.resolve(true)
        if resolvedDoc == nil {
            Log.i(TAG, "Synchronize ", did.toString(), "/", index, "...not exists")
            return false
        }
        Log.d(TAG, "Synchronize ", did.toString(), "/", index, "... exists, got the on-chain copy.")
        var finalDoc = resolvedDoc
        let localDoc = try store!.loadDid(did)
        if localDoc != nil {
            // Update metadata off-store, then store back
            localDoc?.getMetadata().detachStore()
            
            if localDoc?.signature == resolvedDoc?.signature || localDoc?.getMetadata().signature != nil && localDoc?.proof.signature == localDoc?.getMetadata().signature {
                finalDoc?.getMetadata().merge(localDoc!.getMetadata())
            }
            else {
                Log.d(TAG, did.toString(), " on-chain copy conflict with local copy.")
                // Local copy was modified
                finalDoc = h!(resolvedDoc!, localDoc!) // TODO: handle.merge(resolvedDoc, localDoc)
                guard finalDoc != nil, finalDoc!.subject == did else {
                    Log.i(TAG, "Conflict handle merge the DIDDocument error.")
                    throw DIDError.CheckedError.DIDStoreError.ConflictMergeError("deal with local modification error.")
                }
            }
        }
        let metadata = finalDoc!.getMetadata()
        metadata.setRootIdentityId(try getId())
        metadata.setIndex(index)
        try store!.storeDid(using: finalDoc!)
        
        return true
    }
    
    public func synchronize(_ index: Int) throws -> Bool {
        return try synchronize(index, nil)
    }
    
    public func synchronizeAsync(_ index: Int, _ handle: ConflictHandler?) throws -> Promise<Bool> {
        return DispatchQueue.global().async(.promise){ [self] in try synchronize(index, handle) }
    }
    
    public func synchronizeAsync(_ index: Int) throws -> Promise<Bool> {
        return DispatchQueue.global().async(.promise){ [self] in try synchronize(index, nil) }
    }
    
    /// Synchronize DIDStore.
    /// - Parameter handle: the handle to ConflictHandle
    public func synchronize(_ handle: ConflictHandler?) throws {
        Log.i(TAG, "Synchronize root identity ", try getId())
        var lastIndex = index - 1
        var blanks = 0
        var i = 0
        while (i < lastIndex || blanks < 20) {
            if try synchronize(i, handle) {
                if (i > lastIndex){
                    lastIndex = i
                }
                blanks = 0
            }
            else {
                if (i > lastIndex) {
                    blanks = blanks + 1
                }
            }
           i = i + 1
        }
        if (lastIndex >= index) {
            try setIndex(lastIndex + 1)
        }
    }
    
    public func synchronize() throws {
        try synchronize(nil)
    }
    
    /// Synchronize DIDStore with asynchronous mode.
    /// - Parameter handle: the handle to ConflictHandle
    public func synchronizeAsync(_ handle: ConflictHandler?) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try synchronize(handle) }
    }
    
    public func synchronizeAsync() -> Promise<Void> {
        return synchronizeAsync(nil)
    }
}