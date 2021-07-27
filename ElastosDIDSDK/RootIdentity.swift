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


 /// The RootIdentity is a top-level object that represents a real user who
/// owns a series of DIDs
///
/// The users could use RootIdentity object to derive a series of DIDs,
/// all these DIDs are managed by this root identity object.
/// At the same time, these DIDs are independent to the 3rd party verifiers.
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
    
    /// Create a RootIdentity from mnemonic and an optional passphrase.
    /// - Parameters:
    ///   - mnemonic: the mnemonic string
    ///   - passphrase: the password for mnemonic to generate seed
    ///   - overwrite: true will overwrite the identity if the identity exists
    ///                in the store, false will raise exception if the identity
    ///                exists in the store
    ///   - store: the DIDStore where to save this identity
    ///   - storePassword: the password for DIDStore
    /// - Returns: the RootIdentity object
    private static func create(mnemonic: String, passphrase: String?, overwrite: Bool, store: DIDStore, storePassword: String) throws -> RootIdentity {
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
    
    /// Create a RootIdentity from mnemonic and an optional passphrase.
    /// - Parameters:
    ///   - mnemonic: the mnemonic string
    ///   - passphrase: the password for mnemonic to generate seed
    ///   - overwrite: true will overwrite the identity if the identity exists
    ///                in the store, false will raise exception if the identity
    ///                exists in the store
    ///   - store: the DIDStore where to save this identity
    ///   - storePassword: the password for DIDStore
    /// - Returns: the RootIdentity object
    public static func create(_ mnemonic: String, _ passphrase: String, _ overwrite: Bool, _ store: DIDStore, _ storePassword: String) throws -> RootIdentity {
        return try create(mnemonic: mnemonic, passphrase: passphrase, overwrite: overwrite, store: store, storePassword: storePassword)
    }
    
    /// Create a RootIdentity from mnemonic and an optional passphrase.
    /// - Parameters:
    ///   - mnemonic: the mnemonic string
    ///   - overwrite: true will overwrite the identity if the identity exists
    ///                in the store, false will raise exception if the identity
    ///                exists in the store
    ///   - store: the DIDStore where to save this identity
    ///   - storePassword: the password for DIDStore
    /// - Returns: the RootIdentity object
    public static func create(_ mnemonic: String, _ overwrite: Bool, _ store: DIDStore, _ storePassword: String) throws -> RootIdentity {
        return try create(mnemonic: mnemonic, passphrase: nil, overwrite: overwrite, store: store, storePassword: storePassword)
    }
    
    /// Create a RootIdentity from mnemonic and an optional passphrase.
    /// - Parameters:
    ///   - mnemonic: the mnemonic string
    ///   - passphrase: the password for mnemonic to generate seed
    ///   - store: the DIDStore where to save this identity
    ///   - storePassword: the password for DIDStore
    /// - Returns: the RootIdentity object
    public static func create(_ mnemonic: String, _ passphrase: String, _ store: DIDStore, _ storePassword: String) throws -> RootIdentity {
        return try create(mnemonic: mnemonic, passphrase: passphrase, overwrite: false, store: store, storePassword: storePassword)
    }
    
    /// Create a RootIdentity from mnemonic and an optional passphrase.
    /// - Parameters:
    ///   - mnemonic: the mnemonic string
    ///   - store: the DIDStore where to save this identity
    ///   - storePassword: the password for DIDStore
    /// - Returns: the RootIdentity object
    public static func create(_ mnemonic: String, _ store: DIDStore, _ storePassword: String) throws -> RootIdentity {
        return try create(mnemonic: mnemonic, passphrase: nil, overwrite: false, store: store, storePassword: storePassword)
    }
    
    /// Create a RootIdentity from a root extended private key.
    /// - Parameters:
    ///   - extentedPrivateKey: the root extended private key
    ///   - overwrite: true will overwrite the identity if the identity exists
    ///                in the store, false will raise exception if the identity
    ///                exists in the store
    ///   - store: the DIDStore where to save this identity
    ///   - storePassword: the password for DIDStore
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the RootIdentity object
    public static func create(with extentedPrivateKey: String, _ overwrite: Bool, _ store: DIDStore, _ storePassword: String) throws -> RootIdentity {
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
    
    /// Create a RootIdentity from a root extended private key.
    /// - Parameters:
    ///   - extentedPrivateKey: the root extended private key
    ///   - store: the DIDStore where to save this identity
    ///   - storePassword: the password for DIDStore
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the RootIdentity object
    public static func create(with extentedPrivateKey: String, _ store: DIDStore, _ storePassword: String) throws -> RootIdentity {
        return try create(with: extentedPrivateKey, false, store, storePassword)
    }
    
    /// Create a public key only RootIdentity instance.
    /// - Parameters:
    ///   - preDerivedPublicKey: the pre-derived extended public key
    ///   - index: current available derive index
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the RootIdentity object
    public static func create(_ preDerivedPublicKey: String, _ index: Int) throws -> RootIdentity {
        let key = DIDHDKey.deserializeBase58(preDerivedPublicKey)
        return try RootIdentity(key, index)
    }
    
    private func wipe() throws {
        rootPrivateKey?.wipe()
        mnemonic = nil
        rootPrivateKey = nil
    }
    
    /// Get the attached DIDStore instance.
    var store: DIDStore? {
        return metadata?.store
    }
    
    /// Get the metadata object of this RootIdentity.
    /// - Parameter metadata: the metadata object
    func setMetadata(_ metadata: RootIdentityMetadata) {
        self.metadata = metadata
    }
    
    /// Calculate the id of RootIdentity object from the pre-derived public key.
    /// - Parameter key: the pre-derived public key in bytes array
    /// - Returns: the id of RootIdentity object
    static func getId(_ key: [UInt8]) -> String {
        let md5 = MD5Helper()
        var _key = key
        md5.update(&_key)
        let result = md5.finalize()
        let hex = result.hexString
        
        return hex
    }
    
    /// Get the id of this RootIdentity object.
    /// - Returns: the id of this RootIdentity object
    public func getId() throws -> String {
        if id == nil {
            id = RootIdentity.getId(try preDerivedPublicKey.serializePublicKey())
        }

        return id!
    }
    
    /// Get RootIdentity Id from mnemonic and an optional passphrase.
    /// - Parameters:
    ///   - mnemonic: the mnemonic string
    ///   - passphrase: the extra passphrase to generate seed with the mnemonic
    /// - Returns: the RootIdentity Id
    public static func getId(mnemonic: String, passphrase: String = "") throws -> String {
        try checkArgument(!mnemonic.isEmpty, "Invalid mnemonic")
        do {
            try checkArgument(Mnemonic.checkIsValid(mnemonic), "Invalid mnemonic.")
        } catch {
            throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalArgumentError(error.localizedDescription)
        }

        let identity = try RootIdentity(mnemonic, passphrase)
        let id = try identity.getId()
        try identity.wipe()

        return id
    }
    
    /// Get a RootIdentity Id from a root extended private key.
    /// - Parameter extentedPrivateKey: extentedPrivateKey the root extended private key
    /// - Returns: the RootIdentity Id
    public static func getId(with extentedPrivateKey: String) throws -> String {
        try checkArgument(!extentedPrivateKey.isEmpty, "Invalid extended private key")
        let rootPrivateKey = DIDHDKey.deserializeBase58(extentedPrivateKey)

        let identity = try RootIdentity(rootPrivateKey)
        let id = try identity.getId()
        try identity.wipe()

        return id
    }

    /// Get the alias of this RootIdentity object.
    /// Set the alias for this RootIdentity object.
    public var alias: String? {
        set{
            metadata?.setAlias(newValue!)
        }
        get{
            metadata?.getAlias()
        }
    }
    
    /// Get the default DID of this RootIdentity object.
    public func defaultDid() throws -> DID {
        return try metadata!.getDefaultDid()!
    }
    
    /// Set this RootIdentity as the global default identity in current DIDStore.
    public func setAsDefault() throws {
        try store!.setDefaultRootIdentity(self)
    }
    
    /// Set the default DID for this RootIdentity object.
    ///
    /// The default DID object should derived from this RootIdentity.
    /// - Parameter did: a DID object
    public func setDefaultDid(_ did: DID) throws {
        metadata!.setDefaultDid(did)
    }
    
    /// Set the default DID for this RootIdentity object.
    ///
    /// The default DID object should derived from this RootIdentity.
    /// - Parameter did: a DID object
    public func setDefaultDid(_ did: String) throws {
        try metadata!.setDefaultDid(DID.valueOf(did)!)
    }
    
    /// Set the default DID for this RootIdentity object.
    /// - Parameter index: the index of default DID derived from
    public func setDefaultDid(_ index: Int) throws {
        try metadata!.setDefaultDid(getDid(index))
    }
    
    /// Set the next available derive index for this RootIdentity.
    /// - Parameter idx: the next available derive index
    func setIndex(_ idx: Int) throws {
        index = idx
        try store!.storeRootIdentity(self)
    }
    
    /// Increase the next available derive index for this RootIdentity.
    func incrementIndex() throws -> Int {
        index = index + 1
        try store!.storeRootIdentity(self)
        
        return index
    }
    
    /// Get DID that derived from the specific index.
    /// - Parameter index: the derive index
    /// - Returns: a DID object
    public func getDid(_ index: Int) throws -> DID {
        
        let key = try preDerivedPublicKey.derive("0/\(index)")
        let did = DID(DID.METHOD, key.getAddress())
        
        return did
    }
    
    static func lazyCreateDidPrivateKey(_ id: DIDURL, _ store: DIDStore, _ storePassword: String) throws -> Data? {
        let  doc = try store.loadDid(id.did!)
        guard let _ = doc else {
            throw DIDError.CheckedError.DIDStoreError.MissingDocumentError("Missing document for DID: \(String(describing: id.did))")
        }
        let identity = doc?.getMetadata().rootIdentityId
        guard let _ = identity else {
            return nil
        }
        let key: DIDHDKey? = try store.derive(identity!, DIDHDKey.DID_DERIVE_PATH_PREFIX + "\((doc?.getMetadata().index)!)", storePassword)
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
    
    /// Create a new DID that derive from the specified index.
    /// - Parameters:
    ///   - index: the derive index
    ///   - overwrite: true for overwriting the existing one, fail otherwise
    ///   - storePassword: the password for DIDStore
    /// - Returns: the new created DIDDocument object
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
        
        let key = try store!.derive(getId(), DIDHDKey.DID_DERIVE_PATH_PREFIX + "\(index)", storePassword)
        
        let id = try DIDURL(did, "#primary")
        try store?.storePrivateKey(for: id, privateKey: try key.serialize(), using: storePassword)
        let db = DIDDocumentBuilder(did, store!)
        _ = try db.appendAuthenticationKey(with: id, keyBase58: key.getPublicKeyBase58())
        doc = try db.sealed(using: storePassword)
        try store?.storeDid(using: doc!)
        
        return doc!
    }
    
    /// Create a new DID that derive from the specified index.
    /// - Parameters:
    ///   - index: the derive index
    ///   - storePassword: the password for DIDStore
    /// - Returns: the new created DIDDocument object
    public func newDid(_ index: Int, _ storePassword: String) throws -> DIDDocument {
        
        return try newDid(index, false, storePassword)
    }
    
    /// Create a new DID that derive from the specified index.
    /// - Parameters:
    ///   - overwrite: true for overwriting the existing one, fail otherwise
    ///   - storePassword: the password for DIDStore
    /// - Returns: the new created DIDDocument object
    public func newDid(_ overwrite: Bool, _ storePassword: String) throws -> DIDDocument {
        
        let doc = try newDid(index, overwrite, storePassword)
        _ = try incrementIndex()
        
        return doc
    }
    
    /// Create a new DID that derive from the specified index.
    /// - Parameters:
    ///   - storePassword: the password for DIDStore
    /// - Returns: the new created DIDDocument object
    public func newDid(_ storePassword: String) throws -> DIDDocument {
        
        return try newDid(false, storePassword)
    }
    
    /// Check whether this RootIdentity created from mnemonic.
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: true if this RootIdentity created from mnemonic, false otherwise
    public func hasMnemonic() throws -> Bool {
        return try store!.containsRootIdentityMnemonic(getId())
    }
    
    /// Export mnemonic that generated this RootIdentity object.
    /// - Parameter storePassword: the password for DIDStore
    /// - Returns: the mnemonic string
    public func exportMnemonic(_ storePassword: String) throws -> String {
        return try store!.exportRootIdentityMnemonic(getId(), storePassword)!
    }
    
    /// Synchronize the specific DID from ID chain.
    ///
    /// If the ConflictHandle is not set by the developers, this method will
    /// use the default ConflictHandle implementation: if conflict between
    /// the chain copy and the local copy, it will keep the local copy, but
    /// update the local metadata with the chain copy.
    ///
    /// - Parameters:
    ///   - index: the DID derive index
    ///   - handle: an application defined handle to process the conflict
    ///             between the chain copy and the local copy
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Throws DIDStoreError if an error occurred when accessing the store
    /// - Returns: true if synchronized success, false if not synchronized
    private func synchronize(index: Int, _ handle: ConflictHandler?) throws -> Bool {
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

        metadata.setPublishTime((resolvedDoc?.getMetadata().publishTime)!)
        metadata.setSignature(resolvedDoc?.proof.signature)

        metadata.setRootIdentityId(try getId())
        metadata.setIndex(index)
        metadata.attachStore(store!)

        if (localDoc != nil) {
            localDoc!.getMetadata().attachStore(store!)
        }
        try store!.storeDid(using: finalDoc!)
        
        try store!.storeLazyPrivateKey(finalDoc!.defaultPublicKeyId()!)

        return true
    }
    
    /// Synchronize the specific DID from ID chain.
    ///
    /// If the ConflictHandle is not set by the developers, this method will
    /// use the default ConflictHandle implementation: if conflict between
    /// the chain copy and the local copy, it will keep the local copy, but
    /// update the local metadata with the chain copy.
    ///
    /// - Parameters:
    ///   - index: the DID derive index
    ///   - handle: an application defined handle to process the conflict
    ///             between the chain copy and the local copy
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Throws DIDStoreError if an error occurred when accessing the store
    /// - Returns: true if synchronized success, false if not synchronized
    public func synchronize(_ index: Int, _ handle: @escaping ConflictHandler) throws -> Bool {
        return try synchronize(index: index, handle)
    }
    
    /// Synchronize the specific DID from ID chain.
    ///
    /// If the ConflictHandle is not set by the developers, this method will
    /// use the default ConflictHandle implementation: if conflict between
    /// the chain copy and the local copy, it will keep the local copy, but
    /// update the local metadata with the chain copy.
    ///
    /// - Parameters:
    ///   - index: the DID derive index
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Throws DIDStoreError if an error occurred when accessing the store
    /// - Returns: true if synchronized success, false if not synchronized
    public func synchronize(_ index: Int) throws -> Bool {
        return try synchronize(index: index, nil)
    }
    
    /// Synchronize the specific DID from ID chain in asynchronous mode.
    ///
    /// If the ConflictHandle is not set by the developers, this method will
    /// use the default ConflictHandle implementation: if conflict between
    /// the chain copy and the local copy, it will keep the local copy, but
    /// update the local metadata with the chain copy.
    ///
    /// - Parameters:
    ///   - index: the DID derive index
    ///   - handle: an application defined handle to process the conflict
    ///             between the chain copy and the local copy
    /// - Returns: a new Promise, the result is the boolean value that
    ///             indicate the synchronize result
    public func synchronizeAsync(_ index: Int, _ handle: @escaping ConflictHandler) throws -> Promise<Bool> {
        return DispatchQueue.global().async(.promise){ [self] in try synchronize(index: index, handle) }
    }
    
    /// Synchronize the specific DID from ID chain in asynchronous mode.
    ///
    /// If the ConflictHandle is not set by the developers, this method will
    /// use the default ConflictHandle implementation: if conflict between
    /// the chain copy and the local copy, it will keep the local copy, but
    /// update the local metadata with the chain copy.
    ///
    /// - Parameters:
    ///   - index: the DID derive index
    /// - Returns: a new Promise, the result is the boolean value that
    ///             indicate the synchronize result
    public func synchronizeAsync(_ index: Int) throws -> Promise<Bool> {
        return DispatchQueue.global().async(.promise){ [self] in try synchronize(index: index, nil) }
    }
    
    /// Synchronize DIDStore.
    /// - Parameter handle: the handle to ConflictHandle
    
    /// Synchronize all DIDs that derived from this RootIdentity object.
    ///
    /// If the ConflictHandle is not set by the developers, this method will
    /// use the default ConflictHandle implementation: if conflict between
    /// the chain copy and the local copy, it will keep the local copy, but
    /// update the local metadata with the chain copy.
    ///
    /// - Parameter handle: an application defined handle to process the conflict
    ///                     between the chain copy and the local copy
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Throws DIDStoreError if an error occurred when accessing the store
    func synchronize(handle: ConflictHandler?) throws {
        Log.i(TAG, "Synchronize root identity ", try getId())
        var lastIndex = index - 1
        var blanks = 0
        var i = 0
        while (i < lastIndex || blanks < 20) {
            if try synchronize(index: i, handle) {
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
    
    /// Synchronize DIDStore.
    /// - Parameter handle: the handle to ConflictHandle
    
    /// Synchronize all DIDs that derived from this RootIdentity object.
    ///
    /// If the ConflictHandle is not set by the developers, this method will
    /// use the default ConflictHandle implementation: if conflict between
    /// the chain copy and the local copy, it will keep the local copy, but
    /// update the local metadata with the chain copy.
    ///
    /// - Parameter handle: an application defined handle to process the conflict
    ///                     between the chain copy and the local copy
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Throws DIDStoreError if an error occurred when accessing the store
    public func synchronize(_ handle: @escaping ConflictHandler) throws {
        try synchronize(handle: handle)
    }
    
    /// Synchronize DIDStore.
    /// - Parameter handle: the handle to ConflictHandle
    
    /// Synchronize all DIDs that derived from this RootIdentity object.
    ///
    /// If the ConflictHandle is not set by the developers, this method will
    /// use the default ConflictHandle implementation: if conflict between
    /// the chain copy and the local copy, it will keep the local copy, but
    /// update the local metadata with the chain copy.
    ///
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Throws DIDStoreError if an error occurred when accessing the store
    public func synchronize() throws {
        try synchronize(handle: nil)
    }

    /// Synchronize all DIDs that derived from this RootIdentity object in
    /// asynchronous mode.
    ///
    /// If the ConflictHandle is not set by the developers, this method will
    /// use the default ConflictHandle implementation: if conflict between
    /// the chain copy and the local copy, it will keep the local copy, but
    /// update the local metadata with the chain copy.
    ///
    /// - Parameter handle: an application defined handle to process the conflict
    ///                     between the chain copy and the local copy
    /// - Returns: a new Promise
    public func synchronizeAsync(_ handle: @escaping ConflictHandler) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try synchronize(handle: handle) }
    }
    
    /// Synchronize all DIDs that derived from this RootIdentity object in
    /// asynchronous mode.
    ///
    /// If the ConflictHandle is not set by the developers, this method will
    /// use the default ConflictHandle implementation: if conflict between
    /// the chain copy and the local copy, it will keep the local copy, but
    /// update the local metadata with the chain copy.
    ///
    /// - Returns: a new Promise
    public func synchronizeAsync() -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try synchronize(handle: nil) }
    }
}
