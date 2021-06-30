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

public typealias ConflictHandler = (_ chainCopy: DIDDocument, _ localCopy: DIDDocument) -> DIDDocument

/// This class represents a storage facility for DID objects and private keys.

/// The DIDStore manages different types of entries:
/// - RootIdentity
/// - DIDDocument
/// - VerifiableCredential
/// - PrivateKey
@objc(DIDStore)
public class DIDStore: NSObject {
    private let TAG = NSStringFromClass(DIDStore.self)
    /// The type string for DIDStore.
    static let DID_STORE_TYPE = "did:elastos:store"
    /// Current DIDStore version.
    static let DID_STORE_VERSION = 3
    @objc public static let CACHE_INITIAL_CAPACITY = 16
    @objc public static let CACHE_MAX_CAPACITY = 128 // 128
    private var cache: LRUCache<Key, NSObject>

    private var documentCache: LRUCache<DID, DIDDocument>?
    private var credentialCache: LRUCache<DIDURL, VerifiableCredential>?
    private let DID_EXPORT = "did.elastos.export/2.0"
    private static let DID_LAZY_PRIVATEKEY = "lazy-private-key"

    var storage: DIDStorage?
    private var metadata: DIDStoreMetadata?
    private static var storePath: String = ""

    /// the default conflict handle implementation.
    public static let defaultConflictHandle: ConflictHandler = { (c, l) -> DIDDocument in
        l.getMetadata().setPublishTime(c.getMetadata().publishTime!)
        l.getMetadata().setSignature(c.getMetadata().signature!)
        return l
    }
    
    class Key: NSObject {
        static let TYPE_ROOT_IDENTITY = 0x00
        static let TYPE_ROOT_IDENTITY_PRIVATEKEY = 0x01
        static let TYPE_DID_DOCUMENT = 0x10
        static let TYPE_DID_METADATA = 0x11
        static let TYPE_DID_PRIVATEKEY = 0x12
        static let TYPE_CREDENTIAL = 0x20
        static let TYPE_CREDENTIAL_METADATA = 0x21
        
        var type: Int
        var id: NSObject
        
        init(_ type: Int, _ id: NSObject) {
            self.type = type
            self.id = id
        }
      
        override var hash: Int {
            return type + id.hashValue
        }

        override func isEqual(_ object: Any?) -> Bool {
            
            if let obj = object as? Key {
                if obj.type == self.type && obj.id == self.id {
                    return true
                }
                
            }
            return false
        }
        
        public class func forRootIdentity(_ id: String) -> Key {
            return Key(TYPE_ROOT_IDENTITY, id as NSObject)
        }
        
        public class func forRootIdentityPrivateKey(_ id: String) -> Key {
            return Key(TYPE_ROOT_IDENTITY_PRIVATEKEY, id as NSObject)
        }
        
        public class func forDidDocument(_ did: DID) -> Key {
            return Key(TYPE_DID_DOCUMENT, did as NSObject)
        }
        
        public class func forDidMetadata(_ did: DID) -> Key {
            return Key(TYPE_DID_METADATA, did as NSObject)
        }
        
        public class func forDidPrivateKey(_ id: DIDURL) -> Key {
            return Key(TYPE_DID_PRIVATEKEY, id as NSObject)
        }
        
        public class func forCredential(_ id: DIDURL) -> Key {
            return Key(TYPE_CREDENTIAL, id as NSObject)
        }
        
        public class func forCredentialMetadata(_ id: DIDURL) -> Key {
            return Key(TYPE_CREDENTIAL_METADATA, id as NSObject)
        }
    }

    private init(_ initialCacheCapacity: Int, _ maxCacheCapacity: Int, _ storage: DIDStorage) throws {
        if maxCacheCapacity > 0 {
            documentCache = LRUCache<DID, DIDDocument>(initialCacheCapacity, maxCacheCapacity)
            credentialCache = LRUCache<DIDURL, VerifiableCredential>(initialCacheCapacity, maxCacheCapacity)
        }
        cache = LRUCache<Key, NSObject>(initialCacheCapacity, maxCacheCapacity)
        self.storage = storage
        self.metadata = try storage.loadMetadata()
        super.init()
        self.metadata?.attachStore(self)
        Log.i(TAG, "DID store opened: , cache(init:\(initialCacheCapacity), max:\(maxCacheCapacity)")
    }

    private class func openStore(_ path: String,
                                 _ initialCacheCapacity: Int,
                                 _ maxCacheCapacity: Int) throws -> DIDStore {
        
        try checkArgument(!path.isEmpty, "Invalid store location");
        try checkArgument(maxCacheCapacity >= initialCacheCapacity, "Invalid cache capacity spec")
        
        let storage = try FileSystemStorage(path)
        storePath = path
        return try DIDStore(initialCacheCapacity, maxCacheCapacity, storage)
    }
    
    /// Open a DIDStore instance with given storage location.
    /// - Parameters:
    ///   - atPath: the storage location for the DIDStore
    ///   - initialCacheCapacity: the initial cache capacity
    ///   - maxCacheCapacity: the maximum cache capacity
    /// - Throws: If error occurs, throw error.
    /// - Returns: the DIDStore object
    @objc
    public class func open(atPath: String,
                           initialCacheCapacity: Int,
                           maxCacheCapacity: Int) throws -> DIDStore {
        
        return try openStore(atPath, initialCacheCapacity, maxCacheCapacity)
    }
    
    /// Open a DIDStore instance with given storage location.
    /// - Parameters:
    ///   - atPath: the storage location for the DIDStore
    /// - Throws: If error occurs, throw error.
    /// - Returns: DIDStore instance.
    @objc
    public class func open(atPath: String) throws -> DIDStore {

        return try openStore(atPath, CACHE_INITIAL_CAPACITY, CACHE_MAX_CAPACITY)
    }
    
    /// Close this DIDStore object.
    public func close() {
        cache.clear()
        metadata = nil
        storage = nil
    }
    
    private func calcFingerprint(_ password: String) throws -> String {
        /// Here should use Argon2, better to avoid the password attack.
        /// But spongycastle library not include the Argon2 implementation,
        /// so here we use one-time AES encryption to secure the password hash.
        var md5 = MD5Helper()
        var bytes = [UInt8](password.data(using: .utf8)!)
        md5.update(&bytes)
        var result = md5.finalize()
        let str = try DIDStore.encryptToBase64(Data(bytes: result, count: result.count), password)
        md5 = MD5Helper()
        bytes = [UInt8](str.data(using: .utf8)!)
        md5.update(&bytes)
        result = md5.finalize()
        let hex = result.hexString
        
        return hex
    }
    
    class func encryptToBase64(_ input: Data, _ storePassword: String) throws -> String {
        let cinput: UnsafePointer<UInt8> = input.withUnsafeBytes{ (by: UnsafePointer<UInt8>) -> UnsafePointer<UInt8> in
            return by
        }
        let capacity = input.count * 3
        let base64url = UnsafeMutablePointer<CChar>.allocate(capacity: capacity)
        let re = encrypt_to_b64(base64url, storePassword, cinput, input.count)
        guard re >= 0 else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.EncryptToBase64Error("encryptToBase64 error.")
        }
        base64url[re] = 0
        return String(cString: base64url)
    }

    class func decryptFromBase64(_ input: String, _ storePassword: String) throws -> Data {
        let capacity = input.count * 3
        let plain: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
        let re = decrypt_from_b64(plain, storePassword, input)
        guard re >= 0 else {
            // NEW ADD
            throw DIDError.CheckedError.DIDStoreError.WrongPasswordError()
        }
        let temp = UnsafeRawPointer(plain)
            .bindMemory(to: UInt8.self, capacity: re)
        
        let data = Data(bytes: temp, count: re)
        //        let intArray = [UInt8](data).map { Int8(bitPattern: $0) }
        return data
    }

    class func reEncrypt(_ secret: String, _ oldpass: String, _ newpass: String) throws -> String {
        let plain = try DIDStore.decryptFromBase64(secret, oldpass)
        let newSecret = try DIDStore.encryptToBase64(plain, newpass)
        
        return newSecret
    }
    
    private func encrypt(_ input: Data, _ passwd: String) throws -> String {
        let fingerprint = metadata?.fingerprint
        let currentFingerprint = try calcFingerprint(passwd)
        if fingerprint != nil && currentFingerprint != fingerprint {
            throw DIDError.CheckedError.DIDStoreError.WrongPasswordError("Password mismatched with previous password.")
        }
        let result = try DIDStore.encryptToBase64(input, passwd)
        if fingerprint == nil || fingerprint!.isEmpty {
            try metadata!.setFingerprint(currentFingerprint)
        }
        return result
    }
    
    private func decrypt(_ input: String, _ passwd: String) throws -> Data {
        let fingerprint = metadata?.fingerprint
        let currentFingerprint = try calcFingerprint(passwd)
        let result = try DIDStore.decryptFromBase64(input, passwd)
        
        if fingerprint == nil || fingerprint!.isEmpty {
            try metadata!.setFingerprint(currentFingerprint)
        }

        return result
    }
    
    /// Save the RootIdentity object with private keys to this DID store.
    /// - Parameters:
    ///   - identity: an RootIdentity object
    ///   - storePassword: the password for this DID store
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    func storeRootIdentity(_ identity: RootIdentity, _ storePassword: String) throws {
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        var encryptedMnemonic: String = ""
        if identity.mnemonic != nil {
            encryptedMnemonic = try encrypt(identity.mnemonic!.data(using: .utf8)!, storePassword)
        }
        let encryptedPrivateKey = try encrypt(identity.rootPrivateKey!.serialize(), storePassword)
        let publicKey = try identity.preDerivedPublicKey.serializePublicKeyBase58()
        try storage!.storeRootIdentity(identity.getId(), encryptedMnemonic,
                                       encryptedPrivateKey, publicKey, identity.index)
        if metadata?.defaultRootIdentity == nil {
            try metadata!.setDefaultRootIdentity(identity.getId())
        }
        try cache.removeValue(for: Key.forRootIdentity(identity.getId()))
        try cache.removeValue(for: Key.forRootIdentityPrivateKey(identity.getId()))
    }
    
    /// Save the RootIdentity object to this DID store(Update the derive index
    /// only).
    /// - Parameter identity: an RootIdentity object
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    func storeRootIdentity(_ identity: RootIdentity) throws {
        try storage!.updateRootIdentityIndex(identity.getId(), identity.index)
    }
    
    /// Set the identity as the default RootIdentity of the DIDStore.
    /// - Parameter identity: a RootIdentity object
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    func setDefaultRootIdentity(_ identity: RootIdentity) throws {
        if try !containsRootIdentity(try identity.getId()) {
            throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalArgumentError("Invalid identity, not exists in the store")
        }
        try metadata!.setDefaultRootIdentity(identity.getId())
    }
    
    /// Load a RootIdentity object from this DIDStore.
    /// - Parameter id: the id of the RootIdentity
    /// - Returns: the RootIdentity object, null if the identity not exists
    public func loadRootIdentity(_ id: String) throws -> RootIdentity? {
        try checkArgument(!id.isEmpty, "Invalid id")
        do {
            let value = try cache.getValue(for: Key.forRootIdentity(id)) { () -> NSObject? in
                let identity = try storage!.loadRootIdentity(id)
                if identity != nil {
                    identity!.setMetadata(try loadRootIdentityMetadata(id))
                    
                    return identity
                }
                return nil
            }
            return value as? RootIdentity
        } catch {
            throw DIDError.CheckedError.DIDStoreError.DIDStoreError("Load root identity failed: \(id)")
        }
    }
    
    /// Load the default RootIdentity object from this DIDStore.
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the default RootIdentity object, null if the identity exists
    public func loadRootIdentity() throws -> RootIdentity? {
        let id = metadata?.defaultRootIdentity
        if id == nil || id!.isEmpty {
            let ids = try storage!.listRootIdentities()
            if ids.count != 1 {
                return nil
            }
            let identity = ids[0]
            try metadata!.setDefaultRootIdentity(identity.getId())
            return identity
        }
        
        return try loadRootIdentity(id!)
    }
    
    /// Check whether the RootIdentity exists in this DIDStore.
    /// - Parameter id: the id of the RootIdentity to be check
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: true if exists else false
    public func containsRootIdentity(_ id: String) throws -> Bool {
  
        return try storage!.loadRootIdentity(id) != nil
    }
    
    /// Export the mnemonic of the specific RootIdentity from this DIDStore.
    /// - Parameters:
    ///   - id: the id of the RootIdentity
    ///   - storePassword: the password for DIDStore
    /// - Throws: DIDStoreException if an error occurred when accessing the store
    /// - Returns: the mnemonic string, null if the identity not exists or does
    ///           not have mnemonic
    func exportRootIdentityMnemonic(_ id: String, _ storePassword: String) throws -> String? {
        try checkArgument(!id.isEmpty, "Invalid id");
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        let encryptedMnemonic = try storage?.loadRootIdentityMnemonic(id)
        if encryptedMnemonic != nil {
            return String(data: try decrypt(encryptedMnemonic!, storePassword), encoding: .utf8)
        }
        return nil
    }
    
    /// Check whether the RootIdentity has mnemonic.
    /// - Parameter id: the id of the RootIdentity
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: true if exists else false
    func containsRootIdentityMnemonic(_ id: String) throws -> Bool {
        try checkArgument(!id.isEmpty, "Invalid id");
        let encryptedMnemonic = try storage?.loadRootIdentityMnemonic(id)
        
        return encryptedMnemonic != nil
    }
    
    /// Load private identity from DIDStore.
    /// - Parameters:
    ///   - storePassword: the password for DIDStore
    /// - Returns: the HDKey object(private identity)
    private func loadRootIdentityPrivateKey(_ id: String, _ storePassword: String) throws -> DIDHDKey? {
        let value = try cache.getValue(for: Key.forRootIdentityPrivateKey(id)) { () -> NSObject? in
            let encryptedKey = try storage!.loadRootIdentityPrivateKey(id)
            return encryptedKey as NSObject?
        }
        
        if value != nil {
            let keyData = try decrypt(value as! String, storePassword)
            return DIDHDKey.deserialize(keyData)
        }
        else {
            return nil
        }
    }

    func derive(_ id: String, _ path: String, _ storePassword: String) throws -> DIDHDKey {
        try checkArgument(!id.isEmpty, "Invalid identity")
        try checkArgument(!path.isEmpty, "Invalid path")
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        let rootPrivateKey = try loadRootIdentityPrivateKey(id, storePassword)
        let key = try rootPrivateKey!.derive(path)
        rootPrivateKey!.wipe()
        
        return key
    }
    
    /// Delete the specific RootIdentity object from this store.
    /// - Parameter id: the id of RootIdentity object
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: true if the identity exists and delete successful; false otherwise
    public func deleteRootIdentity(_ id: String) throws -> Bool {
        try checkArgument(!id.isEmpty, "Invalid id")
        let success = try storage!.deleteRootIdentity(id)
        if success {
            if metadata?.defaultRootIdentity != nil && metadata!.defaultRootIdentity == id {
                try metadata!.setDefaultRootIdentity(nil)
            }
            cache.removeValue(for: Key.forRootIdentity(id))
            cache.removeValue(for: Key.forRootIdentityPrivateKey(id))
        }
        
        return success
    }
    
    /// List all RootIdentity object from this store.
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: an array of RootIdentity objects
    public func listRootIdentities() throws -> [RootIdentity] {
        return try storage!.listRootIdentities()
    }
    
    /// Check whether the this store has RootIdentity objects.
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: true if the store has RootIdentity objects else false
    public func containsRootIdentities() throws -> Bool {
        return try storage!.containsRootIdenities()
    }
    
    /// Save the RootIdentity metadata to this store.
    /// - Parameters:
    ///   - id: the id of the RootIdentity object
    ///   - metadata: a RootIdentity.Metadata object
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    func storeRootIdentityMetadata(_ id: String, _ metadata: RootIdentityMetadata) throws {
        try checkArgument(!id.isEmpty, "Invalid id")
        try storage?.storeRootIdentityMetadata(id, metadata)
    }
   
    /// Read the RootIdentity metadata from this store.
    /// - Parameter id: the id of the RootIdentity object
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: a RootIdentityMetadata object
    func loadRootIdentityMetadata(_ id: String) throws -> RootIdentityMetadata {
        try checkArgument(!id.isEmpty, "Invalid id")
        var metadata = try storage?.loadRootIdentityMetadata(id)
        if metadata != nil {
            metadata!.setId(id)
            metadata?.attachStore(self)
        }
        else {
            metadata = RootIdentityMetadata(id, self)
        }
        
        return metadata!
    }
    
    /// Save the DID document to this store.
    /// - Parameter doc: the DIDDocument object
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    @objc
    public func storeDid(using doc: DIDDocument) throws {
        try storage!.storeDid(doc)

        if doc.store != self {
            let metadata = try loadDidMetadata(doc.subject)
            doc.getMetadata().merge(metadata)
            try storage!.storeDidMetadata(doc.subject, doc.getMetadata())
            doc.getMetadata().attachStore(self)
        }
        
        for credential in doc.credentials() {
            try storeCredential(using: credential)
        }
        cache.setValue(doc, for: Key.forDidDocument(doc.subject))
    }
    
    /// Read the specific DID document from this store.
    /// - Parameter did: the DID to be load
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the DIDDocument object
    public func loadDid(_ did: DID) throws -> DIDDocument? {
        var doc: DIDDocument?
        let vaule = cache.getValue(for: Key.forDidDocument(did))
        
        doc = vaule as? DIDDocument
        if doc == nil {
            doc = try storage!.loadDid(did)

            if doc != nil {
                let metadata = try loadDidMetadata(did)
                metadata.attachStore(self)
                doc?.setMetadata(metadata)
            }
        }
        
        return doc
    }
    
    /// Read the specific DID document from this store.
    /// - Parameter did: the DID to be load
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the DIDDocument object
    public func loadDid(_ did: String) throws -> DIDDocument? {
        return try loadDid(DID(did))
    }
    
    /// Read the specific DID document from this store with Object-C
    /// - Parameter did: the DID to be load
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the DIDDocument object
    @objc
    public func loadDid(_ did: DID, error: NSErrorPointer) -> DIDDocument? {
        do {
            return try loadDid(did)
        } catch let aError as NSError {
            error?.pointee = aError
            return nil
        }
    }
    
    /// Read the specific DID document from this store with Object-C
    /// - Parameter did: the DID to be load
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: DIDStoreError if an error occurred when accessing the store
    @objc(loadDidWithString:error:)
    public func loadDid(_ did: String, error: NSErrorPointer) -> DIDDocument? {
        do {
            return try loadDid(DID(did))
        } catch let aError as NSError {
            error?.pointee = aError
            return nil
        }
    }
    
    /// Check if this store contains the specific DID.
    /// - Parameter did: the specified DID
    /// - Returns: true if the store contains this DID, false otherwise
    public func containsDid(_ did: DID) throws -> Bool {
        return try loadDid(did) != nil
    }

    /// Check if contain specific DID or not.
    /// - Parameter did: The handle to DID.
    /// - Throws: DIDStoreError if an error occurred when accessing the store.
    /// - Returns: true on success, false if an error occurred.
    public func containsDid(_ did: String) throws -> Bool {
        return try containsDid(try DID(did))
    }
    
    /// Check if this store contains the specific DID with Object-C
    /// - Parameter did: the specified DID
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: true if the store contains this DID, false otherwise
    @objc
    public func containsDid(_ did: String, error: NSErrorPointer) -> Bool {
        do {
            return try containsDid(DID(did))
        } catch let aError as NSError {
            error?.pointee = aError
            return false
        }
    }
    
    /// Save the DID Metadata to this store.
    /// - Parameters:
    ///   - did: the owner of the metadata object
    ///   - metadata: the DID metadata object
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    func storeDidMetadata(_  did: DID, _ metadata: DIDMetadata) throws {
        try storage?.storeDidMetadata(did, metadata)
        metadata.attachStore(self)
        cache.setValue(metadata, for: Key.forDidMetadata(did))
    }
    
    /// Read the specific DID metadata object for this store.
    /// - Parameter did: a DID to be load
    /// - Returns: the DID metadata object
    func loadDidMetadata(_ did: DID) throws -> DIDMetadata {
        let metadata = try cache.getValue(for: Key.forDidMetadata(did), { () -> NSObject? in
            var metadata = try storage!.loadDidMetadata(did)
            if (metadata != nil) {
                metadata!.setDid(did)
                metadata!.attachStore(self)
            } else {
                metadata = DIDMetadata(did, self)
            }

            return metadata
        })
        
        //It must not be nil.
        return metadata as! DIDMetadata
    }

    /// Read the specific DID metadata object for this store.
    /// - Parameter did: a DID to be load
    /// - Returns: the DID metadata object
    func loadDidMetadata(_ did: String) throws -> DIDMetadata {
        let _did = try DID(did)
        return try loadDidMetadata(_did)
    }
    
    /// Delete the specific DID from this store.
    ///
    /// When delete the DID, all private keys, credentials that owned by this
    /// DID will also be deleted.
    ///
    /// - Parameter did: the DID to be delete
    /// - Returns: true if the DID exist and deleted successful, false otherwise
    @objc
    public func deleteDid(_ did: DID) -> Bool {
        let success = storage!.deleteDid(did)
        if success {
            cache.removeValue(for: Key.forDidDocument(did))
            cache.removeValue(for: Key.forDidMetadata(did))
            // invalidate every thing belongs to this did
            for key in cache.keys() {
                if key.id.isKind(of: DIDURL.self) {
                    let id = key.id as? DIDURL
                    if id?.did == did {
                        cache.removeValue(for: key)
                    }
                }
            }
        }
        
        return success
    }
    
    /// Delete the specific DID from this store.
    ///
    /// When delete the DID, all private keys, credentials that owned by this
    /// DID will also be deleted.
    ///
    /// - Parameter did: the DID to be delete
    /// - Returns: true if the DID exist and deleted successful, false otherwise
    public func deleteDid(_ did: String) throws -> Bool {
        return try deleteDid(DID(did))
    }
    
    /// Delete the specific DID from this store with Object-C
    ///
    /// When delete the DID, all private keys, credentials that owned by this
    /// DID will also be deleted.
    ///
    /// - Parameter did: the DID to be delete
    /// - Returns: true if the DID exist and deleted successful, false otherwise
    @objc
    public func deleteDid(_ did: String, error: NSErrorPointer) -> Bool {
        do {
            return try deleteDid(DID(did))
        } catch let aError as NSError {
            error?.pointee = aError
            return false
        }
    }
    
    /// List all DIDs from this store.
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: an array of DIDs
    @objc
    public func listDids() throws -> Array<DID> {
        let dids = try storage!.listDids()

        try dids.forEach { did in
            let metadata = try loadDidMetadata(did)
            did.setMetadata(metadata)
        }

        return dids
    }
    
    /// Save the credential object to this store.
    /// - Parameter credential: a VerifiableCredential object
    /// - Throws:  DIDStoreError if an error occurred when accessing the store
    @objc
    public func storeCredential(using credential: VerifiableCredential) throws {
        try storage!.storeCredential(credential)

        if credential.getMetadata().store != self {
            let metadata = try loadCredentialMetadata(credential.id!)
            credential.getMetadata().merge(metadata)
            try storeCredentialMetadata(credential.getId()!, credential.getMetadata())
        }
        
        cache.setValue(credential, for: Key.forCredential(credential.getId()!))
    }
    
    /// Read the specific credential object from this store.
    /// - Parameters:
    ///   - byId: the credential id
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the VerifiableCredential object
    public func loadCredential(byId: DIDURL) throws -> VerifiableCredential? {
        
        let value = try cache.getValue(for: Key.forCredential(byId)) { () -> NSObject? in
            let vc = try storage?.loadCredential(byId)
            guard vc != nil else {
                return nil
            }
            vc?.setMetadata(try loadCredentialMetadata(byId))
            
            return vc
        }
        
        return value as? VerifiableCredential
    }
    
    /// Read the specific credential object from this store.
    /// - Parameters:
    ///   - byId: the credential id
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the VerifiableCredential object
    public func loadCredential(byId: String) throws -> VerifiableCredential? {
        return try loadCredential(byId: DIDURL.valueOf(byId))
    }
    
    /// Read the specific credential object from this store with Object-C
    /// - Parameters:
    ///   - byId: the credential id
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the VerifiableCredential object
    @objc
    public func loadCredential(byId: DIDURL, error: NSErrorPointer) -> VerifiableCredential? {
        do {
            return try loadCredential(byId: byId)
        } catch let aError as NSError {
            error?.pointee = aError
            return nil
        }
    }
    
    /// Read the specific credential object from this store with Object-C
    /// - Parameters:
    ///   - byId: the credential id
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the VerifiableCredential object
    @objc(loadCredentialbyId:error:)
    public func loadCredential(byId: String, error: NSErrorPointer) -> VerifiableCredential? {
        do {
            return try loadCredential(byId: byId)
        } catch let aError as NSError {
            error?.pointee = aError
            return nil
        }
    }
    
    /// Check whether this store contains the specific credential.
    /// - Parameters:
    ///   - id: the credential id
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: true if the store contains this credential, false otherwise
    public func containsCredential(_ id: DIDURL) throws -> Bool {
        return try loadCredential(byId: id) != nil
    }
    
    /// Check whether this store contains the specific credential.
    /// - Parameters:
    ///   - id: the credential id
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: true if the store contains this credential, false otherwise
    public func containsCredential(_ id: String) throws -> Bool {
        return try containsCredential(DIDURL.valueOf(id))
    }
    
    /// Check whether this store contains the credentials that owned by the
    /// specific DID.
    /// - Parameters:
    ///   - did: the credential owner's DID
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: true if the store contains this credential, false otherwise
    @objc
    public func containsCredentials(_ did:DID) -> Bool {
        return storage!.containsCredentials(did)
    }
    
    /// Check whether this store contains the credentials that owned by the
    /// specific DID.
    /// - Parameters:
    ///   - did: the credential owner's DID
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: true if the store contains this credential, false otherwise
    @objc(containsCredentialsWithDid:)
    public func containsCredentials(_ did: String) -> Bool {
        do {
            return containsCredentials(try DID.valueOf(did)!)
        } catch {
            return false
        }
    }
    
    /// Save the credential's metadata to this store.
    /// - Parameters:
    ///   - id: the credential id
    ///   - metadata: the credential metadata object
    func storeCredentialMetadata(_ id: DIDURL, _ metadata: CredentialMetadata) throws {
        try storage!.storeCredentialMetadata(id, metadata)
        metadata.attachStore(self)
        
        cache.setValue(metadata, for: Key.forCredentialMetadata(id))
    }
    
    /// Save the credential's metadata to this store.
    /// - Parameters:
    ///   - id: the credential id
    ///   - metadata: the credential metadata object
    func storeCredentialMetadata(_ id: String, _ metadata: CredentialMetadata) throws {
        try storeCredentialMetadata(DIDURL.valueOf(id), metadata)
    }
    
    /// Read the credential's metadata from this store.
    /// - Parameters:
    ///   - byId: the credential id
    /// - Returns: the credential metadata object
    func loadCredentialMetadata(_ byId: DIDURL) throws -> CredentialMetadata {        
        let value = try cache.getValue(for: Key.forCredentialMetadata(byId)) { () -> NSObject? in
            var metadata = try storage?.loadCredentialMetadata(byId)
            if metadata != nil {
                metadata?.id = byId
                metadata?.attachStore(self)
            }
            else {
                metadata = CredentialMetadata(byId, self)
            }
            
            return metadata
        }

        return value as! CredentialMetadata
    }
    
    /// Read the credential's metadata from this store.
    /// - Parameters:
    ///   - byId: the credential id
    /// - Returns: the credential metadata object
    func loadCredentialMetadata(_ byId: String) throws -> CredentialMetadata? {
        return try loadCredentialMetadata(DIDURL.valueOf(byId))
    }
    
    /// Delete the specific credential from this store.
    /// - Parameters:
    ///   - id: the credential id to be delete
    /// - Returns: true if the credential exist and deleted successful, false otherwise
    @objc
    public func deleteCredential(_ id: DIDURL) -> Bool{
        let success = storage!.deleteCredential(id)
        
        if success {
            cache.removeValue(for: Key.forCredential(id))
            cache.removeValue(for: Key.forCredentialMetadata(id))
        }
        
        return success
    }
    
    /// Delete the specific credential from this store.
    /// - Parameters:
    ///   - id: the credential id to be delete
    /// - Returns: true if the credential exist and deleted successful, false otherwise
    public func deleteCredential(_ id: String) throws -> Bool{
        return try deleteCredential(DIDURL.valueOf(id))
    }
    
    /// List all credentials that owned the specific DID.
    /// - Parameter did: the credential owner's DID
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: an array of DIDURL denoting the credentials
    @objc
    public func listCredentials(for did: DID) throws -> Array<DIDURL> {
        let ids = try storage!.listCredentials(did)
        for id in ids {
            let metadata = try loadCredentialMetadata(id)
            id.setMetadata(metadata)
        }
        return ids
    }
    
    /// List all credentials that owned the specific DID.
    /// - Parameter did: the credential owner's DID
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: an array of DIDURL denoting the credentials
    @objc(listCredentials:error:)
    public func listCredentials(for did: String) throws -> Array<DIDURL> {
        return try listCredentials(for: DID(did))
    }
    
    /// Save the DID's lazy private key string to the store.
    /// - Parameter id: the private key id
    /// - Throws: if an error occurred when accessing the store
    func storeLazyPrivateKey(_ id: DIDURL) throws {

        try storage?.storePrivateKey(id, DIDStore.DID_LAZY_PRIVATEKEY)
        cache.setValue(DIDStore.DID_LAZY_PRIVATEKEY as NSObject, for: Key.forDidPrivateKey(id))
    }

    /// Save the DID's private key to the store, the private key will be encrypt
    /// using the store password.
    /// - Parameters:
    ///   - id: the private key id
    ///   - privateKey: the binary extended private key
    ///   - storePassword: the password for this store
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    @objc
    public func storePrivateKey(for id: DIDURL,
                                privateKey: Data,
                                using storePassword: String) throws {
        
        try checkArgument(privateKey.count != 0, "Invalid private key")
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        
        let encryptedKey = try DIDStore.encryptToBase64(privateKey, storePassword)
        try storage!.storePrivateKey(id, encryptedKey)
    }
    
    /// Save the DID's private key to the store, the private key will be encrypt
    /// using the store password.
    /// - Parameters:
    ///   - id: the private key id
    ///   - privateKey: the binary extended private key
    ///   - storePassword: the password for this store
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    @objc(storePrivateKeyId:privateKey:storePassword:error:)
    public func storePrivateKey(for id: String,
                                privateKey: Data,
                                using storePassword: String) throws {
        let _key = try DIDURL.valueOf(id)

        return try storePrivateKey(for: _key, privateKey: privateKey, using: storePassword)
    }

    func loadPrivateKey(_ id: DIDURL) throws -> String? {
        let value = try cache.getValue(for: Key.forDidPrivateKey(id)) { () -> NSObject? in
            let encryptedKey = try storage!.loadPrivateKey(id)
            
            return encryptedKey != "" ? encryptedKey as NSObject : nil
        }
        
        return value == nil ? nil : value as? String
    }
    
    /// Load private key.
    /// - Parameters:
    ///   - id: the identifier of key
    ///   - storePassword: the password for DIDStore
    /// - Returns: the original private key
    func loadPrivateKey(_ id: DIDURL, _ storePassword: String) throws -> Data? {
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        let encryptedKey = try loadPrivateKey(id)
        guard encryptedKey != DIDStore.DID_LAZY_PRIVATEKEY else {
            // fail-back to lazy private key generation
            return try RootIdentity.lazyCreateDidPrivateKey(id, self, storePassword)
        }
        
        return try decrypt(encryptedKey!, storePassword)
    }
    
    /// Check if this store contains the specific private key.
    /// - Parameters:
    ///   - id: the key id
    /// - Returns: true if this store contains the specific key, false otherwise
    public func containsPrivateKey(for id: DIDURL) throws -> Bool {
        return try loadPrivateKey(id) != nil
    }
    
    /// Check if this store contains the specific private key.
    /// - Parameters:
    ///   - id: the key id
    /// - Returns: true if this store contains the specific key, false otherwise
    public func containsPrivateKey(for id: String) throws -> Bool {
        do {
            let _key = try DIDURL.valueOf(id)
            return try containsPrivateKey(for: _key)
        } catch {
            return false
        }
    }
    
    /// Check if this store contains the private keys that owned by the
    /// specific DID.
    /// - Parameter did: the owner's DID
    /// - Returns: true if this store contains the private keys owned by the the
    ///            DID, false otherwise
    public func containsPrivateKeys(for did: DID) throws -> Bool {
        return try storage!.containsPrivateKeys(did)
    }
    
    /// Check if this store contains the private keys that owned by the
    /// specific DID.
    /// - Parameter did: the owner's DID
    /// - Returns: true if this store contains the private keys owned by the the
    ///            DID, false otherwise
    @objc(containsPrivateKeys:)
    public func containsPrivateKeys(for did: String) -> Bool {
        do {
            return try containsPrivateKeys(for: try DID(did))
        } catch {
            return false
        }
    }
    
    /// Delete the specific private key from this store.
    /// - Parameters:
    ///   - id: the key id
    /// - Returns: true if the private key exist and deleted successful, false otherwise
    @objc
    public func deletePrivateKey(for id: DIDURL) -> Bool {
        let success = storage!.deletePrivateKey(id)
        if success {
            cache.removeValue(for: Key.forDidPrivateKey(id))
        }
        
        return success
    }
    
    /// Delete the specific private key from this store.
    /// - Parameters:
    ///   - id: the key id
    /// - Returns: true if the private key exist and deleted successful, false otherwise
    @objc(deletePrivateKeyId:)
    public func deletePrivateKey(for id: String) -> Bool {
        do {
            let _key = try DIDURL.valueOf(id)
            
            return deletePrivateKey(for: _key)
        } catch {
            return false
        }
    }
    
    /// Sign the digest using the specified key.
    /// - Parameters:
    ///   - id: the key id
    ///   - storePassword: the password for this store
    ///   - digest: the binary digest of data
    /// - Returns: the base64(URL safe) encoded signature string
    func sign(WithId id: DIDURL, using storePassword: String, for digest: Data, _ capacity: Int) throws -> String {
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        try checkArgument(digest.count > 0, "Invalid digest")
        
        let key = try DIDHDKey.deserialize(loadPrivateKey(id, storePassword)!)
        let privatekeys = key.getPrivateKeyData()
        let toPPointer = privatekeys.toPointer()
        
        let cdigest = digest.toPointer()
        let csig = UnsafeMutablePointer<CChar>.allocate(capacity: capacity)
        let re = ecdsa_sign_base64(csig, toPPointer, UnsafeMutablePointer(mutating: cdigest), digest.count)

        guard re >= 0 else {
            throw DIDError.CheckedError.DIDStoreError.DIDStoreError("sign error.")
        }
        csig[re] = 0
        let sig = String(cString: csig)
        key.wipe()
        return sig
    }

    /// Sign the digest using the specified key.
    /// - Parameters:
    ///   - id: the key id
    ///   - storePassword: the password for this store
    ///   - digest: the binary digest of data
    /// - Returns: the base64(URL safe) encoded signature string
    func sign(WithId id: String, using storePassword: String, for digest: Data, capacity: Int) throws -> String {

        return try sign(WithId: DIDURL.valueOf(id), using: storePassword, for: digest, capacity)
    }
    
    ///  Change the password for this store.
    /// - Parameters:
    ///   - oldPassword: the old password
    ///   - newPassword: the new password
    @objc
    public func changePassword(_ oldPassword: String, _ newPassword: String) throws {
        try checkArgument(!oldPassword.isEmpty, "Invalid old password")
        try checkArgument(!newPassword.isEmpty, "Invalid new password")
        
        try storage?.changePassword{ data -> String in
            let result = try DIDStore.reEncrypt(data, oldPassword, newPassword)
            
            return result
        }

        try metadata!.setFingerprint(calcFingerprint(newPassword))
        cache.clear()
    }

    /// Synchronize all RootIdentities, DIDs and credentials in this store.
    ///
    /// If the ConflictHandle is not set by the developers, this method will
    /// use the default ConflictHandle implementation: if conflict between
    /// the chain copy and the local copy, it will keep the local copy, but
    /// update the local metadata with the chain copy.
    ///
    /// - Parameter conflictHandler: an application defined handle to process the conflict
    ///                  between the chain copy and the local copy
    /// - Throws: DIDResolveError if an error occurred when resolving DIDs
    /// - Throws DIDStoreError if an error occurred when accessing the store
    private func synchronize(_ conflictHandler: ConflictHandler?) throws {
        var h = conflictHandler
        if h == nil {
            h = DIDStore.defaultConflictHandle
        }
        let identities = try storage!.listRootIdentities()
        for identity in identities {
            try identity.synchronize(handle: h)
        }
        let dids = try storage!.listDids()
        for did in dids {
            let localDoc = try storage!.loadDid(did)
            if localDoc != nil && localDoc!.isCustomizedDid() {
                let resolvedDoc = try did.resolve()
                if resolvedDoc == nil {
                    continue
                }
                var finalDoc = resolvedDoc
                localDoc!.getMetadata().detachStore()
                if (localDoc!.signature == (resolvedDoc?.signature) ||
                        (localDoc!.proof.signature == (
                            localDoc!.getMetadata().signature))) {
                    finalDoc?.getMetadata().merge(localDoc!.getMetadata())
                } else {
                    Log.d(TAG, did.toString(), " on-chain copy conflict with local copy.")

                    // Local copy was modified
                    finalDoc = h!(resolvedDoc!, localDoc!)
                    if (finalDoc == nil || finalDoc!.subject != did) {
                        Log.e(TAG, "Conflict handle merge the DIDDocument error.")
                        throw DIDError.CheckedError.DIDStoreError.DIDStoreError("deal with local modification error.")
                    } else {
                        Log.d(TAG, "Conflict handle return the final copy.")
                    }
                }

                try storage!.storeDid(finalDoc!)
            }
            
            let vcIds = try storage!.listCredentials(did)
            for vcId in vcIds {
                let localVc = try storage!.loadCredential(vcId)
                let resolvedVc = try VerifiableCredential.resolve(vcId, localVc!.issuer!)
                if resolvedVc == nil {
                    continue
                }
                resolvedVc!.getMetadata().merge(localVc!.getMetadata())
                try storage!.storeCredential(resolvedVc!)
            }
        }
    }
    
    /// Synchronize all RootIdentities, DIDs and credentials in this store.
    ///
    /// If the ConflictHandle is not set by the developers, this method will
    /// use the default ConflictHandle implementation: if conflict between
    /// the chain copy and the local copy, it will keep the local copy, but
    /// update the local metadata with the chain copy.
    ///
    /// - Parameter conflictHandler: an application defined handle to process the conflict
    ///                  between the chain copy and the local copy
    /// - Throws: DIDResolveError if an error occurred when resolving DIDs
    /// - Throws DIDStoreError if an error occurred when accessing the store
    public func synchronize(conflictHandler: @escaping ConflictHandler) throws {
        try synchronize(conflictHandler)
    }
    
    /// Synchronize all RootIdentities, DIDs and credentials in this store.
    ///
    /// If the ConflictHandle is not set by the developers, this method will
    /// use the default ConflictHandle implementation: if conflict between
    /// the chain copy and the local copy, it will keep the local copy, but
    /// update the local metadata with the chain copy.
    ///
    /// - Throws: DIDResolveError if an error occurred when resolving DIDs
    /// - Throws DIDStoreError if an error occurred when accessing the store
    public func synchronize() throws {
        try synchronize(nil)
    }
    
    /// Synchronize all RootIdentities, DIDs and credentials in
    /// asynchronous mode.
    ///
    /// If the ConflictHandle is not set by the developers, this method will
    /// use the default ConflictHandle implementation: if conflict between
    /// the chain copy and the local copy, it will keep the local copy, but
    /// update the local metadata with the chain copy.
    ///
    /// - Parameter conflictHandler: an application defined handle to process the conflict
    ///                  between the chain copy and the local copy
    /// - Throws: DIDResolveError if an error occurred when resolving DIDs
    /// - Throws DIDStoreError if an error occurred when accessing the store
    /// - Returns: a new Promise
    public func synchronizeAsync(_ handle: @escaping ConflictHandler) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try synchronize(handle) }
    }
    
    /// Synchronize all RootIdentities, DIDs and credentials in
    /// asynchronous mode.
    ///
    /// If the ConflictHandle is not set by the developers, this method will
    /// use the default ConflictHandle implementation: if conflict between
    /// the chain copy and the local copy, it will keep the local copy, but
    /// update the local metadata with the chain copy.
    ///
    /// - Throws: DIDResolveError if an error occurred when resolving DIDs
    /// - Throws DIDStoreError if an error occurred when accessing the store
    /// - Returns: a new Promise
    public func synchronizeAsync() -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try synchronize(nil) }
    }
    
    private func synchronizeAsync_oc(_ conflictHandler: @escaping ConflictHandler) -> AnyPromise {
        return AnyPromise(__resolverBlock: { resolver in
            do {
                try self.synchronize(conflictHandler)
                resolver(nil)
            } catch let error  {
                resolver(error)
            }
        })
    }
    
    /// Synchronize all RootIdentities, DIDs and credentials in
    /// asynchronous mode with Object-C
    ///
    /// If the ConflictHandle is not set by the developers, this method will
    /// use the default ConflictHandle implementation: if conflict between
    /// the chain copy and the local copy, it will keep the local copy, but
    /// update the local metadata with the chain copy.
    ///
    /// - Parameter conflictHandler: an application defined handle to process the conflict
    ///                  between the chain copy and the local copy
    /// - Throws: DIDResolveError if an error occurred when resolving DIDs
    /// - Throws DIDStoreError if an error occurred when accessing the store
    /// - Returns: a new AnyPromise
    @objc
    public func synchornizeAsyncUsingObjectC(_ conflictHandler: @escaping ConflictHandler) -> AnyPromise {

        return synchronizeAsync_oc(conflictHandler)
    }
    
    /// Synchronize all RootIdentities, DIDs and credentials in
    /// asynchronous mode with Object-C
    ///
    /// If the ConflictHandle is not set by the developers, this method will
    /// use the default ConflictHandle implementation: if conflict between
    /// the chain copy and the local copy, it will keep the local copy, but
    /// update the local metadata with the chain copy.
    ///
    /// - Throws: DIDResolveError if an error occurred when resolving DIDs
    /// - Throws DIDStoreError if an error occurred when accessing the store
    /// - Returns: a new Promise
    @objc
    public func synchornizeAsyncUsingObjectC() throws -> AnyPromise {

        return AnyPromise(__resolverBlock: { [self] resolver in
            do {
                try synchronize(nil)
                resolver(nil)
            } catch let error  {
                resolver(error)
            }
        })
    }
    
    private func exportDid(_ did: DID, _ password: String, _ storePassword: String) throws -> DIDExport {
        // All objects should load directly from storage,
        // avoid affects the cached objects.
        let doc = try storage!.loadDid(did)
        if (doc == nil) {
            throw DIDError.CheckedError.DIDStoreError.DIDStoreError("Export DID \(did.toString()) failed, not exist.")
        }
        
        doc!.setMetadata(try storage!.loadDidMetadata(did)!)
        
        Log.i(TAG, "Exporting \(did.toString()...)")
        
        let de = DIDExport(DID_EXPORT, did)
        de.setDocument(doc!)
        
        if (storage!.containsCredentials(did)) {
            var ids = try listCredentials(for: did)
            ids = ids.sorted { (didurlA, didurlB) -> Bool in
                return didurlA.compareTo(didurlB) == ComparisonResult.orderedAscending
            }
            for id in ids {
                Log.d(TAG, "Exporting credential \(id.toString())...")
                
                let vc = try storage!.loadCredential(id)
                if let _ = try storage!.loadCredentialMetadata(id) {
                    vc!.setMetadata(try storage!.loadCredentialMetadata(id)!)
                }
                de.appendCredential(vc!)
            }
        }
        
        if (try storage!.containsPrivateKeys(did)) {
            let pks = doc!.publicKeys()
            for pk in pks {
                let id = pk.getId()
                let key = try storage!.loadPrivateKey(id!)
                if key != "" {
                    Log.d(TAG, "Exporting private key \(String(describing: id?.toString()))...")
                    try de.appendPrivatekey(id!, key, storePassword, password)
                }
            }
        }
        
        return try de.sealed(using: password)
    }
    
    /// Export the specific DID with all DID objects that related with this DID,
    /// include: document, credentials, private keys and their metadata.
    /// - Parameters:
    ///   - did: the DID to be export
    ///   - output: the output stream that the data export to
    ///   - password: the password to encrypt the private keys in the exported data
    ///   - storePassword: the password for this store
    public func exportDid(_ did: DID,
                      to output: OutputStream,
                 using password: String,
                  storePassword: String) throws {
        let exportStr = try exportDid(did, password, storePassword).serialize(true)
        output.open()
        self.writeData(data: exportStr.data(using: .utf8)!, outputStream: output, maxLengthPerWrite: 1024)
        output.close()
    }
    
    /// Export the specific DID with all DID objects that related with this DID,
    /// include: document, credentials, private keys and their metadata.
    /// - Parameters:
    ///   - did: the DID to be export
    ///   - output: the output stream that the data export to
    ///   - password: the password to encrypt the private keys in the exported data
    ///   - storePassword: the password for this store
    public func exportDid(_ did: String,
                      to output: OutputStream,
                 using password: String,
                  storePassword: String) throws {
        let exportStr = try exportDid(DID.valueOf(did)!, password, storePassword).serialize(true)
        output.open()
        self.writeData(data: exportStr.data(using: .utf8)!, outputStream: output, maxLengthPerWrite: 1024)
        output.close()
    }
    
    /// Export the specific DID with all DID objects that related with this DID,
    /// include: document, credentials, private keys and their metadata.
    /// - Parameters:
    ///   - did: the DID to be export
    ///   - fileHandle: the file handle that the data export to
    ///   - password: the password to encrypt the private keys in the exported data
    ///   - storePassword: the password for this store
    public func exportDid(_ did: DID,
                  to fileHandle: FileHandle,
                 using password: String,
                  storePassword: String) throws {
        let exportStr = try exportDid(did, password, storePassword).serialize(true)
        fileHandle.write(exportStr.data(using: .utf8)!)
    }
    
    /// Export the specific DID with all DID objects that related with this DID,
    /// include: document, credentials, private keys and their metadata.
    /// - Parameters:
    ///   - did: the DID to be export
    ///   - fileHandle: the file handle that the data export to
    ///   - password: the password to encrypt the private keys in the exported data
    ///   - storePassword: the password for this store
    public func exportDid(_ did: String,
                  to fileHandle: FileHandle,
                 using password: String,
                  storePassword: String) throws {
        let exportStr = try exportDid(DID.valueOf(did)!, password, storePassword).serialize(true)
        fileHandle.write(exportStr.data(using: .utf8)!)
    }
    
    private func importDid(_ de: DIDExport, _ password: String, _ storepass: String) throws {
        try de.verify(password)
        
        // Save
        Log.d(TAG, "Importing document...")
        let doc = de._document!.content
        try storage!.storeDid(doc)
        try storage!.storeDidMetadata(doc.subject, doc.getMetadata())
        
        let vcs = de.credentials
        for vc in vcs {
            Log.d(TAG, "Importing credential \(vc.id!.toString())")
            try storage!.storeCredential(vc)
            try storage!.storeCredentialMetadata(vc.getId()!, vc.getMetadata())
        }
        
        let sks = de.privateKeys
        for sk in sks {
            Log.d(TAG, "Importing credential \(sk.id.toString())")
            try storage!.storePrivateKey(sk.id, sk.getKey(password, storepass))
        }
    }
    
    /// Import a DID and all related DID object from the exported data to this store.
    /// - Parameters:
    ///   - data: the data for the exported data
    ///   - password: the password for the exported data
    ///   - storePassword: the password for the import data
    /// - Throws: If error occurs, throw error.
    @objc
    public func importDid(from data: Data,
                     using password: String,
                      storePassword: String) throws {
        let dic = try JSONSerialization.jsonObject(with: data,options: JSONSerialization.ReadingOptions.mutableContainers) as? [String: Any]
        guard let _ = dic else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DataParsingError("data is not nil")
        }
        
        let de = try DIDExport.deserialize(dic!)
        try importDid(de, password, storePassword)
    }

    /// Import a DID and all related DID object from the exported data to this store.
    /// - Parameters:
    ///   - input: the input stream for the exported data
    ///   - password: the password for the exported data
    ///   - storePassword: the password for the import data
    /// - Throws: If error occurs, throw error.
    @objc(importDid:password:storePassword:error:)
    public func importDid(from input: InputStream,
                      using password: String,
                       storePassword: String) throws {
        let data = try readData(input: input)
        try importDid(from: data, using: password, storePassword: storePassword)
    }

    /// Import a DID and all related DID object from the exported data to this store.
    /// - Parameters:
    ///   - handle: the fileHandle for the exported data
    ///   - password: the password for the exported data
    ///   - storePassword: the password for the import data
    /// - Throws: If error occurs, throw error.
    @objc(importDidFrom:password:storePassword:error:)
    public func importDid(from handle: FileHandle,
                       using password: String,
                        storePassword: String) throws {
        let data = handle.readDataToEndOfFile()
        try importDid(from: data, using: password, storePassword: storePassword)
    }
    
    private func exportRootIdentity(_ id: String, _ password: String, _ storepass: String) throws -> RootIdentityExport {
        let rie = RootIdentityExport(DID_EXPORT)

        // TODO: support multiple named root identities
        let mnemonic = try storage!.loadRootIdentityMnemonic(id)
        try rie.setMnemonic(mnemonic, storepass, password)

        try rie.setPrivateKey(storage!.loadRootIdentityPrivateKey(id)!, storepass, password)

        let identity = try storage!.loadRootIdentity(id)
        rie.setPubkey(try identity!.preDerivedPublicKey.serializePublicKeyBase58())
        rie.setIndex(identity!.index)
        
        if (identity!.id == metadata?.defaultRootIdentity) {
            rie.setDefault()
        }

        return try rie.sealed(using: password)
    }
    
    /// Export the specific RootIdentity, include: mnemonic, private key,
    /// pre-derived public key, derive index, metadata...
    /// - Parameters:
    ///   - id: the id of the RootIdentity to be export
    ///   - output: the output stream that the data export to
    ///   - password: the password to encrypt the private keys in the exported data
    ///   - storePassword: the password for this store
    public func exportRootIdentity(_ id: String,
                      to output: OutputStream,
                 using password: String,
                  storePassword: String) throws {
        let exportStr = try exportRootIdentity(id, password, storePassword).serialize(true)
        output.open()
        self.writeData(data: exportStr.data(using: .utf8)!, outputStream: output, maxLengthPerWrite: 1024)
        output.close()
    }

    /// Export the specific RootIdentity, include: mnemonic, private key,
    /// pre-derived public key, derive index, metadata...
    /// - Parameters:
    ///   - id: the id of the RootIdentity to be export
    ///   - output: the output stream that the data export to
    ///   - password: the password to encrypt the private keys in the exported data
    ///   - storePassword: the password for this store
    public func exportRootIdentity(_ id: String,
                  to fileHandle: FileHandle,
                 using password: String,
                  storePassword: String) throws {
        let exportStr = try exportRootIdentity(id, password, storePassword).serialize(true)
        fileHandle.write(exportStr.data(using: .utf8)!)
    }
    
    private func importRootIdentity(_ rie: RootIdentityExport, _ password: String, _ storePassword: String) throws {
        try rie.verify(password)

        // Save
        let encryptedMnemonic = try rie.getMnemonic(password, storePassword)
        let encryptedPrivateKey = (try rie.getPrivateKey(password, storePassword))
        let publicKey = rie.publicKey
        let pk = DIDHDKey.deserializeBase58(publicKey)
        let id = RootIdentity.getId(try pk.serializePublicKey())

        try storage!.storeRootIdentity(id, encryptedMnemonic, encryptedPrivateKey,
                                       publicKey, rie.index)
        
        if (rie.isDefault && metadata?.defaultRootIdentity == nil) {
            try metadata!.setDefaultRootIdentity(id)
        }
    }
    
    /// Import a RootIdentity object from the exported data to this store.
    /// - Parameters:
    ///   - data: the data for the exported data
    ///   - password: the password for the exported data
    ///   - storePassword: the password for this store
    /// - Throws: If error occurs, throw error.
    @objc
    public func importRootIdentity(from data: Data,
                     using password: String,
                      storePassword: String) throws {
        let dic = String(data: data, encoding: .utf8)?.toDictionary()
        guard !dic!.isEmpty else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DataParsingError("data is not nil")
        }
    
        let re = try RootIdentityExport.deserialize(dic!)
        try importRootIdentity(re, password, storePassword)
    }

    /// Import a RootIdentity object from the exported data to this store.
    /// - Parameters:
    ///   - data: the input stream for the exported data
    ///   - password: the password for the exported data
    ///   - storePassword: the password for this store
    /// - Throws: If error occurs, throw error.
    @objc(importRootIdentity:password:storePassword:error:)
    public func importRootIdentity(from input: InputStream,
                      using password: String,
                       storePassword: String) throws {
        let data = try readData(input: input)
        try importRootIdentity(from: data, using: password, storePassword: storePassword)
    }

    /// Import a RootIdentity object from the exported data to this store.
    /// - Parameters:
    ///   - data: the input stream for the exported data
    ///   - password: the password for the exported data
    ///   - storePassword: the password for this store
    /// - Throws: If error occurs, throw error.
    @objc(importRootIdentityFrom:password:storePassword:error:)
    public func importRootIdentity(from handle: FileHandle,
                       using password: String,
                        storePassword: String) throws {
        let data = handle.readDataToEndOfFile()
        try importRootIdentity(from: data, using: password, storePassword: storePassword)
    }
    
    private func exportStore(_ password: String, _ storePassword: String) throws -> [String: Any] {
        let ris = try listRootIdentities()
        var dataDic: [String: Any] = [: ]
        var arrayRis: [[String: Any]] = []
        var arrayDids: [[String: Any]] = []
        for ri in ris {
            let rootIdentityStr = try "rootIdentity-" + ri.getId()
            let ert = try exportRootIdentity(ri.id!, password, storePassword).serialize(true).toDictionary()
            arrayRis.append([rootIdentityStr: ert])
        }
        let dids = try listDids()
        for did in dids {
            let didstr = did.methodSpecificId
            let edid = try exportDid(did, password, storePassword).serialize(true).toDictionary()
            arrayDids.append([didstr: edid])
        }
        dataDic["rootIdentity"] = arrayRis
        dataDic["ids"] = arrayDids

        return dataDic
    }

    /// Export all DID objects from this store.
    /// - Parameters:
    ///   - output: the output stream that the data export to
    ///   - password: the password to encrypt the private keys in the exported data
    ///   - storePassword: the password for this store
    /// - Throws: If error occurs, throw error.
    public func exportStore(to path: String,
                 using password: String,
                  storePassword: String) throws {
        let exportDic = try exportStore(password, storePassword)
        let roots = exportDic["rootIdentity"] as! [[String: Any]]
        let ids = exportDic["ids"] as! [[String: Any]]
        
        for root in roots {
            let key = root.keys.first
            let path = path + "/" + key!
            try path.create(forWrite: true)
            let value = root[key!] as! [String: Any]
            try value.toJsonString()?.write(to: URL(fileURLWithPath: path), atomically: true, encoding: .utf8)
        }
        
        for id in ids {
            let key = id.keys.first
            let path = path + "/" + key!
            FileManager.default.createFile(atPath: path, contents: nil, attributes: nil)
            let value = id[key!] as! [String: Any]
            try value.toJsonString()?.write(to: URL(fileURLWithPath: path), atomically: true, encoding: .utf8)
        }
    }
    
    private func importStore(from path: String,
                             _ password: String,
                             _ storePassword: String) throws {
        let fingerprint = metadata?.fingerprint
        let currentFingerprint = try calcFingerprint(storePassword)
        
        if fingerprint != nil && currentFingerprint != fingerprint {
            throw DIDError.CheckedError.DIDStoreError.WrongPasswordError("Password mismatched with previous password.")
        }
        
        let enumerator = try path.files()
        if enumerator.count == 0 {
            return
        }
        var subPath = ""
        var dic: [String: Any] = [: ]
        for element: String in enumerator  {
            subPath = path + "/" + element
            dic = try subPath.readTextFromPath().toDictionary()
            // rootIdentity
            if element.hasPrefix("rootIdentity") {
                let re = try RootIdentityExport.deserialize(dic)
                try importRootIdentity(re, password, storePassword)
            }
            // ids
            else {
                let de = try DIDExport.deserialize(dic)
                try importDid(de, password, storePassword)
            }
        }
        
        if (fingerprint == nil || fingerprint!.isEmpty) {
            try metadata!.setFingerprint(currentFingerprint)
        }
    }
    
    /// Import a exported DIDStore from the exported data to this store.
    /// - Parameters:
    ///   - handle: the handle for the exported data
    ///   - password: the password for the exported data
    ///   - storePassword: the password for this store
    /// - Throws: If error occurs, throw error.
    public func importStore(from path: String,
                            using password: String,
                            storePassword: String) throws {
        try importStore(from: path, password, storePassword)
    }
 
    private func writeData(data: Data, outputStream: OutputStream, maxLengthPerWrite: Int) {
        let size = data.count
        data.withUnsafeBytes({(bytes: UnsafePointer<UInt8>) in
            var bytesWritten = 0
            while bytesWritten < size {
                var maxLength = maxLengthPerWrite
                if size - bytesWritten < maxLengthPerWrite {
                    maxLength = size - bytesWritten
                }
                let n = outputStream.write(bytes.advanced(by: bytesWritten), maxLength: maxLength)
                bytesWritten += n
            }
        })
    }
    
    private func readData(input: InputStream) throws -> Data {
        var data = Data()
        input.open()
        
        let bufferSize = 1024
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        
        while input.hasBytesAvailable {
            let read = input.read(buffer, maxLength: bufferSize)
            if read < 0 {
                //Stream error occured
                throw input.streamError!
            }
            else if read == 0 {
                //EOF
                break
            }
            data.append(buffer, count: read)
        }
        do{
            input.close()
        }
        do{
            buffer.deallocate()
        }
        return data
    }
}
