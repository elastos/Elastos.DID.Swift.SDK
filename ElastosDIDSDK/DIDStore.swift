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

/// DIDStore is local store for specified DID.
@objc(DIDStore)
public class DIDStore: NSObject {
    private let TAG = NSStringFromClass(DIDStore.self)
    static let DID_STORE_TYPE = "did:elastos:store"
    static let DID_STORE_VERSION = 3
    @objc public static let CACHE_INITIAL_CAPACITY = 16
    @objc public static let CACHE_MAX_CAPACITY = 128 // 128
    private var cache: LRUCache<Key, NSObject>

    private var documentCache: LRUCache<DID, DIDDocument>?
    private var credentialCache: LRUCache<DIDURL, VerifiableCredential>?
    private let DID_EXPORT = "did.elastos.export/2.0"

    var storage: DIDStorage?
    private var metadata: DIDStoreMetadata?
    private static var storePath: String = ""

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
            
//            if object as? NSObject != nil && object as! NSObject == self {
//                return true
//            }
//
//            if object as? NSObject != nil && (object as! NSObject).isKind(of: Key.self)  {
//                let key = object as! Key
//                return type == key.type ? id.isEqual(key.id) : false
//            }
//
//            return false
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
        
        try checkArgument(path.isEmpty, "Invalid store location");
        try checkArgument(maxCacheCapacity < initialCacheCapacity, "Invalid cache capacity spec")
        
        let storage = try FileSystemStorage(path)
        storePath = path
        return try DIDStore(initialCacheCapacity, maxCacheCapacity, storage)
    }
    
    /// Initialize or check the DIDStore.
    /// - Parameters:
    ///   - atPath: The path of DIDStore’s root.
    ///   - initialCacheCapacity: min cache capacity
    ///   - maxCacheCapacity: max cache capacity
    /// - Throws: If error occurs, throw error.
    /// - Returns: DIDStore instance.

    @objc
    public class func open(atPath: String,
             initialCacheCapacity: Int,
                 maxCacheCapacity: Int) throws -> DIDStore {

        return try openStore(atPath, initialCacheCapacity, maxCacheCapacity)
    }
    
    /// Initialize or check the DIDStore.
    /// - Parameters:
    ///   - atPath: The path of DIDStore’s root.
    ///   - withType: The type is support ‘filesystem’
    ///   - adapter: The handle to DIDAdapter.
    /// - Throws: If error occurs, throw error.
    /// - Returns: DIDStore instance.
    @objc
    public class func open(atPath: String) throws -> DIDStore {

        return try openStore(atPath, CACHE_INITIAL_CAPACITY, CACHE_MAX_CAPACITY)
    }
    
    public func close() {
        cache.clear()
        metadata = nil
        storage = nil
    }
    
    private func calcFingerprint(_ password: String) throws -> String {
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
        let re = encrypt_to_base64(base64url, storePassword, cinput, input.count)
        guard re >= 0 else {
            throw DIDError.didStoreError("encryptToBase64 error.")
        }
        base64url[re] = 0
        return String(cString: base64url)
    }

    class func decryptFromBase64(_ input: String, _ storePassword: String) throws -> Data {
        let capacity = input.count * 3
        let plain: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
        let re = decrypt_from_base64(plain, storePassword, input)
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
    
    func storeRootIdentity(_ identity: RootIdentity) throws {
        try storage!.updateRootIdentityIndex(identity.getId(), identity.index)
    }
    
    func setDefaultRootIdentity(_ identity: RootIdentity) throws {
        if try !containsRootIdentity(try identity.getId()) {
            throw DIDError.didStoreError("Invalid identity, not exists in the store")
        }
        try metadata!.setDefaultRootIdentity(identity.getId())
    }
    
    /// Load private identity from DIDStore.
    /// - Parameter id: the password for DIDStore
    /// - Returns: the HDKey object(private identity)
    public func loadRootIdentity(_ id: String) throws -> RootIdentity? {
        try checkArgument(!id.isEmpty, "Invalid id")
        do {
            let value = try cache.getValue(for: Key.forRootIdentity(id)) { () -> NSObject? in
                let identity = try storage!.loadRootIdentity(id)
                if identity != nil {
                    identity!.setMetadata(try loadRootIdentityMetadata(id))
                    
                    return identity
                }
                else {
                    return nil
                }
            }
            return value as? RootIdentity
        } catch {
            throw DIDError.didStoreError("Load root identity failed: \(id)")
        }
    }
    
    public func loadRootIdentity() throws -> RootIdentity? {
        let id = metadata?.defaultRootIdentity
        if id == nil || id!.isEmpty {
            let ids = try storage!.listRootIdentities()
            if ids.count != 1 {
                return nil
            }
            else {
                let identity = ids[0]
                try metadata!.setDefaultRootIdentity(identity.getId())
                return identity
            }
        }
        
        return try loadRootIdentity(id!)
    }
    
    /// Judge whether private identity exists in DIDStore.
    /// - Returns: the returned value is true if private identity exists;
    ///            the returned value if false if private identity doesnot exist.
    public func containsRootIdentity(_ id: String) throws -> Bool {
  
        return try storage!.loadRootIdentity(id) != nil
    }
    
    /// Export mnemonic from DIDStore
    /// - Parameters:
    ///   - storePassword: the password for DIDStore
    /// - Returns: the mnemonic string
    func exportRootIdentityMnemonic(_ id: String, _ storePassword: String) throws -> String? {
        try checkArgument(!id.isEmpty, "Invalid id");
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        let encryptedMnemonic = try storage?.loadRootIdentityMnemonic(id)
        if encryptedMnemonic != nil {
            return String(data: try decrypt(encryptedMnemonic!, storePassword), encoding: .utf8)
        }
        else {
            return nil
        }
    }
    
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
    
    public func listRootIdentities() throws -> [RootIdentity] {
        return try storage!.listRootIdentities()
    }
    
    public func containsRootIdentities() throws -> Bool {
        return try storage!.containsRootIdenities()
    }
    
    func storeRootIdentityMetadata(_ id: String, _ metadata: RootIdentityMetadata) throws {
        try checkArgument(!id.isEmpty, "Invalid id")
        try storage?.storeRootIdentityMetadata(id, metadata)
    }
   
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
    
    /// Store DID Document in DID Store.
    /// - Parameter doc: The handle to DID Document.
    /// - Throws: If error occurs, throw error.
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
    
    /// Load DID Document from DID Store.
    /// - Parameter did: The handle to DID.
    /// - Throws: If error occurs, throw error.
    /// - Returns: If no error occurs, return the handle to DID Document. Otherwise, return nil.
     public func loadDid(_ did: DID) throws -> DIDDocument? {
        var doc: DIDDocument?
        let vaule = cache.getValue(for: Key.forDidDocument(did))
        
        doc = vaule as? DIDDocument
        if doc == nil {
            doc = try storage!.loadDid(did)

            if doc != nil {
                let metadata = try storage!.loadDidMetadata(did)
                metadata?.attachStore(self)
                doc?.setMetadata(metadata!)
            }
        }
        
        return doc
    }

    /// Load DID Document from DID Store.
    /// - Parameter did: The handle to DID.
    /// - Throws: If error occurs, throw error.
    /// - Returns: If no error occurs, return the handle to DID Document. Otherwise, return nil.
    public func loadDid(_ did: String) throws -> DIDDocument? {
        return try loadDid(DID(did))
    }

    /// Load DID Document from DID Store.
    /// - Parameter did: The handle to DID.
    /// - Throws: If error occurs, throw error.
    /// - Returns: If no error occurs, return the handle to DID Document. Otherwise, return nil.
    @objc
    public func loadDid(_ did: DID, error: NSErrorPointer) -> DIDDocument? {
        do {
            return try loadDid(did)
        } catch let aError as NSError {
            error?.pointee = aError
            return nil
        }
    }

    /// Load DID Document from DID Store.
    /// - Parameter did: The handle to DID.
    /// - Throws: If error occurs, throw error.
    /// - Returns: If no error occurs, return the handle to DID Document. Otherwise, return nil.
    @objc(loadDidWithString:error:)
    public func loadDid(_ did: String, error: NSErrorPointer) -> DIDDocument? {
        do {
            return try loadDid(DID(did))
        } catch let aError as NSError {
            error?.pointee = aError
            return nil
        }
    }
    
    /// Check if contain specific DID or not.
    /// - Parameter did: The handle to DID.
    /// - Returns: true on success, false if an error occurred.
    public func containsDid(_ did: DID) throws -> Bool {
        return try loadDid(did) != nil
    }

    /// Check if contain specific DID or not.
    /// - Parameter did: The handle to DID.
    /// - Throws: If error occurs, throw error.
    /// - Returns: true on success, false if an error occurred.
    public func containsDid(_ did: String) throws -> Bool {
        return try containsDid(try DID(did))
    }

    /// Check if contain specific DID or not.
    /// - Parameter did: The handle to DID.
    /// - Throws: If error occurs, throw error.
    /// - Returns: true on success, false if an error occurred.
    @objc
    public func containsDid(_ did: String, error: NSErrorPointer) -> Bool {
        do {
            return try containsDid(DID(did))
        } catch let aError as NSError {
            error?.pointee = aError
            return false
        }
    }
    
    func storeDidMetadata(_  did: DID, _ metadata: DIDMetadata) throws {
        try storage?.storeDidMetadata(did, metadata)
        metadata.attachStore(self)
        cache.setValue(metadata, for: Key.forDidMetadata(did))
    }
    
    /// Load Meta data for the specified DID.
    /// - Parameter did: the specified DID
    /// - Returns: the Meta data
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

    func loadDidMetadata(_ did: String) throws -> DIDMetadata {
        let _did = try DID(did)
        return try loadDidMetadata(_did)
    }

    /// Delete the specified DID.
    /// - Parameter did: the specified DID
    /// - Returns: true on success, false if an error occurred.
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
    
    /// Delete specific DID.
    /// - Parameter did: The identifier of DID.
    /// - Throws: If error occurs, throw error.
    /// - Returns: true on success, false if an error occurred.
    public func deleteDid(_ did: String) throws -> Bool {
        return try deleteDid(DID(did))
    }
    
    /// Delete specific DID.
    /// - Parameter did: The identifier of DID.
    /// - Throws: If error occurs, throw error.
    /// - Returns: true on success, false if an error occurred.
    @objc
    public func deleteDid(_ did: String, error: NSErrorPointer) -> Bool {
        do {
            return try deleteDid(DID(did))
        } catch let aError as NSError {
            error?.pointee = aError
            return false
        }
    }
    
    
    /// List all DIDs according to the specified condition.
    /// - Throws: If error occurs, throw error.
    /// - Returns: the DID array.
    @objc
    public func listDids() throws -> Array<DID> {
        let dids = try storage!.listDids()

        try dids.forEach { did in
            let metadata = try loadDidMetadata(did)
            did.setMetadata(metadata)
        }

        return dids
    }
   // TODO:
//    public func selectDids(_ filter: ) throws -> Array<DID> {
//        let dids = try listDids()
//
//        try dids.forEach { did in
//            let metadata = try loadDidMetadata(did)
//            did.setMetadata(metadata)
//        }
//
//        return dids
//    }
    
    /// Store the specified Credential.
    /// - Parameter credential: the Credential object
    /// - Throws: If error occurs, throw error.
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

    /// Load the specified Credential.
    /// - Parameters:
    ///   - did: the owner of Credential
    ///   - byId: the identifier of Credential
    /// - Throws: If error occurs, throw error.
    /// - Returns: If no error occurs, return the Credential object. Otherwise, return nil.
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
    
    public func loadCredential(byId: String) throws -> VerifiableCredential? {
        
        return try loadCredential(byId: DIDURL.valueOf(byId))
    }
    
    /// Load Credential from DID Store.
    /// - Parameters:
    ///   - did: The handle to DID.
    ///   - byId: The identifier of credential.
    /// - Throws: If error occurs, throw error.
    /// - Returns: If no error occurs, return the handle to Credential. Otherwise, return nil.
    @objc
    public func loadCredential(byId: DIDURL, error: NSErrorPointer) -> VerifiableCredential? {
        do {
            return try loadCredential(byId: byId)
        } catch let aError as NSError {
            error?.pointee = aError
            return nil
        }
    }

    /// Load Credential from DID Store.
    /// - Parameters:
    ///   - did: The handle to DID.
    ///   - byId: The identifier of credential.
    /// - Throws: If error occurs, throw error.
    /// - Returns: If no error occurs, return the handle to Credential. Otherwise, return nil.
    @objc(loadCredentialbyId:error:)
    public func loadCredential(byId: String, error: NSErrorPointer) -> VerifiableCredential? {
        do {
            return try loadCredential(byId: byId)
        } catch let aError as NSError {
            error?.pointee = aError
            return nil
        }
    }

    /// Check if contain any credential of specific DID.
    /// - Parameters:
    ///   - did: the owner of Credential
    ///   - id: the identifier of Credential
    /// - Throws: If error occurs, throw error.
    /// - Returns: true on success, false if an error occurred.
    public func containsCredential(_ id: DIDURL) throws -> Bool {
        return try loadCredential(byId: id) != nil
    }
    
    /// Check if contain any credential of specific DID.
    /// - Parameters:
    ///   - did: The handle to DID.
    ///   - id: The identifier of credential.
    /// - Throws: If error occurs, throw error.
    /// - Returns: true on success, false if an error occurred.
    public func containsCredential(_ id: String) throws -> Bool {
        return try containsCredential(DIDURL.valueOf(id))
    }
    
    /// Check if contain any credential of specific DID.
    /// - Parameter did: the owner of Credential
    /// - Returns: true on success, false if an error occurred.
    @objc
    public func containsCredentials(_ did:DID) -> Bool {
        return storage!.containsCredentials(did)
    }
    
    /// Check if contain any credential of specific DID.
    /// - Parameter did: The handle to DID.
    /// - Returns: true on success, false if an error occurred.
    @objc(containsCredentialsWithDid:)
    public func containsCredentials(_ did: String) -> Bool {
        do {
            return containsCredentials(try DID.valueOf(did)!)
        } catch {
            return false
        }
    }
    
    /// Store meta data for the specified Credential.
    /// - Parameters:
    ///   - did: the owner of the specified Credential
    ///   - id: the identifier of Credential
    ///   - metadata: the meta data for Credential
    func storeCredentialMetadata(_ id: DIDURL, _ metadata: CredentialMetadata) throws {
        try storage!.storeCredentialMetadata(id, metadata)
        metadata.attachStore(self)
        
        cache.setValue(metadata, for: Key.forCredentialMetadata(id))
    }
    
    func storeCredentialMetadata(_ id: String, _ metadata: CredentialMetadata) throws {

        try storeCredentialMetadata(DIDURL.valueOf(id), metadata)
    }
    
    /// Load the meta data about the specified Credential.
    /// - Parameters:
    ///   - byId: the identifier of Credential
    /// - Returns: the meta data for Credential
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
    
    func loadCredentialMetadata(_ byId: String) throws -> CredentialMetadata? {

        return try loadCredentialMetadata(DIDURL.valueOf(byId))
    }
    
    /// Delete the specified Credential.
    /// - Parameters:
    ///   - did: the owner of Credential
    ///   - id: the identifier of Credential
    /// - Returns: true on success, false if an error occurred.
    @objc
    public func deleteCredential(_ id: DIDURL) -> Bool{
        let success = storage!.deleteCredential(id)
        
        if success {
            cache.removeValue(for: Key.forCredential(id))
            cache.removeValue(for: Key.forCredentialMetadata(id))
        }
        
        return success
    }
    
    /// List the Credentials owned the specified DID.
    /// - Parameters:
    ///   - did: the owner of Credential
    ///   - id: The identifier of credential.
    /// - Returns: true on success, false if an error occurred.
    public func deleteCredential(_ id: String) throws -> Bool{
        
        return try deleteCredential(DIDURL.valueOf(id))
    }
    
    /// List credentials of specific DID.
    /// - Parameter did: The handle to DID.
    /// - Throws: If error occurs, throw error.
    /// - Returns: the Credential array owned the specified DID.
    @objc
    public func listCredentials(for did: DID) throws -> Array<DIDURL> {
        let ids = try storage!.listCredentials(did)
        for id in ids {
            let metadata = try loadCredentialMetadata(id)
            id.setMetadata(metadata)
        }
        return ids
    }
    
    /// List the Credentials owned the specified DID.
    /// - Parameter did: the owner of Credential
    /// - Throws: if error occurs, throw error.
    /// - Returns: the Credential array owned the specified DID.
    @objc(listCredentials:error:)
    public func listCredentials(for did: String) throws -> Array<DIDURL> {
        return try listCredentials(for: DID(did))
    }

    /// Select the Credentials according to the specified condition.
    /// - Parameters:
    ///   - did: The handle to DID.
    ///   - id: The identifier of credential.
    ///   - type: The type of Credential to be selected.
    /// - Throws: If error occurs, throw error.
    /// - Returns: the Credential array
//    @objc // TODO:
//    public func selectCredentials(for did: DID,
//                                  byId id: DIDURL?,
//                             andType type: Array<String>?) throws -> Array<DIDURL> {
//        return try storage.selectCredentials(did, id, type)
//    }
//
//    /// Get credential conforming to identifier or type property.
//    /// - Parameters:
//    ///   - did: The handle to DID.
//    ///   - id: The identifier of credential.
//    ///   - type: The type of Credential to be selected.
//    /// - Throws: If error occurs, throw error.
//    /// - Returns: Array of DIDURL.
//    @objc(selectCredentials:id:type:error:)
//    public func selectCredentials(for did: String,
//                                  byId id: String?,
//                             andType type: Array<String>?) throws -> Array<DIDURL> {
//        let _did = try DID(did)
//        let _key = id != nil ? try DIDURL(_did, id!) : nil
//
//        return try selectCredentials(for: _did, byId: _key, andType: type)
//    }
    
    /// Store private key. Encrypt and encode private key with base64url method.
    /// - Parameters:
    ///   - did: the owner of key
    ///   - id: the identifier of key
    ///   - privateKey: the original private key(32 bytes)
    ///   - storePassword: the password for DIDStore
    /// - Throws: If error occurs, throw error.
    @objc
    public func storePrivateKey(for id: DIDURL,
                             privateKey: Data,
                    using storePassword: String) throws {

        try checkArgument(privateKey.count != 0, "Invalid private key")
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")

        
        let encryptedKey = try DIDStore.encryptToBase64(privateKey, storePassword)
        try storage!.storePrivateKey(id, encryptedKey)
    }
    
    /// Store private key.
    /// - Parameters:
    ///   - did: The handle to DID.
    ///   - id: The handle to public key identifier.
    ///   - privateKey: Private key string.
    ///   - storePassword: Password for DIDStore.
    /// - Throws: If error occurs, throw error.
    @objc(storePrivateKeyId:privateKey:storePassword:error:)
    public func storePrivateKey(for id: String,
                             privateKey: Data,
                    using storePassword: String) throws {
        let _key = try DIDURL.valueOf(id)

        return try storePrivateKey(for: _key, privateKey: privateKey, using: storePassword)
    }
    
//    func loadPrivateKey(_ did: DID, _ byId: DIDURL, _ storePassword: String) throws -> Data {
//        let encryptedKey = try storage.loadPrivateKey(did, byId)
//        let keyBytes = try DIDStore.decryptFromBase64(encryptedKey, storePassword)
//
//        // For backward compatible, convert to extended private key
//        // TODO: Should be remove in the future
//        var extendedKeyBytes: Data?
//        if keyBytes.count == DIDHDKey.DID_PRIVATEKEY_BYTES {
//            let identity = try? loadPrivateIdentity(storePassword)
//            if identity != nil {
//                for i in 0..<100 {
//                    let path = DIDHDKey.DID_DERIVE_PATH_PREFIX + "\(i)"
//                    let child = try identity!.derive(path)
//                    if child.getPrivateKeyData() == keyBytes {
//                        extendedKeyBytes = try child.serialize()
//                        break
//                    }
//                    child.wipe()
//                }
//                identity?.wipe()
//            }
//            if extendedKeyBytes == nil {
//                extendedKeyBytes = DIDHDKey.paddingToExtendedPrivateKey(keyBytes)
//            }
//            try storePrivateKey(for: did, id: byId, privateKey: extendedKeyBytes!, using: storePassword)
//        }
//        else {
//            extendedKeyBytes = keyBytes
//        }
//
//        return extendedKeyBytes!
//    }
    
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
        guard let _ = encryptedKey else {
            // fail-back to lazy private key generation
            return try RootIdentity.lazyCreateDidPrivateKey(id, self, storePassword)
        }
        
        return try decrypt(encryptedKey!, storePassword)
    }
    
    /// Check if contain specific private key of specific DID.
    /// - Parameters:
    ///   - did: The handle to DID.
    ///   - id: The identifier of public key.
    /// - Returns: true on success, false if an error occurred.
    public func containsPrivateKey(for id: DIDURL) throws -> Bool {
        return try loadPrivateKey(id) != nil
    }
    
    /// Check if contain specific private key of specific DID.
    /// - Parameters:
    ///   - did: The handle to DID.
    ///   - id: The identifier of public key.
    /// - Returns: true on success, false if an error occurred.
    public func containsPrivateKey(for id: String) throws -> Bool {
        do {
            let _key = try DIDURL.valueOf(id)
            return try containsPrivateKey(for: _key)
        } catch {
            return false
        }
    }

    /// Check if contain any private key of specific DID.
    /// - Parameter did: The handle to DID.
    /// - Returns: true on success, false if an error occurred.
    public func containsPrivateKeys(for did: DID) throws -> Bool {
        return try storage!.containsPrivateKeys(did)
    }
    
    /// Check if contain any private key of specific DID.
    /// - Parameter did: The handle to DID.
    /// - Returns: true on success, false if an error occurred.
    @objc(containsPrivateKeys:)
    public func containsPrivateKeys(for did: String) -> Bool {
        do {
            return try containsPrivateKeys(for: try DID(did))
        } catch {
            return false
        }
    }

    /// Delete the private key owned to the specified key.
    /// - Parameters:
    ///   - did: the owner of key
    ///   - id: the identifier of publick key
    /// - Returns: true on success, false if an error occurred.
    @objc
    public func deletePrivateKey(for id: DIDURL) -> Bool {
        let success = storage!.deletePrivateKey(id)
        if success {
            cache.removeValue(for: Key.forDidPrivateKey(id))
        }
        
        return success
    }
    
    /// Delete the private key owned to the specified key.
    /// - Parameters:
    ///   - did: the owner of key
    ///   - id: the identifier of key
    /// - Returns: true on success, false if an error occurred.
    @objc(deletePrivateKeyId:)
    public func deletePrivateKey(for id: String) -> Bool {
        do {
            let _key = try DIDURL.valueOf(id)
            
            return deletePrivateKey(for: _key)
        } catch {
            return false
        }
    }
    
    /// Sign the digest data by the specified key.
    /// - Parameters:
    ///   - did: the owner of sign key
    ///   - id: the identifier of sign key
    ///   - storePassword: storePassword the password for DIDStore
    ///   - digest: the digest data
    /// - Returns: the signature string
    func sign(WithId id: DIDURL, using storePassword: String, for digest: Data, _ capacity: Int) throws -> String {
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        try checkArgument(digest.count > 0, "Invalid digest")
        
        let key = try DIDHDKey.deserialize(loadPrivateKey(id, storePassword)!)
        let privatekeys = key.getPrivateKeyData()
        let toPPointer = privatekeys.toPointer()
        
        let cdigest = digest.toPointer()
        print("capacity = \(capacity)")
        let csig = UnsafeMutablePointer<CChar>.allocate(capacity: capacity)
        let re = ecdsa_sign_base64(csig, toPPointer, UnsafeMutablePointer(mutating: cdigest), digest.count)

        guard re >= 0 else {
            throw DIDError.didStoreError("sign error.")
        }
        csig[re] = 0
        let sig = String(cString: csig)
        key.wipe()
        return sig
    }

    func sign(WithId id: String, using storePassword: String, for digest: Data, capacity: Int) throws -> String {

        return try sign(WithId: DIDURL.valueOf(id), using: storePassword, for: digest, capacity)
    }
    
    ///  Change password for DIDStore.
    /// - Parameters:
    ///   - oldPassword: oldPassword the old password
    ///   - newPassword: newPassword the new password
    @objc
    public func changePassword(_ oldPassword: String, _ newPassword: String) throws {
        try checkArgument(!oldPassword.isEmpty, "Invalid old password")
        try checkArgument(!newPassword.isEmpty, "Invalid new password")
        
        try storage?.changePassword{ data -> String in
            let result = try DIDStore.reEncrypt(data, oldPassword, newPassword)
            
            return result
        }
//        let re: (String) throws -> String = { (data: String) -> String in
////            let udata = try DIDStore.decryptFromBase64(data, oldPassword)
////            let result = try DIDStore.encryptToBase64(udata, newPassword)
//            let result = try DIDStore.reEncrypt(data, oldPassword, newPassword)
//
//            return result
//        }
        try metadata!.setFingerprint(calcFingerprint(newPassword))
        cache.clear()
    }

    private func synchronize(_ conflictHandler: ConflictHandler?) throws {
        var h = conflictHandler
        if h == nil {
            h = DIDStore.defaultConflictHandle
        }
        let identities = try storage!.listRootIdentities()
        for identity in identities {
            try identity.synchronize(h)
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
                        throw DIDError.didStoreError("deal with local modification error.")
                    } else {
                        Log.d(TAG, "Conflict handle return the final copy.")
                    }
                }

                try storage!.storeDid(finalDoc!)
            }
            
            let vcIds = try storage!.listCredentials(did)
            for vcId in vcIds {
                let localVc = try storage!.loadCredential(vcId)
                let resolvedVc = VerifiableCredential.resolve(vcId, localVc!.issuer!)
                if resolvedVc == nil {
                    continue
                }
                resolvedVc.getMetadata().merge(localVc!.getMetadata())
                try storage!.storeCredential(resolvedVc)
            }
        }
    }
    
    public func synchronize() throws {
        try synchronize(nil)
    }
    
    public func synchronizeAsync(_ handle: @escaping ConflictHandler) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try synchronize(handle) }
    }
    
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

    /// Synchronize DIDStore asynchronously.
    /// - Parameters:
    ///   - storePassword: The pass word of DID holder.
    ///   - conflictHandler: The method to merge document.
    /// - Returns: Void
    @objc
    public func synchornizeAsyncUsingObjectC(_ conflictHandler: @escaping ConflictHandler) -> AnyPromise {

        return synchronizeAsync_oc(conflictHandler)
    }

    /// Synchronize DIDStore asynchronously.
    /// - Parameter storePassword: The pass word of DID holder.
    /// - Throws: If error occurs, throw error.
    /// - Returns: Void
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
            throw DIDError.notFoundError("data is not nil")
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
        let dic = try JSONSerialization.jsonObject(with: data,options: JSONSerialization.ReadingOptions.mutableContainers) as? [String: Any]
        guard let _ = dic else {
            throw DIDError.notFoundError("data is not nil")
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
            let ert = try exportRootIdentity(ri.id!, password, storePassword).serialize(true).toDictionary()as [String: Any]
                arrayRis.append([rootIdentityStr: ert])
        }
        let dids = try listDids()
        for did in dids {
            let didstr = did.methodSpecificId
            let edid = try exportDid(did, password, storePassword).serialize(true).toDictionary()as [String: Any]
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
        
        let fileManager = FileManager.default
        let enumerator = try fileManager.contentsOfDirectory(atPath: path)
        if enumerator.count == 0 {
            return
        }
        var path0 = ""
        var dic: [String: Any] = [: ]
        for element: String in enumerator  {
            path0 = path + "/" + element
            if element == ".DS_Store" {
                continue
            }
            path0 = path + "/" + element
            dic = try path0.readTextFromPath().toDictionary() as [String: Any]
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
