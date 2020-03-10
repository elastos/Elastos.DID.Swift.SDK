import Foundation
import PromiseKit

public typealias ConflictHandler = (_ chainCopy: DIDDocument, _ localCopy: DIDDocument) throws -> DIDDocument

public class DIDStore: NSObject {
    public static let CACHE_INITIAL_CAPACITY = 16
    public static let CACHE_MAX_CAPACITY = 32
    
    public static let DID_HAS_PRIVATEKEY = 0
    public static let DID_NO_PRIVATEKEY = 1
    public static let DID_ALL = 2

    private var documentCache: LRUCache<DID, DIDDocument>?
    private var credentialCache: LRUCache<DIDURL, VerifiableCredential>?

    private var storage: DIDStorage
    private var backend: DIDBackend

    private init(_ initialCapacity: Int, _ maxCapacity: Int, _ adapter: DIDAdapter, _ storage: DIDStorage) {
        if maxCapacity > 0 {
            documentCache = LRUCache<DID, DIDDocument>(initialCapacity, maxCapacity)
            credentialCache = LRUCache<DIDURL, VerifiableCredential>(initialCapacity, maxCapacity)
        }

        self.backend = DIDBackend.getInstance(adapter)
        self.storage = storage
    }

    private class func openStore(_ path: String,
                                 _ type: String,
                                 _ initialCacheCapacity: Int,
                                 _ maxCacheCapacity: Int,
                                 _ adapter: DIDAdapter) throws -> DIDStore {
        guard !path.isEmpty else {
            throw DIDError.illegalArgument()
        }

        guard maxCacheCapacity >= initialCacheCapacity else {
            throw DIDError.illegalArgument()
        }

        guard type == "filesystem" else {
            throw DIDError.illegalArgument("Unsupported store type:\(type)")
        }

        return DIDStore(initialCacheCapacity, maxCacheCapacity, adapter, try FileSystemStorage(path))
    }

    public class func openStore(atPath: String,
                              withType: String,
                  initialCacheCapacity: Int,
                      maxCacheCapacity: Int,
                               adapter: DIDAdapter) throws -> DIDStore {

        return try openStore(atPath, withType, initialCacheCapacity, maxCacheCapacity, adapter)
    }
    
    public class func openStore(atPath: String,
                              withType: String,
                               adapter: DIDAdapter) throws -> DIDStore {

        return try openStore(atPath, withType, CACHE_INITIAL_CAPACITY, CACHE_MAX_CAPACITY, adapter)
    }
    
    public func containsPrivateIdentity() throws -> Bool {
        return storage.containsPrivateIdentity()
    }

    class func encryptToBase64(_ input: Data, _ storePass: String) throws -> String {
        // TDDO
        return "TODO"
    }

    class func decryptFromBase64(_ input: String, _ storePass: String) throws -> Data {
        // TODO
        return Data()
    }

    // Initialize & create new private identity and save it to DIDStore.
    private func initializePrivateIdentity(_ language: String,
                                           _ mnemonic: String,
                                           _ passPhrase: String?,
                                           _ storePassword: String,
                                           _ force: Bool ) throws {
        guard try Mnemonic.isValid(language, mnemonic) else {
            throw DIDError.illegalArgument()
        }

        guard !storePassword.isEmpty else {
            throw DIDError.illegalArgument()
        }

        guard try !containsPrivateIdentity() || force else {
            throw DIDError.didStoreError("Already has private indentity.")
        }

        var usedPhrase = passPhrase
        if (usedPhrase == nil) {
            usedPhrase = ""
        }

        let privateIdentity = HDKey.fromMnemonic(mnemonic, usedPhrase!, Mnemonic.getLanguageId(language))
        try initializePrivateIdentity(privateIdentity, storePassword)

        // Save mnemonic
        let mnemonicData = mnemonic.data(using: .utf8)!
        let encryptedMnemonic = try DIDStore.encryptToBase64(mnemonicData, storePassword)
        try storage.storeMnemonic(encryptedMnemonic)
    }

    public func initializePrivateIdentity(using language: String,
                                                mnemonic: String,
                                              passPhrase: String,
                                           storePassword: String,
                                                 _ force: Bool ) throws {

        try initializePrivateIdentity(language, mnemonic, passPhrase, storePassword, force)
    }

    public func initializePrivateIdentity(using language: String,
                                                mnemonic: String,
                                           storePassword: String,
                                                 _ force: Bool ) throws {

        try initializePrivateIdentity(language, mnemonic, nil, storePassword, force)
    }

    public func initializePrivateIdentity(using language: String,
                                                mnemonic: String,
                                              passPhrase: String,
                                           storePassword: String) throws {

        try initializePrivateIdentity(language, mnemonic, passPhrase, storePassword, false)
    }

    public func initializePrivateIdentity(using language: String,
                                                mnemonic: String,
                                           storePassword: String) throws {

        try initializePrivateIdentity(language, mnemonic, nil, storePassword, false)
    }

    private func initializePrivateIdentity(_ privateIdentity: HDKey,
                                           _ storePassword: String) throws {

        let encryptedIdentity = try DIDStore.encryptToBase64(privateIdentity.serialize(), storePassword)
        try storage.storePrivateIdentity(encryptedIdentity)

        try storage.storePrivateIdentityIndex(0)
        privateIdentity.wipe()
    }

    private func initializePrivateIdentity(_ extendedPrivateKey: String,
                                           _ storePassword: String,
                                           _ force: Bool) throws {
        guard !extendedPrivateKey.isEmpty else {
            throw DIDError.illegalArgument()
        }

        guard !storePassword.isEmpty else {
            throw DIDError.illegalArgument()
        }

        guard try !containsPrivateIdentity() || force else {
            throw DIDError.didStoreError("Already has private indentity.")
        }
        let privateIdentity = try HDKey.deserialize(Base58.bytesFromBase58(extendedPrivateKey))
        try initializePrivateIdentity(privateIdentity, storePassword)
    }

    public func initializePrivateIdentity(using extendedPrivateKey: String,
                                                     storePassword: String,
                                                           _ force: Bool) throws {

        return try initializePrivateIdentity(extendedPrivateKey, storePassword, force)
    }

    public func initializePrivateIdentity(using extendedPrivateKey: String,
                                                     storePassword: String) throws {

        return try initializePrivateIdentity(extendedPrivateKey, storePassword, false)
    }
    
    public func exportMnemonic(using storePassword: String) throws -> String {
        guard !storePassword.isEmpty else {
            throw DIDError.illegalArgument()
        }

        let encryptedMnemonic = try storage.loadMnemonic()
        let decryptedMnemonic = try DIDStore.decryptFromBase64(encryptedMnemonic, storePassword)
        return String(data: decryptedMnemonic, encoding: .utf8)!
    }

    // initialized from saved private identity in DIDStore.
    func loadPrivateIdentity(_ storePassword: String) throws -> HDKey {
        guard try containsPrivateIdentity() else {
            throw DIDError.didStoreError("no private identity contained.")
        }

        let privateIdentity: HDKey
        var keyData = try DIDStore.decryptFromBase64(storage.loadPrivateIdentity(), storePassword)
        defer {
            keyData.removeAll()
        }

        if  keyData.count == HDKey.SEED_BYTES {
            privateIdentity = HDKey.fromSeed(keyData)

            // convert to extended root private key.
            let encryptedIdentity = try DIDStore.encryptToBase64(privateIdentity.serialize(), storePassword)
            try storage.storePrivateIdentity(encryptedIdentity)
        } else if keyData.count == HDKey.EXTENDED_PRIVATE_BYTES {
            privateIdentity = try HDKey.deserialize(keyData)
        } else {
            throw DIDError.didStoreError("invalid private identity")
        }
        return privateIdentity
    }

    private func synchronize(_ storePassword: String,
                             _ conflictHandler: ConflictHandler) throws {

        guard !storePassword.isEmpty else {
            throw DIDError.illegalArgument()
        }

        let nextIndex = try storage.loadPrivateIdentityIndex()
        let privateIdentity: HDKey
        do {
            privateIdentity = try loadPrivateIdentity(storePassword)
        } catch {
            throw DIDError.didStoreError("DID Store does not contains private identity")
        }

        defer {
            privateIdentity.wipe()
        }

        var blanks = 0
        var index = 0

        while index < nextIndex || blanks < 10 {
            let key: HDKey.DerivedKey = privateIdentity.derivedKey(index++)
            let did = DID(Constants.METHOD, key.getAddress())
            let chainCopy: DIDDocument?

            defer {
                key.wipe()
            }

            do {
                chainCopy = try DIDBackend.resolve(did, true)
            } catch DIDError.didExpired {
                continue
            } catch DIDError.didDeactivated {
                continue
            }

            if let _ = chainCopy {
                var finalCopy: DIDDocument? = chainCopy!
                let localCopy: DIDDocument?

                do {
                    localCopy = try loadDid(did)
                } catch {
                    localCopy = nil
                }

                if let _ = localCopy {
                    if  localCopy!.getMeta().signature == nil ||
                        localCopy!.proof.signature != localCopy!.getMeta().signature {

                        // local copy was modified.
                        do {
                            finalCopy = try conflictHandler(chainCopy!, localCopy!)
                        } catch {
                            finalCopy = nil
                        }

                        if finalCopy?.subject != did {
                            throw DIDError.didStoreError("deal with local modification error.")
                        }
                    }
                }

                // save private key
                try storePrivateKey(for: did, id: finalCopy!.defaultPublicKey, privateKey: key.serialize(), using: storePassword)
                try storeDid(using: finalCopy!)

                if index >= nextIndex {
                    try storage.storePrivateIdentityIndex(index)
                }
                blanks = 0
            } else {
                if index >= nextIndex {
                    blanks += 1
                }
            }
        }
    }

    public func synchronize(using storePassword: String,
                                conflictHandler: ConflictHandler) throws {

        return try synchronize(storePassword, conflictHandler)
    }

    public func synchronize(using storePassword: String) throws {

        return try synchronize(storePassword) { (chainCopy, localCopy) throws -> DIDDocument in
            return localCopy
        }
    }

    private func synchronizeAsync(_ storePassword: String,
                                  _ conflictHandler: ConflictHandler) -> Promise<Void> {
        return Promise<Void> { resolver in
            do {
                try synchronize(storePassword, conflictHandler)
                resolver.fulfill(())
            } catch let error  {
                resolver.reject(error)
            }
        }
    }

    public func synchornizeAsync(using storePassword: String,
                                     conflictHandler: ConflictHandler) -> Promise<Void> {

        return synchronizeAsync(storePassword, conflictHandler)
    }

    public func synchronizeAsync(using storePassword: String) throws -> Promise<Void> {

        return synchronizeAsync(storePassword) { (chainCopy, localCopy) throws -> DIDDocument in
            return localCopy
        }
    }

    private func newDid(_ privateIdentityIndex: Int,
                        _ alias: String?,
                        _ storePassword: String) throws -> DIDDocument {
        guard privateIdentityIndex >= 0 else {
            throw DIDError.illegalArgument()
        }

        guard !storePassword.isEmpty else {
            throw DIDError.illegalArgument()
        }

        let privateIdentity = try loadPrivateIdentity(storePassword)
        let key = privateIdentity.derivedKey(privateIdentityIndex)

        defer {
            privateIdentity.wipe()
            key.wipe()
        }

        let did = DID(Constants.METHOD, key.getAddress())
        var doc: DIDDocument?
        do {
            doc = try loadDid(did)
            // TODO: throw error
        } catch {
            doc = nil
        }

        let id  = try DIDURL(did, "primary")
        try storePrivateKey(for: did, id: id, privateKey: key.serialize(), using: storePassword)

        let builder = DIDDocumentBuilder(did, self)
        doc = try builder.appendAuthenticationKey(id, key.getPublicKeyBase58()).sealed(using: storePassword)
        doc!.getMeta().setAlias(alias)
        try storeDid(using: doc!)

        return doc!
    }

    public func newDid(withPrivateIdentityIndex: Int,
                                          alias: String,
                            using storePassword: String) throws -> DIDDocument {

        return try newDid(withPrivateIdentityIndex, alias, storePassword)
    }
    
    public func newDid(withPrivateIdentityIndex: Int,
                            using storePassword: String) throws -> DIDDocument {

        return try newDid(withPrivateIdentityIndex, nil, storePassword)
    }

    private func newDid(_ alias: String?, _ storePassword: String) throws -> DIDDocument {
        var nextIndex = try storage.loadPrivateIdentityIndex()
        nextIndex += 1

        let doc = try newDid(nextIndex, alias, storePassword)
        try storage.storePrivateIdentityIndex(nextIndex)

        return doc
    }

    public func newDid(withAlias: String, using storePassword: String) throws -> DIDDocument {
        return try newDid(withAlias, storePassword)
    }

    public func newDid(using storePassword: String) throws -> DIDDocument {
        return try newDid(nil, storePassword)
    }

    public func getDid(byPrivateIdentityIndex: Int, using storePassword: String) throws -> DID {
        guard byPrivateIdentityIndex >= 0 else {
            throw DIDError.illegalArgument()
        }
        guard !storePassword.isEmpty else {
            throw DIDError.illegalArgument()
        }

        let privateIdentity = try loadPrivateIdentity(storePassword)
        let key = privateIdentity.derivedKey(byPrivateIdentityIndex)
        let did = DID(Constants.METHOD, key.getAddress())

        privateIdentity.wipe()
        key.wipe()

        return did
    }

    private func publishDid(_ did: DID,
                            _ confirms: Int,
                            _ signKey: DIDURL?,
                            _ storePassword: String,
                            _ force: Bool) throws -> String {
        guard !storePassword.isEmpty else {
            throw DIDError.illegalArgument()
        }

        let doc: DIDDocument
        do {
            doc = try loadDid(did)
        } catch {
            throw DIDError.didStoreError("Can not find the document for \(did)")
        }

        guard !doc.isDeactivated else {
            throw DIDError.didStoreError("DID already deactivated.")
        }

        var lastTransactionId: String? = nil
        let resolvedDoc = try did.resolve()

        guard !resolvedDoc.isDeactivated else {
            throw  DIDError.didStoreError("DID already deactivated")
        }

        if !force {
            let localTxId = doc.getMeta().transactionId
            let localSignature = doc.getMeta().signature

            let resolvedTxId = resolvedDoc.getMeta().transactionId!
            let resolvedSignature = resolvedDoc.getMeta().signature!

            guard localTxId != nil || localSignature != nil else {
                throw DIDError.didStoreError("DID document not up-to-date")
            }

            guard localTxId == nil || localTxId == resolvedTxId else {
                throw DIDError.didStoreError("DID document not up-to-date")
            }

            guard localSignature == nil || localSignature == resolvedSignature else {
                throw DIDError.didStoreError("DID document not up-to-date")
            }
        }

        lastTransactionId = resolvedDoc.transactionId!

        var usedSignKey = signKey
        if  usedSignKey == nil {
            usedSignKey = doc.defaultPublicKey
        }

        if  lastTransactionId?.isEmpty ?? true {
            lastTransactionId = try backend.create(doc, confirms, usedSignKey!, storePassword)
        } else {
            lastTransactionId = try backend.update(doc, lastTransactionId!, confirms, usedSignKey!, storePassword)
        }

        if let _ = lastTransactionId {
            doc.getMeta().setTransactionId(lastTransactionId!)
        }

        doc.getMeta().setSignature(doc.proof.signature)
        try storage.storeDidMeta(doc.subject, doc.getMeta())

        return lastTransactionId ?? ""
    }

    public func publishDid(for did: DID,
                   waitForConfirms: Int,
                     using signKey: DIDURL,
                     storePassword: String,
                           _ force: Bool) throws -> String {

        return try publishDid(did, waitForConfirms, signKey, storePassword, force)
    }

    public func publishDid(for did: DID,
                   waitForConfirms: Int,
                     using signKey: DIDURL,
                     storePassword: String) throws -> String {

        return try publishDid(did, waitForConfirms, signKey, storePassword, false)
    }

    public func publishDid(for did: String,
                   waitForConfirms: Int,
                     using signKey: String,
                     storePassword: String,
                           _ force: Bool) throws -> String {

        let _did = try DID(did)
        let _key = try DIDURL(_did, signKey)

        return try publishDid(_did, waitForConfirms, _key, storePassword, force)
    }

    public func publishDid(for did: String,
                   waitForConfirms: Int,
                     using signKey: String,
                     storePassword: String) throws -> String {

        let _did = try DID(did)
        let _key = try DIDURL(_did, signKey)

        return try publishDid(_did, waitForConfirms, _key, storePassword, false)
    }

    public func publishDid(for did: DID,
                     using signKey: DIDURL,
                     storePassword: String) throws -> String {

        return try publishDid(did, 0, signKey, storePassword, false)
    }

    public func publishDid(for did: String,
                     using signKey: String,
                     storePassword: String) throws -> String {

        let _did = try DID(did)
        let _key = try DIDURL(_did, signKey)

        return try publishDid(_did, 0, _key, storePassword, false)
    }

    public func publishDid(for did: DID,
                   waitForConfirms: Int,
               using storePassword: String) throws -> String {

        return try publishDid(did, 0, nil, storePassword, false)
    }

    public func publishDid(for did: String,
                   waitForConfirms: Int,
               using storePassword: String) throws -> String {

        return try publishDid(DID(did), 0, nil, storePassword, false)
    }

    public func publishDid(for did: DID,
               using storePassword: String) throws -> String {

        return try publishDid(did, 0, nil, storePassword, false)
    }

    public func publishDid(for did: String,
               using storePassword: String) throws -> String {

        return try publishDid(DID(did), 0, nil, storePassword, false)
    }

    private func publishDidAsync(_ did: DID,
                                 _ confirms: Int,
                                 _ signKey: DIDURL?,
                                 _ storePassword: String,
                                 _ force: Bool) -> Promise<String> {

        return Promise<String> { resolver in
            do {
                resolver.fulfill(try publishDid(did, confirms, signKey, storePassword, force))
            } catch let error  {
                resolver.reject(error)
            }
        }
    }

    public func publishDidAsync(for did: DID,
                        waitForConfirms: Int,
                          using signKey: DIDURL,
                          storePassword: String,
                                _ force: Bool) -> Promise<String> {

        return publishDidAsync(did, waitForConfirms, signKey, storePassword, force)
    }

    public func publishDidAsync(for did: DID,
                        waitForConfirms: Int,
                          using signKey: DIDURL,
                          storePassword: String) -> Promise<String> {

        return publishDidAsync(did, waitForConfirms, signKey, storePassword, false)
    }

    public func publishDidAsync(for did: String,
                        waitForConfirms: Int,
                          using signKey: String,
                          storePassword: String,
                                _ force: Bool) throws -> Promise<String> {

        let _did = try DID(did)
        let _key = try DIDURL(_did, signKey)

        return publishDidAsync(_did, waitForConfirms, _key, storePassword, force)
    }

    public func publishDidAsync(for did: String,
                        waitForConfirms: Int,
                          using signKey: String,
                          storePassword: String) throws -> Promise<String> {

        let _did = try DID(did)
        let _key = try DIDURL(_did, signKey)

        return publishDidAsync(_did, waitForConfirms, _key, storePassword, false)
    }

    public func publishDidAsync(for did: DID,
                     using signKey: DIDURL,
                     storePassword: String) -> Promise<String> {

        return publishDidAsync(did, 0, signKey, storePassword, false)
    }

    public func publishDidAsync(for did: String,
                     using signKey: String,
                     storePassword: String) throws -> Promise<String> {

        let _did = try DID(did)
        let _key = try DIDURL(_did, signKey)

        return publishDidAsync(_did, 0, _key, storePassword, false)
    }

    public func publishDidAsync(for did: DID,
                   waitForConfirms: Int,
               using storePassword: String) -> Promise<String> {

        return publishDidAsync(did, 0, nil, storePassword, false)
    }

    public func publishDidAsync(for did: String,
                   waitForConfirms: Int,
               using storePassword: String) throws -> Promise<String> {

        return publishDidAsync(try DID(did), 0, nil, storePassword, false)
    }

    public func publishDidAsync(for did: DID,
               using storePassword: String) -> Promise<String> {

        return publishDidAsync(did, 0, nil, storePassword, false)
    }

    public func publishDidAsync(for did: String,
               using storePassword: String) throws -> Promise<String> {

        return publishDidAsync(try DID(did), 0, nil, storePassword, false)
    }

    // Deactivate self DID using authentication keys
    private func deactivateDid(_ did: DID,
                               _ confirms: Int,
                               _ signKey: DIDURL?,
                               _ storePassword: String) throws -> String {

        guard !storePassword.isEmpty else {
            throw DIDError.didStoreError()
        }

        // Document should use the IDChain's copy
        var localCopy = false
        var doc: DIDDocument?
        do {
            doc = try DIDBackend.resolve(did)
        } catch {
            throw DIDError.didStoreError("Can not find the document for \(did)")
        }

        if doc == nil {
            // Fail-back: try to load document from local store.
            do {
                doc = try loadDid(did)
            } catch {
                throw DIDError.didStoreError("Can not resolve DID document")
            }
            localCopy = true
        } else {
            doc!.getMeta().setStore(self)
        }

        var usedSignKey = signKey
        if  usedSignKey == nil {
            usedSignKey = doc!.defaultPublicKey
        }

        let transactionId = try backend.deactivate(doc!, usedSignKey!, storePassword)

        // Save deactivated status to DID metadata
        if localCopy {
            doc!.getMeta().setDeactivated(true)
            try storage.storeDidMeta(did, doc!.getMeta())
        }

        return transactionId
    }

    public func deactivateDid(for target: DID,
                         waitForConfirms: Int,
                           using signKey: DIDURL,
                           storePassword: String) throws -> String {

        return try deactivateDid(target, waitForConfirms, signKey, storePassword)
    }

    public func deactivateDid(for target: String,
                         waitForConfirms: Int,
                           using signKey: String,
                           storePassword: String) throws -> String {

        let _did = try DID(target)
        let _key = try DIDURL(_did, signKey)

        return try deactivateDid(_did, waitForConfirms, _key, storePassword)
    }

    public func deactivateDid(for target: DID,
                           using signKey: DIDURL,
                           storePassword: String) throws -> String {

        return try deactivateDid(target, 0, signKey, storePassword)
    }

    public func deactivateDid(for target: String,
                           using signKey: String,
                           storePassword: String) throws -> String {

        let _did = try DID(target)
        let _key = try DIDURL(_did, signKey)

        return try deactivateDid(_did, 0, _key, storePassword)
    }

    public func deactivateDid(for target: DID,
                         waitForConfirms: Int,
                     using storePassword: String) throws -> String {

        return try deactivateDid(target, waitForConfirms, nil, storePassword)
    }

    public func deactivateDid(for target: String,
                         waitForConfirms: Int,
                     using storePassword: String) throws -> String {

        return try deactivateDid(DID(target), waitForConfirms, nil, storePassword)
    }

    public func deactivateDid(for target: DID,
                     using storePassword: String) throws -> String {

        return try deactivateDid(target, 0, nil, storePassword)
    }

    public func deactivateDid(for target: String,
                     using storePassword: String) throws -> String {

        return try deactivateDid(DID(target), 0, nil, storePassword)
    }

    private func deactivateDidAsync(_ target: DID,
                                    _ confirms: Int,
                                    _ signKey: DIDURL?,
                                    _ storePassword: String) -> Promise<String> {

        return Promise<String> { resolver in
            do {
                resolver.fulfill(try deactivateDid(target, confirms, signKey, storePassword))
            } catch let error  {
                resolver.reject(error)
            }
        }
    }

    public func deactivateDidAsync(for target: DID,
                         waitForConfirms: Int,
                           using signKey: DIDURL,
                           storePassword: String) throws -> Promise<String> {

        return deactivateDidAsync(target, waitForConfirms, signKey, storePassword)
    }

    public func deactivateDidAsync(for target: String,
                         waitForConfirms: Int,
                           using signKey: String,
                           storePassword: String) throws -> Promise<String> {

        let _did = try DID(target)
        let _key = try DIDURL(_did, signKey)

        return deactivateDidAsync(_did, waitForConfirms, _key, storePassword)
    }

    public func deactivateDidAsync(for target: DID,
                           using signKey: DIDURL,
                           storePassword: String) throws -> Promise<String> {

        return deactivateDidAsync(target, 0, signKey, storePassword)
    }

    public func deactivateDidAsync(for target: String,
                           using signKey: String,
                           storePassword: String) throws -> Promise<String> {

        let _did = try DID(target)
        let _key = try DIDURL(_did, signKey)

        return deactivateDidAsync(_did, 0, _key, storePassword)
    }

    public func deactivateDidAsync(for target: DID,
                         waitForConfirms: Int,
                     using storePassword: String) throws -> Promise<String> {

        return deactivateDidAsync(target, waitForConfirms, nil, storePassword)
    }

    public func deactivateDidAsync(for target: String,
                         waitForConfirms: Int,
                     using storePassword: String) throws -> Promise<String> {

        return deactivateDidAsync(try DID(target), waitForConfirms, nil, storePassword)
    }

    public func deactivateDidAsync(for target: DID,
                     using storePassword: String) throws -> Promise<String> {

        return deactivateDidAsync(target, 0, nil, storePassword)
    }

    public func deactivateDidAsync(for target: String,
                     using storePassword: String) throws -> Promise<String> {

        return deactivateDidAsync(try DID(target), 0, nil, storePassword)
    }

    // Deactivate target DID with authorization
    private func deactivateDid(_ target: DID,
                               _ did: DID,
                               _ confirms: Int,
                               _ signKey: DIDURL?,
                               _ storePassword: String) throws -> String {
        guard !storePassword.isEmpty else {
            throw DIDError.didStoreError()
        }

        // All document should use the IDChain's copy
        var doc: DIDDocument?
        do {
            doc = try DIDBackend.resolve(did)
        } catch {
            throw DIDError.didStoreError("Can not find the document for \(did)")
        }

        if doc == nil {
            // Fail-back: try to load document from local store.
            do {
                doc = try loadDid(did)
            } catch {
                throw DIDError.didStoreError("Can not resolve DID document")
            }
        } else {
            doc!.getMeta().setStore(self)
        }

        var signPk: PublicKey? = nil
        if let _ = signKey {
            signPk = doc!.authenticationKey(ofId: signKey!)
            guard let _ = signPk else {
                throw DIDError.unknownFailure("Not authentication key.") // TODO:
            }
        }

        let targetDoc = try DIDBackend.resolve(target)
        guard let _ = targetDoc else {
            throw DIDError.didResolveError("DID \(target) not exist")
        }
        guard targetDoc!.authorizationKeyCount > 0 else {
            throw DIDError.unknownFailure("No authorization.")      // TODO:
        }

        // The authorization key id in the target doc
        var targetSignKey: DIDURL? = nil
        var usedSignKey: DIDURL? = signKey
        matchLoop: for targetKey in targetDoc!.authorizationKeys() {
            if targetKey.controller != did {
                continue
            }
            if let _ = signPk {
                if targetKey.publicKeyBase58 != signPk!.publicKeyBase58 {
                    continue
                }

                targetSignKey = targetKey.getId()
                break
            } else {
                for pk in doc!.authenticationKeys() {
                    if pk.publicKeyBase58 == targetKey.publicKeyBase58 {
                        signPk = pk
                        usedSignKey = signPk?.getId()
                        targetSignKey = targetKey.getId()
                    }
                }
            }
        }

        guard let _ = targetSignKey else {
            throw DIDError.didStoreError("no matched authorization key found.")
        }

        return try backend.deactivate(target, targetSignKey!, doc!, usedSignKey!, storePassword)
    }


    public func deactivateDid(for target: DID,
                    withAuthroizationDid: DID,
                         waitForConfirms: Int,
                           using signKey: DIDURL,
                           storePassword: String) throws -> String {

        return try deactivateDid(target, withAuthroizationDid, waitForConfirms, signKey, storePassword)
    }

    public func deactivateDid(for target: String,
                    withAuthroizationDid: String,
                         waitForConfirms: Int,
                           using signKey: String,
                           storePassword: String) throws -> String {

        let _did = try DID(withAuthroizationDid)
        let _key = try DIDURL(_did, signKey)

        return try deactivateDid(DID(target), _did, waitForConfirms, _key, storePassword)
    }

    public func deactivateDid(for target: DID,
                    withAuthroizationDid: DID,
                           using signKey: DIDURL,
                           storePassword: String) throws -> String {

        return try deactivateDid(target, withAuthroizationDid, 0, signKey, storePassword)
    }

    public func deactivateDid(for target: String,
                    withAuthroizationDid: String,
                           using signKey: String,
                           storePassword: String) throws -> String {

        let _did = try DID(withAuthroizationDid)
        let _key = try DIDURL(_did, signKey)

        return try deactivateDid(DID(target), _did, 0, _key, storePassword)
    }

    public func deactivateDid(for target: DID,
                    withAuthroizationDid: DID,
                         waitForConfirms: Int,
                           storePassword: String) throws -> String {

        return try deactivateDid(target, withAuthroizationDid, waitForConfirms, nil, storePassword)
    }

    public func deactivateDid(for target: String,
                    withAuthroizationDid: String,
                         waitForConfirms: Int,
                           storePassword: String) throws -> String {

        return try deactivateDid(DID(target), DID(withAuthroizationDid), waitForConfirms, nil, storePassword)
    }

    public func deactivateDid(for target: DID,
                    withAuthroizationDid: DID,
                           storePassword: String) throws -> String {

        return try deactivateDid(target, withAuthroizationDid, 0, nil, storePassword)
    }

    public func deactivateDid(for target: String,
                    withAuthroizationDid: String,
                           storePassword: String) throws -> String {

        return try deactivateDid(DID(target), DID(withAuthroizationDid), 0, nil, storePassword)
    }

    private func deactivateDidAsync(_ target: DID,
                                    _ did: DID,
                                    _ confirms: Int,
                                    _ signKey: DIDURL?,
                                    _ storePassword: String) -> Promise<String> {

        return Promise<String> { resolver in
            do {
                resolver.fulfill(try deactivateDid(target, did, confirms, signKey, storePassword))
            } catch let error  {
                resolver.reject(error)
            }
        }
    }

    public func deactivateDidAsync(for target: DID,
                    withAuthroizationDid: DID,
                         waitForConfirms: Int,
                           using signKey: DIDURL,
                           storePassword: String) -> Promise<String> {

        return deactivateDidAsync(target, withAuthroizationDid, waitForConfirms, signKey, storePassword)
    }

    public func deactivateDidAsync(for target: String,
                    withAuthroizationDid: String,
                         waitForConfirms: Int,
                           using signKey: String,
                           storePassword: String) throws ->  Promise<String> {

        let _did = try DID(withAuthroizationDid)
        let _key = try DIDURL(_did, signKey)

        return deactivateDidAsync(try DID(target), _did, waitForConfirms, _key, storePassword)
    }

    public func deactivateDidAsync(for target: DID,
                    withAuthroizationDid: DID,
                           using signKey: DIDURL,
                           storePassword: String) ->  Promise<String> {

        return deactivateDidAsync(target, withAuthroizationDid, 0, signKey, storePassword)
    }

    public func deactivateDidAsync(for target: String,
                    withAuthroizationDid: String,
                           using signKey: String,
                           storePassword: String) throws ->  Promise<String> {

        let _did = try DID(withAuthroizationDid)
        let _key = try DIDURL(_did, signKey)

        return deactivateDidAsync(try DID(target), _did, 0, _key, storePassword)
    }

    public func deactivateDidAsync(for target: DID,
                    withAuthroizationDid: DID,
                         waitForConfirms: Int,
                           storePassword: String) ->  Promise<String> {

        return deactivateDidAsync(target, withAuthroizationDid, waitForConfirms, nil, storePassword)
    }

    public func deactivateDidAsync(for target: String,
                    withAuthroizationDid: String,
                         waitForConfirms: Int,
                           storePassword: String) throws ->  Promise<String> {

        return try deactivateDidAsync(DID(target), DID(withAuthroizationDid), waitForConfirms, nil, storePassword)
    }

    public func deactivateDidAsync(for target: DID,
                    withAuthroizationDid: DID,
                           storePassword: String) ->  Promise<String> {

        return deactivateDidAsync(target, withAuthroizationDid, 0, nil, storePassword)
    }

    public func deactivateDidAsync(for target: String,
                    withAuthroizationDid: String,
                           storePassword: String) throws ->  Promise<String> {

        return try deactivateDidAsync(DID(target), DID(withAuthroizationDid), 0, nil, storePassword)
    }

    public func storeDid(using doc: DIDDocument, with alias: String) throws {
        doc.getMeta().setAlias(alias)
        try storeDid(using: doc)
    }
    
    public func storeDid(using doc: DIDDocument) throws {
        try storage.storeDid(doc)

        let meta = try loadDidMeta(for: doc.subject)
        try meta.merge(doc.getMeta())
        meta.setStore(self)
        doc.setMeta(meta)

        try storage.storeDidMeta(doc.subject, meta)

        for credential in doc.credentials() {
            try storeCredential(using: credential)
        }
    }
    
    func storeDidMeta(_ meta: DIDMeta, for did: DID) throws {
        try storage.storeDidMeta(did, meta)
    }
    
    func storeDidMeta(_ meta: DIDMeta, for did: String) throws {
        try storeDidMeta(meta, for: try DID(did))
    }
    
    func loadDidMeta(for did: DID) throws -> DIDMeta {
        return try storage.loadDidMeta(did)
    }

    func loadDidMeta(for did: String) throws -> DIDMeta {
        return try loadDidMeta(for: DID(did))
    }
    
    public func loadDid(_ did: DID) throws -> DIDDocument {
        let doc = try storage.loadDid(did)
        doc.setMeta(try storage.loadDidMeta(did))
        doc.getMeta().setStore(self)
        return doc
    }

    public func loadDid(_ did: String) throws -> DIDDocument {
        return try loadDid(DID(did))
    }
    
    public func containsDid(_ did: DID) -> Bool {
        return storage.containsDid(did)
    }

    public func containsDid(_ did: String) throws -> Bool {
        return containsDid(try DID(did))
    }

    public func deleteDid(_ did: DID) -> Bool {
        return storage.deleteDid(did)
    }

    public func deleteDid(_ did: String) throws -> Bool {
        return try deleteDid(DID(did))
    }

    public func listDids(using filter: Int) throws -> Array<DID> {
        let dids = try storage.listDids(filter)

        try dids.forEach { did in
            let meta = try loadDidMeta(for: did)
            meta.setStore(self)
            did.setMeta(meta)
        }

        return dids
    }
    
    public func storeCredential(using credential: VerifiableCredential, with alias: String) throws {
        credential.getMeta().setAlias(alias)
        try storeCredential(using: credential)
    }
    
    public func storeCredential(using credential: VerifiableCredential) throws {
        try storage.storeCredential(credential)

        let meta = try loadCredentialMeta(for: credential.subject.did, byId: credential.getId())
        try meta.merge(credential.getMeta())
        meta.setStore(self)
        credential.setMeta(meta)
        credential.getMeta().setStore(self)
        try storage.storeCredentialMeta(credential.subject.did, credential.getId(), meta)
    }

    func storeCredentialMeta(for did: DID, key id: DIDURL, meta: CredentialMeta) throws {
        try storage.storeCredentialMeta(did, id, meta)
    }
    
    func storeCredentialMeta(for did: String, key id: String, meta: CredentialMeta) throws {
        let _did = try DID(did)
        let _key = try DIDURL(_did, id)
        try storeCredentialMeta(for: _did, key: _key, meta: meta)
    }
    
    func loadCredentialMeta(for did: DID, byId: DIDURL) throws -> CredentialMeta {
        return try storage.loadCredentialMeta(did, byId)
    }

    func loadCredentialMeta(for did: String, byId: String) throws -> CredentialMeta? {
        let _did = try DID(did)
        let _key = try DIDURL(_did, byId)
        return try loadCredentialMeta(for: _did, byId: _key)
    }

    public func loadCredential(for did: DID, byId: DIDURL) throws -> VerifiableCredential? {
        return try storage.loadCredential(did, byId)
    }
    
    public func loadCredential(for did: String, byId: String) throws -> VerifiableCredential? {
        let _did = try DID(did)
        let _key = try DIDURL(_did, byId)
        return try loadCredential(for: _did, byId: _key)
    }
    
    public func containsCredentials(_ did:DID) throws -> Bool {
        return storage.containsCredentials(did)
    }
    
    public func containsCredentials(_ did: String) throws -> Bool {
        return try containsCredentials(DID(did))
    }
    
    public func containsCredential(_ did: DID, _ id: DIDURL) throws -> Bool {
        return storage.containsCredential(did, id)
    }
    
    public func containsCredential(_ did: String, _ id: String) throws -> Bool {
        let _did: DID = try DID(did)
        return try containsCredential(_did, DIDURL(_did, id))
    }
    
    public func deleteCredential(for did: DID, id: DIDURL) throws -> Bool{
        return try storage.deleteCredential(did, id)
    }
    
    public func deleteCredential(for did: String, id: String) throws -> Bool{
        let _did = try DID(did)
        let _key = try DIDURL(_did, id)
        return try deleteCredential(for: _did, id: _key)
    }
    
    public func listCredentials(for did: DID) throws -> Array<DIDURL> {
        let ids = try storage.listCredentials(did)
        for id in ids {
            let meta = try loadCredentialMeta(for: did, byId: id)
            meta.setStore(self)
            id.setMeta(meta)
        }
        return ids
    }
    
    public func listCredentials(for did: String) throws -> Array<DIDURL> {
        return try listCredentials(for: DID(did))
    }

    public func selectCredentials(for did: DID,
                                  byId id: DIDURL,
                             andType type: Array<String>) throws -> Array<DIDURL> {
        return try storage.selectCredentials(did, id, type)
    }
    
    public func selectCredentials(for did: String,
                                  byId id: String,
                             andType type: Array<String>) throws -> Array<DIDURL> {
        let _did = try DID(did)
        let _key = try DIDURL(_did, id)

        return try selectCredentials(for: _did, byId: _key, andType: type)
    }
    
    public func storePrivateKey(for did: DID,
                                     id: DIDURL,
                             privateKey: Data,
                    using storePassword: String) throws {

        guard !storePassword.isEmpty else {
            throw DIDError.illegalArgument()
        }

        let encryptedKey = try DIDStore.encryptToBase64(privateKey, storePassword)
        try storage.storePrivateKey(did, id, encryptedKey)
    }

    public func storePrivateKey(for did: String,
                                     id: String,
                             privateKey: Data,
                    using storePassword: String) throws {

        let _did = try DID(did)
        let _key = try DIDURL(_did, id)

        return try storePrivateKey(for: _did, id: _key, privateKey: privateKey, using: storePassword)
    }
    
   public func loadPrivateKey(for did: DID, byId: DIDURL) throws -> String {
        return try storage.loadPrivateKey(did, byId)
    }
    
    public func containsPrivateKeys(for did: DID) -> Bool {
        return storage.containsPrivateKeys(did)
    }
    
    public func containsPrivateKeys(for did: String) throws -> Bool {
        return try containsPrivateKeys(for: DID(did))
    }
    
    public func containsPrivateKey(for did: DID, id: DIDURL) -> Bool {
        return storage.containsPrivateKey(did, id)
    }
    
    public func containsPrivateKey(for did: String, id: String) throws -> Bool {
        let _did = try DID(did)
        let _key = try DIDURL(_did, id)

        return containsPrivateKey(for: _did, id: _key)
    }
    
    public func deletePrivateKey(for did: DID, id: DIDURL) -> Bool {
        return storage.deletePrivateKey(did, id)
    }
    
    public func deletePrivateKey(for did: String, id: String) throws -> Bool {
        let _did = try DID(did)
        let _key = try DIDURL(_did, id)

        return deletePrivateKey(for: _did, id: _key)
    }

    func sign(_ did: DID, _ id: DIDURL?, _ storePassword: String, _ data: [Data]) throws -> String {
        guard !storePassword.isEmpty else {
            throw DIDError.illegalArgument()
        }

        var usedId: DIDURL? = id
        if  usedId == nil {
            do {
                let doc = try loadDid(did)
                usedId = doc.defaultPublicKey
            } catch {
                throw DIDError.didStoreError("Can not resolve DID document")
            }
        }

        let privatekeys = try DIDStore.decryptFromBase64(loadPrivateKey(for: did, byId: usedId!), storePassword)

        var cinputs: [CVarArg] = []
        data.forEach { data in
            let cdata = data.withUnsafeBytes { cdata -> UnsafePointer<Int8> in
                return cdata
            }
            cinputs.append(cdata)
            cinputs.append(data.count)
        }
        
        let toPPointer = privatekeys.toPointer()
        
        let c_inputs = getVaList(cinputs)
        let count = cinputs.count / 2
        // UnsafeMutablePointer(mutating: toPPointer)
        let csig: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: 4096)
        let re = ecdsa_sign_base64v(csig, UnsafeMutablePointer(mutating: toPPointer), Int32(count), c_inputs)
        guard re >= 0 else {
            throw DIDError.didStoreError("sign error.")
        }
        let jsonStr: String = String(cString: csig)
        let endIndex = jsonStr.index(jsonStr.startIndex, offsetBy: re)
        let sig = String(jsonStr[jsonStr.startIndex..<endIndex])
        return sig
    }

    public func sign(WithDid did: DID,
                              id: DIDURL,
             using storePassword: String,
                        for data: Data...) throws -> String {

        return try sign(did, id, storePassword, data)
    }

    public func sign(WithDid did: DID,
             using storePassword: String,
                        for data: Data...) throws -> String {

        return try sign(did, nil, storePassword, data)
    }

    private func exportDid(_ did: DID,
                    _ generator: JsonGenerator,
                     _ password: String,
                _ storePassword: String) throws {
        // TODO:
    }

    public func exportDid(_ did: DID,
                      to output: OutputStream,
                 using password: String,
                  storePassword: String) throws {
        // TODO:
    }

    public func exportDid(_ did: String,
                      to output: OutputStream,
                 using password: String,
                  storePassword: String) throws {
        // TODO:
    }

    public func exportDid(_ did: DID,
                  to fileHandle: FileHandle,
                 using password: String,
                  storePassword: String) throws {
        // TODO:
    }

    public func exportDid(_ did: String,
                  to fileHandle: FileHandle,
                 using password: String,
                  storePassword: String) throws {
        // TODO:
    }

    private func importDid(_ root: JsonNode,
                       _ password: String,
                  _ storePassword: String) throws {
        // TODO:
    }

    public func importDid(from data: Data,
                     using password: String,
                      storePassword: String) throws {
        // TODO:
    }

    public func importDid(from input: InputStream,
                      using password: String,
                       storePassword: String) throws {
        // TODO:
    }

    public func importDid(from handle: FileHandle,
                      using password: String,
                       storePassword: String) throws {
        // TODO:
    }

    private func exportPrivateIdentity(_ generator: JsonGenerator,
                                        _ password: String,
                                   _ storePassword: String) throws {
        // TODO:
    }

    public func exportPrivateIdentity(to output: OutputStream,
                                     _ password: String,
                                _ storePassword: String) throws {
        // TODO:
    }

    public func exportPrivateIdentity(to handle: FileHandle,
                                     _ password: String,
                                _ storePassword: String) throws {
        // TODO:
    }

    public func exportPrivateIdentity(to data: Data,
                                   _ password: String,
                              _ storePassword: String) throws {
        // TODO:
    }

    private func importPrivateIdentity(_ root: JsonNode,
                                   _ password: String,
                              _ storePassword: String) throws {
        // TODO:
    }

    public func importPrivateIdentity(from data: Data,
                                 using password: String,
                                  storePassword: String) throws {
        // TODO:
    }

    public func importPrivateIdentity(from input: InputStream,
                                  using password: String,
                                   storePassword: String) throws {
        // TODO:
    }

    public func importPrivateIdentity(from handle: FileHandle,
                                   using password: String,
                                    storePassword: String) throws {
        // TODO:
    }

    public func exportStore(to output: OutputStream,
                           _ password: String,
                      _ storePassword: String) throws {
        // TODO:
    }

    public func exportStore(to handle: FileHandle,
                           _ password: String,
                      _ storePassword: String) throws {
        // TODO:
    }

    public func importStore(from input: InputStream,
                            _ password: String,
                       _ storePassword: String) throws {
        // TODO:
    }

    public func importStore(from handle: FileHandle,
                             _ password: String,
                        _ storePassword: String) throws {
        // TODO:
    }
}
