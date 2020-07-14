
import XCTest
@testable import ElastosDIDSDK

class DIDStoreTests: XCTestCase {
    
    var store: DIDStore!
    static var ids: Dictionary<DID, String> = [: ]
    static var primaryDid: DID!
    var adapter: SPVAdaptor!
    
    func testCreateEmptyStore() {
        do {
            let testData: TestData = TestData()
            try _ = testData.setup(true)
            _ = testData.exists(storeRoot)
            
            let path = storeRoot + "/" + ".meta"
            _ = testData.existsFile(path)
        } catch {
            print("testCreateEmptyStore error: \(error)")
            XCTFail()
        }
    }
    
    func testCreateDidInEmptyStore()  {
        do {
            let testData: TestData = TestData()
            
            let store = try testData.setup(true)
            _ = try store.newDid("this will be fail", storePass)
        } catch {
            print(error)
            XCTAssertTrue(true)
        }
    }

    func testInitPrivateIdentity0() {
        do {
            let testData: TestData = TestData()
            var store: DIDStore = try testData.setup(true)
            XCTAssertFalse(store.containsPrivateIdentity())
            
            _ = try testData.initIdentity()
            XCTAssertTrue(store.containsPrivateIdentity())
            var path = storeRoot + "/" + "private" + "/" + "key"
            XCTAssertTrue(testData.existsFile(path))
            path = storeRoot + "/" + "private" + "/" + "index"
            XCTAssertTrue(testData.existsFile(path))
            
            store = try DIDStore.open("filesystem", storeRoot, testData.adapter!)
            XCTAssertTrue(store.containsPrivateIdentity())
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func testInitPrivateIdentityWithMnemonic() {
        do {
            let expectedIDString = "iY4Ghz9tCuWvB5rNwvn4ngWvthZMNzEA7U"
            let mnemonic = "cloth always junk crash fun exist stumble shift over benefit fun toe"

            let testData = TestData()
            var store = try testData.setup(true)
            XCTAssertFalse(store.containsPrivateIdentity())

            try store.initPrivateIdentity(using: Mnemonic.ENGLISH, mnemonic: mnemonic, passphrase: "", storepass: storePass)
            XCTAssertTrue(store.containsPrivateIdentity())

            var path = storeRoot + "/" + "private" + "/" + "key"
            XCTAssertTrue(testData.existsFile(path))

            path = storeRoot + "/" + "private" + "/" + "index"
            XCTAssertTrue(testData.existsFile(path))

            path = storeRoot + "/" + "private" + "/" + "mnemonic"
            XCTAssertTrue(testData.existsFile(path))

            store = try DIDStore.open("filesystem", storeRoot, testData.adapter!)
            XCTAssertTrue(store.containsPrivateIdentity())
            let exportedMnemonic = try store.exportMnemonic(using: storePass)
            XCTAssertEqual(mnemonic, exportedMnemonic)

            let doc = try store.newDid(storePass)
            XCTAssertNotNil(doc)
            XCTAssertEqual(expectedIDString, doc.subject.methodSpecificId)
        } catch {
            XCTFail()
        }
    }

    func testInitPrivateIdentityWithRootKey() {
        do {
            let expectedIDString = "iYbPqEA98rwvDyA5YT6a3mu8UZy87DLEMR";
            let rootKey = "xprv9s21ZrQH143K4biiQbUq8369meTb1R8KnstYFAKtfwk3vF8uvFd1EC2s49bMQsbdbmdJxUWRkuC48CXPutFfynYFVGnoeq8LJZhfd9QjvUt";

            let testData = TestData()
            var store = try testData.setup(true)
            XCTAssertFalse(store.containsPrivateIdentity())

            try store.initPrivateIdentity(rootKey, storePass)
            XCTAssertTrue(store.containsPrivateIdentity())

            var path = storeRoot + "/" + "private" + "/" + "key"
            XCTAssertTrue(testData.existsFile(path))

            path = storeRoot + "/" + "private" + "/" + "index"
            XCTAssertTrue(testData.existsFile(path))

            path = storeRoot + "/" + "private" + "/" + "mnemonic"
            XCTAssertFalse(testData.existsFile(path))

            store = try DIDStore.open("filesystem", storeRoot, testData.adapter!)
            XCTAssertTrue(store.containsPrivateIdentity())

            let doc = try store.newDid(storePass)
            XCTAssertNotNil(doc)
            XCTAssertEqual(expectedIDString, doc.subject.methodSpecificId)
        } catch {
            XCTFail()
        }
    }

    func testCreateDIDWithAlias() throws {
        do {
            let testData: TestData = TestData()
            let store: DIDStore = try testData.setup(true)
            _ = try testData.initIdentity()
            
            let alias: String = "my first did"
            
            let doc: DIDDocument = try store.newDid(alias, storePass)
            XCTAssertTrue(doc.isValid)
            
            var resolved = try doc.subject.resolve(true)
            XCTAssertNil(resolved)
            
            _ = try store.publishDid(doc.subject, storePass)
            var path = ""
            
            path = storeRoot + "/ids/" + doc.subject.methodSpecificId + "/document"
            XCTAssertTrue(testData.existsFile(path))
            path = storeRoot + "/ids/" + doc.subject.methodSpecificId + "/.meta"
            XCTAssertTrue(testData.existsFile(path))
            resolved = try doc.subject.resolve(true)
            
            XCTAssertNotNil(resolved)

            try store.storeDid(resolved!)
            XCTAssertEqual(alias, resolved!.getMetadata().aliasName)
            XCTAssertEqual(doc.subject, resolved!.subject)
            XCTAssertEqual(doc.proof.signature, resolved!.proof.signature)
            
            XCTAssertTrue(resolved!.isValid)
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func testCreateDIDWithoutAlias() {
        do {
            let testData: TestData = TestData()
            let store: DIDStore = try testData.setup(true)
            _ = try testData.initIdentity()
            
            let doc: DIDDocument = try store.newDid(storePass)
            XCTAssertTrue(doc.isValid)
            
            var resolved = try doc.subject.resolve(true)
            XCTAssertNil(resolved)
            
            _ = try store.publishDid(doc.subject, storePass)
            let path = storeRoot + "/ids/" + doc.subject.methodSpecificId + "/document"
            XCTAssertTrue(testData.existsFile(path))

            resolved = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.subject, resolved!.subject)
            XCTAssertEqual(doc.proof.signature, resolved!.proof.signature)
            XCTAssertTrue(resolved!.isValid)
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func testCreateDIDByIndex() {
        do {
            let testData = TestData()
            let store = try testData.setup(true)
            _ = try testData.initIdentity()

            let alias = "my first did"
            let did = try store.getDid(0)
            var doc = try store.newDid(0, alias, storePass)
            XCTAssertTrue(doc.isValid)
            XCTAssertEqual(did, doc.subject)

            XCTAssertThrowsError(try store.newDid(alias, storePass)){ (error) in
                switch error {
                case DIDError.didStoreError("DID already exists."): break
                //everything is fine
                default:
                XCTFail("Unexpected error thrown")
                }
            }

            let success = store.deleteDid(did)
            XCTAssertTrue(success)
            doc = try store.newDid(alias, storePass)
            XCTAssertTrue(doc.isValid)
            XCTAssertEqual(did, doc.subject)
        } catch {
            XCTFail()
        }
    }

    func testGetDid() {
        do {
            let testData = TestData()
            let store = try testData.setup(true)
            _ = try testData.initIdentity()
            for i in 0...100 {
                let alias = "did#\(i)"
                let doc = try store.newDid(i, alias, storePass)
                XCTAssertTrue(doc.isValid)
                let did = try store.getDid(i)
                XCTAssertEqual(doc.subject, did)
            }
        } catch {
            XCTFail()
        }
    }

    func testUpdateDid() {
        do {
            let testData: TestData = TestData()
            let store: DIDStore = try testData.setup(true)
            _ = try testData.initIdentity()
            
            let doc: DIDDocument = try store.newDid(storePass)
            XCTAssertTrue(doc.isValid)
            _ = try store.publishDid(doc.subject, storePass)
            
            var resolved = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            try store.storeDid(resolved!)
            
            // Update
            var db: DIDDocumentBuilder = resolved!.editing()
            var key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "key1", keyBase58: key.getPublicKeyBase58())
            var newDoc = try db.sealed(using: storePass)
            XCTAssertEqual(2, newDoc.publicKeyCount)
            XCTAssertEqual(2, newDoc.authenticationKeyCount)
            try store.storeDid(newDoc)
            
            _ = try store.publishDid(newDoc.subject, storePass)
            
            resolved = try doc.subject.resolve(true)

            XCTAssertNotNil(resolved)
            XCTAssertEqual(newDoc.description, resolved!.description)
            try store.storeDid(resolved!)

            // Update again
            db = resolved!.editing()
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "key2", keyBase58: key.getPublicKeyBase58())
            newDoc = try db.sealed(using: storePass)
            XCTAssertEqual(3, newDoc.publicKeyCount)
            XCTAssertEqual(3, newDoc.authenticationKeyCount)
            try store.storeDid(newDoc)
            _ = try store.publishDid(newDoc.subject, storePass)
            
            resolved = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            XCTAssertEqual(newDoc.description, resolved!.description)
        } catch {
            XCTFail()
        }
    }
    

    func testUpdateDidWithoutPrevSignature() {
        do {
            let testData = TestData()
            let store = try testData.setup(true)
            _ = try testData.initIdentity()

            var doc = try store.newDid(storePass)
            XCTAssertTrue(doc.isValid)

            _ = try store.publishDid(doc.subject, storePass)

            var resolved = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())

            // Update
            var db = doc.editing()
            var key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePass)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store.storeDid(doc)

            _ = try store.publishDid(doc.subject, storePass)

            resolved = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())

            doc.getMetadata().setPreviousSignature(nil)
            try doc.saveMetadata()

            // Update again
            db = doc.editing()
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "key2", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePass)
            XCTAssertEqual(3, doc.publicKeyCount)
            XCTAssertEqual(3, doc.authenticationKeyCount)
            try store.storeDid(doc)

            _ = try store.publishDid(doc.subject, storePass)
            resolved = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())
        } catch {
            XCTFail()
        }
    }

    func testUpdateDidWithoutSignature() {
        do {
            let testData = TestData()
            let store = try testData.setup(true)
            _ = try testData.initIdentity()

            var doc = try store.newDid(storePass)
            XCTAssertTrue(doc.isValid)

            _ = try store.publishDid(doc.subject, storePass)

            var resolved = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())

            // Update
            var db = doc.editing()
            var key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePass)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store.storeDid(doc)
            _ = try store.publishDid(doc.subject, storePass)

            resolved = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())

            doc.getMetadata().setSignature(nil)
            try doc.saveMetadata()

            // Update again
            db = doc.editing()
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "key2", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePass)
            XCTAssertEqual(3, doc.publicKeyCount)
            XCTAssertEqual(3, doc.authenticationKeyCount)
            try store.storeDid(doc)

            XCTAssertThrowsError(try store.publishDid(doc.subject, storePass)) { (error) in
                switch error {
                case DIDError.didStoreError:
                    XCTAssertTrue(true)
                    break
                //everything is fine
                default:  //TODO:
                XCTFail("Unexpected error thrown")
                    break
                }
            }
        } catch {
            XCTFail()
        }
    }

    func testUpdateDidWithoutAllSignatures() {
        do {
            let testData = TestData()
            let store = try testData.setup(true)
            _ = try testData.initIdentity()

            var doc = try store.newDid(storePass)
            XCTAssertTrue(doc.isValid)

            _ = try store.publishDid(doc.subject, storePass)

            let resolved = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())

            doc.getMetadata().setPreviousSignature(nil)
            doc.getMetadata().setSignature(nil)
            try doc.saveMetadata()

            // Update
            let db = doc.editing()
            let key = try TestData.generateKeypair()
            _ =  try db.appendAuthenticationKey(with: "key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePass)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store.storeDid(doc)
            let did = doc.subject

            XCTAssertThrowsError(try store.publishDid(did, storePass)) { error in
                switch error as! DIDError {
                case .didStoreError("DID document not up-to-date"):
                    XCTAssertTrue(true)
                default:
                    XCTFail()
                }
            }
        } catch {
            XCTFail()
        }
    }

    func testUpdateDidWithWrongPrevSignature() {
        do {
            let testData = TestData()
            let store = try testData.setup(true)
            _ = try testData.initIdentity()

            var doc = try store.newDid(storePass)
            XCTAssertTrue(doc.isValid)

            _ = try store.publishDid(doc.subject, storePass)

            var resolved = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())

            // Update
            var db = doc.editing()
            var key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePass)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store.storeDid(doc)

            _ = try store.publishDid(doc.subject, storePass)

            resolved = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())

            doc.getMetadata().setPreviousSignature("1234567890")
            try doc.saveMetadata()

            // Update
            db = doc.editing()
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "key2", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePass)

            XCTAssertEqual(3, doc.publicKeyCount)
            XCTAssertEqual(3, doc.authenticationKeyCount)
            try store.storeDid(doc)

            try store.publishDid(doc.subject, storePass)

            resolved = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())

        } catch {
            XCTFail()
        }
    }

    func testUpdateDidWithWrongSignature() {
        do {
            let testData = TestData()
            let store = try testData.setup(true)
            _ = try testData.initIdentity()

            var doc = try store.newDid(storePass)
            XCTAssertTrue(doc.isValid)

            _ = try store.publishDid(doc.subject, storePass)

            var resolved = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())

            // Update
            var db = doc.editing()
            var key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePass)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store.storeDid(doc)

            try store.publishDid(doc.subject, storePass)
            resolved = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())

            doc.getMetadata().setSignature("1234567890")
            try doc.saveMetadata()

            // Update
             db = doc.editing()
             key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "key2", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePass)
            XCTAssertEqual(3, doc.publicKeyCount)
            XCTAssertEqual(3, doc.authenticationKeyCount)
            try store.storeDid(doc)

            let did = doc.subject

            XCTAssertThrowsError(try store.publishDid(did, storePass)) { error in
                switch error as! DIDError {
                case .didStoreError("DID document not up-to-date"):
                    XCTAssertTrue(true)
                default:
                    XCTFail()
                }
            }
        } catch {
            XCTFail()
        }
    }

    func testForceUpdateDidWithWrongPrevSignature() {
        do {
            let testData = TestData()
            let store = try testData.setup(true)
            _ = try testData.initIdentity()

            var doc = try store.newDid(storePass)
            XCTAssertTrue(doc.isValid)

            _ = try store.publishDid(doc.subject, storePass)

            var resolved = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())

            doc.getMetadata().setPreviousSignature("1234567890")
            try doc.saveMetadata()

            // Update
            let db = doc.editing()
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePass)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store.storeDid(doc)

            _ = try store.publishDid(doc.subject, doc.defaultPublicKey, true, storePass)
            resolved = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())
        } catch {
            XCTFail()
        }
    }

    func testForceUpdateDidWithWrongSignature() {
        do {
            let testData = TestData()
            let store = try testData.setup(true)
            _ = try testData.initIdentity()

            var doc = try store.newDid(storePass)
            XCTAssertTrue(doc.isValid)

            _ = try store.publishDid(doc.subject, storePass)

            var resolved = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())

            doc.getMetadata().setSignature("1234567890")
            try doc.saveMetadata()

            // Update
            let db = doc.editing()
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePass)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store.storeDid(doc)

            _ = try store.publishDid(doc.subject, doc.defaultPublicKey, true,storePass)

            resolved = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateSelfAfterCreate() {
        do {
            let testData: TestData = TestData()
            let store: DIDStore = try testData.setup(true)
            _ = try testData.initIdentity()
            
            let doc = try store.newDid(storePass)
            XCTAssertTrue(doc.isValid)
            
            _ = try store.publishDid(doc.subject, storePass)
            let resolved: DIDDocument = try doc.subject.resolve(true)!
            XCTAssertNotNil(resolved)
            
            _ = try store.deactivateDid(doc.subject, storePass)
            
            let resolvedNil = try doc.subject.resolve(true)
            
            XCTAssertNil(resolvedNil)
        } catch  {
            switch error as! DIDError{
            case .didDeactivated(nil):
                XCTAssertTrue(true)
            default:
                XCTFail()
            }
        }
    }
    
    func testDeactivateSelfAfterUpdate() {
        do {
            let testData: TestData = TestData()
            let store: DIDStore = try testData.setup(true)
            _ = try testData.initIdentity()
            
            var doc = try store.newDid(storePass)
            XCTAssertTrue(doc.isValid)
            
            _ = try store.publishDid(doc.subject, storePass)
            
            var resolved = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())

            // update
            let db = doc.editing()
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePass)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store.storeDid(doc)
            
            _ = try store.publishDid(doc.subject, storePass)
            
            resolved = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())
            _ = try store.deactivateDid(doc.subject, storePass)
            let did = doc.subject

            XCTAssertThrowsError(try did.resolve(true)) { (error) in
                switch error {
                case DIDError.didDeactivated: break
                //everything is fine
                default:
                    XCTFail("Unexpected error thrown")
                }
            }
        } catch  {
            XCTFail()
        }
    }
    
    func testDeactivateWithAuthorization1() {
        do {
            let testData: TestData = TestData()
            let store: DIDStore = try testData.setup(true)
            _ = try testData.initIdentity()
            
            let doc = try store.newDid(storePass)
            XCTAssertTrue(doc.isValid)
            
            _ = try store.publishDid(doc.subject, storePass)
            
            var resolved: DIDDocument = try doc.subject.resolve(true)!
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved.toString())
            
            var target = try store.newDid(storePass)
            let db: DIDDocumentBuilder = target.editing()
            _ = try db.authorizationDid(with: "recovery", controller: doc.subject.toString())
            target = try db.sealed(using: storePass)
            XCTAssertNotNil(target)
            XCTAssertEqual(1, target.authorizationKeyCount)
            XCTAssertEqual(doc.subject, target.authorizationKeys()[0].controller)

            try store.storeDid(target)
            _ = try store.publishDid(target.subject, storePass)
            resolved = try target.subject.resolve()!
            XCTAssertNotNil(resolved)
            XCTAssertEqual(target.toString(), resolved.toString())
            _ = try store.deactivateDid(target.subject, doc.subject, storePass)
            let did = target.subject

            XCTAssertThrowsError(try did.resolve(true)) { (error) in
                switch error {
                case DIDError.didDeactivated: break
                //everything is fine
                default: //TODO:
                    XCTFail("Unexpected error thrown")
                }
            }
        } catch  {
            XCTFail()
        }
    }
    
    func testDeactivateWithAuthorization2() {
        do {
            let testData: TestData = TestData()
            let store: DIDStore = try testData.setup(true)
            _ = try testData.initIdentity()
            
            var doc = try store.newDid(storePass)
            var db: DIDDocumentBuilder = doc.editing()
            let key = try TestData.generateKeypair()
            let id = try DIDURL(doc.subject, "key-2")
            _ = try db.appendAuthenticationKey(with: id, keyBase58: key.getPublicKeyBase58())
            try store.storePrivateKey(for: doc.subject, id: id, privateKey: key.getPrivateKeyData(), using: storePass)
            doc = try db.sealed(using: storePass)
            XCTAssertTrue(doc.isValid)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store.storeDid(doc)
            
            _ = try store.publishDid(doc.subject, storePass)
            var resolved: DIDDocument? = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), doc.toString())
            
            var target: DIDDocument = try store.newDid(storePass)
            db = target.editing()
            _ = try db.appendAuthorizationKey(with: "recovery", controller: doc.subject.toString(), keyBase58: key.getPublicKeyBase58())
            target = try db.sealed(using: storePass)
            XCTAssertNotNil(target)
            XCTAssertEqual(1, target.authorizationKeyCount)
            let controller = target.authorizationKeys()[0].controller
            XCTAssertEqual(doc.subject, controller)
            try store.storeDid(target)
            
            _ = try store.publishDid(target.subject, storePass)
            
            resolved = try target.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(target.toString(), resolved!.toString())
            
            _ = try store.deactivateDid(target.subject, doc.subject, id, storePass)
            let did = target.subject

            XCTAssertThrowsError(try did.resolve(true)) { (error) in
                switch error {
                case DIDError.didDeactivated: break
                //everything is fine
                default: break //TODO:
                XCTFail("Unexpected error thrown")
                }
            }
        } catch  {
            XCTFail()
        }
    }
    
    func testDeactivateWithAuthorization3() {
        do {
            let testData: TestData = TestData()
            let store: DIDStore = try testData.setup(true)
            _ = try testData.initIdentity()
            
            var doc = try store.newDid(storePass)
            var db: DIDDocumentBuilder = doc.editing()
            
            let key = try TestData.generateKeypair()
            let id: DIDURL = try DIDURL(doc.subject, "key-2")
            _ = try db.appendAuthenticationKey(with: id, keyBase58: key.getPublicKeyBase58())
            
            try store.storePrivateKey(for: doc.subject, id: id, privateKey: key.getPrivateKeyData(), using: storePass)
            doc = try db.sealed(using: storePass)
            XCTAssertTrue(doc.isValid)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store.storeDid(doc)
            
            _ = try store.publishDid(doc.subject, storePass)
            
            var resolved: DIDDocument? = try doc.subject.resolve(true)
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())
            
            var target = try store.newDid(storePass)
            db = target.editing()
            _ = try db.appendAuthorizationKey(with: "recovery", controller: doc.subject.toString(), keyBase58: key.getPublicKeyBase58())
            target = try db.sealed(using: storePass)
            XCTAssertNotNil(target)
            XCTAssertEqual(1, target.authorizationKeyCount)
            let controller = target.authorizationKeys()[0].controller
            XCTAssertEqual(doc.subject, controller)
            try store.storeDid(target)
            
            _ = try store.publishDid(target.subject, storePass)
            
            resolved = try target.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(target.toString(), resolved!.toString())

            _ = try store.deactivateDid(target.subject, doc.subject, storePass)

            let did = target.subject
            XCTAssertThrowsError(try did.resolve(true)) { (error) in
                switch error {
                case DIDError.didDeactivated: break
                //everything is fine
                default: break //TODO:
                XCTFail("Unexpected error thrown")
                }
            }
        } catch  {
            XCTFail()
        }
    }

    func testBulkCreate() {
        do {
            let testData: TestData = TestData()
            let store: DIDStore = try testData.setup(true)
            _ = try testData.initIdentity()
            
            for i in 0..<100 {
                let alias: String = "my did \(i)"
                let doc: DIDDocument = try! store.newDid(alias, storePass )
                XCTAssertTrue(doc.isValid)
                
                var resolved = try doc.subject.resolve(true)
                XCTAssertNil(resolved)
                
                _ = try store.publishDid(doc.subject, storePass)
                
                var path = storeRoot + "/ids/" + doc.subject.methodSpecificId + "/document"
                XCTAssertTrue(testData.existsFile(path))
                
                path = storeRoot + "/ids/" + doc.subject.methodSpecificId + "/.meta"
                XCTAssertTrue(testData.existsFile(path))
                
                resolved = try doc.subject.resolve(true)
                try store.storeDid(resolved!)
                XCTAssertNotNil(resolved)
                XCTAssertEqual(alias, resolved!.getMetadata().aliasName)
                XCTAssertEqual(doc.subject, resolved!.subject)
                XCTAssertEqual(doc.proof.signature, resolved!.proof.signature)
                XCTAssertTrue(resolved!.isValid)
            }
            var dids: Array<DID> = try store.listDids(DIDStore.DID_ALL)
            XCTAssertEqual(100, dids.count)
            
            dids = try store.listDids(DIDStore.DID_HAS_PRIVATEKEY)
            XCTAssertEqual(100, dids.count)
            
            dids = try store.listDids(DIDStore.DID_NO_PRIVATEKEY)
            XCTAssertEqual(0, dids.count)
        } catch {
            XCTFail()
        }
    }
    
    func testDeleteDID() {
        do {
            let testData: TestData = TestData()
            let store: DIDStore = try testData.setup(true)
            _ = try testData.initIdentity()
            // Create test DIDs
            var dids: Array<DID> = []
            for i in 0..<100 {
                let alias: String = "my did \(i)"
                let doc: DIDDocument = try! store.newDid(alias, storePass)
                _ =  try! store.publishDid(doc.subject, storePass)
                dids.append(doc.subject)
            }
            
            for i in 0..<100 {
                if (i % 5 != 0){
                    continue
                }
                
                let did: DID = dids[i]
                
                var deleted: Bool = store.deleteDid(did)
                XCTAssertTrue(deleted)
                
                let path = storeRoot + "/ids/" + did.methodSpecificId
                XCTAssertFalse(testData.exists(path))
                
                deleted = store.deleteDid(did)
                XCTAssertFalse(deleted)
            }
            var remains: Array<DID> = try! store.listDids(DIDStore.DID_ALL)
            XCTAssertEqual(80, remains.count)
            
            remains = try! store.listDids(DIDStore.DID_HAS_PRIVATEKEY)
            XCTAssertEqual(80, remains.count)
            
            remains = try! store.listDids(DIDStore.DID_NO_PRIVATEKEY)
            XCTAssertEqual(0, remains.count)
        } catch  {
            XCTFail()
        }
    }
    
    func testStoreAndLoadDID() {
        do {
            let testData: TestData = TestData()
            let store: DIDStore = try testData.setup(true)
            _ = try testData.initIdentity()
            
            // Store test data into current store
            let issuer: DIDDocument = try testData.loadTestIssuer()
            let test: DIDDocument = try testData.loadTestDocument()
                        
            var doc: DIDDocument? = try  store.loadDid(issuer.subject)
            XCTAssertEqual(issuer.subject, doc!.subject)
            XCTAssertEqual(issuer.proof.signature, doc!.proof.signature)
            XCTAssertTrue(doc!.isValid)
            
            doc = try store.loadDid(test.subject.description)
            XCTAssertEqual(test.subject, doc!.subject)
            XCTAssertEqual(test.proof.signature, doc!.proof.signature)
            XCTAssertTrue(doc!.isValid)
            
            var dids: Array<DID> = try store.listDids(DIDStore.DID_ALL)
            XCTAssertEqual(2, dids.count)
            
            dids = try store.listDids(DIDStore.DID_HAS_PRIVATEKEY)
            XCTAssertEqual(2, dids.count)
            
            dids = try store.listDids(DIDStore.DID_NO_PRIVATEKEY)
            XCTAssertEqual(0, dids.count)
        }
        catch {
            XCTFail()
        }
    }
    
    func testLoadCredentials() {
        do {
            let testData: TestData = TestData()
            let store: DIDStore = try testData.setup(true)
            _ = try testData.initIdentity()
            
            // Store test data into current store
            _ = try testData.loadTestIssuer()
            let test: DIDDocument = try testData.loadTestDocument()
            var vc = try testData.loadProfileCredential()
            vc?.getMetadata().setAlias("MyProfile")
            vc = try testData.loadEmailCredential()
            vc?.getMetadata().setAlias("Email")
            vc = try testData.loadTwitterCredential()
            vc?.getMetadata().setAlias("Twitter")
            vc = try testData.loadPassportCredential()
            vc?.getMetadata().setAlias("Passport")

            var id: DIDURL = try DIDURL(test.subject, "profile")
            vc = try store.loadCredential(test.subject, id)
            XCTAssertNotNil(vc)
            XCTAssertEqual("MyProfile", vc!.getMetadata().aliasName)
            XCTAssertEqual(test.subject, vc!.subject.did)
            XCTAssertEqual(id, vc!.getId())
            XCTAssertTrue(vc!.isValid)
            
            // try with full id string
            vc = try store.loadCredential(test.subject.description, id.description)
            XCTAssertNotNil(vc)
            XCTAssertEqual("MyProfile", vc!.getMetadata().aliasName)
            XCTAssertEqual(test.subject, vc!.subject.did)
            XCTAssertEqual(id, vc!.getId())
            XCTAssertTrue(vc!.isValid)
            
            id = try DIDURL(test.subject, "twitter")
            vc = try store.loadCredential(test.subject.description, "twitter")
            XCTAssertNotNil(vc)
            XCTAssertEqual("Twitter", vc!.getMetadata().aliasName)
            XCTAssertEqual(test.subject, vc!.subject.did)
            XCTAssertEqual(id, vc!.getId())
            XCTAssertTrue(vc!.isValid)
            
            vc = try store.loadCredential(test.subject.description, "notExist")
            XCTAssertNil(vc)

            id = try DIDURL(test.subject, "twitter")
            XCTAssertTrue(try store.containsCredential(test.subject, id))
            XCTAssertTrue(try store.containsCredential(test.subject.description, "twitter"))
            XCTAssertFalse(try store.containsCredential(test.subject.description, "notExist"))
        }
        catch {
            XCTFail()
        }
    }
    
    func testListCredentials() {
        do {
            let testData: TestData = TestData()
            let store: DIDStore = try testData.setup(true)
            _ = try testData.initIdentity()
            
            // Store test data into current store
            _ = try testData.loadTestIssuer()
            let test: DIDDocument = try testData.loadTestDocument()
            var vc = try testData.loadProfileCredential()
            vc?.getMetadata().setAlias("MyProfile")
            vc = try testData.loadEmailCredential()
            vc?.getMetadata().setAlias("Email")
            vc = try testData.loadTwitterCredential()
            vc?.getMetadata().setAlias("Twitter")
            vc = try testData.loadPassportCredential()
            vc?.getMetadata().setAlias("Passport")

            let vcs: Array<DIDURL> = try store.listCredentials(test.subject)
            XCTAssertEqual(4, vcs.count)
            for id in vcs {
                var re = id.fragment == "profile" || id.fragment == "email" || id.fragment == "twitter" || id.fragment == "passport"
                XCTAssertTrue(re)
                
                re = id.getMetadata().aliasName == "MyProfile" || id.getMetadata().aliasName == "Email" || id.getMetadata().aliasName == "Twitter" || id.getMetadata().aliasName == "Passport"
                XCTAssertTrue(re)
            }
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func testDeleteCredential() {
        do {
            let testData: TestData = TestData()
            let store = try testData.setup(true)
            _ = try testData.initIdentity()
            
            // Store test data into current store
            _ = try testData.loadTestIssuer()
            let test: DIDDocument = try testData.loadTestDocument()
            var vc = try testData.loadProfileCredential()
            vc?.getMetadata().setAlias("MyProfile")
            try vc?.saveMetadata()
            vc = try testData.loadEmailCredential()
            vc?.getMetadata().setAlias("Email")
            try vc?.saveMetadata()
            vc = try testData.loadTwitterCredential()
            vc?.getMetadata().setAlias("Twitter")
            try vc?.saveMetadata()
            vc = try testData.loadPassportCredential()
            vc?.getMetadata().setAlias("Passport")
            try vc?.saveMetadata()

            var path = storeRoot + "/ids/" + test.subject.methodSpecificId + "/credentials/twitter/credential"
            XCTAssertTrue(testData.existsFile(path))
            
            path = storeRoot + "/" + "ids" + "/" + test.subject.methodSpecificId + "/" + "credentials" + "/" + "twitter" + "/" + ".meta"
            XCTAssertTrue(testData.existsFile(path))
            
            path = storeRoot + "/" + "ids" + "/" + test.subject.methodSpecificId + "/" + "credentials" + "/" + "passport" + "/" + "credential"
            XCTAssertTrue(testData.existsFile(path))
            
            path = storeRoot + "/" + "ids" + "/" + test.subject.methodSpecificId
                + "/" + "credentials" + "/" + "passport" + "/" + ".meta"
            XCTAssertTrue(testData.existsFile(path))
            
            var deleted: Bool = store.deleteCredential(test.subject, try DIDURL(test.subject, "twitter"))
            XCTAssertTrue(deleted)
            
            deleted = store.deleteCredential(test.subject.description, "passport")
            XCTAssertTrue(deleted)
            
            deleted = store.deleteCredential(test.subject.description, "notExist")
            XCTAssertFalse(deleted)
            
            path = storeRoot + "/" + "ids"
                + "/" + test.subject.methodSpecificId
                + "/" + "credentials" + "/" + "twitter"
            XCTAssertFalse(testData.existsFile(path))
            
            path = storeRoot + "/" + "ids"
                + "/" + test.subject.methodSpecificId
                + "/" + "credentials" + "/" + "passport"
            XCTAssertFalse(testData.existsFile(path))
            
            XCTAssertTrue(try store.containsCredential(test.subject.description, "email"))
            XCTAssertTrue(try store.containsCredential(test.subject.description, "profile"))
            
            XCTAssertFalse(try store.containsCredential(test.subject.description, "twitter"))
            XCTAssertFalse(try store.containsCredential(test.subject.description, "passport"))
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func testCompatibility() throws {
        let bundle = Bundle(for: type(of: self))
        let jsonPath: String = bundle.path(forResource: "teststore", ofType: "")!
        print(jsonPath)
        
        let adapter = DummyAdapter()
        try DIDBackend.initializeInstance(resolver, TestData.getResolverCacheDir())
        let store = try DIDStore.open("filesystem", jsonPath, adapter)
        
        let dids = try store.listDids(DIDStore.DID_ALL)
        XCTAssertEqual(2, dids.count)
        
        for did in dids {
            if did.getMetadata().aliasName == "Issuer" {
                let vcs: [DIDURL] = try store.listCredentials(did)
                XCTAssertEqual(1, vcs.count)
                
                let id: DIDURL = vcs[0]
                XCTAssertEqual("Profile", id.getMetadata().aliasName)
                
                XCTAssertNotNil(try store.loadCredential(did, id))
            } else if did.getMetadata().aliasName == "Test" {
                let vcs: [DIDURL] = try store.listCredentials(did)
                XCTAssertEqual(4, vcs.count)
                
                for id: DIDURL in vcs {
                    XCTAssertTrue(id.getMetadata().aliasName == "Profile"
                        || id.getMetadata().aliasName == "Email"
                        || id.getMetadata().aliasName == "Passport"
                        || id.getMetadata().aliasName == "Twitter")
                    
                    XCTAssertNotNil(try store.loadCredential(did, id))
                }
            }
        }
    }

    func testCompatibilityNewDIDandGetDID() {
        do {
            let bundle = Bundle(for: type(of: self))
            let jsonPath: String = bundle.path(forResource: "teststore", ofType: "")!

            let adapter = DummyAdapter()
            try DIDBackend.initializeInstance(adapter, TestData.getResolverCacheDir())
            let store = try DIDStore.open("filesystem", jsonPath, adapter)

            var doc = try store.newDid(storePass)
            XCTAssertNotNil(doc)

            _ = store.deleteDid(doc.subject)

            let did = try store.getDid(1000)

            doc = try store.newDid(1000, storePass)
            XCTAssertNotNil(doc)
            XCTAssertEqual(doc.subject, did)

            _ = store.deleteDid(doc.subject)
        } catch {
            XCTFail()
        }
    }
    
    func testCompatibilityNewDIDWithWrongPass() {
        do {
            try DIDBackend.initializeInstance(resolver, TestData.getResolverCacheDir())
            let bundle = Bundle(for: type(of: self))
            let jsonPath = bundle.path(forResource: "teststore", ofType: "")
            let store = try DIDStore.open("filesystem", jsonPath!, DummyAdapter())

            _ = try store.newDid("wrongpass")
        } catch {
            if error is DIDError {
                let err = error as! DIDError
                switch err {
                case .didStoreError(_desc: "decryptFromBase64 error."):
                    XCTAssertTrue(true)
                default:
                    XCTFail()
                }
            }
        }
    }
    
    func testCompatibilityNewDID() throws {
        try DIDBackend.initializeInstance(resolver, TestData.getResolverCacheDir())
        let bundle = Bundle(for: type(of: self))
        let jsonPath = bundle.path(forResource: "teststore", ofType: "")
        let store = try DIDStore.open("filesystem", jsonPath!, DummyAdapter())
        
        let doc: DIDDocument = try store.newDid(storePass)
        XCTAssertNotNil(doc)
                
        _ = store.deleteDid(doc.subject)
    }

    func createDataForPerformanceTest(_ store: DIDStore) {
        do {
            var props: Dictionary<String, String> = [: ]
            props["name"] = "John"
            props["gender"] = "Male"
            props["nation"] = "Singapore"
            props["language"] = "English"
            props["email"] = "john@example.com"
            props["twitter"] = "@john"
            
            for i in 0..<10 {
                let alias: String = "my did \(i)"
                let doc: DIDDocument = try store.newDid(alias, storePass)
                
                let issuer = try VerifiableCredentialIssuer(doc)
                let cb = issuer.editingVerifiableCredentialFor(did: doc.subject)
                let vc: VerifiableCredential = try cb.withId("cred-1")
                    .withTypes("BasicProfileCredential", "InternetAccountCredential")
                    .withProperties(props)
                    .sealed(using: storePass)
                try store.storeCredential(vc)
            }
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func testStorePerformance(_ cached: Bool) {
        do {
            let adapter = DummyAdapter()
            _ = TestData()
            TestData.deleteFile(storeRoot)
            var store: DIDStore
            if (cached){
                store = try DIDStore.open("filesystem", storeRoot, adapter)
            }
            else {
                store = try DIDStore.open("filesystem", storeRoot, 0, 0, adapter)
            }
                        
            let mnemonic: String = try Mnemonic.generate("0")
            try store.initPrivateIdentity(using: "0", mnemonic: mnemonic, passphrase: passphrase, storepass: storePass)
            
            createDataForPerformanceTest(store)
            let dids: Array<DID> = try store.listDids(DIDStore.DID_ALL)
            XCTAssertEqual(10, dids.count)
            // TODO: TimeMillis
            /*
             long start = System.currentTimeMillis()
             private void testStorePerformance(boolean cached) throws DIDException {
             
             for (int i = 0; i < 1000; i++) {
             for (DID did : dids) {
             DIDDocument doc = store.loadDid(did);
             assertEquals(did, doc.getSubject());
             
             DIDURL id = new DIDURL(did, "cred-1");
             VerifiableCredential vc = store.loadCredential(did, id);
             assertEquals(id, vc.getId());
             }
             }
             
             long end = System.currentTimeMillis();
             
             System.out.println("Store " + (cached ? "with " : "without ") +
             "cache took " + (end - start) + " milliseconds.");
             }
             */
            
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func testStoreWithCache() {
        testStorePerformance(true)
    }
    
    func testStoreWithoutCache() {
        testStorePerformance(false)
    }
    
    func testMultipleStore() {
        do {
            var stores: Array = Array<DIDStore>()
            var docs: Array = Array<DIDDocument>()
            
            for i in 0..<10 {
                let path = storeRoot + String(i)
                TestData.deleteFile(path)
                let store = try DIDStore.open("filesystem", storeRoot + String(i), DummyAdapter())
                stores.append(store)
                let mnemonic: String = try Mnemonic.generate("0")
                try store.initPrivateIdentity("0", mnemonic, passphrase, storePass, true)
            }
            
            for i in 0..<10 {
                let doc: DIDDocument = try stores[i].newDid(storePass)
                XCTAssertNotNil(doc)
                docs.append(doc)
            }
            
            for i in 0..<10 {
                let doc = try stores[i].loadDid(docs[i].subject)
                XCTAssertNotNil(doc)
                XCTAssertEqual(docs[i].toString(true, forSign: true), doc!.toString(true, forSign: true))
            }
        } catch {
            print(error)
            XCTFail()
        }

    }
    
    func testChangePassword() {
        do {
            let testData: TestData = TestData()
            let store = try testData.setup(true)
            _ = try testData.initIdentity()
            
            for i in 0..<10 {
                let alias: String = "my did \(i)"
                let doc = try store.newDid(alias, storePass)
                XCTAssertTrue(doc.isValid)
                var resolved = try doc.subject.resolve(true)
                XCTAssertNil(resolved)
                _ = try store.publishDid(doc.subject, storePass)
                var path: String = storeRoot + "/ids/" + doc.subject.methodSpecificId + "/document"
                XCTAssertTrue(testData.existsFile(path))
                
                path = storeRoot + "/ids/" + doc.subject.methodSpecificId + "/.meta"
                XCTAssertTrue(testData.existsFile(path))
                resolved = try doc.subject.resolve(true)
                XCTAssertNotNil(resolved)
                try store.storeDid(resolved!)
                XCTAssertEqual(alias, resolved!.getMetadata().aliasName)
                XCTAssertEqual(doc.subject, resolved!.subject)
                XCTAssertEqual(doc.proof.signature, resolved!.proof.signature)
                XCTAssertTrue(resolved!.isValid)
            }
            var dids = try store.listDids(DIDStore.DID_ALL)
            XCTAssertEqual(10, dids.count)

            dids = try store.listDids(DIDStore.DID_HAS_PRIVATEKEY);
            XCTAssertEqual(10, dids.count)

            dids = try store.listDids(DIDStore.DID_NO_PRIVATEKEY);
            XCTAssertEqual(0, dids.count)

            try store.changePassword(storePass, "newpasswd")

            dids = try store.listDids(DIDStore.DID_ALL)
            XCTAssertEqual(10, dids.count)

            dids = try store.listDids(DIDStore.DID_HAS_PRIVATEKEY)
            XCTAssertEqual(10, dids.count)

            dids = try store.listDids(DIDStore.DID_NO_PRIVATEKEY)
            XCTAssertEqual(0, dids.count)

            let doc = try store.newDid("newpasswd")
            XCTAssertNotNil(doc)
        } catch {
            print(error)
            XCTFail()
        }
    }

    func testChangePasswordWithWrongPassword() {
        do {
            let testData: TestData = TestData()
            let store = try testData.setup(true)
            _ = try testData.initIdentity()
            for i in 0..<10 {
                let alias = "my did \(i)"
                let doc = try store.newDid(alias, storePass)
                XCTAssertTrue(doc.isValid)
                var resolved = try doc.subject.resolve(true)
                XCTAssertNil(resolved)
                _ = try store.publishDid(doc.subject, storePass)
                var path: String = storeRoot + "/ids/" + doc.subject.methodSpecificId + "/document"
                XCTAssertTrue(testData.existsFile(path))
                
                path = storeRoot + "/ids/" + doc.subject.methodSpecificId + "/.meta"
                XCTAssertTrue(testData.existsFile(path))
                resolved = try doc.subject.resolve(true)
                XCTAssertNotNil(resolved)
                try store.storeDid(resolved!)
                XCTAssertEqual(alias, resolved!.getMetadata().aliasName)
                XCTAssertEqual(doc.subject, resolved!.subject)
                XCTAssertEqual(doc.proof.signature, resolved!.proof.signature)
                XCTAssertTrue(resolved!.isValid)
            }

            var dids = try store.listDids(DIDStore.DID_ALL)
            XCTAssertEqual(10, dids.count)

            dids = try store.listDids(DIDStore.DID_HAS_PRIVATEKEY)
            XCTAssertEqual(10, dids.count)

            dids = try store.listDids(DIDStore.DID_NO_PRIVATEKEY)
            XCTAssertEqual(0, dids.count)

            XCTAssertThrowsError(try store.changePassword("wrongpasswd", "newpasswd")) { error in
                switch error as! DIDError{
                case .didStoreError("Change store password failed."):
                    XCTAssertTrue(true)
                default:
                    XCTFail()
                }
            }
        } catch {
            XCTFail()
        }
    }

    func testExportAndImportDid() {
        do {
            let testData: TestData = TestData()
            let bundle = Bundle(for: type(of: self))
            let jsonPath: String = bundle.path(forResource: "teststore", ofType: "")!

            let adapter = DummyAdapter()
            try DIDBackend.initializeInstance(adapter, TestData.getResolverCacheDir())
            let store = try DIDStore.open("filesystem", jsonPath, adapter)

            let did = try store.listDids(DIDStore.DID_ALL)[0]

            let exportPath = tempDir + "/" + "didexport.json"
            try create(exportPath, forWrite: true)
            let fileHndle: FileHandle = FileHandle(forWritingAtPath: exportPath)!

            try store.exportDid(did, to: fileHndle, using: "password", storepass: storePass)
            let restorePath = tempDir + "/" + "restore"
            TestData.deleteFile(restorePath)

            let store2 = try DIDStore.open("filesystem", restorePath, adapter)

            let readerHndle = FileHandle(forReadingAtPath: exportPath)
            readerHndle?.seek(toFileOffset: 0)
            try store2.importStore(from: readerHndle!, "password", storePass)

//            let didDirPath = storeRoot + "/ids/" + did.methodSpecificId
            let reDidDirPath = restorePath + "/ids/" + did.methodSpecificId

//            XCTAssertTrue(testData.existsFile(didDirPath))
            XCTAssertTrue(testData.exists(reDidDirPath))
//            XCTAssertTrue(Utils.equals(reDidDir, didDir))
            
        } catch {
            XCTFail()
        }
    }

    func testExportAndImportPrivateIdentity() {
        do {
            let testData: TestData = TestData()
            let bundle = Bundle(for: type(of: self))
            let jsonPath: String = bundle.path(forResource: "teststore", ofType: "")!

            let adapter = DummyAdapter()
            try DIDBackend.initializeInstance(adapter, TestData.getResolverCacheDir())
            let store = try DIDStore.open("filesystem", jsonPath, adapter)

            let exportPath = tempDir + "/" + "didexport2.json"
            try create(exportPath, forWrite: true)
            let fileHndle: FileHandle = FileHandle(forWritingAtPath: exportPath)!

            try store.exportPrivateIdentity(to: fileHndle, "password", storePass)
            let restorePath = tempDir + "/" + "restore"
            TestData.deleteFile(restorePath)

            let store2 = try DIDStore.open("filesystem", restorePath, adapter)

            let readerHndle = FileHandle(forReadingAtPath: exportPath)
            readerHndle?.seek(toFileOffset: 0)
            try store2.importPrivateIdentity(from: readerHndle!, using: "password", storepass: storePass)

            //            let didDirPath = storeRoot + "/private"
            let reDidDirPath = restorePath + "/private"
            XCTAssertTrue(testData.exists(reDidDirPath))
        } catch {
            XCTFail()
        }
    }

    func create(_ path: String, forWrite: Bool) throws {

        if !FileManager.default.fileExists(atPath: path) && forWrite {
            let dirPath: String = PathExtracter(path).dirname()
            let fileM = FileManager.default
            let re = fileM.fileExists(atPath: dirPath)
            if !re {
                try fileM.createDirectory(atPath: dirPath, withIntermediateDirectories: true, attributes: nil)
            }
            FileManager.default.createFile(atPath: path, contents: nil, attributes: nil)
        }
    }
}

