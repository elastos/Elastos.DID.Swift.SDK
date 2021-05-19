
import XCTest
@testable import ElastosDIDSDK

class DIDDoucumentTests: XCTestCase {
    var testData: TestData?
    var store: DIDStore?
    var simulatedIDChain: SimulatedIDChain = SimulatedIDChain()
    var adapter: SimulatedIDChainAdapter = SimulatedIDChainAdapter("http://localhost:\(DEFAULT_PORT)/")
    override func setUp() {
        testData = TestData()
        store = testData?.store!
//       try! simulatedIDChain.httpServer.start(in_port_t(DEFAULT_PORT), forceIPv4: true)
//        simulatedIDChain.start()
//        let adapter = simulatedIDChain.getAdapter()
        try! DIDBackend.initialize(adapter)
    }
    
    override func tearDownWithError() throws {
        testData?.cleanup()
        simulatedIDChain.httpServer.stop()
    }
    override func tearDown() {
        testData?.reset()
        testData?.cleanup()
        simulatedIDChain.httpServer.stop()
    }

    func testGetPublicKeyV1() {
        GetPublicKey(1)
    }
    
    func testGetPublicKeyV2() {
        GetPublicKey(2)
    }
    
    func GetPublicKey(_ version: Int) {
        do {
            let doc = try testData!.getCompatibleData(version).getDocument("user1")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())
            XCTAssertEqual(4, doc.publicKeyCount)

            // Count and list.
            XCTAssertEqual(4, doc.publicKeyCount)

            var pks = doc.publicKeys()
            XCTAssertEqual(4, pks.count)
            
            pks.forEach { pk in
                XCTAssertEqual(doc.subject, pk.getId()!.did)
                XCTAssertEqual(Constants.DEFAULT_PUBLICKEY_TYPE, pk.getType())
                if pk.getId()!.fragment == "recovery" {
                    XCTAssertNotEqual(doc.subject, pk.controller)
                }
                else {
                    XCTAssertEqual(doc.subject, pk.controller)
                }
                
                let re = pk.getId()!.fragment == "primary" || pk.getId()!.fragment == "key2" || pk.getId()!.fragment == "key3" || pk.getId()!.fragment == "recovery"
                XCTAssertTrue(re)
            }
            // PublicKey getter.
            var pk = try doc.publicKey(ofId: "#primary")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "#primary"), pk?.getId())
            var id = try DIDURL(doc.subject, "#key2")
            pk = try doc.publicKey(ofId: id)
            XCTAssertNotNil(pk)
            XCTAssertEqual(id, pk?.getId())
            
            id = doc.defaultPublicKeyId()!
            XCTAssertNotNil(id)
            XCTAssertEqual(try DIDURL(doc.subject, "#primary"), id)
            
            // Key not exist, should fail.
            pk = try doc.publicKey(ofId: "#notExist")
            XCTAssertNil(pk)
            
            id = try DIDURL(doc.subject, "#notExist")
            pk = try doc.publicKey(ofId: id)
            XCTAssertNil(pk)
            
            // Selector
            id = doc.defaultPublicKeyId()!
            pks = try doc.selectPublicKeys(byId: id, andType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.subject, "#primary"), pks[0].getId())
            
            pks = try doc.selectPublicKeys(byId: id, andType: nil)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.subject, "#primary"), pks[0].getId())
            
            pks = doc.selectPublicKeys(byType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(4, pks.count)
            
            pks = try doc.selectPublicKeys(byId: "#key2", andType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.subject, "#key2"), pks[0].getId())
            
            pks = try doc.selectPublicKeys(byId: "#key3", andType: nil)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.subject, "#key3"), pks[0].getId())
        } catch {
            XCTFail("\(error)")
        }
    }
    
    func testGetPublicKeyWithCid() {
        do {
            let cd = try testData!.getCompatibleData(2)

            let issuer = try cd.getDocument("issuer")
            
            let doc = try cd.getDocument("examplecorp")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            // Count and list.
            XCTAssertEqual(1, doc.publicKeyCount)

            var pks = doc.publicKeys()
            XCTAssertEqual(1, pks.count)

            XCTAssertEqual(issuer.defaultPublicKeyId(), pks[0].getId())
            
            // PublicKey getter.
            var pk = try doc.publicKey(ofId: "#primary")
            XCTAssertNil(pk)

            var id = try DIDURL(doc.controller!, "#primary")
            pk = try doc.publicKey(ofId: id)
            XCTAssertNotNil(pk)
            XCTAssertEqual(id, pk!.getId())

            id = doc.defaultPublicKeyId()!
            XCTAssertNotNil(id)
            XCTAssertEqual(issuer.defaultPublicKeyId(), id)

            // Key not exist, should fail.
            pk = try doc.publicKey(ofId: "#notExist")
            XCTAssertNil(pk)

            id = try DIDURL(doc.controller!, "#notExist")
            pk = try doc.publicKey(ofId: id)
            XCTAssertNil(pk)
            
            // Selector
            id = doc.defaultPublicKeyId()!
            pks = try doc.selectPublicKeys(byId: id, andType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.controller!, "#primary"), pks[0].getId())

            pks = try doc.selectPublicKeys(byId: id, andType: nil)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.controller!, "#primary"), pks[0].getId())

            pks = doc.selectPublicKeys(byType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
        } catch {
            XCTFail()
        }
    }
    
    func testGetPublicKeyWithMultiControllerCid1() {
        do {
            let cd = try testData!.getCompatibleData(2)

            let user1 = try cd.getDocument("user1")
            let user2 = try cd.getDocument("user2")
            let user3 = try cd.getDocument("user3")
            let doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            // Count and list.
            XCTAssertEqual(7, doc.publicKeyCount)

            var pks = doc.publicKeys()
            XCTAssertEqual(7, pks.count)

            var ids: [DIDURL] = []
            for pk in pks {
                ids.append(pk.getId()!)
            }

            var refs: [DIDURL] = []
            refs.append(user1.defaultPublicKeyId()!)
            refs.append(user2.defaultPublicKeyId()!)
            refs.append(user3.defaultPublicKeyId()!)
            refs.append(try DIDURL(user1.subject, "#key2"))
            refs.append(try DIDURL(user1.subject, "#key3"))
            refs.append(try DIDURL(doc.subject, "#key2"))
            refs.append(try DIDURL(doc.subject, "#key3"))

            XCTAssertEqual(refs.count, ids.count)

            // PublicKey getter.
            var pk = try doc.publicKey(ofId: "#primary")
            XCTAssertNil(pk)

            var id: DIDURL? = try DIDURL(user1.subject, "#primary")
            pk = try doc.publicKey(ofId: id!)
            XCTAssertNotNil(pk)
            XCTAssertEqual(id, pk!.getId())

            id = try DIDURL(user1.subject, "#key2")
            pk = try doc.publicKey(ofId: id!)
            XCTAssertNotNil(pk)
            XCTAssertEqual(id, pk!.getId())

            id = try DIDURL(doc.subject, "#key2")
            pk = try doc.publicKey(ofId: id!)
            XCTAssertNotNil(pk)
            XCTAssertEqual(id, pk!.getId())

            id = try DIDURL(doc.subject, "#key3")
            pk = try doc.publicKey(ofId: id!)
            XCTAssertNotNil(pk)
            XCTAssertEqual(id, pk!.getId())

            id = doc.defaultPublicKeyId()
            XCTAssertNil(id)

            // Key not exist, should fail.
            pk = try doc.publicKey(ofId: "#notExist")
            XCTAssertNil(pk)
            XCTAssertNil(doc.controller)
//            id = try DIDURL("#notExist")
//            pk = try doc.publicKey(ofId: id!)
//            XCTAssertNil(pk)

            // Selector
            id = user1.defaultPublicKeyId()!
            pks = try doc.selectPublicKeys(byId: id!, andType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(id, pks[0].getId())

            pks = try doc.selectPublicKeys(byId: id!, andType: nil)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(id, pks[0].getId())

            pks = doc.selectPublicKeys(byType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(7, pks.count)

            pks = try doc.selectPublicKeys(byId: try DIDURL(user1.subject, "#key2"),
                                       andType: Constants.DEFAULT_PUBLICKEY_TYPE)
            
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(user1.subject, "#key2"), pks[0].getId())

            pks = try doc.selectPublicKeys(byId: try DIDURL(doc.subject, "#key3"), andType: nil)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.subject, "#key3"), pks[0].getId())
        } catch {
            XCTFail()
        }
    }
    
    func testGetPublicKeyWithMultiControllerCid2() {
        do {
            let cd = try testData!.getCompatibleData(2)

            let user1 = try cd.getDocument("user1")
            let user2 = try cd.getDocument("user2")
            let user3 = try cd.getDocument("user3")
            let doc = try cd.getDocument("baz")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            // Count and list.
            XCTAssertEqual(5, doc.publicKeyCount)

            var pks = doc.publicKeys()
            XCTAssertEqual(5, pks.count)

            var ids: [DIDURL] = []
            for pk in pks {
                ids.append(pk.getId()!)
            }

            var refs: [DIDURL] = []
            refs.append(user1.defaultPublicKeyId()!)
            refs.append(user2.defaultPublicKeyId()!)
            refs.append(user3.defaultPublicKeyId()!)
            refs.append(try DIDURL(user1.subject, "#key2"))
            refs.append(try DIDURL(user1.subject, "#key3"))

            XCTAssertEqual(refs.count, ids.count)

            // PublicKey getter.
            var pk = try doc.publicKey(ofId: "#primary")
            XCTAssertNil(pk)

            var id: DIDURL? = try DIDURL(user1.subject, "#primary")
            pk = try doc.publicKey(ofId: id!)
            XCTAssertNotNil(pk)
            XCTAssertEqual(id, pk?.getId())

            id = try DIDURL(user1.subject, "#key2")
            pk = try doc.publicKey(ofId: id!)
            XCTAssertNotNil(pk)
            XCTAssertEqual(id, pk?.getId())

            id = doc.defaultPublicKeyId()
            XCTAssertNil(id)

            // Key not exist, should fail.
            pk = try doc.publicKey(ofId: "#notExist")
            XCTAssertNil(pk)

            id = try DIDURL(user2.subject, "#notExist")
            pk = try doc.publicKey(ofId: id!)
            XCTAssertNil(pk)

            // Selector
            id = user2.defaultPublicKeyId()!
            pks = try doc.selectPublicKeys(byId: id!, andType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(id, pks[0].getId())

            id = user3.defaultPublicKeyId()!
            pks = try doc.selectPublicKeys(byId: id!, andType: nil)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(id, pks[0].getId())

            pks = doc.selectPublicKeys(byType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(5, pks.count)

            pks = try doc.selectPublicKeys(byId: try DIDURL(user1.subject, "#key2"),
                                       andType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(user1.subject, "#key2"), pks[0].getId())

            pks = try doc.selectPublicKeys(byId: try DIDURL(user1.subject, "#key3"), andType: nil)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(user1.subject, "#key3"), pks[0].getId())
        } catch {
            XCTFail()
        }
    }
    
    func testAddPublicKey1() {
        AddPublicKey(1)
    }
    
    func testAddPublicKey2() {
        AddPublicKey(2)
    }
    
    func AddPublicKey(_ version: Int) {
        do {
            _ = try testData!.getRootIdentity()
            
            var doc = try testData!.getCompatibleData(version).getDocument("user1")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())
            
            let db = try doc.editing()
            
            // Add 2 public keys
            let id = try DIDURL(db.getSubject(), "#test1")
            var key = try TestData.generateKeypair()
            _ = try db.appendPublicKey(with: id, controller: db.getSubject().toString(), keyBase58: key.getPublicKeyBase58())
            
            key = try TestData.generateKeypair()
            _ = try db.appendPublicKey(with: "#test2", controller: doc.subject.toString(), keyBase58: key.getPublicKeyBase58())
            
            doc = try db.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())
            
            // Check existence
            var pk = try doc.publicKey(ofId: "#test1")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "#test1"), pk?.getId())
            
            pk = try doc.publicKey(ofId: "#test2")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "#test2"), pk?.getId())
            
            // Check the final count.
            XCTAssertEqual(6, doc.publicKeyCount)
            XCTAssertEqual(3, doc.authenticationKeyCount)
            XCTAssertEqual(1, doc.authorizationKeyCount)
        } catch {
            XCTFail()
        }
    }
    
    func testAddPublicKeyWithCid() {
        do {
            let cd = try testData!.getCompatibleData(2)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            let user1 = try cd.getDocument("user1")
            let user2 = try cd.getDocument("user2")
            _ = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            var doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            let db = try doc.editing(user1)

            // Add 2 public keys
            let id = try DIDURL(db.getSubject(), "#test1")
            var key = try TestData.generateKeypair()
            _ = try db.appendPublicKey(id, db.getSubject(), key.getPublicKeyBase58())

            key = try TestData.generateKeypair();
            _ = try db.appendPublicKey(with: "#test2", controller: doc.subject.toString(), keyBase58: key.getPublicKeyBase58())

            doc = try db.sealed(using: storePassword)
            doc = try user2.sign(doc, storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            // Check existence
            var pk = try doc.publicKey(ofId: "#test1")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "#test1"), pk?.getId())

            pk = try doc.publicKey(ofId: "#test2")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "#test2"), pk?.getId())

            // Check the final count.
            XCTAssertEqual(9, doc.publicKeyCount)
            XCTAssertEqual(7, doc.authenticationKeyCount)
            XCTAssertEqual(0, doc.authorizationKeyCount)
        } catch {
            XCTFail()
        }
    }
    
    func testRemovePublicKey1() {
        RemovePublicKey(1)
    }
    
    func testRemovePublicKey2() {
        RemovePublicKey(2)
    }
    
    func RemovePublicKey(_ version: Int) {
        do {
            _ = try testData!.getRootIdentity()
            
            var doc = try testData!.getCompatibleData(version).getDocument("user1")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())
            
            let db = try doc.editing()
            
            // recovery used by authorization, should failed.
            let id = try DIDURL(doc.subject, "#recovery")
            XCTAssertThrowsError(_ = try db.removePublicKey(with: id)){ error in
                switch error {
                case DIDError.UncheckedError.UnsupportedOperationError.DIDObjectHasReferenceError:
                    XCTAssertTrue(true)
                    break
                default:
                    XCTFail()
                }
            }
            
            // force remove public key, should success
            _ = try db.removePublicKey(with: id, true)
            
            _ = try db.removePublicKey(with: "#key2", true)
            
            // Key not exist, should fail.
            XCTAssertThrowsError(_ = try db.removePublicKey(with: "#notExistKey", true)){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError: break
                default:
                    XCTFail()
                }
            }
            
            // Can not remove default publickey, should fail.
            let d = doc
            
            // Key not exist, should fail.
            XCTAssertThrowsError(_ = try db.removePublicKey(with: d.defaultPublicKeyId()!, true)){ error in
                switch error {
                case DIDError.UncheckedError.UnsupportedOperationError.DIDObjectHasReferenceError: break
                default:
                    XCTFail()
                }
            }
            
            doc = try db.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())
            
            // Check existence
            var pk = try doc.publicKey(ofId: "#recovery")
            XCTAssertNil(pk)
            
            pk = try doc.publicKey(ofId: "#key2")
            XCTAssertNil(pk)
            
            // Check the final count.
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            XCTAssertEqual(0, doc.authorizationKeyCount)
        } catch {
            XCTFail()
        }
    }
    
    func testRemovePublicKeyWithCid() {
        do {
            let cd = try testData!.getCompatibleData(2)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            let user1 = try cd.getDocument("user1")
            let user2 = try cd.getDocument("user2")
            _ = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            var doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            let db = try doc.editing(user2)

            // Can not remove the controller's key
            let key2 = try DIDURL(user1.subject, "#key2")
            XCTAssertThrowsError(_ = try db.removePublicKey(with: key2)){ error in
                switch error {
                case DIDError.UncheckedError.UnsupportedOperationError.DIDObjectHasReferenceError: break
                default:
                    XCTFail()
                }
            }

            // key2 used by authentication, should failed.
            let id = try DIDURL(doc.subject, "#key2")
            XCTAssertThrowsError(_ = try db.removePublicKey(with: id)){ error in
                switch error {
                case DIDError.UncheckedError.UnsupportedOperationError.DIDObjectHasReferenceError: break
                default:
                    XCTFail()
                }
            }
            
            // force remove public key, should success
            _ = try db.removePublicKey(with: id, true)

            _ = try db.removePublicKey(with: "#key3", true)

            // Key not exist, should fail.
            XCTAssertThrowsError(_ = try db.removePublicKey(with: "#notExistKey", true)){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError: break
                default:
                    XCTFail()
                }
            }

            doc = try db.sealed(using: storePassword)
            doc = try user1.sign(doc, storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            // Check existence
            var pk = try doc.publicKey(ofId: "#key2")
            XCTAssertNil(pk)

            pk = try doc.publicKey(ofId: "#key3")
            XCTAssertNil(pk)

            // Check the final count.
            XCTAssertEqual(5, doc.publicKeyCount)
            XCTAssertEqual(5, doc.authenticationKeyCount)
            XCTAssertEqual(0, doc.authorizationKeyCount)
        } catch {
            XCTFail()
        }
    }
    
    func testGetAuthenticationKey1() {
        GetAuthenticationKey(1)
    }
    
    func testGetAuthenticationKey2() {
        GetAuthenticationKey(2)
    }
    
    func GetAuthenticationKey(_ version: Int) {
        do {
            _ = try testData!.getRootIdentity()
            
            let doc = try testData!.getCompatibleData(version).getDocument("user1")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())
            
            // Count and list.
            XCTAssertEqual(3, doc.authenticationKeyCount)
            
            var pks = doc.authenticationKeys()
            XCTAssertEqual(3, pks.count)
            
            for pk in pks {
                XCTAssertEqual(doc.subject, pk.getId()!.did)
                XCTAssertEqual(Constants.DEFAULT_PUBLICKEY_TYPE, pk.getType())
                
                XCTAssertEqual(doc.subject, pk.controller)
                let re = pk.getId()?.fragment == "primary" || pk.getId()?.fragment == "key2" || pk.getId()?.fragment == "key3"
                XCTAssertTrue(re)
            }
            
            // AuthenticationKey getter
            var pk = try doc.authenticationKey(ofId: "#primary")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "#primary"), pk?.getId())
            
            var id = try DIDURL(doc.subject, "#key3")
            pk = try doc.authenticationKey(ofId: id)
            XCTAssertNotNil(pk)
            XCTAssertEqual(id, pk?.getId())
            
            // Key not exist, should fail.
            pk = try doc.authenticationKey(ofId: "#notExist")
            XCTAssertNil(pk)
            
            id = try DIDURL(doc.subject, "#notExist")
            pk = try doc.authenticationKey(ofId: id)
            XCTAssertNil(pk)
            
            // selector
            id = try DIDURL(doc.subject, "#key3")
            pks = try doc.selectAuthenticationKeys(byId: id, andType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(id, pks[0].getId())
            
            pks = try doc.selectAuthenticationKeys(byId: id, andType: nil)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(id, pks[0].getId())
            
            pks = doc.selectAuthenticationKeys(byType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(3, pks.count)
            
            pks = try doc.selectAuthenticationKeys(byId: "#key2", andType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.subject, "#key2"), pks[0].getId())
            
            pks = try doc.selectAuthenticationKeys(byId: "#key2", andType: nil)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.subject, "#key2"), pks[0].getId())
        } catch {
            XCTFail()
        }
    }
    
    func testGetAuthenticationKeyWithCid() {
        do {
            let cd = try testData!.getCompatibleData(2)

            let issuer = try cd.getDocument("issuer")
            let doc = try cd.getDocument("examplecorp")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            // Count and list.
            XCTAssertEqual(1, doc.authenticationKeyCount)

            var pks = doc.authenticationKeys()
            XCTAssertEqual(1, pks.count)

            XCTAssertEqual(issuer.defaultPublicKeyId(), pks[0].getId())

            var pk = try doc.authenticationKey(ofId: "#primary")
            XCTAssertNil(pk)

            var id = try DIDURL(doc.controller!, "#primary")
            pk = try doc.authenticationKey(ofId: id)
            XCTAssertNotNil(pk)
            XCTAssertEqual(id, pk?.getId())

            // Key not exist, should fail.
            pk = try doc.authenticationKey(ofId: "#notExist")
            XCTAssertNil(pk)

            id = try DIDURL(doc.controller!, "#notExist")
            pk = try doc.authenticationKey(ofId: id)
            XCTAssertNil(pk)

            // Selector
            id = doc.defaultPublicKeyId()!
            pks = try doc.selectAuthenticationKeys(byId: id, andType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.controller!, "#primary"),
                    pks[0].getId())

            pks = try doc.selectPublicKeys(byId: id, andType: nil)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.controller!, "#primary"),
                    pks[0].getId())

            pks = doc.selectAuthenticationKeys(byType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
        } catch {
            XCTFail()
        }
    }
    
    func testGetAuthenticationKeyWithMultiControllerCid1() {
        do {
            let cd = try testData!.getCompatibleData(2)

            let user1 = try cd.getDocument("user1")
            let user2 = try cd.getDocument("user2")
            let user3 = try cd.getDocument("user3")
            let doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            // Count and list.
            XCTAssertEqual(7, doc.authenticationKeyCount)

            var pks = doc.authenticationKeys()
            XCTAssertEqual(7, pks.count)

            var ids: [DIDURL] = []
            for pk in pks {
                ids.append(pk.getId()!)
            }

            var refs: [DIDURL] = []
            refs.append(user1.defaultPublicKeyId()!)
            refs.append(user2.defaultPublicKeyId()!)
            refs.append(user3.defaultPublicKeyId()!)
            refs.append(try DIDURL(user1.subject, "#key2"))
            refs.append(try DIDURL(user1.subject, "#key3"))
            refs.append(try DIDURL(doc.subject, "#key2"))
            refs.append(try DIDURL(doc.subject, "#key3"))

            XCTAssertEqual(refs.count, ids.count)

            // PublicKey getter.
            var pk = try doc.authenticationKey(ofId: "#primary")
            XCTAssertNil(pk)

            var id = try DIDURL(user1.subject, "#primary")
            pk = try doc.authenticationKey(ofId: id)
            XCTAssertNotNil(pk)
            XCTAssertEqual(id, pk?.getId())

            id = try DIDURL(user1.subject, "#key2")
            pk = try doc.authenticationKey(ofId: id)
            XCTAssertNotNil(pk)
            XCTAssertEqual(id, pk?.getId())

            id = try DIDURL(doc.subject, "#key2")
            pk = try doc.authenticationKey(ofId: id)
            XCTAssertNotNil(pk)
            XCTAssertEqual(id, pk?.getId())

            id = try DIDURL(doc.subject, "#key3")
            pk = try doc.authenticationKey(ofId: id)
            XCTAssertNotNil(pk)
            XCTAssertEqual(id, pk?.getId())

            // Key not exist, should fail.
            pk = try doc.authenticationKey(ofId: "#notExist")
            XCTAssertNil(pk)
            
            XCTAssertNil(doc.controller)
//            id = try DIDURL("#notExist")
//            pk = try doc.authenticationKey(ofId: id)
//            XCTAssertNil(pk)

            // Selector
            id = user1.defaultPublicKeyId()!
            pks = try doc.selectAuthenticationKeys(byId: id, andType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(id, pks[0].getId())

            pks = try doc.selectAuthenticationKeys(byId: id, andType: nil)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(id, pks[0].getId())

            pks = doc.selectAuthenticationKeys(byType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(7, pks.count)

            pks = try doc.selectAuthenticationKeys(byId: try DIDURL(user1.subject, "#key2"),
                                               andType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(user1.subject, "#key2"), pks[0].getId())

            pks = try doc.selectAuthenticationKeys(byId: try DIDURL(doc.subject, "#key3"), andType: nil)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.subject, "#key3"), pks[0].getId())
        } catch {
            XCTFail()
        }
    }
    
    func testGetAuthenticationKeyWithMultiControllerCid2() {
        do {
            let cd = try testData!.getCompatibleData(2)

            let user1 = try cd.getDocument("user1")
            let user2 = try cd.getDocument("user2")
            let user3 = try cd.getDocument("user3")
            let doc = try cd.getDocument("baz")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            // Count and list.
            XCTAssertEqual(5, doc.authenticationKeyCount)

            var pks = doc.authenticationKeys()
            XCTAssertEqual(5, pks.count)

            var ids: [DIDURL] = []
            for pk in pks {
                ids.append(pk.getId()!)
            }
            
            var refs: [DIDURL] = []
            refs.append(user1.defaultPublicKeyId()!)
            refs.append(user2.defaultPublicKeyId()!)
            refs.append(user3.defaultPublicKeyId()!)
            refs.append(try DIDURL(user1.subject, "#key2"))
            refs.append(try DIDURL(user1.subject, "#key3"))

            XCTAssertEqual(refs.count, ids.count)

            // PublicKey getter.
            var pk = try doc.authenticationKey(ofId: "#primary")
            XCTAssertNil(pk)

            var id = try DIDURL(user1.subject, "#primary")
            pk = try doc.authenticationKey(ofId: id)
            XCTAssertNotNil(pk)
            XCTAssertEqual(id, pk?.getId())

            id = try DIDURL(user1.subject, "#key2")
            pk = try doc.authenticationKey(ofId: id)
            XCTAssertNotNil(pk)
            XCTAssertEqual(id, pk?.getId())

            // Key not exist, should fail.
            pk = try doc.authenticationKey(ofId: "#notExist")
            XCTAssertNil(pk)

            id = try DIDURL(user2.subject, "#notExist")
            pk = try doc.publicKey(ofId: id)
            XCTAssertNil(pk)

            // Selector
            id = user2.defaultPublicKeyId()!
            pks = try doc.selectAuthenticationKeys(byId: id, andType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(id, pks[0].getId())

            id = user3.defaultPublicKeyId()!
            pks = try doc.selectAuthenticationKeys(byId: id, andType: nil)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(id, pks[0].getId())

            pks = doc.selectAuthenticationKeys(byType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(5, pks.count)

            pks = try doc.selectAuthenticationKeys(byId: try DIDURL(user1.subject, "#key2"),
                                               andType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(user1.subject, "#key2"), pks[0].getId())

            pks = try doc.selectAuthenticationKeys(byId: try DIDURL(user1.subject, "#key3"), andType: nil)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(user1.subject, "#key3"), pks[0].getId())
        } catch {
            XCTFail()
        }
    }
    
    func testAddAuthenticationKey1() {
        AddAuthenticationKey(1)
    }
    
    func testAddAuthenticationKey2() {
        AddAuthenticationKey(2)
    }
    
    func AddAuthenticationKey(_ version: Int) {
        do {
            _ = try testData!.getRootIdentity()
            
            var doc = try testData!.getCompatibleData(version).getDocument("user1")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())
            
            let db = try doc.editing()
            
            // Add 2 public keys for test.
            let id = try DIDURL(db.getSubject(), "#test1")
            var key = try TestData.generateKeypair()
            _ = try db.appendPublicKey(with: id, controller: db.getSubject().toString(), keyBase58: key.getPublicKeyBase58())
            
            key = try TestData.generateKeypair()
            _ = try db.appendPublicKey(with: "#test2", controller: doc.subject.toString(), keyBase58: key.getPublicKeyBase58())
            
            // Add by reference
            _ = try db.appendAuthenticationKey(with: try DIDURL(doc.subject, "#test1"))
            
            _ = try db.appendAuthenticationKey(with: "#test2")
            
            // Add new keys
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: try DIDURL(doc.subject, "#test3"),
                                               keyBase58: key.getPublicKeyBase58())
            
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#test4", keyBase58: key.getPublicKeyBase58())
            
            // Try to add a non existing key, should fail.
            XCTAssertThrowsError(_ = try db.appendAuthenticationKey(with: "#notExistKey")){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError: break
                default:
                    XCTFail()
                }
            }
            
            // Try to add a key not owned by self, should fail.
            XCTAssertThrowsError(_ = try db.appendAuthenticationKey(with: "#recovery")){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.IllegalUsageError: break
                default:
                    XCTFail()
                }
            }
            
            doc = try db.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())
            
            // Check existence
            var pk = try doc.authenticationKey(ofId: "#test1")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "#test1"), pk?.getId())
            
            pk = try doc.authenticationKey(ofId: "#test2")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "#test2"), pk?.getId())
            
            pk = try doc.authenticationKey(ofId: "#test3")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "#test3"), pk?.getId())
            
            pk = try doc.authenticationKey(ofId: "#test4")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "#test4"), pk?.getId())
            
            // Check the final count.
            XCTAssertEqual(8, doc.publicKeyCount)
            XCTAssertEqual(7, doc.authenticationKeyCount)
            XCTAssertEqual(1, doc.authorizationKeyCount)
        } catch {
            XCTFail()
        }
    }
    
    func testAddAuthenticationKeyWithCid() {
        do {
            let cd = try testData!.getCompatibleData(2)

            let user1 = try cd.getDocument("user1")
            _ = try cd.getDocument("user2")
            let user3 = try cd.getDocument("user3")
            var doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            let db = try doc.editing(user1)

            // Add 2 public keys for test.
            let id = try DIDURL(db.getSubject(), "#test1")
            var key = try TestData.generateKeypair()
            _ = try db.appendPublicKey(id, db.getSubject(), key.getPublicKeyBase58())

            key = try TestData.generateKeypair()
            _ = try db.appendPublicKey(with: "#test2", controller: doc.subject.toString(), keyBase58: key.getPublicKeyBase58())

            // Add by reference
            _ = try db.appendAuthenticationKey(with: try DIDURL(doc.subject, "#test1"))

            _ = try db.appendAuthenticationKey(with: "#test2")

            // Add new keys
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: try DIDURL(doc.subject, "#test3"),
                                       keyBase58: key.getPublicKeyBase58())

            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#test4", keyBase58: key.getPublicKeyBase58())

            // Try to add a controller's key, should fail.
            let key3 = try DIDURL(user1.subject, "#testkey")
            // Try to add a key not owned by self, should fail.
            XCTAssertThrowsError(_ = try db.appendAuthenticationKey(with: key3)){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError: break
                default:
                    XCTFail()
                }
            }

            // Try to add a non existing key, should fail.
            XCTAssertThrowsError(_ = try db.appendAuthenticationKey(with: "#notExistKey")){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError: break
                default:
                    XCTFail()
                }
            }
            
            // Try to add a key not owned by self, should fail.
            let recovery = try DIDURL(user1.subject, "#recovery")
            XCTAssertThrowsError(_ = try db.appendAuthenticationKey(with: recovery)){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError: break
                default:
                    XCTFail()
                }
            }

            doc = try db.sealed(using: storePassword)
            doc = try user3.sign(doc, storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            // Check existence
            var pk = try doc.authenticationKey(ofId: "#test1")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "#test1"), pk?.getId())

            pk = try doc.authenticationKey(ofId: "#test2")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "#test2"), pk?.getId())

            pk = try doc.authenticationKey(ofId: "#test3")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "#test3"), pk?.getId())

            pk = try doc.authenticationKey(ofId: "#test4")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "#test4"), pk?.getId())

            // Check the final count.
            XCTAssertEqual(11, doc.publicKeyCount)
            XCTAssertEqual(11, doc.authenticationKeyCount)
            XCTAssertEqual(0, doc.authorizationKeyCount)
        } catch {
            XCTFail()
        }
    }
    
    func testRemoveAuthenticationKey1() {
            RemoveAuthenticationKey(1)
    }
    
    func testRemoveAuthenticationKey2() {
            RemoveAuthenticationKey(2)
    }
    
    func RemoveAuthenticationKey(_ version: Int) {
        do {
            _ = try testData!.getRootIdentity()
            
            var doc = try testData!.getCompatibleData(version).getDocument("user1")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())
            
            let db = try doc.editing()
            
            // Add 2 public keys for test
            var key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: try DIDURL(doc.subject, "#test1"),
                                               keyBase58: key.getPublicKeyBase58())
            
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#test2", keyBase58: key.getPublicKeyBase58())
            
            // Remote keys
            _ = try db.removeAuthenticationKey(with: try DIDURL(doc.subject, "#test1"))
                .removeAuthenticationKey(with: "#test2")
                .removeAuthenticationKey(with: "#key2")
            
            // Key not exist, should fail.
            XCTAssertThrowsError(_ = try db.removeAuthenticationKey(with: "#notExistKey")){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError: break
                default:
                    XCTFail()
                }
            }
            
            // Default publickey, can not remove, should fail.
            let id = doc.defaultPublicKeyId()
            XCTAssertThrowsError(_ = try db.removeAuthenticationKey(with: id!)){ error in
                switch error {
                case DIDError.UncheckedError.UnsupportedOperationError.DIDObjectHasReferenceError: break
                default:
                    XCTFail()
                }
            }
            
            doc = try db.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())
            
            // Check existence
            var pk = try doc.authenticationKey(ofId: "#test1")
            XCTAssertNil(pk)
            
            pk = try doc.authenticationKey(ofId: "#test2")
            XCTAssertNil(pk)
            
            pk = try doc.authenticationKey(ofId: "#key2")
            XCTAssertNil(pk)
            
            // Check the final count.
            XCTAssertEqual(6, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            XCTAssertEqual(1, doc.authorizationKeyCount)
        } catch {
            XCTFail()
        }
    }
    
    func testRemoveAuthenticationKeyWithCid() {
        do {
            let cd = try testData!.getCompatibleData(2)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            let user1 = try cd.getDocument("user1")
            let user2 = try cd.getDocument("user2")
            _ = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            var doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            XCTAssertEqual(7, doc.publicKeyCount)
            XCTAssertEqual(7, doc.authenticationKeyCount)
            XCTAssertEqual(0, doc.authorizationKeyCount)

            let db = try doc.editing(user1)

            // Remote keys
            _ = try db.removeAuthenticationKey(with: try DIDURL(doc.subject, "#key2"))
                .removeAuthenticationKey(with: "#key3")

            _ = try db.removePublicKey(with: "#key3")

            // Key not exist, should fail.
            XCTAssertThrowsError(_ = try db.removeAuthenticationKey(with: "#notExistKey")){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError: break
                default:
                    XCTFail()
                }
            }

            // Remove controller's key, should fail.
            let key2 = try DIDURL(user1.subject, "#key2")
            XCTAssertThrowsError(_ = try db.removeAuthenticationKey(with: key2)){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError: break
                default:
                    XCTFail()
                }
            }

            doc = try db.sealed(using: storePassword)
            doc = try user2.sign(doc, storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            // Check existence
            var pk = try doc.authenticationKey(ofId: "#key2")
            XCTAssertNil(pk)

            pk = try doc.authenticationKey(ofId: "#key3")
            XCTAssertNil(pk)

            // Check the final count.
            XCTAssertEqual(6, doc.publicKeyCount)
            XCTAssertEqual(5, doc.authenticationKeyCount)
            XCTAssertEqual(0, doc.authorizationKeyCount)
        } catch {
            XCTFail()
        }
    }
    
    func testGetAuthorizationKey1() {
        do {
            try GetAuthorizationKey(1)
        } catch {
            XCTFail()
        }
    }
    
    func testGetAuthorizationKey2() {
        do {
            try GetAuthorizationKey(2)
        } catch {
            XCTFail()
        }
    }
    
    func GetAuthorizationKey(_ version: Int) throws {
        _ = try testData!.getRootIdentity()

        let doc = try testData!.getCompatibleData(version).getDocument("user1")
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid())

        // Count and list.
        XCTAssertEqual(1, doc.authorizationKeyCount)
        var pks = doc.authorizationKeys()
        XCTAssertEqual(1, pks.count)

        for pk in pks {
            XCTAssertEqual(doc.subject, pk.getId()?.did)
            XCTAssertEqual(Constants.DEFAULT_PUBLICKEY_TYPE, pk.getType())
            XCTAssertNotEqual(doc.subject, pk.controller)
            XCTAssertEqual(pk.getId()?.fragment, "recovery")
        }

        // AuthorizationKey getter
        var pk = try doc.authorizationKey(ofId: "#recovery")
        XCTAssertNotNil(pk)
        XCTAssertEqual(try DIDURL(doc.subject, "#recovery"), pk?.getId())

        var id = try DIDURL(doc.subject, "#recovery")
        pk = try doc.authorizationKey(ofId: id)
        XCTAssertNotNil(pk)
        XCTAssertEqual(id, pk?.getId())

        // Key not exist, should fail.
        pk = try doc.authorizationKey(ofId: "#notExistKey")
        XCTAssertNil(pk)

        id = try DIDURL(doc.subject, "#notExistKey")
        pk = try doc.authorizationKey(ofId: id)
        XCTAssertNil(pk)

        // Selector
        id = try DIDURL(doc.subject, "#recovery")
        pks = try doc.selectAuthorizationKeys(byId: id, andType: Constants.DEFAULT_PUBLICKEY_TYPE)
        XCTAssertEqual(1, pks.count)
        XCTAssertEqual(id, pks[0].getId())

        pks = try doc.selectAuthorizationKeys(byId: id, andType: nil)
        XCTAssertEqual(1, pks.count)
        XCTAssertEqual(id, pks[0].getId())

        pks = doc.selectAuthorizationKeys(byType: Constants.DEFAULT_PUBLICKEY_TYPE)
        XCTAssertEqual(1, pks.count)
    }
    
    func testGetAuthorizationKeyWithCid() {
        do {
            let cd = try testData!.getCompatibleData(2)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            _ = try cd.getDocument("user1")
            _ = try cd.getDocument("user2")
            _ = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            let doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            // Count and list.
            XCTAssertEqual(0, doc.authorizationKeyCount)

            let pks = doc.authorizationKeys
            XCTAssertEqual(0, pks().count)
        } catch {
            XCTFail()
        }
    }
    
    func testAddAuthorizationKey1() {
        do {
            try AddAuthorizationKey(1)
        } catch {
            XCTFail()
        }
    }
    
    func testAddAuthorizationKey2() {
        do {
            try AddAuthorizationKey(2)
        } catch {
            XCTFail()
        }
    }
    
    func AddAuthorizationKey(_ version: Int) throws {
        _ = try testData!.getRootIdentity()

        var doc = try testData!.getCompatibleData(version).getDocument("user1")
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid())

        let db = try doc.editing()

        // Add 2 public keys for test.
        let id = try DIDURL(db.getSubject(), "#test1")
        var key = try TestData.generateKeypair()
        _ = try db.appendPublicKey(with: id, controller: DID(DID.METHOD, key.getAddress()).toString(),
                           keyBase58: key.getPublicKeyBase58())

        key = try TestData.generateKeypair()
        _ = try db.appendPublicKey(with: "#test2",
                           controller: DID(DID.METHOD, key.getAddress()).toString(),
                           keyBase58: key.getPublicKeyBase58())

        // Add by reference
        _ = try db.appendAuthorizationKey(with: try DIDURL(doc.subject, "#test1"))

        _ = try db.appendAuthorizationKey(with: "#test2")

        // Add new keys
        key = try TestData.generateKeypair()
        _ = try db.appendAuthorizationKey(try DIDURL(doc.subject, "#test3"),
                DID(DID.METHOD, key.getAddress()),
                key.getPublicKeyBase58())

        key = try TestData.generateKeypair()
        _ = try db.appendAuthorizationKey(with: "#test4",
                                  controller: DID(DID.METHOD, key.getAddress()).toString(),
                                  keyBase58: key.getPublicKeyBase58())

        // Try to add a non existing key, should fail.
        XCTAssertThrowsError(_ = try db.appendAuthorizationKey(with: "#notExistKey")){ error in
            switch error {
            case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError: break
            default:
                XCTFail()
            }
        }
        
        // Try to add key owned by self, should fail.
        XCTAssertThrowsError(_ = try db.appendAuthorizationKey(with: "#key2")){ error in
            switch error {
            case DIDError.UncheckedError.IllegalArgumentErrors.IllegalUsageError: break
            default:
                XCTFail()
            }
        }

        doc = try db.sealed(using: storePassword)
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid())

        var pk = try doc.authorizationKey(ofId: "#test1")
        XCTAssertNotNil(pk)
        XCTAssertEqual(try DIDURL(doc.subject, "#test1"), pk?.getId())

        pk = try doc.authorizationKey(ofId: "#test2")
        XCTAssertNotNil(pk)
        XCTAssertEqual(try DIDURL(doc.subject, "#test2"), pk?.getId())

        pk = try doc.authorizationKey(ofId: "#test3")
        XCTAssertNotNil(pk)
        XCTAssertEqual(try DIDURL(doc.subject, "#test3"), pk?.getId())

        pk = try doc.authorizationKey(ofId: "#test4")
        XCTAssertNotNil(pk)
        XCTAssertEqual(try DIDURL(doc.subject, "#test4"), pk?.getId())

        // Check the final key count.
        XCTAssertEqual(8, doc.publicKeyCount)
        XCTAssertEqual(3, doc.authenticationKeyCount)
        XCTAssertEqual(5, doc.authorizationKeyCount)
    }
    
    func testAddAuthorizationKeyWithCid() {
        do {
            let cd = try testData!.getCompatibleData(2)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            let user1 = try cd.getDocument("user1")
            let user2 = try cd.getDocument("user2")
            _ = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            var doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            let did = doc.subject
            let db = try doc.editing(user1)

            // Add 2 public keys for test.
            let id = try DIDURL(db.getSubject(), "#test1")
            var key = try TestData.generateKeypair()
            _ = try db.appendPublicKey(with: id,controller: DID(DID.METHOD, key.getAddress()).toString(), keyBase58:
                    key.getPublicKeyBase58())

            key = try TestData.generateKeypair()
            _ = try db.appendPublicKey(with: "#test2", controller: DID(DID.METHOD, key.getAddress()).toString(),
                               keyBase58: key.getPublicKeyBase58())

            XCTAssertThrowsError(_ = try db.appendAuthorizationKey(with: DIDURL(did, "#test1"))){ error in
                switch error {
                case DIDError.UncheckedError.IllegalStateError.NotPrimitiveDIDError: break
                default:
                    XCTFail()
                }
            }

            XCTAssertThrowsError(_ = try db.appendAuthorizationKey(with: "#test2")){ error in
                switch error {
                case DIDError.UncheckedError.IllegalStateError.NotPrimitiveDIDError: break
                default:
                    XCTFail()
                }
            }

            // Try to add a non existing key, should fail.
            XCTAssertThrowsError(_ = try db.appendAuthorizationKey(with: "#notExistKey")){ error in
                switch error {
                case DIDError.UncheckedError.IllegalStateError.NotPrimitiveDIDError: break
                default:
                    XCTFail()
                }
            }

            // Try to add controller's, should fail.
            let recovery = try DIDURL(user1.subject, "#recovery")
            XCTAssertThrowsError(_ = try db.appendAuthorizationKey(with: recovery)){ error in
                switch error {
                case DIDError.UncheckedError.IllegalStateError.NotPrimitiveDIDError: break
                default:
                    XCTFail()
                }
            }

            doc = try db.sealed(using: storePassword)
            doc = try user2.sign(doc, storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            var pk = try doc.authorizationKey(ofId: "#test1")
            XCTAssertNil(pk)

            pk = try doc.authorizationKey(ofId: "#test2")
            XCTAssertNil(pk)

            pk = try doc.authorizationKey(ofId: "#test3")
            XCTAssertNil(pk)

            pk = try doc.authorizationKey(ofId: "#test4")
            XCTAssertNil(pk)

            // Check the final key count.
            XCTAssertEqual(9, doc.publicKeyCount)
            XCTAssertEqual(7, doc.authenticationKeyCount)
            XCTAssertEqual(0, doc.authorizationKeyCount)
        } catch {
            XCTFail()
        }
    }
    
    func testRemoveAuthorizationKey1() {
        do {
            try RemoveAuthorizationKey(1)
        } catch {
            XCTFail()
        }
    }
    
    func testRemoveAuthorizationKey2() {
        do {
            try RemoveAuthorizationKey(2)
        } catch {
            XCTFail()
        }
    }
    
    func RemoveAuthorizationKey(_ version: Int) throws {
        _ = try testData!.getRootIdentity()

        var doc = try testData!.getCompatibleData(version).getDocument("user1")
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid())

        let db = try doc.editing()

        // Add 2 keys for test.
        let id = try DIDURL(db.getSubject(), "#test1")
        var key = try TestData.generateKeypair()
        _ = try db.appendAuthorizationKey(with: id, controller: DID(DID.METHOD, key.getAddress()),
                                  keyBase58: key.getPublicKeyBase58())

        key = try TestData.generateKeypair()
        _ = try db.appendAuthorizationKey(with: "#test2", controller: DID(DID.METHOD, key.getAddress()).toString(),
                                  keyBase58: key.getPublicKeyBase58())

        // Remove keys.
        _ = try db.removeAuthorizationKey(with: try DIDURL(doc.subject, "#test1"))
            .removeAuthorizationKey(with: "#recovery")

        // Key not exist, should fail.
        XCTAssertThrowsError(_ = try db.removeAuthorizationKey(with: "#notExistKey")){ error in
            switch error {
            case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError: break
            default:
                XCTFail()
            }
        }

        doc = try db.sealed(using: storePassword)
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid())

        // Check existence
        var pk = try doc.authorizationKey(ofId: "#test1")
        XCTAssertNil(pk)

        pk = try doc.authorizationKey(ofId: "#test2")
        XCTAssertNotNil(pk)

        pk = try doc.authorizationKey(ofId: "#recovery")
        XCTAssertNil(pk)

        // Check the final count.
        XCTAssertEqual(6, doc.publicKeyCount)
        XCTAssertEqual(3, doc.authenticationKeyCount)
        XCTAssertEqual(1, doc.authorizationKeyCount)
    }
    
    func testGetJceKeyPair() {
        do {
            
        } catch {
            
        }
    }
    
    func testGetCredential1() {
        do {
            try GetCredential(1)
        } catch {
            XCTFail()
        }
    }
    
    func testGetCredential2() {
        do {
            try GetCredential(2)
        } catch {
            XCTFail()
        }
    }
    
    func GetCredential(_ version: Int) throws {
        _ = try testData!.getRootIdentity()

        let doc = try testData!.getCompatibleData(version).getDocument("user1")
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid())

        // Count and list.
        XCTAssertEqual(2, doc.credentialCount)
        var vcs = doc.credentials()
        XCTAssertEqual(2, vcs.count)

        for vc in vcs {
            XCTAssertEqual(doc.subject, vc.getId()?.did)
            XCTAssertEqual(doc.subject, vc.subject?.did)
            
            let re = vc.getId()?.fragment == "profile" || vc.getId()?.fragment == "email"
            XCTAssertTrue(re)
        }

        // Credential getter.
        var vc = try doc.credential(ofId: "#profile")
        XCTAssertNotNil(vc)
        XCTAssertEqual(try DIDURL(doc.subject, "#profile"), vc?.getId())

        vc = doc.credential(ofId: try DIDURL(doc.subject, "#email"))
        XCTAssertNotNil(vc)
        XCTAssertEqual(try DIDURL(doc.subject, "#email"), vc!.getId())

        // Credential not exist.
        vc = try doc.credential(ofId: "#notExistVc")
        XCTAssertNil(vc)

        // Credential selector.
        vcs = try doc.selectCredentials(byId: try DIDURL(doc.subject, "#profile"),
                                    andType: "SelfProclaimedCredential")
        XCTAssertEqual(1, vcs.count)
        XCTAssertEqual(try DIDURL(doc.subject, "#profile"),
                vcs[0].getId())

        vcs = try doc.selectCredentials(byId: try DIDURL(doc.subject, "#profile"), andType: nil)
        XCTAssertEqual(1, vcs.count)
        XCTAssertEqual(try DIDURL(doc.subject, "#profile"), vcs[0].getId())

        vcs = doc.selectCredentials(byType: "SelfProclaimedCredential");
        XCTAssertEqual(1, vcs.count)
        XCTAssertEqual(try DIDURL(doc.subject, "#profile"), vcs[0].getId())

        vcs = doc.selectCredentials(byType: "TestingCredential");
        XCTAssertEqual(0, vcs.count)
    }
    
    func testGetCredentialWithCid() {
        do {
            let cd = try testData!.getCompatibleData(2)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            _ = try cd.getDocument("user1")
            _ = try cd.getDocument("user2")
            _ = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            let doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            // Count and list.
            XCTAssertEqual(2, doc.credentialCount)
            var vcs = doc.credentials()
            XCTAssertEqual(2, vcs.count)

            for vc in vcs {
                XCTAssertEqual(doc.subject, vc.getId()?.did)
                XCTAssertEqual(doc.subject, vc.subject?.did)

                let re = vc.getId()?.fragment == "profile" || vc.getId()?.fragment == "email"
                XCTAssertTrue(re)
            }

            // Credential getter.
            var vc = try doc.credential(ofId: "#profile")
            XCTAssertNotNil(vc)
            XCTAssertEqual(try DIDURL(doc.subject, "#profile"), vc?.getId())

            vc = doc.credential(ofId: try DIDURL(doc.subject, "#email"))
            XCTAssertNotNil(vc)
            XCTAssertEqual(try DIDURL(doc.subject, "#email"), vc?.getId())

            // Credential not exist.
            vc = try doc.credential(ofId: "#notExistVc")
            XCTAssertNil(vc)

            // Credential selector.
            vcs = try doc.selectCredentials(byId: try DIDURL(doc.subject, "#profile"),
                                        andType: "SelfProclaimedCredential")
            XCTAssertEqual(1, vcs.count)
            XCTAssertEqual(try DIDURL(doc.subject, "#profile"), vcs[0].getId())

            vcs = try doc.selectCredentials(byId: try DIDURL(doc.subject, "#profile"), andType: nil)
            XCTAssertEqual(1, vcs.count)
            XCTAssertEqual(try DIDURL(doc.subject, "#profile"), vcs[0].getId())

            vcs = doc.selectCredentials(byType: "SelfProclaimedCredential")
            XCTAssertEqual(1, vcs.count)
            XCTAssertEqual(try DIDURL(doc.subject, "#profile"), vcs[0].getId())

            vcs = doc.selectCredentials(byType: "TestingCredential")
            XCTAssertEqual(0, vcs.count)
        } catch {
            XCTFail()
        }
    }
    
    func testAddCredential1() {
        do {
            try AddCredential(1)
        } catch {
            XCTFail()
        }
    }
    
    func testAddCredential2() {
        do {
            try AddCredential(2)
        } catch {
            XCTFail()
        }
    }
    
    func AddCredential(_ version: Int) throws {
        let cd = try testData!.getCompatibleData(version)

        _ = try testData!.getRootIdentity()

        var doc = try cd.getDocument("user1")
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid())

        let db = try doc.editing()

        // Add credentials.
        var vc = try cd.getCredential("user1", "passport")
        _ = try db.appendCredential(with: vc)

        vc = try cd.getCredential("user1", "twitter")
        _ = try db.appendCredential(with: vc)

        let fvc = vc
        // Credential already exist, should fail.
        XCTAssertThrowsError(_ = try db.appendCredential(with: fvc)){ error in
            switch error {
            case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectAlreadyExistError: break
            default:
                XCTFail()
            }
        }

        doc = try db.sealed(using: storePassword)
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid())

        // Check new added credential.
        vc = try doc.credential(ofId: "#passport")!
        XCTAssertNotNil(vc)
        XCTAssertEqual(try DIDURL(doc.subject, "#passport"), vc.getId())

        let id = try DIDURL(doc.subject, "#twitter")
        vc = doc.credential(ofId: id)!
        XCTAssertNotNil(vc)
        XCTAssertEqual(id, vc.getId())

        // Should contains 3 credentials.
//        assertEquals(4, doc.getCredentialCount());
    }
    
    func testAddCredentialWithCid() {
        do {
            let cd = try testData!.getCompatibleData(2)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            let user1 = try cd.getDocument("user1")
            let user2 = try cd.getDocument("user2")
            _ = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            var doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            let db = try doc.editing(user1)

            // Add credentials.
            var vc = try cd.getCredential("foobar", "license")
            _ = try db.appendCredential(with: vc)

            vc = try cd.getCredential("foobar", "services")
            _ = try db.appendCredential(with: vc)

            let fvc = vc
            // Credential already exist, should fail.
            XCTAssertThrowsError(_ = try db.appendCredential(with: fvc)){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectAlreadyExistError: break
                default:
                    XCTFail()
                }
            }

            // Credential not belongs to current did, should fail.
            XCTAssertThrowsError(_ = try db.appendCredential(with: cd.getCredential("user1", "passport"))){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.IllegalUsageError: break
                default:
                    XCTFail()
                }
            }

            doc = try db.sealed(using: storePassword)
            doc = try user2.sign(doc, storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            // Check new added credential.
            vc = try doc.credential(ofId: "#license")!
            XCTAssertNotNil(vc)
            XCTAssertEqual(try DIDURL(doc.subject, "#license"), vc.getId())

            let id = try DIDURL(doc.subject, "#services")
            vc = doc.credential(ofId: id)!
            XCTAssertNotNil(vc)
            XCTAssertEqual(id, vc.getId())

            XCTAssertEqual(4, doc.credentialCount)
        } catch {
            XCTFail()
        }
    }
    
    func testAddSelfClaimedCredential1() {
        do {
            try AddSelfClaimedCredential(1)
        } catch {
            XCTFail()
        }
    }
    
    func testAddSelfClaimedCredential2() {
        do {
            try AddSelfClaimedCredential(2)
        } catch {
            XCTFail()
        }
    }
    
    func AddSelfClaimedCredential(_ version: Int) throws {
        _ = try testData!.getRootIdentity()

        var doc = try testData!.getCompatibleData(version).getDocument("user1")
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid())

        let db = try doc.editing()

        // Add credentials.
        let subject: [String: String] = ["passport": "S653258Z07"]
        _ = try db.appendCredential(with: "#passport", subject: subject, using: storePassword)

        var json = "{\"name\":\"Jay Holtslander\",\"alternateName\":\"Jason Holtslander\"}"
        _ = try db.appendCredential(with: "#name", json: json, using: storePassword)

        json = "{\"twitter\":\"@john\"}";
        _ = try db.appendCredential(with: "#twitter", json: json, using: storePassword)

        doc = try db.sealed(using: storePassword)
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid())

        // Check new added credential.
        var vc = try doc.credential(ofId: "#passport")
        XCTAssertNotNil(vc)
        XCTAssertEqual(try DIDURL(doc.subject, "#passport"), vc!.getId())
        XCTAssertTrue(vc!.isSelfProclaimed)

        var id = try DIDURL(doc.subject, "#name")
        vc = doc.credential(ofId: id)
        XCTAssertNotNil(vc)
        XCTAssertEqual(id, vc!.getId())
        XCTAssertTrue(vc!.isSelfProclaimed)

        id = try DIDURL(doc.subject, "#twitter")
        vc = doc.credential(ofId: id)
        XCTAssertNotNil(vc)
        XCTAssertEqual(id, vc!.getId())
        XCTAssertTrue(vc!.isSelfProclaimed)

        XCTAssertEqual(5, doc.credentialCount)
    }
    
    func testAddSelfClaimedCredentialWithCid() {
        do {
            let cd = try testData!.getCompatibleData(2)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            let user1 = try cd.getDocument("user1")
            let user2 = try cd.getDocument("user2")
            _ = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            var doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            let db = try doc.editing(user2)

            // Add credentials.
            let subject: [String: String] = ["foo": "bar"]
            _ = try db.appendCredential(with: "#testvc", subject: subject, using: storePassword)

            var json = "{\"name\":\"Foo Bar\",\"alternateName\":\"Jason Holtslander\"}"
            _ = try db.appendCredential(with: "#name", json: json, using: storePassword)

            json = "{\"twitter\":\"@foobar\"}"
            _ = try db.appendCredential(with: "#twitter", json: json, using: storePassword)

            doc = try db.sealed(using: storePassword)
            doc = try user1.sign(doc, storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            // Check new added credential.
            var vc = try doc.credential(ofId: "#testvc")
            XCTAssertNotNil(vc)
            XCTAssertEqual(try DIDURL(doc.subject, "#testvc"), vc!.getId())
            XCTAssertTrue(vc!.isSelfProclaimed)

            var id = try DIDURL(doc.subject, "#name")
            vc = doc.credential(ofId: id)
            XCTAssertNotNil(vc)
            XCTAssertEqual(id, vc!.getId())
            XCTAssertTrue(vc!.isSelfProclaimed)

            id = try DIDURL(doc.subject, "#twitter")
            vc = doc.credential(ofId: id)
            XCTAssertNotNil(vc)
            XCTAssertEqual(id, vc!.getId())
            XCTAssertTrue(vc!.isSelfProclaimed)

            XCTAssertEqual(5, doc.credentialCount)
        } catch {
            XCTFail()
        }
    }
    
    func testRemoveCredential1() {
        do {
            try RemoveCredentia(1)
        } catch {
            XCTFail()
        }
    }
    
    func testRemoveCredential2() {
        do {
            try RemoveCredentia(2)
        } catch {
            XCTFail()
        }
    }
    
    func RemoveCredentia(_ version: Int) throws {
        _ = try testData!.getRootIdentity()
        let cd = try testData!.getCompatibleData(version)

        var doc = try cd.getDocument("user1")
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid())

        let db = try doc.editing()

        // Add test credentials.
        var vc: VerifiableCredential? = try cd.getCredential("user1", "passport")
        _ = try db.appendCredential(with: vc!)

        vc = try cd.getCredential("user1", "twitter")
        _ = try db.appendCredential(with: vc!)

        // Remove credentials
        _ = try db.removeCredential(with: "#profile")

        _ = try db.removeCredential(with: try DIDURL(doc.subject, "#twitter"))

        // Credential not exist, should fail.
        XCTAssertThrowsError(_ = try db.removeCredential(with: "notExistCredential")){ error in
            switch error {
            case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError: break
            default:
                XCTFail()
            }
        }

        let did = doc.subject
        XCTAssertThrowsError(_ = try db.removeCredential(with: DIDURL(did, "#notExistCredential"))){ error in
            switch error {
            case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError: break
            default:
                XCTFail()
            }
        }

        doc = try db.sealed(using: storePassword)
        XCTAssertNotNil(doc);
        XCTAssertTrue(try doc.isValid())

        // Check existence
        vc = try doc.credential(ofId: "#profile")
        XCTAssertNil(vc)

        vc = doc.credential(ofId: try DIDURL(doc.subject, "#twitter"))
        XCTAssertNil(vc)

        // Check the final count.
        XCTAssertEqual(2, doc.credentialCount)
    }
    
    func testRemoveCredentialWithCid() {
        do {
            let cd = try testData!.getCompatibleData(2)
            _ = try testData!.getRootIdentity()
            
            _ = try cd.getDocument("issuer")
            let user1 = try cd.getDocument("user1")
            let user2 = try cd.getDocument("user2")
            _ = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")
            
            var doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())
            
            let db = try doc.editing(user1)
            
            // Remove credentials
            _ = try db.removeCredential(with: "#profile")
            
            _ = try db.removeCredential(with: try DIDURL(doc.subject, "#email"))
            
            // Credential not exist, should fail.
            XCTAssertThrowsError(_ = try db.removeCredential(with: "#notExistCredential")){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError: break
                default:
                    XCTFail()
                }
            }
            
            let did = doc.subject
            XCTAssertThrowsError(_ = try db.removeCredential(with: DIDURL(did, "#notExistCredential"))){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError: break
                default:
                    XCTFail()
                }
            }

            doc = try db.sealed(using: storePassword)
            doc = try user2.sign(doc, storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())
            
            // Check existence
            var vc = try doc.credential(ofId: "#profile")
            XCTAssertNil(vc)
            
            vc = doc.credential(ofId: try DIDURL(doc.subject, "#email"))
            XCTAssertNil(vc)
            
            // Check the final count.
            XCTAssertEqual(0, doc.credentialCount)
        } catch {
            XCTFail()
        }
    }
    
    func testGetService1() {
        do {
            try GetService(1)
        } catch {
            XCTFail()
        }
    }
    
    func testGetService2() {
        do {
            try GetService(2)
        } catch {
            XCTFail()
        }
    }
    
    func GetService(_ version: Int) throws {
        _ = try testData!.getRootIdentity()

        let doc = try testData!.getCompatibleData(version).getDocument("user1")
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid())

        // Count and list
        XCTAssertEqual(3, doc.serviceCount)
        let svcs = doc.services
        XCTAssertEqual(3, svcs().count)

        for svc in svcs() {
            XCTAssertEqual(doc.subject, svc.getId()?.did)
            let re = svc.getId()?.fragment == "openid" || svc.getId()?.fragment == "vcr" || svc.getId()?.fragment == "carrier"
            XCTAssertTrue(re)
        }

        // Service getter, should success.
        var svc = try doc.service(ofId: "#openid")
        XCTAssertNotNil(svc)
        XCTAssertEqual(try DIDURL(doc.subject, "#openid"), svc?.getId())
        XCTAssertEqual("OpenIdConnectVersion1.0Service", svc?.getType());
        XCTAssertEqual("https://openid.example.com/", svc?.endpoint)
        var props = svc!.properties
        XCTAssertTrue(props.isEmpty)

        svc = doc.service(ofId: try DIDURL(doc.subject, "#vcr"))
        XCTAssertNotNil(svc)
        XCTAssertEqual(try DIDURL(doc.subject, "#vcr"), svc?.getId())
        props = svc!.properties
        XCTAssertTrue(props.isEmpty)

        // Service not exist, should fail.
        svc = try doc.service(ofId: "#notExistService")
        XCTAssertNil(svc)

        // Service selector.
        var svcss = try doc.selectServices(byId: "#vcr", andType: "CredentialRepositoryService")
        XCTAssertEqual(1, svcss.count)
        XCTAssertEqual(try DIDURL(doc.subject, "#vcr"), svcss[0].getId())

        svcss = doc.selectServices(byId: try DIDURL(doc.subject, "#openid"), andType: nil)
        XCTAssertEqual(1, svcss.count)
        XCTAssertEqual(try DIDURL(doc.subject, "#openid"),
                     svcss[0].getId())

        svcss = doc.selectServices(byType: "CarrierAddress")
        XCTAssertEqual(1, svcss.count)
        XCTAssertEqual(try DIDURL(doc.subject, "#carrier"),
                svcss[0].getId())
        props = svcss[0].properties
        if (version == 1) {
            XCTAssertTrue(props.isEmpty)
        } else {
            XCTAssertEqual(12, props.count)
            XCTAssertEqual("lalala...", props["foobar"] as? String)
            XCTAssertEqual("Lalala...", props["FOOBAR"] as? String)
        }

        // Service not exist, should return a empty list.
        svcss = try doc.selectServices(byId: "#notExistService",
                                   andType: "CredentialRepositoryService")
        XCTAssertEqual(0, svcss.count)

        svcss = doc.selectServices(byType: "notExistType")
        XCTAssertEqual(0, svcss.count)
    }
    
    func testGetServiceWithCid() {
        do {
            let cd = try testData!.getCompatibleData(2)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            _ = try cd.getDocument("user1")
            _ = try cd.getDocument("user2")
            _ = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            let doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            // Count and list
            XCTAssertEqual(2, doc.serviceCount)
            var svcs = doc.services()
            XCTAssertEqual(2, svcs.count)

            for svc in svcs {
                XCTAssertEqual(doc.subject, svc.getId()?.did)
                let re = svc.getId()?.fragment == "vault" || svc.getId()?.fragment == "vcr"
                XCTAssertTrue(re)
            }

            // Service getter, should success.
            var svc = try doc.service(ofId: "#vault")
            XCTAssertNotNil(svc)
            XCTAssertEqual(try DIDURL(doc.subject, "#vault"), svc?.getId())
            XCTAssertEqual("Hive.Vault.Service", svc?.getType())
            XCTAssertEqual("https://foobar.com/vault", svc?.endpoint)
            var props = svc?.properties
            XCTAssertTrue(props!.isEmpty)

            svc = doc.service(ofId: try DIDURL(doc.subject, "#vcr"))
            XCTAssertNotNil(svc)
            XCTAssertEqual(try DIDURL(doc.subject, "#vcr"), svc?.getId())
            props = svc?.properties
            XCTAssertEqual(12, props?.count)
            XCTAssertEqual("lalala...", props!["foobar"] as! String)
            XCTAssertEqual("Lalala...", props!["FOOBAR"] as! String)

            // Service not exist, should fail.
            svc = try doc.service(ofId: "#notExistService")
            XCTAssertNil(svc)

            // Service selector.
            svcs = try doc.selectServices(byId: "#vcr", andType: "CredentialRepositoryService")
            XCTAssertEqual(1, svcs.count)
            XCTAssertEqual(try DIDURL(doc.subject, "#vcr"), svcs[0].getId())

            svcs = doc.selectServices(byId: try DIDURL(doc.subject, "#openid"), andType: nil)
            XCTAssertEqual(0, svcs.count)

            // Service not exist, should return a empty list.
            svcs = try doc.selectServices(byId: "#notExistService", andType: "CredentialRepositoryService")
            XCTAssertEqual(0, svcs.count)

            svcs = doc.selectServices(byType: "notExistType")
            XCTAssertEqual(0, svcs.count)
        } catch {
            XCTFail()
        }
    }
    
    func testAddService1() {
        do {
            try AddService(1)
        } catch {
            XCTFail()
        }
    }
    
    func testAddService2() {
        do {
            try AddService(2)
        } catch {
            XCTFail()
        }
    }
    
    func AddService(_ version: Int) throws {
        _ = try testData!.getRootIdentity()

        var doc = try testData!.getCompatibleData(version).getDocument("user1")
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid())

        let db = try doc.editing()

        // Add services
        _ = try db.appendService(with: "#test-svc-1", type: "Service.Testing",
                         endpoint: "https://www.elastos.org/testing1")

        _ = try db.appendService(with: try DIDURL(doc.subject, "#test-svc-2"),
                         type: "Service.Testing", endpoint: "https://www.elastos.org/testing2")

        // Service id already exist, should failed.
        XCTAssertThrowsError(_ = try db.appendService(with: "#vcr", type: "test", endpoint: "https://www.elastos.org/test")){ error in
            switch error {
            case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectAlreadyExistError: break
            default:
                XCTFail()
            }
        }
        
        doc = try db.sealed(using: storePassword)
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid())

        // Check the final count
        XCTAssertEqual(5, doc.serviceCount)

        // Try to select new added 2 services
        let svcs = doc.selectServices(byType: "Service.Testing")
        XCTAssertEqual(2, svcs.count)
        XCTAssertEqual("Service.Testing", svcs[0].getType())
        XCTAssertEqual("Service.Testing", svcs[1].getType())
    }
    
    func testAddServiceWithDescription1() {
        AddServiceWithDescription(1)
    }
    
    func testAddServiceWithDescription2() {
        AddServiceWithDescription(2)
    }
    
    func AddServiceWithDescription(_ version: Int) {
        do {
            _ = try testData!.getRootIdentity()
            
            let map = ["abc": "helloworld",
                       "foo": 123,
                       "bar": "foobar",
                       "foobar": "lalala...",
                       "date": DateFormatter.currentDate(),
                       "ABC": "Helloworld",
                       "FOO": 678,
                       "BAR": "Foobar",
                       "FOOBAR": "Lalala...",
                       "DATE": DateFormatter.currentDate()] as [String : Any]
            let props = ["abc": "helloworld",
                         "foo": 123,
                         "bar": "foobar",
                         "foobar": "lalala...",
                         "date": DateFormatter.currentDate(),
                         "map": map,
                         "ABC": "Helloworld",
                         "FOO": 678,
                         "BAR": "Foobar",
                         "FOOBAR": "Lalala...",
                         "DATE": DateFormatter.currentDate(),
                         "MAP": map] as [String : Any]
            
            var doc = try testData!.getCompatibleData(version).getDocument("user1")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())
            
            let db = try doc.editing()
            
            // Add services
            _ = try db.appendService(with: "#test-svc-1", type: "Service.Testing",
                                     endpoint: "https://www.elastos.org/testing1", properties: props)
            
            _ = try db.appendService(with: try DIDURL(doc.subject, "#test-svc-2"),
                                     type: "Service.Testing", endpoint: "https://www.elastos.org/testing2", properties: props)
            
            _ = try db.appendService(with: try DIDURL(doc.subject, "#test-svc-3"),
                                     type: "Service.Testing", endpoint: "https://www.elastos.org/testing3")
            
            // Service id already exist, should failed.
            XCTAssertThrowsError(_ = try db.appendService(with: "#vcr", type: "test", endpoint: "https://www.elastos.org/test")){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectAlreadyExistError: break
                default:
                    XCTFail()
                }
            }
            
            doc = try db.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())
            
            // Check the final count
            XCTAssertEqual(6, doc.serviceCount)
            
            // Try to select new added 2 services
            let svcs = doc.selectServices(byType: "Service.Testing")
            XCTAssertEqual(3, svcs.count)
            let re1 = !svcs[0].properties.isEmpty || !svcs[1].properties.isEmpty || !svcs[2].properties.isEmpty
            let re2 = svcs[2].properties.isEmpty || svcs[1].properties.isEmpty || svcs[0].properties.isEmpty
            
            XCTAssertEqual("Service.Testing", svcs[0].getType())
            XCTAssertTrue(re1)
            XCTAssertTrue(re2)
//            XCTAssertTrue(svcs[0].properties.isEmpty == false)
            XCTAssertEqual("Service.Testing", svcs[1].getType())
//            XCTAssertTrue(svcs[1].properties.isEmpty == false)
            XCTAssertEqual("Service.Testing", svcs[2].getType())
//            XCTAssertTrue(svcs[2].properties.isEmpty == true)
        } catch {
            XCTFail()
        }
    }
    
    func testAddServiceWithCid() {
        do {
            let cd = try testData!.getCompatibleData(2)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            let user1 = try cd.getDocument("user1")
            _ = try cd.getDocument("user2")
            let user3 = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            var doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            let db = try doc.editing(user3)

            // Add services
            _ = try db.appendService(with: "#test-svc-1", type: "Service.Testing",
                             endpoint: "https://www.elastos.org/testing1")

            _ = try db.appendService(with: try DIDURL(doc.subject, "#test-svc-2"),
                             type: "Service.Testing", endpoint: "https://www.elastos.org/testing2")

            // Service id already exist, should failed.
            XCTAssertThrowsError(_ = try db.appendService(with: "#vcr", type: "test", endpoint: "https://www.elastos.org/test")){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectAlreadyExistError: break
                default:
                    XCTFail()
                }
            }

            doc = try db.sealed(using: storePassword)
            doc = try user1.sign(doc, storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            // Check the final count
            XCTAssertEqual(4, doc.serviceCount)

            // Try to select new added 2 services
            let svcs = doc.selectServices(byType: "Service.Testing")
            XCTAssertEqual(2, svcs.count)
            XCTAssertEqual("Service.Testing", svcs[0].getType())
            XCTAssertEqual("Service.Testing", svcs[1].getType())
        } catch {
            XCTFail()
        }
    }
    
    func testAddServiceWithCidAndDescription() {
        do {
            let cd = try testData!.getCompatibleData(2)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            let user1 = try cd.getDocument("user1")
            _ = try cd.getDocument("user2")
            let user3 = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            var doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            let db = try doc.editing(user3)

            let map = ["abc": "helloworld",
                       "foo": 123,
                       "bar": "foobar",
                       "foobar": "lalala...",
                       "date": DateFormatter.currentDate(),
                       "ABC": "Helloworld",
                       "FOO": 678,
                       "BAR": "Foobar",
                       "FOOBAR": "Lalala...",
                       "DATE": DateFormatter.currentDate()] as [String : Any]
            let props = ["abc": "helloworld",
                       "foo": 123,
                       "bar": "foobar",
                       "foobar": "lalala...",
                       "date": DateFormatter.currentDate(),
                       "map": map,
                       "ABC": "Helloworld",
                       "FOO": 678,
                       "BAR": "Foobar",
                       "FOOBAR": "Lalala...",
                       "DATE": DateFormatter.currentDate(),
                       "MAP": map] as [String : Any]
            // Add services
            _ = try db.appendService(with: "#test-svc-1", type: "Service.Testing",
                             endpoint: "https://www.elastos.org/testing1", properties: props)

            _ = try db.appendService(with: try DIDURL(doc.subject, "#test-svc-2"),
                             type: "Service.Testing", endpoint: "https://www.elastos.org/testing2", properties: props)

            _ = try db.appendService(with: try DIDURL(doc.subject, "#test-svc-3"),
                             type: "Service.Testing", endpoint: "https://www.elastos.org/testing3")

            // Service id already exist, should failed.
            XCTAssertThrowsError(_ = try db.appendService(with: "#vcr", type: "test", endpoint: "https://www.elastos.org/test", properties: props)){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectAlreadyExistError: break
                default:
                    XCTFail()
                }
            }

            doc = try db.sealed(using: storePassword)
            doc = try user1.sign(doc, storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            // Check the final count
            XCTAssertEqual(5, doc.serviceCount)

            // Try to select new added 2 services
            let svcs = doc.selectServices(byType: "Service.Testing")
            XCTAssertEqual(3, svcs.count)
            XCTAssertEqual("Service.Testing", svcs[0].getType())
            XCTAssertTrue(!svcs[0].properties.isEmpty)
            XCTAssertEqual("Service.Testing", svcs[1].getType())
            XCTAssertTrue(!svcs[1].properties.isEmpty)
            XCTAssertEqual("Service.Testing", svcs[2].getType())
            XCTAssertTrue(svcs[2].properties.isEmpty)
        } catch {
            XCTFail()
        }
    }
    
    func testRemoveService1() {
        do {
            try RemoveService(1)
        } catch {
            XCTFail()
        }
    }
    
    func testRemoveService2() {
        do {
            try RemoveService(2)
        } catch {
            XCTFail()
        }
    }
    
    func RemoveService(_ version: Int) throws {
        do {
            _ = try testData!.getRootIdentity()

            var doc = try testData!.getCompatibleData(version).getDocument("user1")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            let db = try doc.editing()

            // remove services
            _ = try db.removeService(with: "#openid")
            _ = try db.removeService(with: try DIDURL(doc.subject, "#vcr"))

            // Service not exist, should fail.
            XCTAssertThrowsError(_ = try db.removeService(with: "#notExistService")){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError: break
                default:
                    XCTFail()
                }
            }

            doc = try db.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            var svc = try doc.service(ofId: "#openid")
            XCTAssertNil(svc)

            svc = doc.service(ofId: try DIDURL(doc.subject, "#vcr"))
            XCTAssertNil(svc)

            // Check the final count
            XCTAssertEqual(1, doc.serviceCount)
        } catch {
            XCTFail()
        }
    }
    
    func testRemoveServiceWithCid() {
        do {
            let cd = try testData!.getCompatibleData(2)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            let user1 = try cd.getDocument("user1")
            _ = try cd.getDocument("user2")
            let user3 = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            var doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            let db = try doc.editing(user1)

            // remove services
            _ = try db.removeService(with: "#vault")

            _ = try db.removeService(with: try DIDURL(doc.subject, "#vcr"))

            // Service not exist, should fail.
            XCTAssertThrowsError(_ = try db.removeService(with: "#notExistService")){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError: break
                default:
                    XCTFail()
                }
            }

            doc = try db.sealed(using: storePassword)
            doc = try user3.sign(doc, storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            var svc = try doc.service(ofId: "#openid")
            XCTAssertNil(svc)

            svc = doc.service(ofId: try DIDURL(doc.subject, "#vcr"))
            XCTAssertNil(svc)

            // Check the final count
            XCTAssertEqual(0, doc.serviceCount)
        } catch {
            XCTFail()
        }
    }
    
    func testParseAndSerializeDocument1() {
        ParseAndSerializeDocument(1, "issuer")
    }
    
    func testParseAndSerializeDocument2() {
        ParseAndSerializeDocument(1, "user1")
    }
    
    func testParseAndSerializeDocument3() {
        ParseAndSerializeDocument(1, "user2")
    }
    
    func testParseAndSerializeDocument4() {
        ParseAndSerializeDocument(1, "user3")
    }
    
    func testParseAndSerializeDocument5() {
        ParseAndSerializeDocument(2, "examplecorp")
    }
    
    func testParseAndSerializeDocument6() {
        ParseAndSerializeDocument(2, "foobar")
    }
    
    func testParseAndSerializeDocument7() {
        ParseAndSerializeDocument(2, "foo")
    }
    
    func testParseAndSerializeDocument8() {
        ParseAndSerializeDocument(2, "bar")
    }
    
    func testParseAndSerializeDocument9() {
        ParseAndSerializeDocument(2, "baz")
    }
    
    func ParseAndSerializeDocument(_ version: Int, _ did: String) {
        do {
            let cd = try testData!.getCompatibleData(version)
            try cd.loadAll()
            
            let compactJson = try cd.getDocumentJson(did, "compact")
            let compact = try DIDDocument.convertToDIDDocument(fromJson: compactJson)
            XCTAssertNotNil(compact)
            XCTAssertTrue(try compact.isValid())
            
            let normalizedJson = try cd.getDocumentJson(did, "normalized")
            let normalized = try DIDDocument.convertToDIDDocument(fromJson: normalizedJson)
            XCTAssertNotNil(normalized)
            XCTAssertTrue(try normalized.isValid())
            
            let doc = try cd.getDocument(did)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())
            
            let compactStr = compact.toString(true)
            let normalizedStr = normalized.toString(true)
            let docStr = doc.toString(true)
            XCTAssertEqual(normalizedJson, compactStr)
            XCTAssertEqual(normalizedJson, normalizedStr)
            XCTAssertEqual(normalizedJson, docStr)
            
            // Don't check the compact mode for the old versions
            if (cd.isLatestVersion) {
                let compactStrfalse = compact.toString(false)
                let normalizedStrfalse = normalized.toString(false)
                let docStrfalse = doc.toString(false)
                XCTAssertEqual(compactJson, compactStrfalse)
                XCTAssertEqual(compactJson, normalizedStrfalse)
                XCTAssertEqual(compactJson, docStrfalse)
            }
        }
        catch {
            XCTFail()
        }
    }
    
    func testSignAndVerify() {
        do {
            let identity = try testData!.getRootIdentity()
            let doc = try identity.newDid(storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())
            
            //            let data = byte[1024]
            _ = try DIDURL(doc.subject, "#primary")
            
            //            for i in 0...10 {
            ////                Arrays.fill(data, (byte) i);
            //
            //                let sig = doc.sign(pkid, storePassword, data)
            //                let result = doc.verify(pkid, sig, data)
            //                XCTAssertTrue(result)
            //
            //                data[0] = 0xF
            //                result = doc.verify(pkid, sig, data)
            //                XCTAssertFalse(result)
            //
            //                sig = doc.sign(storePassword, data)
            //                result = doc.verify(sig, data)
            //                assertTrue(result)
            //
            //                data[0] =  i
            //                result = doc.verify(sig, data)
            //                XCTAssertFalse(result)
            //            }
        } catch {
            XCTFail()
        }
    }
    
    func testDerive() {
        do {
            let identity = try testData!.getRootIdentity()
            let doc = try identity.newDid(storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            for i in 0...1000 {
                let strKey = try doc.derive(index: i, storePassword: storePassword)
                let key = DIDHDKey.deserializeBase58(strKey)

                let binKey = Base58.bytesFromBase58(strKey)
                let sk = Array(binKey[46..<78])
                XCTAssertEqual(key.getPrivateKeyBytes().count, sk.count)
                XCTAssertEqual(key.getPrivateKeyBytes(), sk)
            }
        } catch {
            XCTFail()
        }
    }
    
    func testDerive2() {
        do {
            let doc = try testData!.getCompatibleData(2).getDocument("user1")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())
            for i in 0...1000 {
                let strKey = try doc.derive(index: i, storePassword: storePassword)
                let key = DIDHDKey.deserializeBase58(strKey)

                let binKey = Base58.bytesFromBase58(strKey)
                let sk = Array(binKey[46..<78])

                XCTAssertEqual(key.getPrivateKeyBytes().count, sk.count)
                XCTAssertEqual(key.getPrivateKeyBytes(), sk)
            }
        } catch {
            XCTFail()
        }
    }
    
    func testDeriveFromIdentifier() {
        do {
            let identifier = "org.elastos.did.test"

            let identity = try testData!.getRootIdentity()
            let doc = try identity.newDid(storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            for i in 0...1000 {
                let strKey = try doc.derive(identifier, i, storePassword);
                let key = DIDHDKey.deserializeBase58(strKey)

                let binKey = Base58.bytesFromBase58(strKey)
                let sk = Array(binKey[46..<78])

                XCTAssertEqual(key.getPrivateKeyBytes().count, sk.count)
                XCTAssertEqual(key.getPrivateKeyBytes(), sk)
            }
        } catch {
            XCTFail()
        }
    }
    
    func testDeriveFromIdentifier2() {
        do {
            let identifier = "org.elastos.did.test"

            let doc = try testData!.getCompatibleData(2).getDocument("user1")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            for i in 0...100 {
                let strKey = try doc.derive(identifier, i, storePassword)
                let key = DIDHDKey.deserializeBase58(strKey)

                let binKey = Base58.bytesFromBase58(strKey)
                let sk = Array(binKey[46..<78])

                XCTAssertEqual(key.getPrivateKeyBytes().count, sk.count)
                XCTAssertEqual(key.getPrivateKeyBytes(), sk);
            }
        } catch {
            XCTFail()
        }
    }
    
    func testCreateCustomizedDid() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let controller = try identity.newDid(storePassword)
            XCTAssertTrue(try controller.isValid())

            var resolved = try controller.subject.resolve()
            XCTAssertNil(resolved)

            try controller.publish(storePassword);

            resolved = try controller.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(controller.subject, resolved?.subject)
            XCTAssertEqual(controller.proof.signature,
                           resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Create customized DID
            let did = try DID("did:elastos:helloworld")
            let doc = try controller.newCustomizedDid(did, storePassword)
            XCTAssertTrue(try doc.isValid())

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(controller.subject, doc.controller)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.publish(storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(controller.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func testCreateMultisigCustomizedDid() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let ctrl1 = try identity.newDid(storePassword)
            
            try ctrl1.publish(storePassword)

            var resolved = try ctrl1.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl1.subject, resolved?.subject)
            XCTAssertEqual(ctrl1.proof.signature,
                           resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            let ctrl2 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl2.isValid())
            try ctrl2.publish(storePassword)

            resolved = try ctrl2.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl2.subject, resolved?.subject)
            XCTAssertEqual(ctrl2.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            let ctrl3 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl3.isValid())
            try ctrl3.publish(storePassword)

            resolved = try ctrl3.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl3.subject, resolved?.subject)
            XCTAssertEqual(ctrl3.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Create customized DID
            let did = try DID("did:elastos:helloworld3")
            var doc = try ctrl1.newCustomizedDid(did, [ctrl2.subject, ctrl3.subject],
                    2, storePassword)
            XCTAssertFalse(try doc.isValid())

//            XCTAssertThrowsError(_ = try ctrl1.sign(using: storePassword, for: [doc.toString().data(using: .utf8)!])){ error in
//                switch error {
//                case DIDError.UncheckedError.IllegalStateError.AlreadySignedError: break
//                default:
//                    XCTFail()
//                }
//            }
            doc = try ctrl2.sign(doc, storePassword)
            XCTAssertTrue(try doc.isValid());

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(3, doc.controllerCount())
            var ctrls = [ctrl1.subject, ctrl2.subject, ctrl3.subject]
            ctrls = ctrls.sorted { (didA, didB) -> Bool in
                let compareResult = didA.toString().compare(didB.toString())
                return compareResult == ComparisonResult.orderedAscending
            }
            XCTAssertEqual(doc.controllers(), ctrls)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.setEffectiveController(ctrl1.subject)
            try doc.publish(storePassword)

            resolved = try did.resolve()
//            XCTAssertNotNil(resolved)
//            XCTAssertEqual(did, resolved?.subject)
//            XCTAssertEqual(doc.proof.signature,
//                    resolved?.proof.signature)
//
//            XCTAssertTrue(try resolved!.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func testUpdateDid() {
        do {
            let identity = try testData!.getRootIdentity()

            var doc = try identity.newDid(storePassword)
            XCTAssertTrue(try doc.isValid())

            try doc.publish(storePassword)

            var resolved = try doc.subject.resolve() 
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())

            // Update
            var db = try doc.editing()
            var key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())

            // Update again
            db = try doc.editing()
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key2", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            XCTAssertEqual(3, doc.publicKeyCount)
            XCTAssertEqual(3, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())
        } catch {
            XCTFail()
        }
    }
    
    func testUpdateCustomizedDid() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let controller = try identity.newDid(storePassword)
            XCTAssertTrue(try controller.isValid())

            var resolved = try controller.subject.resolve();
            XCTAssertNil(resolved)

            try controller.publish(storePassword)

            resolved = try controller.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(controller.subject, resolved!.subject)
            XCTAssertEqual(controller.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Create customized DID
            let did = try DID("did:elastos:helloworld")
            var doc = try controller.newCustomizedDid(did, storePassword)
            XCTAssertTrue(try doc.isValid())

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(controller.subject, doc.controller)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.publish(storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(controller.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Update
            var db = try doc.editing()
            var key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            // Update again
            db = try doc.editing()
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key2", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            XCTAssertEqual(3, doc.publicKeyCount)
            XCTAssertEqual(3, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())
        } catch {
            XCTFail()
        }
    }
    
    func testUpdateMultisigCustomizedDid() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let ctrl1 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl1.isValid())
            try ctrl1.publish(storePassword)

            var resolved = try ctrl1.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl1.subject, resolved?.subject)
            XCTAssertEqual(ctrl1.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            let ctrl2 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl2.isValid())
            try ctrl2.publish(storePassword)

            resolved = try ctrl2.subject.resolve();
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl2.subject, resolved?.subject)
            XCTAssertEqual(ctrl2.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            let ctrl3 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl3.isValid())
            try ctrl3.publish(storePassword)

            resolved = try ctrl3.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl3.subject, resolved?.subject)
            XCTAssertEqual(ctrl3.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Create customized DID
            let did = try DID("did:elastos:helloworld3")
            var doc = try ctrl1.newCustomizedDid(did, [ctrl2.subject, ctrl3.subject],
                    2, storePassword)
            XCTAssertFalse(try doc.isValid())

            _ = doc
//            XCTAssertThrowsError(_ = try ctrl1.sign(using: storePassword, for: [doc.toString().data(using: .utf8)!])){ error in
//                switch error {
//                case DIDError.UncheckedError.IllegalStateError.AlreadySignedError: break
//                default:
//                    XCTFail()
//                }
//            }

            doc = try ctrl2.sign(doc, storePassword)
            XCTAssertTrue(try doc.isValid())

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(3, doc.controllerCount())
            let ctrls = [ctrl1.subject, ctrl2.subject, ctrl3.subject]
            XCTAssertEqual(doc.controllers().count, ctrls.count)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.setEffectiveController(ctrl1.subject)
            try doc.publish(storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Update
            var db = try doc.editing(ctrl2)
            var key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            doc = try ctrl1.sign(doc, storePassword)
            try store!.storeDid(using: doc)

            try doc.publish(storePassword)

            resolved = try doc.subject.resolve()
            
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())
            XCTAssertEqual(4, resolved?.publicKeyCount)
            XCTAssertEqual(4, resolved?.authenticationKeyCount)

            // Update again
            db = try doc.editing(ctrl3)
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key2", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            doc = try ctrl2.sign(doc, storePassword)
            try store!.storeDid(using: doc)

            try doc.publish(storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())
            XCTAssertEqual(5, resolved?.publicKeyCount)
            XCTAssertEqual(5, resolved?.authenticationKeyCount)
        } catch {
            XCTFail()
        }
    }
    
    func testTransferCustomizedDidAfterCreate() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let controller = try identity.newDid(storePassword)
            XCTAssertTrue(try controller.isValid())

            var resolved = try controller.subject.resolve()
            XCTAssertNil(resolved)

            try controller.publish(storePassword)

            resolved = try controller.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(controller.subject, resolved?.subject)
            XCTAssertEqual(controller.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Create customized DID
            let did = try DID("did:elastos:helloworld")
            var doc = try controller.newCustomizedDid(did, storePassword)
            XCTAssertTrue(try doc.isValid())

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(controller.subject, doc.controller)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.publish(storePassword);

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(controller.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // create new controller
            let newController = try identity.newDid(storePassword)
            XCTAssertTrue(try controller.isValid())

            resolved = try newController.subject.resolve()
            XCTAssertNil(resolved)

            try newController.publish(storePassword)

            resolved = try newController.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(newController.subject, resolved?.subject)
            XCTAssertEqual(newController.proof.signature,
                           resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // create the transfer ticket
            try doc.setEffectiveController(controller.subject)
            let ticket = try doc.createTransferTicket(to: newController.subject, storePassword)
            XCTAssertTrue(try ticket.isValid())

            // create new document for customized DID
            doc = try newController.newCustomizedDid(did, true, storePassword)
            XCTAssertTrue(try doc.isValid())

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(newController.subject, doc.controller)

            // transfer
            try doc.publish(ticket, storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(newController.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func testTransferCustomizedDidAfterUpdate() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let controller = try identity.newDid(storePassword)
            XCTAssertTrue(try controller.isValid())

            var resolved = try controller.subject.resolve()
            XCTAssertNil(resolved)

            try controller.publish(storePassword)

            resolved = try controller.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(controller.subject, resolved?.subject)
            XCTAssertEqual(controller.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Create customized DID
            let did = try DID("did:elastos:helloworld")
            var doc = try controller.newCustomizedDid(did, storePassword)
            XCTAssertTrue(try doc.isValid())

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(controller.subject, doc.controller)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.publish(storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(controller.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                           resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Update
            let db = try doc.editing()
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            // create new controller
            let newController = try identity.newDid(storePassword)
            XCTAssertTrue(try controller.isValid())

            resolved = try newController.subject.resolve()
            XCTAssertNil(resolved)

            try newController.publish(storePassword)

            resolved = try newController.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(newController.subject, resolved?.subject)
            XCTAssertEqual(newController.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // create the transfer ticket
            let ticket = try controller.createTransferTicket(did, newController.subject, storePassword)
            XCTAssertTrue(try ticket.isValid());

            // create new document for customized DID
            doc = try newController.newCustomizedDid(did, true, storePassword)
            XCTAssertTrue(try doc.isValid())

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(newController.subject, doc.controller)

            // transfer
            try doc.publish(ticket, storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(newController.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func testTransferMultisigCustomizedDidAfterCreate() {
        do {
            let payolad1 = "eyJpZCI6ImRpZDplbGFzdG9zOmhlbGxvd29ybGQzIiwidG8iOiJkaWQ6ZWxhc3RvczppZGNpeU5tM0hROENSejVEQk1xZlM2aXFSSGVnVEhEN2JkIiwidHhpZCI6ImU4Mjc4MzQ5ZTRkMDBkNWEwODVjMzVlMmFiMzVkMDE5IiwicHJvb2YiOlt7InR5cGUiOiJFQ0RTQXNlY3AyNTZyMSIsImNyZWF0ZWQiOiIyMDIxLTA1LTEyVDA0OjAzOjMzWiIsInZlcmlmaWNhdGlvbk1ldGhvZCI6ImRpZDplbGFzdG9zOmlnc05MUzJVcVpKeGh0N2hRTkdLZ1d1bmRza3lBOUVERWkjcHJpbWFyeSIsInNpZ25hdHVyZSI6IkRsOTh6b2NIVnpKUDNOaERZZ3FienVRZG5FZEZreWFOdk1SU1dlNS1LZE85ZWRjcm0zY3BsMGpPRnN1M2ZtZHp5OW56MkVoQURpZzNzZTFGQnl1T2x3In0seyJ0eXBlIjoiRUNEU0FzZWNwMjU2cjEiLCJjcmVhdGVkIjoiMjAyMS0wNS0xMlQwNDowMzozM1oiLCJ2ZXJpZmljYXRpb25NZXRob2QiOiJkaWQ6ZWxhc3RvczppZnJ6alg0S25CaGJaSEI0b0ZZTWhnb0tOUUNVYVBqUlc3I3ByaW1hcnkiLCJzaWduYXR1cmUiOiJtWVliSkpGcmJDTXEyQUItOFpISzJGT3FJVFVnYl9xY0VrbWlISE9XUktYVTRhV3NNTlNZZmFpYlhRR1dLUl9DUXdOWUNaV3F6QXhBM0RFbjVnZmxaZyJ9XX0"
            let capacity = payolad1.count * 3
            let buffer: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
            let cp = payolad1.toUnsafePointerInt8()
            let c = b64_url_decode(buffer, cp)
            buffer[c] = 0
            let json: String = String(cString: buffer)
//            let d = try DIDDocument.convertToDIDDocument(fromJson: json)

            
            let payolad2 = "eyJpZCI6ImRpZDplbGFzdG9zOmhlbGxvd29ybGQzIiwidG8iOiJkaWQ6ZWxhc3RvczppZGNpeU5tM0hROENSejVEQk1xZlM2aXFSSGVnVEhEN2JkIiwidHhpZCI6ImU4Mjc4MzQ5ZTRkMDBkNWEwODVjMzVlMmFiMzVkMDE5IiwicHJvb2YiOlt7InR5cGUiOiJFQ0RTQXNlY3AyNTZyMSIsImNyZWF0ZWQiOiIyMDIxLTA1LTEyVDA0OjAzOjMzWiIsInZlcmlmaWNhdGlvbk1ldGhvZCI6ImRpZDplbGFzdG9zOmlmcnpqWDRLbkJoYlpIQjRvRllNaGdvS05RQ1VhUGpSVzcjcHJpbWFyeSIsInNpZ25hdHVyZSI6Im1ZWWJKSkZyYkNNcTJBQi04WkhLMkZPcUlUVWdiX3FjRWttaUhIT1dSS1hVNGFXc01OU1lmYWliWFFHV0tSX0NRd05ZQ1pXcXpBeEEzREVuNWdmbFpnIn0seyJ0eXBlIjoiRUNEU0FzZWNwMjU2cjEiLCJjcmVhdGVkIjoiMjAyMS0wNS0xMlQwNDowMzozM1oiLCJ2ZXJpZmljYXRpb25NZXRob2QiOiJkaWQ6ZWxhc3RvczppZ3NOTFMyVXFaSnhodDdoUU5HS2dXdW5kc2t5QTlFREVpI3ByaW1hcnkiLCJzaWduYXR1cmUiOiJEbDk4em9jSFZ6SlAzTmhEWWdxYnp1UWRuRWRGa3lhTnZNUlNXZTUtS2RPOWVkY3JtM2NwbDBqT0ZzdTNmbWR6eTluejJFaEFEaWczc2UxRkJ5dU9sdyJ9XX0"
            let capacity2 = payolad2.count * 3
            let buffer2: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity2)
            let cp2 = payolad2.toUnsafePointerInt8()
            let c2 = b64_url_decode(buffer2, cp2)
            buffer2[c2] = 0
            let json2: String = String(cString: buffer2)
//            let d2 = try DIDDocument.convertToDIDDocument(fromJson: json2)

            
            
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let ctrl1 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl1.isValid())
            try ctrl1.publish(storePassword)

            var resolved = try ctrl1.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl1.subject, resolved?.subject)
            XCTAssertEqual(ctrl1.proof.signature,
                           resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            let ctrl2 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl2.isValid())
            try ctrl2.publish(storePassword)

            resolved = try ctrl2.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl2.subject, resolved?.subject)
            XCTAssertEqual(ctrl2.proof.signature,
                           resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

               let ctrl3 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl3.isValid())
            try ctrl3.publish(storePassword)

            resolved = try ctrl3.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl3.subject, resolved?.subject)
            XCTAssertEqual(ctrl3.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Create customized DID
            let did = try DID("did:elastos:helloworld3")
            var doc = try ctrl1.newCustomizedDid(did, [ctrl2.subject, ctrl3.subject],
                    2, storePassword)
            XCTAssertFalse(try doc.isValid())

            _ = doc
        
            doc = try ctrl2.sign(doc, storePassword)
            XCTAssertTrue(try doc.isValid())

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(3, doc.controllerCount())
            var ctrls = [ctrl1.subject, ctrl2.subject, ctrl3.subject]
            ctrls = ctrls.sorted { (didA, didB) -> Bool in
                let compareResult = didA.toString().compare(didB.toString())
                return compareResult == ComparisonResult.orderedAscending
            }
            XCTAssertEqual(doc.controllers(), ctrls)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.setEffectiveController(ctrl1.subject)
            try doc.publish(storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // new controllers for the did
            let td = testData!.sharedInstantData()
            _ = try td.getIssuerDocument()
            let u1 = try td.getUser1Document()
            let u2 = try td.getUser2Document()
            let u3 = try td.getUser3Document()
            let u4 = try td.getUser4Document()

            // transfer ticket
            var ticket = try ctrl1.createTransferTicket(did, u1.subject, storePassword)
            ticket = try ctrl2.sign(ticket, storePassword)
            XCTAssertTrue(try ticket.isValid())

            try doc = u1.newCustomizedDid(did, [u2.subject, u3.subject, u4.subject],
                        3, true, storePassword)
            try doc = u2.sign(doc, storePassword)
            try doc = u3.sign(doc, storePassword)
            XCTAssertTrue(try doc.isValid())

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(4, doc.controllerCount())
            XCTAssertEqual("3:4", doc.multiSignature!.description)

            // transfer
            try doc.publish(ticket, storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)

            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func testTransferMultisigCustomizedDidAfterUpdate() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let ctrl1 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl1.isValid())
            try ctrl1.publish(storePassword)

            var resolved = try ctrl1.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl1.subject, resolved?.subject)
            XCTAssertEqual(ctrl1.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            let ctrl2 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl2.isValid())
            try  ctrl2.publish(storePassword)

            resolved = try ctrl2.subject.resolve()
            XCTAssertNotNil(resolved);
            XCTAssertEqual(ctrl2.subject, resolved?.subject)
            XCTAssertEqual(ctrl2.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

               let ctrl3 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl3.isValid())
            try ctrl3.publish(storePassword)

            resolved = try ctrl3.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl3.subject, resolved?.subject)
            XCTAssertEqual(ctrl3.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Create customized DID
            let did = try DID("did:elastos:helloworld3")
            var doc = try ctrl1.newCustomizedDid(did, [ctrl2.subject, ctrl3.subject], 2, storePassword)
            XCTAssertFalse(try doc.isValid())

//            XCTAssertThrowsError(_ = try ctrl1.sign(using: storePassword, for: [doc.toString().data(using: .utf8)!])){ error in
//                switch error {
//                case DIDError.UncheckedError.IllegalStateError.AlreadySignedError: break
//                default:
//                    XCTFail()
//                }
//            }
            
            doc = try ctrl2.sign(doc, storePassword)
            XCTAssertTrue(try doc.isValid())

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(3, doc.controllerCount())
            var ctrls = [ctrl1.subject, ctrl2.subject, ctrl3.subject]
            ctrls = ctrls.sorted { (didA, didB) -> Bool in
                let compareResult = didA.toString().compare(didB.toString())
                return compareResult == ComparisonResult.orderedAscending
            }
            XCTAssertEqual(doc.controllers(), ctrls)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.setEffectiveController(ctrl1.subject)
            try doc.publish(storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Update
            let db = try doc.editing(ctrl2)
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            doc = try ctrl1.sign(doc, storePassword)
            try store!.storeDid(using: doc)

            try doc.publish(storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())
            XCTAssertEqual(4, resolved?.publicKeyCount)
            XCTAssertEqual(4, resolved?.authenticationKeyCount)

            // new controllers for the did
            let td = testData!.sharedInstantData()
            _ = try td.getIssuerDocument()
            let u1 = try td.getUser1Document()
            let u2 = try td.getUser2Document()
            let u3 = try td.getUser3Document()
            let u4 = try td.getUser4Document()

            // transfer ticket
            try doc.setEffectiveController(ctrl1.subject)
            var ticket = try doc.createTransferTicket(to: u1.subject, storePassword)
            ticket = try ctrl2.sign(ticket, storePassword)
            XCTAssertTrue(try ticket.isValid())

            doc = try u1.newCustomizedDid(did, [u2.subject, u3.subject, u4.subject], 3, true, storePassword)
            doc = try u2.sign(doc, storePassword)
            doc = try u3.sign(doc, storePassword)
            XCTAssertTrue(try doc.isValid())

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(4, doc.controllerCount())
            XCTAssertEqual("3:4", doc.multiSignature?.description)

            // transfer
            try doc.publish(ticket, storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)

            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func testUpdateDidWithoutPrevSignature() {
        do {
            let identity = try testData!.getRootIdentity()

            var doc = try identity.newDid(storePassword)
            XCTAssertTrue(try doc.isValid())

            try doc.publish(storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            // Update
            var db = try doc.editing()
            var key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

//            doc.getMetadata().previousSignature = nil
//            doc.getMetadata().setPreviousSignature(nil) //TODO:

            // Update again
            db = try doc.editing()
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key2", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            XCTAssertEqual(3, doc.publicKeyCount)
            XCTAssertEqual(3, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(storePassword);

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())
        } catch {
            XCTFail()
        }
    }
    
    func testUpdateDidWithoutSignature() {
        do {
            let identity = try testData!.getRootIdentity()

            var doc = try identity.newDid(storePassword)
            XCTAssertTrue(try doc.isValid())

            try doc.publish(storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            // Update
            var db = try doc.editing()
            var key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            doc.getMetadata().setSignature(nil)

            // Update again
            db = try doc.editing()
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key2", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            XCTAssertEqual(3, doc.publicKeyCount)
            XCTAssertEqual(3, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            XCTAssertThrowsError(_ = try doc.publish(storePassword)){ error in
                switch error {
                case DIDError.UncheckedError.IllegalStateError.DIDNotUpToDateError: break
                default:
                    XCTFail()
                }
            }
        } catch {
            XCTFail()
        }
    }
    
    func testUpdateDidWithoutAllSignatures() {
        do {
            let identity = try testData!.getRootIdentity()

            var doc = try identity.newDid(storePassword)
            XCTAssertTrue(try doc.isValid())

            try doc.publish(storePassword)

            let resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

//            doc.getMetadata().setPreviousSignature(null);
//            doc.getMetadata().setSignature(null);

            // Update
            let db = try doc.editing()
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

//            XCTAssertThrowsError(_ = try doc.publish(storePassword)){ error in
//                switch error {
//                case DIDError.UncheckedError.IllegalStateError.DIDNotUpToDateError: break
//                default:
//                    XCTFail()
//                }
//            }
        } catch {
            XCTFail()
        }
    }
    
    func testForceUpdateDidWithoutAllSignatures() {
        do {
            let identity = try testData!.getRootIdentity()

            var doc = try identity.newDid(storePassword)
            XCTAssertTrue(try doc.isValid())

            try doc.publish(storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

//            doc.getMetadata().setPreviousSignature(null);
//            doc.getMetadata().setSignature(null);

            // Update
            let db = try doc.editing()
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(doc.defaultPublicKeyId()!, true, storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved);
            XCTAssertEqual(doc.toString(), resolved?.toString())
        } catch {
            XCTFail()
        }
    }
    
    func testUpdateDidWithWrongPrevSignature() {
        do {
            let identity = try testData!.getRootIdentity()

            var doc = try identity.newDid(storePassword)
            XCTAssertTrue(try doc.isValid())

            try doc.publish(storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString());

            // Update
            var db = try doc.editing()
            var key = try TestData.generateKeypair();
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(storePassword)

            resolved = try doc.subject.resolve();
            XCTAssertNotNil(resolved);
            XCTAssertEqual(doc.toString(), resolved?.toString());

            doc.getMetadata().setPreviousSignature("1234567890");

            // Update
            db = try doc.editing()
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key2", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            XCTAssertEqual(3, doc.publicKeyCount)
            XCTAssertEqual(3, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())
        } catch {
            XCTFail()
        }
    }
    
    func testUpdateDidWithWrongSignature() {
        do {
            let identity = try testData!.getRootIdentity()

            var doc = try identity.newDid(storePassword)
            XCTAssertTrue(try doc.isValid())

            try doc.publish(storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            // Update
            var db = try doc.editing()
            var key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved);
            XCTAssertEqual(doc.toString(), resolved?.toString())

            doc.getMetadata().setSignature("1234567890");

            // Update
            db = try doc.editing()
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key2", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            XCTAssertEqual(3, doc.publicKeyCount)
            XCTAssertEqual(3, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            _ = doc
            XCTAssertThrowsError(_ = try doc.publish(storePassword)){ error in
                switch error {
                case DIDError.UncheckedError.IllegalStateError.DIDNotUpToDateError: break
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
            let identity = try testData!.getRootIdentity()

            var doc = try identity.newDid(storePassword)
            XCTAssertTrue(try doc.isValid())

            try doc.publish(storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            doc.getMetadata().setPreviousSignature("1234567890")
            // Update
            let db = try doc.editing()
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(doc.defaultPublicKeyId()!, true, storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())
        } catch {
            XCTFail()
        }
    }
    
    func testForceUpdateDidWithWrongSignature() {
        do {
            let identity = try testData!.getRootIdentity()

            var doc = try identity.newDid(storePassword)
            XCTAssertTrue(try doc.isValid())

            try doc.publish(storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            doc.getMetadata().setSignature("1234567890")

            // Update
            let db = try doc.editing()
            let key = try TestData.generateKeypair();
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(doc.defaultPublicKeyId()!, true, storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateSelfAfterCreate() {
        do {
            let identity = try testData!.getRootIdentity()

            var doc = try identity.newDid(storePassword)
            XCTAssertTrue(try doc.isValid())

            try doc.publish(storePassword)

            let resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            try doc.deactivate(storePassword)

            doc = try doc.subject.resolve()!
            XCTAssertTrue(doc.isDeactivated)
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateSelfAfterUpdate() {
        do {
            let identity = try testData!.getRootIdentity()

            var doc = try identity.newDid(storePassword)
            XCTAssertTrue(try doc.isValid())

            try doc.publish(storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            // Update
            let db = try doc.editing()
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            try doc.deactivate(storePassword)
            doc = try doc.subject.resolve()!
            XCTAssertTrue(doc.isDeactivated)
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateCustomizedDidAfterCreate() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let controller = try identity.newDid(storePassword)
            XCTAssertTrue(try controller.isValid())

            var resolved = try controller.subject.resolve()
            XCTAssertNil(resolved)

            try controller.publish(storePassword)

            resolved = try controller.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(controller.subject, resolved?.subject)
            XCTAssertEqual(controller.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Create customized DID
            let did = try DID("did:elastos:helloworld")
            var doc = try controller.newCustomizedDid(did, storePassword)
            XCTAssertTrue(try doc.isValid())

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(controller.subject, doc.controller)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.publish(storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(controller.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Deactivate
            try doc.deactivate(storePassword)
            doc = try doc.subject.resolve()!
            XCTAssertTrue(doc.isDeactivated)
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateCustomizedDidAfterUpdate() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let controller = try identity.newDid(storePassword)
            XCTAssertTrue(try controller.isValid())

            var resolved = try controller.subject.resolve()
            XCTAssertNil(resolved)

            try controller.publish(storePassword)

            resolved = try controller.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(controller.subject, resolved?.subject)
            XCTAssertEqual(controller.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Create customized DID
            let did = try DID("did:elastos:helloworld")
            var doc = try controller.newCustomizedDid(did, storePassword)
            XCTAssertTrue(try doc.isValid())

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(controller.subject, doc.controller)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.publish(storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(controller.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Update
            let db = try doc.editing()
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString());

            // Deactivate
            try doc.deactivate(storePassword)
            doc = try doc.subject.resolve()!
            XCTAssertTrue(doc.isDeactivated)
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateCidAfterCreateByController() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let controller = try identity.newDid(storePassword)
            XCTAssertTrue(try controller.isValid())

            var resolved = try controller.subject.resolve()
            XCTAssertNil(resolved)

            try controller.publish(storePassword)

            resolved = try controller.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(controller.subject, resolved?.subject)
            XCTAssertEqual(controller.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Create customized DID
            let did = try DID("did:elastos:helloworld")
            var doc = try controller.newCustomizedDid(did, storePassword)
            XCTAssertTrue(try doc.isValid())

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(controller.subject, doc.controller)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.publish(storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(controller.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Deactivate
            try controller.deactivate(did, storePassword)
            doc = try did.resolve()!
            XCTAssertTrue(doc.isDeactivated)
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateCidAfterUpdateByController() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let controller = try identity.newDid(storePassword)
            XCTAssertTrue(try controller.isValid())

            var resolved = try controller.subject.resolve()
            XCTAssertNil(resolved)

            try controller.publish(storePassword)

            resolved = try controller.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(controller.subject, resolved?.subject)
            XCTAssertEqual(controller.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Create customized DID
            let did = try DID("did:elastos:helloworld")
            var doc = try controller.newCustomizedDid(did, storePassword)
            XCTAssertTrue(try doc.isValid())

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(controller.subject, doc.controller)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.publish(storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(controller.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Update
            let db = try doc.editing()
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            // Deactivate
            try controller.deactivate(did, storePassword)
            doc = try did.resolve()!
            XCTAssertTrue(doc.isDeactivated)
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateMultisigCustomizedDidAfterCreate() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let ctrl1 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl1.isValid())
            try ctrl1.publish(storePassword)

            var resolved = try ctrl1.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl1.subject, resolved?.subject)
            XCTAssertEqual(ctrl1.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            let ctrl2 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl2.isValid())
            try ctrl2.publish(storePassword)

            resolved = try ctrl2.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl2.subject, resolved?.subject)
            XCTAssertEqual(ctrl2.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

               let ctrl3 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl3.isValid())
            try ctrl3.publish(storePassword)

            resolved = try ctrl3.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl3.subject, resolved?.subject)
            XCTAssertEqual(ctrl3.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Create customized DID
            let did = try DID("did:elastos:helloworld3")
            var doc = try ctrl1.newCustomizedDid(did, [ctrl2.subject, ctrl3.subject], 2, storePassword)
            XCTAssertFalse(try doc.isValid())
            
            XCTAssertThrowsError(_ = try ctrl1.sign(doc, storePassword)){ error in
                switch error {
                case DIDError.UncheckedError.IllegalStateError.AlreadySignedError: break
                default:
                    XCTFail()
                }
            }

            doc = try ctrl2.sign(doc, storePassword)
            XCTAssertTrue(try doc.isValid())

            XCTAssertEqual(did, doc.subject)
            let ctrls = [ctrl1.subject, ctrl2.subject, ctrl3.subject]
            XCTAssertEqual(doc.controllers().count, ctrls.count)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.setEffectiveController(ctrl1.subject)
            try doc.publish(storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(doc.proof.signature,
                           resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Deactivate
            try doc.deactivate(ctrl1.defaultPublicKeyId()!, storePassword)
            doc = try doc.subject.resolve()!
            XCTAssertTrue(doc.isDeactivated)
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateMultisigCustomizedDidAfterUpdate() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let ctrl1 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl1.isValid())
            try ctrl1.publish(storePassword)

            var resolved = try ctrl1.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl1.subject, resolved?.subject)
            XCTAssertEqual(ctrl1.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

               let ctrl2 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl2.isValid())
            try ctrl2.publish(storePassword)

            resolved = try ctrl2.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl2.subject, resolved?.subject)
            XCTAssertEqual(ctrl2.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

               let ctrl3 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl3.isValid())
            try ctrl3.publish(storePassword)

            resolved = try ctrl3.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl3.subject, resolved?.subject)
            XCTAssertEqual(ctrl3.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Create customized DID
            let did = try DID("did:elastos:helloworld3")
            var doc = try ctrl1.newCustomizedDid(did, [ctrl2.subject, ctrl3.subject], 2, storePassword)
            XCTAssertFalse(try doc.isValid())

            XCTAssertThrowsError(_ = try ctrl1.sign(doc, storePassword)){ error in
                switch error {
                case DIDError.UncheckedError.IllegalStateError.AlreadySignedError: break
                default:
                    XCTFail()
                }
            }

            doc = try ctrl2.sign(doc, storePassword)
            XCTAssertTrue(try doc.isValid())

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(3, doc.controllerCount())
            var ctrls = [ctrl1.subject, ctrl2.subject, ctrl3.subject]
            ctrls = ctrls.sorted { (didA, didB) -> Bool in
                let compareResult = didA.toString().compare(didB.toString())
                return compareResult == ComparisonResult.orderedAscending
            }
            XCTAssertEqual(doc.controllers(), ctrls)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.setEffectiveController(ctrl1.subject)
            try doc.publish(storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Update
            let db = try doc.editing(ctrl2)
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword)
            doc = try ctrl1.sign(doc, storePassword)
            try store!.storeDid(using: doc)

            try doc.publish(storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())
            XCTAssertEqual(4, resolved?.publicKeyCount)
            XCTAssertEqual(4, resolved?.authenticationKeyCount)

            // Deactivate
            try doc.deactivate(ctrl1.defaultPublicKeyId()!, storePassword)
            doc = try doc.subject.resolve()!
            XCTAssertTrue(doc.isDeactivated)
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateMultisigCidAfterCreateByController() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let ctrl1 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl1.isValid())
            try ctrl1.publish(storePassword)

            var resolved = try ctrl1.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl1.subject, resolved?.subject)
            XCTAssertEqual(ctrl1.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

               let ctrl2 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl2.isValid())
            try ctrl2.publish(storePassword)

            resolved = try ctrl2.subject.resolve()
            XCTAssertNotNil(resolved);
            XCTAssertEqual(ctrl2.subject, resolved?.subject)
            XCTAssertEqual(ctrl2.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

               let ctrl3 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl3.isValid())
            try ctrl3.publish(storePassword)

            resolved = try ctrl3.subject.resolve()
            XCTAssertNotNil(resolved);
            XCTAssertEqual(ctrl3.subject, resolved?.subject)
            XCTAssertEqual(ctrl3.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Create customized DID
            let did = try DID("did:elastos:helloworld3")
            var doc = try ctrl1.newCustomizedDid(did, [ctrl2.subject, ctrl3.subject],
                    2, storePassword)
            XCTAssertFalse(try doc.isValid())

            _ = doc
//            assertThrows(AlreadySignedException.class, () -> {
//                ctrl1.sign(d, storePassword);
//            });

            doc = try ctrl2.sign(doc, storePassword)
            XCTAssertTrue(try doc.isValid())

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(3, doc.controllerCount())
            var ctrls = [ctrl1.subject, ctrl2.subject, ctrl3.subject]
            ctrls = ctrls.sorted { (didA, didB) -> Bool in
                let compareResult = didA.toString().compare(didB.toString())
                return compareResult == ComparisonResult.orderedAscending
            }
            XCTAssertEqual(doc.controllers(), ctrls)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.setEffectiveController(ctrl1.subject)
            try doc.publish(storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved);
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Deactivate
            try ctrl1.deactivate(did, storePassword)
            doc = try did.resolve()!
            XCTAssertTrue(doc.isDeactivated)
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateMultisigCidAfterUpdateByController() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let ctrl1 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl1.isValid())
            try ctrl1.publish(storePassword)

            var resolved = try ctrl1.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl1.subject, resolved?.subject)
            XCTAssertEqual(ctrl1.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            let ctrl2 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl2.isValid())
            try ctrl2.publish(storePassword)

            resolved = try ctrl2.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl2.subject, resolved?.subject)
            XCTAssertEqual(ctrl2.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

               let ctrl3 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl3.isValid())
            try ctrl3.publish(storePassword)

            resolved = try ctrl3.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl3.subject, resolved?.subject)
            XCTAssertEqual(ctrl3.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Create customized DID
            let did = try DID("did:elastos:helloworld3")
            var doc = try ctrl1.newCustomizedDid(did, [ctrl2.subject, ctrl3.subject],
                    2, storePassword);
            XCTAssertFalse(try doc.isValid())

            _ = doc
//            assertThrows(AlreadySignedException.class, () -> {
//                ctrl1.sign(d, storePassword);
//            });

            doc = try ctrl2.sign(doc, storePassword)
            XCTAssertTrue(try doc.isValid())

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(3, doc.controllerCount())
            var ctrls = [ctrl1.subject, ctrl2.subject, ctrl3.subject]
            ctrls = ctrls.sorted { (didA, didB) -> Bool in
                let compareResult = didA.toString().compare(didB.toString())
                return compareResult == ComparisonResult.orderedAscending
            }
            XCTAssertEqual(doc.controllers(), ctrls)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.setEffectiveController(ctrl1.subject)
            try doc.publish(storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid())

            // Update
            let db = try doc.editing(ctrl2)
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.sealed(using: storePassword);
            doc = try ctrl1.sign(doc, storePassword)
            try store!.storeDid(using: doc)

            try doc.publish(storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved);
            XCTAssertEqual(doc.toString(), resolved?.toString())
            XCTAssertEqual(4, resolved!.publicKeyCount)
            XCTAssertEqual(4, resolved!.authenticationKeyCount)

            // Deactivate
            try ctrl2.deactivate(did, storePassword)
            doc = try did.resolve()!
            XCTAssertTrue(doc.isDeactivated)
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateWithAuthorization1() {
        do {
            let identity = try testData!.getRootIdentity()

            var doc = try identity.newDid(storePassword)
            XCTAssertTrue(try doc.isValid())

            try doc.publish(storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            var target = try identity.newDid(storePassword)
            let db = try target.editing()
            _ = try db.authorizationDid(with: "#recovery", controller: doc.subject.toString())
            target = try db.sealed(using: storePassword)
            XCTAssertNotNil(target);
            XCTAssertEqual(1, target.authorizationKeyCount)
            XCTAssertEqual(doc.subject, target.authorizationKeys()[0].controller)
            try store!.storeDid(using: target)

            try target.publish(storePassword)

            resolved = try target.subject.resolve()
            XCTAssertNotNil(resolved);
            XCTAssertEqual(target.toString(), resolved?.toString());

            try doc.deactivate(target.subject, storePassword)
            target = try target.subject.resolve()!
            XCTAssertTrue(target.isDeactivated)

            doc = try doc.subject.resolve()!
            XCTAssertFalse(doc.isDeactivated)
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateWithAuthorization2() {
        do {
            let identity = try testData!.getRootIdentity()

            var doc = try identity.newDid(storePassword)
            var db = try doc.editing()
            let key = try TestData.generateKeypair()
            let id = try DIDURL(doc.subject, "#key-2")
            _ = try db.appendAuthenticationKey(with: id, keyBase58: key.getPublicKeyBase58())
            try store!.storePrivateKey(for: id, privateKey: key.serialize(), using: storePassword)
            doc = try db.sealed(using: storePassword)
            XCTAssertTrue(try doc.isValid())
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            var target = try identity.newDid(storePassword)
            db = try target.editing()
            _ = try db.appendAuthorizationKey(with: "#recovery", controller: doc.subject.toString(),
                                      keyBase58: key.getPublicKeyBase58())
            target = try db.sealed(using: storePassword)
            XCTAssertNotNil(target)
            XCTAssertEqual(1, target.authorizationKeyCount)
            XCTAssertEqual(doc.subject, target.authorizationKeys()[0].controller)
            try store!.storeDid(using: target)

            try target.publish(storePassword)

            resolved = try target.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(target.toString(), resolved?.toString())

            try doc.deactivate(target.subject, id, storePassword)
            target = try target.subject.resolve()!
            XCTAssertTrue(target.isDeactivated)

            doc = try doc.subject.resolve()!
            XCTAssertFalse(doc.isDeactivated)
        } catch {
         XCTFail()
        }
    }
    
    func testDeactivateWithAuthorization3() {
        do {
            let identity = try testData!.getRootIdentity()

            var doc = try identity.newDid(storePassword)
            var db = try doc.editing()
            let key = try TestData.generateKeypair()
            let id = try  DIDURL(doc.subject, "#key-2")
            _ = try db.appendAuthenticationKey(with: id, keyBase58: key.getPublicKeyBase58())
            try store!.storePrivateKey(for: id, privateKey: key.serialize(), using: storePassword)
            doc = try db.sealed(using: storePassword)
            XCTAssertTrue(try doc.isValid())
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            var target = try identity.newDid(storePassword)
            db = try target.editing()
            _ = try db.appendAuthorizationKey(with: "#recovery", controller: doc.subject.toString(),
                                      keyBase58: key.getPublicKeyBase58())
            target = try db.sealed(using: storePassword)
            XCTAssertNotNil(target)
            XCTAssertEqual(1, target.authorizationKeyCount)
            XCTAssertEqual(doc.subject, target.authorizationKeys()[0].controller)
            try store!.storeDid(using: target)

            try target.publish(storePassword)

            resolved = try target.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(target.toString(), resolved?.toString())

            try doc.deactivate(target.subject, storePassword)
            target = try target.subject.resolve()!
            XCTAssertTrue(target.isDeactivated)

            doc = try doc.subject.resolve()!
            XCTAssertFalse(doc.isDeactivated)
        } catch {
            XCTFail()
        }
    }
}
