
import XCTest
@testable import ElastosDIDSDK

class DD: DefaultDIDAdapter {
    
    override func createIdTransaction(_ payload: String, _ memo: String?) throws {
        
    }
}

class DIDDoucumentTests: XCTestCase {
    var testData: TestData?
    var store: DIDStore?
    var simulatedIDChain: SimulatedIDChain = SimulatedIDChain()
    var adapter: SimulatedIDChainAdapter = SimulatedIDChainAdapter("http://localhost:\(DEFAULT_PORT)/")
    var debug = TestEventListener()
    
    override func setUp() {
        testData = TestData()
        store = testData?.store!
//       try! simulatedIDChain.httpServer.start(in_port_t(DEFAULT_PORT), forceIPv4: true)
//        simulatedIDChain.start()
//        let adapter = simulatedIDChain.getAdapter()
        try! DIDBackend.initialize(adapter)
        Log.setLevel(.Debug)
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
    
    func testPayload() {
        let payload = "eyJpYXQiOjE2Mzk2NDMwNzQsImlzcyI6ImRpZDplbGFzdG9zOmlhQU1rZnpMRTZKZkVVSjRrRkNBbjU3ZWFWVjFaQkhLVzciLCJleHAiOjE2Mzk4MTU4NzQsInByZXNlbnRhdGlvbiI6eyJob2xkZXIiOiJkaWQ6ZWxhc3RvczppYUFNa2Z6TEU2SmZFVUo0a0ZDQW41N2VhVlYxWkJIS1c3IiwiY3JlYXRlZCI6IjIwMjEtMTItMTZUMDg6MjQ6MzRaIiwicHJvb2YiOnsibm9uY2UiOiI5OGU2Mjk0NC01ZTQ5LTExZWMtYmQwOS0wMjQyYWMxNjAwMDQiLCJzaWduYXR1cmUiOiJPYUZzT005OEdyb3cxU2p5eXJ3VVVBVVk4dVM5SUlYMzNsZy04RnZhS2ZDU3lxZmxLNWhuOHFES2htU0YxeXlNYVhUUDNPa0YzaC1hLTF0QlRSb1lOQSIsInZlcmlmaWNhdGlvbk1ldGhvZCI6ImRpZDplbGFzdG9zOmlhQU1rZnpMRTZKZkVVSjRrRkNBbjU3ZWFWVjFaQkhLVzcjcHJpbWFyeSIsInR5cGUiOiJFQ0RTQXNlY3AyNTZyMSIsInJlYWxtIjoiZGlkOmVsYXN0b3M6aWtLNVZSajFKQjdXekpTYTNFeUd1VG8xVlF6U1R3SE45ZiJ9LCJ0eXBlIjoiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiIsInZlcmlmaWFibGVDcmVkZW50aWFsIjpbeyJleHBpcmF0aW9uRGF0ZSI6IjIwMjYtMTItMTZUMDg6MDA6MDBaIiwiaXNzdWVyIjoiZGlkOmVsYXN0b3M6aWtIUDM4OUZoc3NBQURuVXdNM1JGRjQxNUYxd3ZpWjhDQyIsImlzc3VhbmNlRGF0ZSI6IjIwMjEtMTItMTZUMDg6MjI6MTJaIiwiaWQiOiJkaWQ6ZWxhc3RvczppYUFNa2Z6TEU2SmZFVUo0a0ZDQW41N2VhVlYxWkJIS1c3I2FwcC1pZC1jcmVkZW50aWFsIiwicHJvb2YiOnsidHlwZSI6IkVDRFNBc2VjcDI1NnIxIiwic2lnbmF0dXJlIjoiWFl2Uk5qaHIzR2tiNlU1eFNzb0JuRVU5U1FLMlQ3T1FhQlVtSEY1QzhiQ1JpbW1vVlRqZ0tndzczNE5hSm9ka01rb21ETTlTNEQ4ajZqdHhjM2ZmMWciLCJ2ZXJpZmljYXRpb25NZXRob2QiOiJkaWQ6ZWxhc3Rvczppa0hQMzg5Rmhzc0FBRG5Vd00zUkZGNDE1RjF3dmlaOENDI3ByaW1hcnkifSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6ZWxhc3RvczppYUFNa2Z6TEU2SmZFVUo0a0ZDQW41N2VhVlYxWkJIS1c3IiwiYXBwRGlkIjoiZGlkOmVsYXN0b3M6aXF0V1JWano3Z3NZaHl1UUViMWhZTk5tV1F0MVo5Z2VYZyIsImFwcEluc3RhbmNlRGlkIjoiZGlkOmVsYXN0b3M6aWFBTWtmekxFNkpmRVVKNGtGQ0FuNTdlYVZWMVpCSEtXNyJ9LCJ0eXBlIjpbIkFwcElkQ3JlZGVudGlhbCIsIlZlcmlmaWFibGVDcmVkZW50aWFsIl19XX19"
        let capacity = payload.count * 3
        let buffer: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
        let cp = payload.toUnsafePointerInt8()
        let c = b64_url_decode(buffer, cp)
        buffer[c] = 0
        let json: String = String(cString: buffer)
        print(json)
        print(json)
    }

    func testGetPublicKeyV1() {
        GetPublicKey(1)
    }
    
    func testGetPublicKeyV2() {
        GetPublicKey(2)
    }
    
    func testGetPublicKeyV3() {
        GetPublicKey(3)
    }
    
    func GetPublicKey(_ version: Int) {
        do {
            let doc = try testData!.getCompatibleData(version).getDocument("user1")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))
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
            
            pks = try doc.selectPublicKeys(byId: id)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.subject, "#primary"), pks[0].getId())
            
            pks = try doc.selectPublicKeys(byType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(4, pks.count)
            
            pks = try doc.selectPublicKeys(byId: "#key2", andType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.subject, "#key2"), pks[0].getId())
            
            pks = try doc.selectPublicKeys(byId: "#key3")
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.subject, "#key3"), pks[0].getId())
        } catch {
            XCTFail("\(error)")
        }
    }
    
    
    func testGetPublicKeyWithCidV2() {
        GetPublicKeyWithCid(2)
    }
    
    func testGetPublicKeyWithCidV3() {
        GetPublicKeyWithCid(3)
    }
    
    func GetPublicKeyWithCid(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(version)

            let issuer = try cd.getDocument("issuer")
            
            let doc = try cd.getDocument("examplecorp")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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

            pks = try doc.selectPublicKeys(byId: id)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.controller!, "#primary"), pks[0].getId())

            pks = try doc.selectPublicKeys(byType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
        } catch {
            XCTFail()
        }
    }
    
    
    func testGetPublicKeyWithMultiControllerCidV2() {
        GetPublicKeyWithMultiControllerCid1(2)
    }
    
    func testGetPublicKeyWithMultiControllerCidV3() {
        GetPublicKeyWithMultiControllerCid1(3)
    }
    
    func GetPublicKeyWithMultiControllerCid1(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(version)

            let user1 = try cd.getDocument("user1")
            let user2 = try cd.getDocument("user2")
            let user3 = try cd.getDocument("user3")
            let doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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

            pks = try doc.selectPublicKeys(byId: id!)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(id, pks[0].getId())

            pks = try doc.selectPublicKeys(byType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(7, pks.count)

            pks = try doc.selectPublicKeys(byId: try DIDURL(user1.subject, "#key2"),
                                       andType: Constants.DEFAULT_PUBLICKEY_TYPE)
            
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(user1.subject, "#key2"), pks[0].getId())

            pks = try doc.selectPublicKeys(byId: try DIDURL(doc.subject, "#key3"))
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.subject, "#key3"), pks[0].getId())
        } catch {
            XCTFail()
        }
    }
    
    func testGetPublicKeyWithMultiControllerCid2V2() {
        GetPublicKeyWithMultiControllerCid2(2)
    }
    
    func testGetPublicKeyWithMultiControllerCid2V3() {
        GetPublicKeyWithMultiControllerCid2(3)
    }
    
    func GetPublicKeyWithMultiControllerCid2(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(version)

            let user1 = try cd.getDocument("user1")
            let user2 = try cd.getDocument("user2")
            let user3 = try cd.getDocument("user3")
            let doc = try cd.getDocument("baz")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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
            pks = try doc.selectPublicKeys(byId: id!)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(id, pks[0].getId())

            pks = try doc.selectPublicKeys(byType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(5, pks.count)

            pks = try doc.selectPublicKeys(byId: try DIDURL(user1.subject, "#key2"),
                                       andType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(user1.subject, "#key2"), pks[0].getId())

            pks = try doc.selectPublicKeys(byId: try DIDURL(user1.subject, "#key3"))
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
    
    func testAddPublicKey3() {
        AddPublicKey(3)
    }
    
    func AddPublicKey(_ version: Int) {
        do {
            _ = try testData!.getRootIdentity()
            
            var doc = try testData!.getCompatibleData(version).getDocument("user1")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))
            
            let db = try doc.editing()
            
            // Add 2 public keys
            let id = try DIDURL(db.getSubject(), "#test1")
            var key = try TestData.generateKeypair()
            _ = try db.appendPublicKey(with: id, controller: db.getSubject().toString(), keyBase58: key.getPublicKeyBase58())
            
            key = try TestData.generateKeypair()
            _ = try db.appendPublicKey(with: "#test2", controller: doc.subject.toString(), keyBase58: key.getPublicKeyBase58())
            
            doc = try db.seal(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))
            
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
            print(error)
            XCTFail()
        }
    }
    
    func testAddPublicKeyWithCid2() {
        AddPublicKeyWithCid(2)
    }
    
    func testAddPublicKeyWithCid3() {
        AddPublicKeyWithCid(3)
    }
    
    func AddPublicKeyWithCid(_ verison: Int) {
        do {
            let cd = try testData!.getCompatibleData(verison)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            let user1 = try cd.getDocument("user1")
            let user2 = try cd.getDocument("user2")
            _ = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            var doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

            let db = try doc.editing(user1)

            // Add 2 public keys
            let id = try DIDURL(db.getSubject(), "#test1")
            var key = try TestData.generateKeypair()
            _ = try db.appendPublicKey(id, db.getSubject(), key.getPublicKeyBase58())

            key = try TestData.generateKeypair();
            _ = try db.appendPublicKey(with: "#test2", controller: doc.subject.toString(), keyBase58: key.getPublicKeyBase58())

            doc = try db.seal(using: storePassword)
            doc = try user2.sign(with: doc, using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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
    
    func testRemovePublicKey3() {
        RemovePublicKey(3)
    }
    
    func RemovePublicKey(_ version: Int) {
        do {
            _ = try testData!.getRootIdentity()
            
            var doc = try testData!.getCompatibleData(version).getDocument("user1")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))
            
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
            
            doc = try db.seal(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))
            
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
    
    func testRemovePublicKeyWithCid2() {
        RemovePublicKeyWithCid(2)
    }
    
    func testRemovePublicKeyWithCid3() {
        RemovePublicKeyWithCid(3)
    }
    
    func RemovePublicKeyWithCid(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(version)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            let user1 = try cd.getDocument("user1")
            let user2 = try cd.getDocument("user2")
            _ = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            var doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

            let db = try doc.editing(user2)

            // Can not remove the controller's key
            let key2 = try DIDURL(user1.subject, "#key2")
            XCTAssertThrowsError(_ = try db.removePublicKey(with: key2)){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError: break
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

            doc = try db.seal(using: storePassword)
            doc = try user1.sign(with: doc, using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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
    
    func testGetAuthenticationKey3() {
        GetAuthenticationKey(3)
    }
    
    func GetAuthenticationKey(_ version: Int) {
        do {
            _ = try testData!.getRootIdentity()
            
            let doc = try testData!.getCompatibleData(version).getDocument("user1")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))
            
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
            
            pks = try doc.selectAuthenticationKeys(byId: id)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(id, pks[0].getId())
            
            pks = try doc.selectAuthenticationKeys(byType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(3, pks.count)
            
            pks = try doc.selectAuthenticationKeys(byId: "#key2", andType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.subject, "#key2"), pks[0].getId())
            
            pks = try doc.selectAuthenticationKeys(byId: "#key2")
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.subject, "#key2"), pks[0].getId())
        } catch {
            XCTFail()
        }
    }
    
    func testGetAuthenticationKeyWithCid2() {
        GetAuthenticationKeyWithCid(2)
    }
    
    func testGetAuthenticationKeyWithCid3() {
        GetAuthenticationKeyWithCid(3)
    }
    
    func GetAuthenticationKeyWithCid(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(2)

            let issuer = try cd.getDocument("issuer")
            let doc = try cd.getDocument("examplecorp")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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

            pks = try doc.selectPublicKeys(byId: id)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.controller!, "#primary"),
                    pks[0].getId())

            pks = try doc.selectAuthenticationKeys(byType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
        } catch {
            XCTFail()
        }
    }
    
    func testGetAuthenticationKeyWithMultiControllerCid2() {
        GetAuthenticationKeyWithMultiControllerCid1(2)
    }
    
    func testGetAuthenticationKeyWithMultiControllerCid3() {
        GetAuthenticationKeyWithMultiControllerCid1(3)
    }
    
    func GetAuthenticationKeyWithMultiControllerCid1(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(2)

            let user1 = try cd.getDocument("user1")
            let user2 = try cd.getDocument("user2")
            let user3 = try cd.getDocument("user3")
            let doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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

            pks = try doc.selectAuthenticationKeys(byId: id)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(id, pks[0].getId())

            pks = try doc.selectAuthenticationKeys(byType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(7, pks.count)

            pks = try doc.selectAuthenticationKeys(byId: try DIDURL(user1.subject, "#key2"),
                                               andType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(user1.subject, "#key2"), pks[0].getId())

            pks = try doc.selectAuthenticationKeys(byId: try DIDURL(doc.subject, "#key3"))
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.subject, "#key3"), pks[0].getId())
        } catch {
            XCTFail()
        }
    }
    
    func testGetAuthenticationKeyWithMultiControllerCidV2() {
        GetAuthenticationKeyWithMultiControllerCid2(2)
    }
    
    func testGetAuthenticationKeyWithMultiControllerCidV3() {
        GetAuthenticationKeyWithMultiControllerCid2(3)
    }
    
    func GetAuthenticationKeyWithMultiControllerCid2(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(2)

            let user1 = try cd.getDocument("user1")
            let user2 = try cd.getDocument("user2")
            let user3 = try cd.getDocument("user3")
            let doc = try cd.getDocument("baz")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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
            pks = try doc.selectAuthenticationKeys(byId: id)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(id, pks[0].getId())

            pks = try doc.selectAuthenticationKeys(byType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(5, pks.count)

            pks = try doc.selectAuthenticationKeys(byId: try DIDURL(user1.subject, "#key2"),
                                               andType: Constants.DEFAULT_PUBLICKEY_TYPE)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(user1.subject, "#key2"), pks[0].getId())

            pks = try doc.selectAuthenticationKeys(byId: try DIDURL(user1.subject, "#key3"))
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
    
    func testAddAuthenticationKey3() {
        AddAuthenticationKey(3)
    }
    
    func AddAuthenticationKey(_ version: Int) {
        do {
            _ = try testData!.getRootIdentity()
            
            var doc = try testData!.getCompatibleData(version).getDocument("user1")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))
            
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
            
            doc = try db.seal(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))
            
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
    
    func testAddAuthenticationKeyWithCid2() {
        AddAuthenticationKeyWithCid(2)
    }
    
    func testAddAuthenticationKeyWithCid3() {
        AddAuthenticationKeyWithCid(3)
    }
    
    func AddAuthenticationKeyWithCid(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(version)

            let user1 = try cd.getDocument("user1")
            _ = try cd.getDocument("user2")
            let user3 = try cd.getDocument("user3")
            var doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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

            doc = try db.seal(using: storePassword)
            doc = try user3.sign(with: doc, using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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
    
    func testRemoveAuthenticationKey3() {
            RemoveAuthenticationKey(3)
    }
    
    func RemoveAuthenticationKey(_ version: Int) {
        do {
            _ = try testData!.getRootIdentity()
            
            var doc = try testData!.getCompatibleData(version).getDocument("user1")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))
            
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
            
            doc = try db.seal(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))
            
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
    
    func testRemoveAuthenticationKeyWithCid2() {
        RemoveAuthenticationKeyWithCid(2)
    }
    
    func testRemoveAuthenticationKeyWithCid3() {
        RemoveAuthenticationKeyWithCid(3)
    }
    
    func RemoveAuthenticationKeyWithCid(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(version)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            let user1 = try cd.getDocument("user1")
            let user2 = try cd.getDocument("user2")
            _ = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            var doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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

            doc = try db.seal(using: storePassword)
            doc = try user2.sign(with: doc, using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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
    
    func testGetAuthorizationKey3() {
        do {
            try GetAuthorizationKey(3)
        } catch {
            XCTFail()
        }
    }
    
    func GetAuthorizationKey(_ version: Int) throws {
        _ = try testData!.getRootIdentity()

        let doc = try testData!.getCompatibleData(version).getDocument("user1")
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid(debug))

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

        pks = try doc.selectAuthorizationKeys(byId: id)
        XCTAssertEqual(1, pks.count)
        XCTAssertEqual(id, pks[0].getId())

        pks = try doc.selectAuthorizationKeys(byType: Constants.DEFAULT_PUBLICKEY_TYPE)
        XCTAssertEqual(1, pks.count)
    }
    
    
    func testGetAuthorizationKeyWithCid2() {
          GetAuthorizationKeyWithCid(2)
    }
    
    func testGetAuthorizationKeyWithCid3() {
          GetAuthorizationKeyWithCid(3)
    }
    
    func GetAuthorizationKeyWithCid(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(version)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            _ = try cd.getDocument("user1")
            _ = try cd.getDocument("user2")
            _ = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            let doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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
    
    func testAddAuthorizationKey3() {
        do {
            try AddAuthorizationKey(3)
        } catch {
            XCTFail()
        }
    }
    
    func AddAuthorizationKey(_ version: Int) throws {
        _ = try testData!.getRootIdentity()

        var doc = try testData!.getCompatibleData(version).getDocument("user1")
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid(debug))

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

        doc = try db.seal(using: storePassword)
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid(debug))

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
    
    func testAddAuthorizationKeyWithCidError2() {
        AddAuthorizationKeyWithCidError(2)
    }
    
    func testAddAuthorizationKeyWithCidError3() {
        AddAuthorizationKeyWithCidError(3)
    }
    
    func AddAuthorizationKeyWithCidError(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(version)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            let user1 = try cd.getDocument("user1")
            let user2 = try cd.getDocument("user2")
            _ = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            var doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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

            doc = try db.seal(using: storePassword)
            doc = try user2.sign(with: doc, using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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
    
    func testRemoveAuthorizationKey3() {
        do {
            try RemoveAuthorizationKey(3)
        } catch {
            XCTFail()
        }
    }
    
    func RemoveAuthorizationKey(_ version: Int) throws {
        _ = try testData!.getRootIdentity()

        var doc = try testData!.getCompatibleData(version).getDocument("user1")
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid(debug))

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

        doc = try db.seal(using: storePassword)
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid(debug))

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
    
    func testGetCredential3() {
        do {
            try GetCredential(3)
        } catch {
            XCTFail()
        }
    }
    
    func GetCredential(_ version: Int) throws {
        _ = try testData!.getRootIdentity()

        let doc = try testData!.getCompatibleData(version).getDocument("user1")
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid(debug))

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

        vcs = try doc.selectCredentials(byId: try DIDURL(doc.subject, "#profile"))
        XCTAssertEqual(1, vcs.count)
        XCTAssertEqual(try DIDURL(doc.subject, "#profile"), vcs[0].getId())

        vcs = try doc.selectCredentials(byType: "SelfProclaimedCredential")
        XCTAssertEqual(1, vcs.count)
        XCTAssertEqual(try DIDURL(doc.subject, "#profile"), vcs[0].getId())

        vcs = try doc.selectCredentials(byType: "TestingCredential")
        XCTAssertEqual(0, vcs.count)
    }
    
    func testGetCredentialWithCid2() {
        GetCredentialWithCid(2)
    }
    
    func testGetCredentialWithCid3() {
        GetCredentialWithCid(3)
    }
    
    func GetCredentialWithCid(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(version)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            _ = try cd.getDocument("user1")
            _ = try cd.getDocument("user2")
            _ = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            let doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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

            vcs = try doc.selectCredentials(byId: try DIDURL(doc.subject, "#profile"))
            XCTAssertEqual(1, vcs.count)
            XCTAssertEqual(try DIDURL(doc.subject, "#profile"), vcs[0].getId())

            vcs = try doc.selectCredentials(byType: "SelfProclaimedCredential")
            XCTAssertEqual(1, vcs.count)
            XCTAssertEqual(try DIDURL(doc.subject, "#profile"), vcs[0].getId())

            vcs = try doc.selectCredentials(byType: "TestingCredential")
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
    
    func testAddCredential3() {
        do {
            try AddCredential(3)
        } catch {
            XCTFail()
        }
    }
    
    func AddCredential(_ version: Int) throws {
        let cd = try testData!.getCompatibleData(version)
        // load issuer doc for vc verification
        _ = try cd.getDocument("issuer")

        _ = try testData!.getRootIdentity()

        var doc = try cd.getDocument("user1")
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid(debug))

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

        doc = try db.seal(using: storePassword)
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid(debug))

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
    
    func testAddCredentialWithCid2() {
        AddCredentialWithCid(2)
    }
    
    func testAddCredentialWithCid3() {
        AddCredentialWithCid(3)
    }
    
    func AddCredentialWithCid(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(version)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            let user1 = try cd.getDocument("user1")
            let user2 = try cd.getDocument("user2")
            _ = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            var doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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

            doc = try db.seal(using: storePassword)
            doc = try user2.sign(with: doc, using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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
    
    func testAddSelfClaimedCredential3() {
        do {
            try AddSelfClaimedCredential(3)
        } catch {
            XCTFail()
        }
    }
    
    func AddSelfClaimedCredential(_ version: Int) throws {
        _ = try testData!.getRootIdentity()

        var doc = try testData!.getCompatibleData(version).getDocument("user1")
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid(debug))

        let db = try doc.editing()

        // Add credentials.
        let subject: [String: String] = ["passport": "S653258Z07"]
        _ = try db.appendCredential(with: "#passport", subject: subject, using: storePassword)

        var json = "{\"name\":\"Jay Holtslander\",\"alternateName\":\"Jason Holtslander\"}"
        _ = try db.appendCredential(with: "#name", json: json, using: storePassword)

        json = "{\"twitter\":\"@john\"}";
        _ = try db.appendCredential(with: "#twitter", json: json, using: storePassword)

        doc = try db.seal(using: storePassword)
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid(debug))

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
    
    func testAddSelfClaimedCredentialWithCid2() {
        AddSelfClaimedCredentialWithCid(2)
    }
    
    func testAddSelfClaimedCredentialWithCid3() {
        AddSelfClaimedCredentialWithCid(3)
    }
    
    func AddSelfClaimedCredentialWithCid(_ verison: Int) {
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
            XCTAssertTrue(try doc.isValid(debug))

            let db = try doc.editing(user2)

            // Add credentials.
            let subject: [String: String] = ["foo": "bar"]
            _ = try db.appendCredential(with: "#testvc", subject: subject, using: storePassword)

            var json = "{\"name\":\"Foo Bar\",\"alternateName\":\"Jason Holtslander\"}"
            _ = try db.appendCredential(with: "#name", json: json, using: storePassword)

            json = "{\"twitter\":\"@foobar\"}"
            _ = try db.appendCredential(with: "#twitter", json: json, using: storePassword)

            doc = try db.seal(using: storePassword)
            doc = try user1.sign(with: doc, using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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
    
    func testRemoveCredential3() {
        do {
            try RemoveCredentia(3)
        } catch {
            XCTFail()
        }
    }
    
    func RemoveCredentia(_ version: Int) throws {
        _ = try testData!.getRootIdentity()
        let cd = try testData!.getCompatibleData(version)
        // load issuer doc for vc verification
        _ = try cd.getDocument("issuer");

        var doc = try cd.getDocument("user1")
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid(debug))

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

        doc = try db.seal(using: storePassword)
        XCTAssertNotNil(doc);
        XCTAssertTrue(try doc.isValid(debug))

        // Check existence
        vc = try doc.credential(ofId: "#profile")
        XCTAssertNil(vc)

        vc = doc.credential(ofId: try DIDURL(doc.subject, "#twitter"))
        XCTAssertNil(vc)

        // Check the final count.
        XCTAssertEqual(2, doc.credentialCount)
    }
    
    func testRemoveCredentialWithCid2() {
        RemoveCredentialWithCid(2)
    }
    
    func testRemoveCredentialWithCid3() {
        RemoveCredentialWithCid(3)
    }
    
    func RemoveCredentialWithCid(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(version)
            _ = try testData!.getRootIdentity()
            
            _ = try cd.getDocument("issuer")
            let user1 = try cd.getDocument("user1")
            let user2 = try cd.getDocument("user2")
            _ = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")
            
            var doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))
            
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

            doc = try db.seal(using: storePassword)
            doc = try user2.sign(with: doc, using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))
            
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
    
    func testGetService3() {
        do {
            try GetService(3)
        } catch {
            XCTFail()
        }
    }
    
    func GetService(_ version: Int) throws {
        _ = try testData!.getRootIdentity()

        let doc = try testData!.getCompatibleData(version).getDocument("user1")
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid(debug))

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

        svcss = try doc.selectServices(byId: try DIDURL(doc.subject, "#openid"))
        XCTAssertEqual(1, svcss.count)
        XCTAssertEqual(try DIDURL(doc.subject, "#openid"),
                     svcss[0].getId())

        svcss = try doc.selectServices(byType: "CarrierAddress")
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

        svcss = try doc.selectServices(byType: "notExistType")
        XCTAssertEqual(0, svcss.count)
    }
    
    func testGetServiceWithCid2() {
        GetServiceWithCid(2)
    }
    
    func testGetServiceWithCid3() {
        GetServiceWithCid(3)
    }
    
    func GetServiceWithCid(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(version)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            _ = try cd.getDocument("user1")
            _ = try cd.getDocument("user2")
            _ = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            let doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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

            svcs = try doc.selectServices(byId: try DIDURL(doc.subject, "#openid"))
            XCTAssertEqual(0, svcs.count)

            // Service not exist, should return a empty list.
            svcs = try doc.selectServices(byId: "#notExistService", andType: "CredentialRepositoryService")
            XCTAssertEqual(0, svcs.count)

            svcs = try doc.selectServices(byType: "notExistType")
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
    
    func testAddService3() {
        do {
            try AddService(3)
        } catch {
            XCTFail()
        }
    }
    
    func AddService(_ version: Int) throws {
        _ = try testData!.getRootIdentity()

        var doc = try testData!.getCompatibleData(version).getDocument("user1")
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid(debug))

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
        
        doc = try db.seal(using: storePassword)
        XCTAssertNotNil(doc)
        XCTAssertTrue(try doc.isValid(debug))

        // Check the final count
        XCTAssertEqual(5, doc.serviceCount)

        // Try to select new added 2 services
        let svcs = try doc.selectServices(byType: "Service.Testing")
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
    
    func testAddServiceWithDescription3() {
        AddServiceWithDescription(3)
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
                       "DATE": DateFormatter.currentDate(),
                       "empty": "",
                       "nil": NSNull()] as [String : Any]
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
                         "MAP": map,
                         "empty": "",
                         "nil": NSNull()] as [String : Any]
            
            var doc = try testData!.getCompatibleData(version).getDocument("user1")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))
            
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
            
            doc = try db.seal(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))
            
            // Check the final count
            XCTAssertEqual(6, doc.serviceCount)
            
            // Try to select new added 2 services
            let svcs = try doc.selectServices(byType: "Service.Testing")
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
            
            let svc = try doc.service(ofId: "#test-svc-1")
            XCTAssertTrue(svc!.hasProperty("nil"))
            let re = svc!.getProperty("nil")
//            XCTAssertNil(re)
            XCTAssertTrue(svc!.hasProperty("empty"))
            XCTAssertEqual("", svc!.getProperty("empty") as! String)
        } catch {
            XCTFail()
        }
    }
    
    func testAddServiceWithCid2() {
        AddServiceWithCid(2)
    }
    
    func testAddServiceWithCid3() {
        AddServiceWithCid(3)
    }
    
    func AddServiceWithCid(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(version)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            let user1 = try cd.getDocument("user1")
            _ = try cd.getDocument("user2")
            let user3 = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            var doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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

            doc = try db.seal(using: storePassword)
            doc = try user1.sign(with: doc, using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

            // Check the final count
            XCTAssertEqual(4, doc.serviceCount)

            // Try to select new added 2 services
            let svcs = try doc.selectServices(byType: "Service.Testing")
            XCTAssertEqual(2, svcs.count)
            XCTAssertEqual("Service.Testing", svcs[0].getType())
            XCTAssertEqual("Service.Testing", svcs[1].getType())
        } catch {
            XCTFail()
        }
    }
    
    func testAddServiceWithCidAndDescription2() {
        AddServiceWithCidAndDescription(2)
    }
    
    func testAddServiceWithCidAndDescription3() {
        AddServiceWithCidAndDescription(3)
    }
    
    func AddServiceWithCidAndDescription(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(version)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            let user1 = try cd.getDocument("user1")
            _ = try cd.getDocument("user2")
            let user3 = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            var doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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

            doc = try db.seal(using: storePassword)
            doc = try user1.sign(with: doc, using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

            // Check the final count
            XCTAssertEqual(5, doc.serviceCount)

            // Try to select new added 2 services
            let svcs = try doc.selectServices(byType: "Service.Testing")
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
    
    func testRemoveService3() {
        do {
            try RemoveService(3)
        } catch {
            XCTFail()
        }
    }
    
    func RemoveService(_ version: Int) throws {
        do {
            _ = try testData!.getRootIdentity()

            var doc = try testData!.getCompatibleData(version).getDocument("user1")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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

            doc = try db.seal(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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
    
    func testRemoveServiceWithCid2() {
        RemoveServiceWithCid(2)
    }
    
    func testRemoveServiceWithCid3() {
        RemoveServiceWithCid(3)
    }
    
    func RemoveServiceWithCid(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(version)
            _ = try testData!.getRootIdentity()

            _ = try cd.getDocument("issuer")
            let user1 = try cd.getDocument("user1")
            _ = try cd.getDocument("user2")
            let user3 = try cd.getDocument("user3")
            _ = try cd.getDocument("examplecorp")

            var doc = try cd.getDocument("foobar")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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

            doc = try db.seal(using: storePassword)
            doc = try user3.sign(with: doc, using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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
        ParseAndSerializeDocument(2, "issuer")
    }
    
    func testParseAndSerializeDocument6() {
        ParseAndSerializeDocument(2, "user1")
    }
    
    func testParseAndSerializeDocument7() {
        ParseAndSerializeDocument(2, "user2")
    }
    
    func testParseAndSerializeDocument8() {
        ParseAndSerializeDocument(2, "user3")
    }
    
    func testParseAndSerializeDocument9() {
        ParseAndSerializeDocument(2, "user4")
    }
    
    func testParseAndSerializeDocument10() {
        ParseAndSerializeDocument(2, "examplecorp")
    }
    
    func testParseAndSerializeDocument11() {
        ParseAndSerializeDocument(2, "foobar")
    }
    
    func testParseAndSerializeDocument12() {
        ParseAndSerializeDocument(2, "foo")
    }
    
    func testParseAndSerializeDocument13() {
        ParseAndSerializeDocument(2, "bar")
    }
    
    func testParseAndSerializeDocument14() {
        ParseAndSerializeDocument(2, "baz")
    }
    
    func testParseAndSerializeDocument15() {
        ParseAndSerializeDocument(3, "issuer")
    }
    func testParseAndSerializeDocument16() {
        ParseAndSerializeDocument(3, "user1")
    }
    func testParseAndSerializeDocument17() {
        ParseAndSerializeDocument(3, "user2")
    }
    func testParseAndSerializeDocument18() {
        ParseAndSerializeDocument(3, "user3")
    }
    func testParseAndSerializeDocument19() {
        ParseAndSerializeDocument(3, "user4")
    }
    func testParseAndSerializeDocument20() {
        ParseAndSerializeDocument(3, "examplecorp")
    }
    func testParseAndSerializeDocument21() {
        ParseAndSerializeDocument(3, "foobar")
    }
    func testParseAndSerializeDocument22() {
        ParseAndSerializeDocument(3, "foo")
    }
    func testParseAndSerializeDocument23() {
        ParseAndSerializeDocument(3, "bar")
    }
    func testParseAndSerializeDocument24() {
        ParseAndSerializeDocument(3, "baz")
    }

    func ParseAndSerializeDocument(_ version: Int, _ did: String) {
        do {
            let cd = try testData!.getCompatibleData(version)
            try cd.loadAll()
            
            let compactJson = try cd.getDocumentJson(did, "compact")
            let compact = try DIDDocument.convertToDIDDocument(fromJson: compactJson)
            XCTAssertNotNil(compact)
            XCTAssertTrue(try compact.isValid(debug))
            
            let normalizedJson = try cd.getDocumentJson(did, "normalized")
            let normalized = try DIDDocument.convertToDIDDocument(fromJson: normalizedJson)
            XCTAssertNotNil(normalized)
            XCTAssertTrue(try normalized.isValid(debug))
            
            let doc = try cd.getDocument(did)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))
            
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
    
    func testGenuineAndValidWithListener1() {
        GenuineAndValidWithListener(1, "issuer")
    }
    
    func testGenuineAndValidWithListener2() {
        GenuineAndValidWithListener(1, "user1")
    }
    
    func testGenuineAndValidWithListener3() {
        GenuineAndValidWithListener(1, "user2")
    }
    
    func testGenuineAndValidWithListener4() {
        GenuineAndValidWithListener(1, "user3")
    }
    
    func testGenuineAndValidWithListener5() {
        GenuineAndValidWithListener(2, "issuer")
    }
    
    func testGenuineAndValidWithListener6() {
        GenuineAndValidWithListener(2, "user1")
    }
    
    func testGenuineAndValidWithListener7() {
        GenuineAndValidWithListener(2, "user2")
    }
    
    func testGenuineAndValidWithListener8() {
        GenuineAndValidWithListener(2, "user3")
    }
    
    func testGenuineAndValidWithListener9() {
        GenuineAndValidWithListener(2, "user4")
    }
    
    func testGenuineAndValidWithListener10() {
        GenuineAndValidWithListener(2, "examplecorp")
    }
    
    func testGenuineAndValidWithListener11() {
        GenuineAndValidWithListener(2, "foobar")
    }
    
    func testGenuineAndValidWithListener12() {
        GenuineAndValidWithListener(2, "foo")
    }
    
    func testGenuineAndValidWithListener13() {
        GenuineAndValidWithListener(2, "bar")
    }
    
    func testGenuineAndValidWithListener14() {
        GenuineAndValidWithListener(2, "baz")
    }
    
    func testGenuineAndValidWithListener15() {
        GenuineAndValidWithListener(3, "baz")
    }
    func testGenuineAndValidWithListener16() {
        GenuineAndValidWithListener(3, "issuer")
    }
    func testGenuineAndValidWithListener17() {
        GenuineAndValidWithListener(3, "user1")
    }
    func testGenuineAndValidWithListener18() {
        GenuineAndValidWithListener(3, "user2")
    }
    func testGenuineAndValidWithListener19() {
        GenuineAndValidWithListener(3, "user3")
    }
    func testGenuineAndValidWithListener20() {
        GenuineAndValidWithListener(3, "user4")
    }

    func testGenuineAndValidWithListener21() {
        GenuineAndValidWithListener(3, "examplecorp")
    }
    func testGenuineAndValidWithListener22() {
        GenuineAndValidWithListener(3, "foobar")
    }
    func testGenuineAndValidWithListener23() {
        GenuineAndValidWithListener(3, "foo")
    }
    func testGenuineAndValidWithListener24() {
        GenuineAndValidWithListener(3, "bar")
    }
    func testGenuineAndValidWithListener25() {
        GenuineAndValidWithListener(3, "baz")
    }
    
    func GenuineAndValidWithListener(_ version: Int, _ did: String) {
        do {
            let cd = try testData!.getCompatibleData(version)
            try cd.loadAll()

            let listener = VerificationEventListener.getDefault("  ", "- ", "* ")

            let compactJson = try cd.getDocumentJson(did, "compact")
            let compact = try DIDDocument.convertToDIDDocument(fromJson: compactJson)
            XCTAssertNotNil(compact)

            XCTAssertTrue(try compact.isGenuine(listener))
            XCTAssertTrue(listener.description.hasPrefix(" "))
            listener.reset()

            XCTAssertTrue(try compact.isValid(listener))
            XCTAssertTrue(listener.description.hasPrefix(" "))
            listener.reset()

            let normalizedJson = try cd.getDocumentJson(did, "normalized")
            let normalized = try DIDDocument.convertToDIDDocument(fromJson: normalizedJson)
            XCTAssertNotNil(normalized)

            XCTAssertTrue(try normalized.isGenuine(listener))
            XCTAssertTrue(listener.toString().hasPrefix(" "))
            listener.reset()

            XCTAssertTrue(try normalized.isValid(listener))
            XCTAssertTrue(listener.toString().hasPrefix(" "))
            listener.reset()

            let doc = try cd.getDocument(did)
            XCTAssertNotNil(doc)

            XCTAssertTrue(try doc.isGenuine(listener))
            XCTAssertTrue(listener.toString().hasPrefix(" "))
            listener.reset()

            XCTAssertTrue(try doc.isValid(listener))
            XCTAssertTrue(listener.toString().hasPrefix(" "))
            listener.reset()
        } catch {
            XCTFail()
        }
    }
   
    func testSignAndVerify() {
        do {
            let identity = try testData!.getRootIdentity()
            let doc = try identity.newDid(storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))
            
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
            XCTAssertTrue(try doc.isValid(debug))

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
        Derive2(2)
    }
    func testDerive3() {
        Derive2(3)
    }

    func Derive2(_ version: Int) {
        do {
            let doc = try testData!.getCompatibleData(version).getDocument("user1")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))
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
            XCTAssertTrue(try doc.isValid(debug))

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
        DeriveFromIdentifier2(2)
    }
    func testDeriveFromIdentifier3() {
        DeriveFromIdentifier2(3)
    }
    func DeriveFromIdentifier2(_ version: Int) {
        do {
            let identifier = "org.elastos.did.test"

            let doc = try testData!.getCompatibleData(version).getDocument("user1")
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid(debug))

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
            XCTAssertTrue(try controller.isValid(debug))

            var resolved = try controller.subject.resolve()
            XCTAssertNil(resolved)

            try controller.publish(using: storePassword);

            resolved = try controller.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(controller.subject, resolved?.subject)
            XCTAssertEqual(controller.proof.signature,
                           resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Create customized DID
            let did = try DID("did:elastos:helloworld")
            let doc = try controller.newCustomizedDid(withId: did, storePassword)
            XCTAssertTrue(try doc.isValid(debug))

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(controller.subject, doc.controller)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.publish(using: storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(controller.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))
        } catch {
            XCTFail()
        }
    }
    
    func testCreateMultisigCustomizedDid() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let ctrl1 = try identity.newDid(storePassword)
            
            try ctrl1.publish(using: storePassword)

            var resolved = try ctrl1.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl1.subject, resolved?.subject)
            XCTAssertEqual(ctrl1.proof.signature,
                           resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            let ctrl2 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl2.isValid(debug))
            try ctrl2.publish(using: storePassword)

            resolved = try ctrl2.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl2.subject, resolved?.subject)
            XCTAssertEqual(ctrl2.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            let ctrl3 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl3.isValid(debug))
            try ctrl3.publish(using: storePassword)

            resolved = try ctrl3.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl3.subject, resolved?.subject)
            XCTAssertEqual(ctrl3.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Create customized DID
            let did = try DID("did:elastos:helloworld3")
            var doc = try ctrl1.newCustomizedDid(withId: did, [ctrl2.subject, ctrl3.subject],
                    2, storePassword)
            XCTAssertFalse(try doc.isValid(debug))

//            XCTAssertThrowsError(_ = try ctrl1.sign(using: storePassword, for: [doc.toString().data(using: .utf8)!])){ error in
//                switch error {
//                case DIDError.UncheckedError.IllegalStateError.AlreadySignedError: break
//                default:
//                    XCTFail()
//                }
//            }
            doc = try ctrl2.sign(with: doc, using: storePassword)
            XCTAssertTrue(try doc.isValid(debug));

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
            try doc.publish(using: storePassword)

            resolved = try did.resolve()
//            XCTAssertNotNil(resolved)
//            XCTAssertEqual(did, resolved?.subject)
//            XCTAssertEqual(doc.proof.signature,
//                    resolved?.proof.signature)
//
//            XCTAssertTrue(try resolved!.isValid(debug))
        } catch {
            XCTFail()
        }
    }
    
    func testUpdateDid() {
        do {
            let identity = try testData!.getRootIdentity()

            var doc = try identity.newDid(storePassword)
            XCTAssertTrue(try doc.isValid(debug))

            try doc.publish(using: storePassword)

            var resolved = try doc.subject.resolve() 
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())

            // Update
            var db = try doc.editing()
            var key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(using: storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved!.toString())

            // Update again
            db = try doc.editing()
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key2", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            XCTAssertEqual(3, doc.publicKeyCount)
            XCTAssertEqual(3, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(using: storePassword)

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
            XCTAssertTrue(try controller.isValid(debug))

            var resolved = try controller.subject.resolve();
            XCTAssertNil(resolved)

            try controller.publish(using: storePassword)

            resolved = try controller.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(controller.subject, resolved!.subject)
            XCTAssertEqual(controller.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Create customized DID
            let did = try DID("did:elastos:helloworld")
            var doc = try controller.newCustomizedDid(withId: did, storePassword)
            XCTAssertTrue(try doc.isValid(debug))

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(controller.subject, doc.controller)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.publish(using: storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(controller.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Update
            var db = try doc.editing()
            var key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(using: storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            // Update again
            db = try doc.editing()
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key2", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            XCTAssertEqual(3, doc.publicKeyCount)
            XCTAssertEqual(3, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(using: storePassword)

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
            XCTAssertTrue(try ctrl1.isValid(debug))
            try ctrl1.publish(using: storePassword)

            var resolved = try ctrl1.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl1.subject, resolved?.subject)
            XCTAssertEqual(ctrl1.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            let ctrl2 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl2.isValid(debug))
            try ctrl2.publish(using: storePassword)

            resolved = try ctrl2.subject.resolve();
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl2.subject, resolved?.subject)
            XCTAssertEqual(ctrl2.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            let ctrl3 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl3.isValid(debug))
            try ctrl3.publish(using: storePassword)

            resolved = try ctrl3.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl3.subject, resolved?.subject)
            XCTAssertEqual(ctrl3.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Create customized DID
            let did = try DID("did:elastos:helloworld3")
            var doc = try ctrl1.newCustomizedDid(withId: did, [ctrl2.subject, ctrl3.subject],
                    2, storePassword)
            XCTAssertFalse(try doc.isValid(debug))

            _ = doc
//            XCTAssertThrowsError(_ = try ctrl1.sign(using: storePassword, for: [doc.toString().data(using: .utf8)!])){ error in
//                switch error {
//                case DIDError.UncheckedError.IllegalStateError.AlreadySignedError: break
//                default:
//                    XCTFail()
//                }
//            }

            doc = try ctrl2.sign(with: doc, using: storePassword)
            XCTAssertTrue(try doc.isValid(debug))

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(3, doc.controllerCount())
            let ctrls = [ctrl1.subject, ctrl2.subject, ctrl3.subject]
            XCTAssertEqual(doc.controllers().count, ctrls.count)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.setEffectiveController(ctrl1.subject)
            try doc.publish(using: storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Update
            var db = try doc.editing(ctrl2)
            var key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            doc = try ctrl1.sign(with: doc, using: storePassword)
            try store!.storeDid(using: doc)

            try doc.publish(using: storePassword)

            resolved = try doc.subject.resolve()
            
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())
            XCTAssertEqual(4, resolved?.publicKeyCount)
            XCTAssertEqual(4, resolved?.authenticationKeyCount)

            // Update again
            db = try doc.editing(ctrl3)
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key2", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            doc = try ctrl2.sign(with: doc, using: storePassword)
            try store!.storeDid(using: doc)

            try doc.publish(using: storePassword)

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
            XCTAssertTrue(try controller.isValid(debug))

            var resolved = try controller.subject.resolve()
            XCTAssertNil(resolved)

            try controller.publish(using: storePassword)

            resolved = try controller.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(controller.subject, resolved?.subject)
            XCTAssertEqual(controller.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Create customized DID
            let did = try DID("did:elastos:helloworld")
            var doc = try controller.newCustomizedDid(withId: did, storePassword)
            XCTAssertTrue(try doc.isValid(debug))

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(controller.subject, doc.controller)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.publish(using: storePassword);

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(controller.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // create new controller
            let newController = try identity.newDid(storePassword)
            XCTAssertTrue(try controller.isValid(debug))

            resolved = try newController.subject.resolve()
            XCTAssertNil(resolved)

            try newController.publish(using: storePassword)

            resolved = try newController.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(newController.subject, resolved?.subject)
            XCTAssertEqual(newController.proof.signature,
                           resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // create the transfer ticket
            try doc.setEffectiveController(controller.subject)
            let ticket = try doc.createTransferTicket(to: newController.subject, using: storePassword)
            XCTAssertTrue(try ticket.isValid(debug))

            // create new document for customized DID
            doc = try newController.newCustomizedDid(withId: did, true, storePassword)
            XCTAssertTrue(try doc.isValid(debug))

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(newController.subject, doc.controller)

            // transfer
            try doc.publish(with: ticket, using: storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(newController.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))
        } catch {
            XCTFail()
        }
    }
    
    func testTransferCustomizedDidAfterUpdate() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let controller = try identity.newDid(storePassword)
            XCTAssertTrue(try controller.isValid(debug))

            var resolved = try controller.subject.resolve()
            XCTAssertNil(resolved)

            try controller.publish(using: storePassword)

            resolved = try controller.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(controller.subject, resolved?.subject)
            XCTAssertEqual(controller.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Create customized DID
            let did = try DID("did:elastos:helloworld")
            var doc = try controller.newCustomizedDid(withId: did, storePassword)
            XCTAssertTrue(try doc.isValid(debug))

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(controller.subject, doc.controller)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.publish(using: storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(controller.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                           resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Update
            let db = try doc.editing()
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(using: storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            // create new controller
            let newController = try identity.newDid(storePassword)
            XCTAssertTrue(try controller.isValid(debug))

            resolved = try newController.subject.resolve()
            XCTAssertNil(resolved)

            try newController.publish(using: storePassword)

            resolved = try newController.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(newController.subject, resolved?.subject)
            XCTAssertEqual(newController.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // create the transfer ticket
            let ticket = try controller.createTransferTicket(withId: did, to: newController.subject, using: storePassword)
            XCTAssertTrue(try ticket.isValid(debug));

            // create new document for customized DID
            doc = try newController.newCustomizedDid(withId: did, true, storePassword)
            XCTAssertTrue(try doc.isValid(debug))

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(newController.subject, doc.controller)

            // transfer
            try doc.publish(with: ticket, using: storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(newController.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))
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
            XCTAssertTrue(try ctrl1.isValid(debug))
            try ctrl1.publish(using: storePassword)

            var resolved = try ctrl1.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl1.subject, resolved?.subject)
            XCTAssertEqual(ctrl1.proof.signature,
                           resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            let ctrl2 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl2.isValid(debug))
            try ctrl2.publish(using: storePassword)

            resolved = try ctrl2.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl2.subject, resolved?.subject)
            XCTAssertEqual(ctrl2.proof.signature,
                           resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

               let ctrl3 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl3.isValid(debug))
            try ctrl3.publish(using: storePassword)

            resolved = try ctrl3.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl3.subject, resolved?.subject)
            XCTAssertEqual(ctrl3.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Create customized DID
            let did = try DID("did:elastos:helloworld3")
            var doc = try ctrl1.newCustomizedDid(withId: did, [ctrl2.subject, ctrl3.subject],
                    2, storePassword)
            XCTAssertFalse(try doc.isValid(debug))

            _ = doc
        
            doc = try ctrl2.sign(with: doc, using: storePassword)
            XCTAssertTrue(try doc.isValid(debug))

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
            try doc.publish(using: storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // new controllers for the did
            let td = testData!.sharedInstantData()
            _ = try td.getIssuerDocument()
            let u1 = try td.getUser1Document()
            let u2 = try td.getUser2Document()
            let u3 = try td.getUser3Document()
            let u4 = try td.getUser4Document()

            // transfer ticket
            var ticket = try ctrl1.createTransferTicket(withId: did, to: u1.subject, using: storePassword)
            ticket = try ctrl2.sign(with: ticket, using: storePassword)
            XCTAssertTrue(try ticket.isValid(debug))

            try doc = u1.newCustomizedDid(withId: did, [u2.subject, u3.subject, u4.subject],
                        3, true, storePassword)
            try doc = u2.sign(with: doc, using: storePassword)
            try doc = u3.sign(with: doc, using: storePassword)
            XCTAssertTrue(try doc.isValid(debug))

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(4, doc.controllerCount())
            XCTAssertEqual("3:4", doc.multiSignature!.description)

            // transfer
            try doc.publish(with: ticket, using: storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)

            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))
        } catch {
            XCTFail()
        }
    }
    
    func testTransferMultisigCustomizedDidAfterUpdate() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let ctrl1 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl1.isValid(debug))
            try ctrl1.publish(using: storePassword)

            var resolved = try ctrl1.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl1.subject, resolved?.subject)
            XCTAssertEqual(ctrl1.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            let ctrl2 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl2.isValid(debug))
            try  ctrl2.publish(using: storePassword)

            resolved = try ctrl2.subject.resolve()
            XCTAssertNotNil(resolved);
            XCTAssertEqual(ctrl2.subject, resolved?.subject)
            XCTAssertEqual(ctrl2.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

               let ctrl3 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl3.isValid(debug))
            try ctrl3.publish(using: storePassword)

            resolved = try ctrl3.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl3.subject, resolved?.subject)
            XCTAssertEqual(ctrl3.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Create customized DID
            let did = try DID("did:elastos:helloworld3")
            var doc = try ctrl1.newCustomizedDid(withId: did, [ctrl2.subject, ctrl3.subject], 2, storePassword)
            XCTAssertFalse(try doc.isValid(debug))

//            XCTAssertThrowsError(_ = try ctrl1.sign(using: storePassword, for: [doc.toString().data(using: .utf8)!])){ error in
//                switch error {
//                case DIDError.UncheckedError.IllegalStateError.AlreadySignedError: break
//                default:
//                    XCTFail()
//                }
//            }
            
            doc = try ctrl2.sign(with: doc, using: storePassword)
            XCTAssertTrue(try doc.isValid(debug))

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
            try doc.publish(using: storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Update
            let db = try doc.editing(ctrl2)
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            doc = try ctrl1.sign(with: doc, using: storePassword)
            try store!.storeDid(using: doc)

            try doc.publish(using: storePassword)

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
            var ticket = try doc.createTransferTicket(to: u1.subject, using: storePassword)
            ticket = try ctrl2.sign(with: ticket, using: storePassword)
            XCTAssertTrue(try ticket.isValid(debug))

            doc = try u1.newCustomizedDid(withId: did, [u2.subject, u3.subject, u4.subject], 3, true, storePassword)
            doc = try u2.sign(with: doc, using: storePassword)
            doc = try u3.sign(with: doc, using: storePassword)
            XCTAssertTrue(try doc.isValid(debug))

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(4, doc.controllerCount())
            XCTAssertEqual("3:4", doc.multiSignature?.description)

            // transfer
            try doc.publish(with: ticket, using: storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)

            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))
        } catch {
            XCTFail()
        }
    }
    
    func testUpdateDidWithoutPrevSignature() {
        do {
            let identity = try testData!.getRootIdentity()

            var doc = try identity.newDid(storePassword)
            XCTAssertTrue(try doc.isValid(debug))

            try doc.publish(using: storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            // Update
            var db = try doc.editing()
            var key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(using: storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

//            doc.getMetadata().previousSignature = nil
//            doc.getMetadata().setPreviousSignature(nil) //TODO:

            // Update again
            db = try doc.editing()
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key2", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            XCTAssertEqual(3, doc.publicKeyCount)
            XCTAssertEqual(3, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(using: storePassword);

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
            XCTAssertTrue(try doc.isValid(debug))

            try doc.publish(using: storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            // Update
            var db = try doc.editing()
            var key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(using: storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            doc.getMetadata().setSignature(nil)

            // Update again
            db = try doc.editing()
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key2", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            XCTAssertEqual(3, doc.publicKeyCount)
            XCTAssertEqual(3, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            XCTAssertThrowsError(_ = try doc.publish(using: storePassword)){ error in
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
            XCTAssertTrue(try doc.isValid(debug))

            try doc.publish(using: storePassword)

            let resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

//            doc.getMetadata().setPreviousSignature(null);
//            doc.getMetadata().setSignature(null);

            // Update
            let db = try doc.editing()
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
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
            XCTAssertTrue(try doc.isValid(debug))

            try doc.publish(using: storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

//            doc.getMetadata().setPreviousSignature(null);
//            doc.getMetadata().setSignature(null);

            // Update
            let db = try doc.editing()
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(with: doc.defaultPublicKeyId()!, force: true, using: storePassword)

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
            XCTAssertTrue(try doc.isValid(debug))

            try doc.publish(using: storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString());

            // Update
            var db = try doc.editing()
            var key = try TestData.generateKeypair();
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(using: storePassword)

            resolved = try doc.subject.resolve();
            XCTAssertNotNil(resolved);
            XCTAssertEqual(doc.toString(), resolved?.toString());

            doc.getMetadata().setPreviousSignature("1234567890");

            // Update
            db = try doc.editing()
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key2", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            XCTAssertEqual(3, doc.publicKeyCount)
            XCTAssertEqual(3, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(using: storePassword)

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
            XCTAssertTrue(try doc.isValid(debug))

            try doc.publish(using: storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            // Update
            var db = try doc.editing()
            var key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(using: storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved);
            XCTAssertEqual(doc.toString(), resolved?.toString())

            doc.getMetadata().setSignature("1234567890");

            // Update
            db = try doc.editing()
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key2", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            XCTAssertEqual(3, doc.publicKeyCount)
            XCTAssertEqual(3, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            _ = doc
            XCTAssertThrowsError(_ = try doc.publish(using: storePassword)){ error in
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
            XCTAssertTrue(try doc.isValid(debug))

            try doc.publish(using: storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            doc.getMetadata().setPreviousSignature("1234567890")
            // Update
            let db = try doc.editing()
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(with: doc.defaultPublicKeyId()!, force: true, using: storePassword)

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
            XCTAssertTrue(try doc.isValid(debug))

            try doc.publish(using: storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            doc.getMetadata().setSignature("1234567890")

            // Update
            let db = try doc.editing()
            let key = try TestData.generateKeypair();
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(with: doc.defaultPublicKeyId()!, force: true, using: storePassword)

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
            XCTAssertTrue(try doc.isValid(debug))

            try doc.publish(using: storePassword)

            let resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            try doc.deactivate(using: storePassword)

            doc = try doc.subject.resolve()!
            XCTAssertTrue(try doc.isDeactivated())
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateSelfAfterUpdate() {
        do {
            let identity = try testData!.getRootIdentity()

            var doc = try identity.newDid(storePassword)
            XCTAssertTrue(try doc.isValid(debug))

            try doc.publish(using: storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            // Update
            let db = try doc.editing()
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(using: storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            try doc.deactivate(using: storePassword)
            doc = try doc.subject.resolve()!
            XCTAssertTrue(try doc.isDeactivated())
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateCustomizedDidAfterCreate() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let controller = try identity.newDid(storePassword)
            XCTAssertTrue(try controller.isValid(debug))

            var resolved = try controller.subject.resolve()
            XCTAssertNil(resolved)

            try controller.publish(using: storePassword)

            resolved = try controller.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(controller.subject, resolved?.subject)
            XCTAssertEqual(controller.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Create customized DID
            let did = try DID("did:elastos:helloworld")
            var doc = try controller.newCustomizedDid(withId: did, storePassword)
            XCTAssertTrue(try doc.isValid(debug))

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(controller.subject, doc.controller)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.publish(using: storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(controller.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Deactivate
            try doc.deactivate(using: storePassword)
            doc = try doc.subject.resolve()!
            XCTAssertTrue(try doc.isDeactivated())
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateCustomizedDidAfterUpdate() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let controller = try identity.newDid(storePassword)
            XCTAssertTrue(try controller.isValid(debug))

            var resolved = try controller.subject.resolve()
            XCTAssertNil(resolved)

            try controller.publish(using: storePassword)

            resolved = try controller.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(controller.subject, resolved?.subject)
            XCTAssertEqual(controller.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Create customized DID
            let did = try DID("did:elastos:helloworld")
            var doc = try controller.newCustomizedDid(withId: did, storePassword)
            XCTAssertTrue(try doc.isValid(debug))

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(controller.subject, doc.controller)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.publish(using: storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(controller.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Update
            let db = try doc.editing()
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(using: storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString());

            // Deactivate
            try doc.deactivate(using: storePassword)
            doc = try doc.subject.resolve()!
            XCTAssertTrue(try doc.isDeactivated())
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateCidAfterCreateByController() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let controller = try identity.newDid(storePassword)
            XCTAssertTrue(try controller.isValid(debug))

            var resolved = try controller.subject.resolve()
            XCTAssertNil(resolved)

            try controller.publish(using: storePassword)

            resolved = try controller.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(controller.subject, resolved?.subject)
            XCTAssertEqual(controller.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Create customized DID
            let did = try DID("did:elastos:helloworld")
            var doc = try controller.newCustomizedDid(withId: did, storePassword)
            XCTAssertTrue(try doc.isValid(debug))

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(controller.subject, doc.controller)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.publish(using: storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(controller.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Deactivate
            try controller.deactivate(with: did, using: storePassword)
            doc = try did.resolve()!
            XCTAssertTrue(try doc.isDeactivated())
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateCidAfterUpdateByController() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let controller = try identity.newDid(storePassword)
            XCTAssertTrue(try controller.isValid(debug))

            var resolved = try controller.subject.resolve()
            XCTAssertNil(resolved)

            try controller.publish(using: storePassword)

            resolved = try controller.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(controller.subject, resolved?.subject)
            XCTAssertEqual(controller.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Create customized DID
            let did = try DID("did:elastos:helloworld")
            var doc = try controller.newCustomizedDid(withId: did, storePassword)
            XCTAssertTrue(try doc.isValid(debug))

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(controller.subject, doc.controller)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.publish(using: storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(controller.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Update
            let db = try doc.editing()
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(using: storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            // Deactivate
            try controller.deactivate(with: did, using: storePassword)
            doc = try did.resolve()!
            XCTAssertTrue(try doc.isDeactivated())
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateMultisigCustomizedDidAfterCreate() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let ctrl1 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl1.isValid(debug))
            try ctrl1.publish(using: storePassword)

            var resolved = try ctrl1.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl1.subject, resolved?.subject)
            XCTAssertEqual(ctrl1.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            let ctrl2 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl2.isValid(debug))
            try ctrl2.publish(using: storePassword)

            resolved = try ctrl2.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl2.subject, resolved?.subject)
            XCTAssertEqual(ctrl2.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

               let ctrl3 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl3.isValid(debug))
            try ctrl3.publish(using: storePassword)

            resolved = try ctrl3.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl3.subject, resolved?.subject)
            XCTAssertEqual(ctrl3.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Create customized DID
            let did = try DID("did:elastos:helloworld3")
            var doc = try ctrl1.newCustomizedDid(withId: did, [ctrl2.subject, ctrl3.subject], 2, storePassword)
            XCTAssertFalse(try doc.isValid(debug))
            
            XCTAssertThrowsError(_ = try ctrl1.sign(with: doc, using: storePassword)){ error in
                switch error {
                case DIDError.UncheckedError.IllegalStateError.AlreadySignedError: break
                default:
                    XCTFail()
                }
            }

            doc = try ctrl2.sign(with: doc, using: storePassword)
            XCTAssertTrue(try doc.isValid(debug))

            XCTAssertEqual(did, doc.subject)
            let ctrls = [ctrl1.subject, ctrl2.subject, ctrl3.subject]
            XCTAssertEqual(doc.controllers().count, ctrls.count)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.setEffectiveController(ctrl1.subject)
            try doc.publish(using: storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(doc.proof.signature,
                           resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Deactivate
            try doc.deactivate(with: ctrl1.defaultPublicKeyId()!, using: storePassword)
            doc = try doc.subject.resolve()!
            XCTAssertTrue(try doc.isDeactivated())
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateMultisigCustomizedDidAfterUpdate() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let ctrl1 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl1.isValid(debug))
            try ctrl1.publish(using: storePassword)

            var resolved = try ctrl1.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl1.subject, resolved?.subject)
            XCTAssertEqual(ctrl1.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

               let ctrl2 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl2.isValid(debug))
            try ctrl2.publish(using: storePassword)

            resolved = try ctrl2.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl2.subject, resolved?.subject)
            XCTAssertEqual(ctrl2.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

               let ctrl3 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl3.isValid(debug))
            try ctrl3.publish(using: storePassword)

            resolved = try ctrl3.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl3.subject, resolved?.subject)
            XCTAssertEqual(ctrl3.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Create customized DID
            let did = try DID("did:elastos:helloworld3")
            var doc = try ctrl1.newCustomizedDid(withId: did, [ctrl2.subject, ctrl3.subject], 2, storePassword)
            XCTAssertFalse(try doc.isValid(debug))

            XCTAssertThrowsError(_ = try ctrl1.sign(with: doc, using: storePassword)){ error in
                switch error {
                case DIDError.UncheckedError.IllegalStateError.AlreadySignedError: break
                default:
                    XCTFail()
                }
            }

            doc = try ctrl2.sign(with: doc, using: storePassword)
            XCTAssertTrue(try doc.isValid(debug))

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
            try doc.publish(using: storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Update
            let db = try doc.editing(ctrl2)
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            doc = try ctrl1.sign(with: doc, using: storePassword)
            try store!.storeDid(using: doc)

            try doc.publish(using: storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())
            XCTAssertEqual(4, resolved?.publicKeyCount)
            XCTAssertEqual(4, resolved?.authenticationKeyCount)

            // Deactivate
            try doc.deactivate(with: ctrl1.defaultPublicKeyId()!, using: storePassword)
            doc = try doc.subject.resolve()!
            XCTAssertTrue(try doc.isDeactivated())
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateMultisigCidAfterCreateByController() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let ctrl1 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl1.isValid(debug))
            try ctrl1.publish(using: storePassword)

            var resolved = try ctrl1.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl1.subject, resolved?.subject)
            XCTAssertEqual(ctrl1.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

               let ctrl2 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl2.isValid(debug))
            try ctrl2.publish(using: storePassword)

            resolved = try ctrl2.subject.resolve()
            XCTAssertNotNil(resolved);
            XCTAssertEqual(ctrl2.subject, resolved?.subject)
            XCTAssertEqual(ctrl2.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

               let ctrl3 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl3.isValid(debug))
            try ctrl3.publish(using: storePassword)

            resolved = try ctrl3.subject.resolve()
            XCTAssertNotNil(resolved);
            XCTAssertEqual(ctrl3.subject, resolved?.subject)
            XCTAssertEqual(ctrl3.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Create customized DID
            let did = try DID("did:elastos:helloworld3")
            var doc = try ctrl1.newCustomizedDid(withId: did, [ctrl2.subject, ctrl3.subject],
                    2, storePassword)
            XCTAssertFalse(try doc.isValid(debug))

            _ = doc
//            assertThrows(AlreadySignedException.class, () -> {
//                ctrl1.sign(d, storePassword);
//            });

            doc = try ctrl2.sign(with: doc, using: storePassword)
            XCTAssertTrue(try doc.isValid(debug))

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
            try doc.publish(using: storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved);
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Deactivate
            try ctrl1.deactivate(with: did, using: storePassword)
            doc = try did.resolve()!
            XCTAssertTrue(try doc.isDeactivated())
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateMultisigCidAfterUpdateByController() {
        do {
            let identity = try testData!.getRootIdentity()

            // Create normal DID first
            let ctrl1 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl1.isValid(debug))
            try ctrl1.publish(using: storePassword)

            var resolved = try ctrl1.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl1.subject, resolved?.subject)
            XCTAssertEqual(ctrl1.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            let ctrl2 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl2.isValid(debug))
            try ctrl2.publish(using: storePassword)

            resolved = try ctrl2.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl2.subject, resolved?.subject)
            XCTAssertEqual(ctrl2.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

               let ctrl3 = try identity.newDid(storePassword)
            XCTAssertTrue(try ctrl3.isValid(debug))
            try ctrl3.publish(using: storePassword)

            resolved = try ctrl3.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl3.subject, resolved?.subject)
            XCTAssertEqual(ctrl3.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Create customized DID
            let did = try DID("did:elastos:helloworld3")
            var doc = try ctrl1.newCustomizedDid(withId: did, [ctrl2.subject, ctrl3.subject],
                    2, storePassword);
            XCTAssertFalse(try doc.isValid(debug))

            _ = doc
//            assertThrows(AlreadySignedException.class, () -> {
//                ctrl1.sign(d, storePassword);
//            });

            doc = try ctrl2.sign(with: doc, using: storePassword)
            XCTAssertTrue(try doc.isValid(debug))

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
            try doc.publish(using: storePassword)

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Update
            let db = try doc.editing(ctrl2)
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword);
            doc = try ctrl1.sign(with: doc, using: storePassword)
            try store!.storeDid(using: doc)

            try doc.publish(using: storePassword)

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved);
            XCTAssertEqual(doc.toString(), resolved?.toString())
            XCTAssertEqual(4, resolved!.publicKeyCount)
            XCTAssertEqual(4, resolved!.authenticationKeyCount)

            // Deactivate
            try ctrl2.deactivate(with: did, using: storePassword)
            doc = try did.resolve()!
            XCTAssertTrue(try doc.isDeactivated())
        } catch {
            XCTFail()
        }
    }
    
    func testDeactivateWithAuthorization1() {
        do {
            let identity = try testData!.getRootIdentity()

            var doc = try identity.newDid(storePassword)
            XCTAssertTrue(try doc.isValid(debug))

            try doc.publish(using: storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            var target = try identity.newDid(storePassword)
            let db = try target.editing()
            _ = try db.authorizeDID(with: "#recovery", controller: doc.subject.toString())
            target = try db.seal(using: storePassword)
            XCTAssertNotNil(target)
            XCTAssertEqual(1, target.authorizationKeyCount)
            XCTAssertEqual(doc.subject, target.authorizationKeys()[0].controller)
            try store!.storeDid(using: target)

            try target.publish(using: storePassword)

            resolved = try target.subject.resolve()
            XCTAssertNotNil(resolved);
            XCTAssertEqual(target.toString(), resolved?.toString())

            try doc.deactivate(with: target.subject, using: storePassword)
            target = try target.subject.resolve()!
            XCTAssertTrue(try target.isDeactivated())

            doc = try doc.subject.resolve()!
            XCTAssertFalse(try doc.isDeactivated())
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
            doc = try db.seal(using: storePassword)
            XCTAssertTrue(try doc.isValid(debug))
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(using: storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            var target = try identity.newDid(storePassword)
            db = try target.editing()
            _ = try db.appendAuthorizationKey(with: "#recovery", controller: doc.subject.toString(),
                                      keyBase58: key.getPublicKeyBase58())
            target = try db.seal(using: storePassword)
            XCTAssertNotNil(target)
            XCTAssertEqual(1, target.authorizationKeyCount)
            XCTAssertEqual(doc.subject, target.authorizationKeys()[0].controller)
            try store!.storeDid(using: target)

            try target.publish(using: storePassword)

            resolved = try target.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(target.toString(), resolved?.toString())

            try doc.deactivate(with: target.subject, of: id, using: storePassword)
            target = try target.subject.resolve()!
            XCTAssertTrue(try target.isDeactivated())

            doc = try doc.subject.resolve()!
            XCTAssertFalse(try doc.isDeactivated())
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
            doc = try db.seal(using: storePassword)
            XCTAssertTrue(try doc.isValid(debug))
            XCTAssertEqual(2, doc.authenticationKeyCount)
            try store!.storeDid(using: doc)

            try doc.publish(using: storePassword)

            var resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            var target = try identity.newDid(storePassword)
            db = try target.editing()
            _ = try db.appendAuthorizationKey(with: "#recovery", controller: doc.subject.toString(),
                                      keyBase58: key.getPublicKeyBase58())
            target = try db.seal(using: storePassword)
            XCTAssertNotNil(target)
            XCTAssertEqual(1, target.authorizationKeyCount)
            XCTAssertEqual(doc.subject, target.authorizationKeys()[0].controller)
            try store!.storeDid(using: target)

            try target.publish(using: storePassword)

            resolved = try target.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(target.toString(), resolved?.toString())

            try doc.deactivate(with: target.subject, using: storePassword)
            target = try target.subject.resolve()!
            XCTAssertTrue(try target.isDeactivated())

            doc = try doc.subject.resolve()!
            XCTAssertFalse(try doc.isDeactivated())
        } catch {
            XCTFail()
        }
    }
}
