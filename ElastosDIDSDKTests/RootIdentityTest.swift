
import XCTest
@testable import ElastosDIDSDK

class RootIdentityTest: XCTestCase {
    var testData: TestData?
    var store: DIDStore?
    var simulatedIDChain: SimulatedIDChain = SimulatedIDChain()
    
    override func setUp() {
        testData = TestData()
        store = testData?.store!
//        try! simulatedIDChain.httpServer.start(in_port_t(DEFAULT_PORT), forceIPv4: true)
//        simulatedIDChain.start()
//        try! DIDBackend.initialize(simulatedIDChain.getAdapter());
        let adapter = SimulatedIDChainAdapter("http://localhost:\(DEFAULT_PORT)/")
        try! DIDBackend.initialize(adapter)
        testData?.reset()
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
    
    func testGenerateDid() {
        do {
            let mnemonics = [
                ["mnemonic": "movie borrow suggest tenant special evolve trial reason worth pelican bean manual", "passphrase": "secret", "AppDID": "io.trinity-tech.did.testcase", "securityCode": 619, "did": "did:elastos:iYLpo6qv9uAsnKMjhwH9wroBmgTa1wFm32"],
                ["mnemonic": "gain tag blur dress champion dream meadow tattoo elephant pudding patrol stamp", "passphrase": "secret", "AppDID": "io.trinity-tech.did.testcase", "securityCode": 619, "did": "did:elastos:iV38NKNqW7PbRqM52U5L3hd5Bax6MVk8kE"],
                ["mnemonic": "space strategy hard flock initial cigar educate piano network test lawn wagon", "passphrase": "secret", "AppDID": "io.trinity-tech.did.testcase", "securityCode": 619, "did": "did:elastos:ietb7xtNvUvHarjwqgb1iCF2LLb4aGdM6N"],
                ["mnemonic": "veteran trash trial tumble hybrid network chair drink entire inherit palace try", "passphrase": "secret", "AppDID": "io.trinity-tech.showcase", "securityCode": 12345678, "did": "did:elastos:iVUFFdf69EJw7TuaijVKVrKt8h8RmraYHx"],
                ["mnemonic": "inner pigeon field banner tide inside scout pattern arm ordinary birth again", "passphrase": "secret", "AppDID": "io.trinity-tech.showcase", "securityCode": 12345678, "did": "did:elastos:iZHETmuoU3xMWnWUDprwFWah58YVLwjr1g"],
                ["mnemonic": "air possible rubber flame actor together rifle skull cricket silver half width", "passphrase": "secret", "AppDID": "io.trinity-tech.showcase", "securityCode": 12345678, "did": "did:elastos:iinhWmnUkwyk8TGgM889gBjx1jBW1rBEev"]]
            try mnemonics.forEach { item in
                let mnemonic: String = item["mnemonic"] as! String
                let passphrase: String = item["passphrase"] as! String
                let appId: String = item["AppDID"] as! String
                let securityCode: Int = item["securityCode"] as! Int
                let did: String = item["did"] as! String
                let identity = try RootIdentity.create(mnemonic, passphrase, store!, storePassword)
                let generateDid = try identity.getDid(appId, securityCode)
                print(generateDid)
                XCTAssertEqual(did, generateDid.toString())
            }
        } catch {
            XCTFail()
        }
    }
    
    func testCreateAppDid() {
        do {
            let identity = try testData!.getRootIdentity()
            let appId = "io.trinity-tech.did.testcase"
            let appCode = 619
            let did = try identity.getDid(appId, appCode)
            var doc = try identity.newDid(appId, appCode, storePassword)
            XCTAssertTrue(try doc.isValid())
            XCTAssertEqual(did, doc.subject)
        
            XCTAssertThrowsError(_ = try identity.newDid(appId, appCode, storePassword)){ error in
                switch error {
                case DIDError.UncheckedError.IllegalStateError.DIDAlreadyExistError:
                    XCTAssertTrue(true)
                    print("error.localizedDescription ====== ", error.localizedDescription)
                    XCTAssertEqual("DID already exists in the store.", error.localizedDescription)
                    break
                default:
                    XCTFail()
                }
            }

            let success = store!.deleteDid(did)
            XCTAssertTrue(success)
            doc = try identity.newDid(appId, appCode, storePassword)
            XCTAssertTrue(try doc.isValid())
            XCTAssertEqual(did, doc.subject)
        } catch {
            XCTFail()
        }
    }

    func testInitPrivateIdentity() {
        do {
            XCTAssertFalse(try store!.containsRootIdentities())
            
            let identity = try testData!.getRootIdentity()
            XCTAssertTrue(try store!.containsRootIdentities())
            
            let store2 = try DIDStore.open(atPath: storeRoot)
            XCTAssertTrue(try store2.containsRootIdentities())
            let identity2 = try store2.loadRootIdentity()
            XCTAssertNotNil(identity2)
            
            XCTAssertEqual(try identity.preDerivedPublicKey.serializePublicKeyBase58(),
                           try identity2?.preDerivedPublicKey.serializePublicKeyBase58())
            
            let exportedMnemonic = try identity2!.exportMnemonic(storePassword)
            XCTAssertEqual(testData!.mnemonic, exportedMnemonic)
        } catch {
            XCTFail()
        }
    }
    
    func testInitPrivateIdentityWithMnemonic() {
        do {
            let expectedIDString = "iY4Ghz9tCuWvB5rNwvn4ngWvthZMNzEA7U"
            let mnemonic = "cloth always junk crash fun exist stumble shift over benefit fun toe"
            
            XCTAssertFalse(try store!.containsRootIdentities())
            
            try RootIdentity.create(mnemonic, "", store!, storePassword)
            XCTAssertTrue(try store!.containsRootIdentities())
            
            let store2 = try DIDStore.open(atPath: storeRoot)
            XCTAssertTrue(try store2.containsRootIdentities())
            
            let identity2 = try store2.loadRootIdentity()
            
            let doc = try identity2!.newDid(storePassword)
            XCTAssertNotNil(doc)
            XCTAssertEqual(expectedIDString, doc.subject.methodSpecificId)
        } catch {
            XCTFail()
        }
    }
    
    func testInitPrivateIdentityWithRootKey() {
        do {
            let expectedIDString = "iYbPqEA98rwvDyA5YT6a3mu8UZy87DLEMR"
            let rootKey = "xprv9s21ZrQH143K4biiQbUq8369meTb1R8KnstYFAKtfwk3vF8uvFd1EC2s49bMQsbdbmdJxUWRkuC48CXPutFfynYFVGnoeq8LJZhfd9QjvUt"
            
            XCTAssertFalse(try store!.containsRootIdentities())
            
            try RootIdentity.create(with: rootKey, store!, storePassword)
            XCTAssertTrue(try store!.containsRootIdentities())
            
            let store2 = try DIDStore.open(atPath: storeRoot)
            XCTAssertTrue(try store2.containsRootIdentities())
            
            let identity2 = try store2.loadRootIdentity()
            
            let doc = try identity2!.newDid(storePassword)
            XCTAssertNotNil(doc)
            XCTAssertEqual(expectedIDString, doc.subject.methodSpecificId)
        } catch {
            XCTFail()
        }
    }
    
    func testCreateDIDWithAlias() {
        do {
            let identity = try testData!.getRootIdentity()
            
            let alias = "my first did"
            
            let doc = try identity.newDid(storePassword)
            doc.getMetadata().setAlias(alias)
            XCTAssertTrue(try doc.isValid())
            
            var resolved = try doc.subject.resolve()
            XCTAssertNil(resolved)
            
            try doc.publish(using: storePassword)
            
            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            
            // test alias
            try store!.storeDid(using: resolved!)
            XCTAssertEqual(alias, resolved!.getMetadata().getAlias())
            XCTAssertEqual(doc.subject, resolved?.subject)
            XCTAssertEqual(doc.proof.signature,
                           resolved?.proof.signature)
            
            XCTAssertTrue(try resolved!.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func testCreateDIDWithoutAlias() {
        do {
            let identity = try testData!.getRootIdentity()
            
            let doc = try identity.newDid(storePassword)
            XCTAssertTrue(try doc.isValid())
            
            var resolved = try doc.subject.resolve()
            XCTAssertNil(resolved)
            
            try doc.publish(using: storePassword)
            
            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.subject, resolved!.subject)
            XCTAssertEqual(doc.proof.signature,
                           resolved!.proof.signature)
            
            XCTAssertTrue(try resolved!.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func testCreateDIDByIndex() {
        do {
            let identity = try testData!.getRootIdentity()
            
            let did = try identity.getDid(0)
            var doc = try identity.newDid(0, storePassword)
            XCTAssertTrue(try doc.isValid())
            XCTAssertEqual(did, doc.subject)
            
            XCTAssertThrowsError(_ = try identity.newDid(storePassword)){ error in
                switch error {
                case DIDError.UncheckedError.IllegalStateError.DIDAlreadyExistError:
                    XCTAssertTrue(true)// DID already exists in the store.
                    break
                default:
                    XCTFail()
                }
            }
            
            let success = store!.deleteDid(did)
            XCTAssertTrue(success)
            doc = try identity.newDid(storePassword)
            XCTAssertTrue(try doc.isValid())
            XCTAssertEqual(did, doc.subject)
        } catch {
            XCTFail()
        }
    }
    
    func testGetDid() {
        do {
            let identity = try testData!.getRootIdentity()
            
            for i in 0...100 {
                let doc = try identity.newDid(i, storePassword)
                XCTAssertTrue(try doc.isValid())
                
                let did = try identity.getDid(i)
                
                XCTAssertEqual(doc.subject, did)
            }
        } catch {
            XCTFail()
        }
    }
}
