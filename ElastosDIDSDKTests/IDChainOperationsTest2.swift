import XCTest
@testable import ElastosDIDSDK
import PromiseKit

class IDChainOperationsTest2: XCTestCase {
    static let testData: TestData = TestData()
    static var dids: [DID] = []
    var store:  DIDStore?
    var mnemonic: String = ""
    var identity: RootIdentity?
//    static var adapter: Web3Adapter?
    static var adapter: SimulatedIDChainAdapter?
    var debug = TestEventListener()

    static private var persons: [IDChainEntity] = [ ]

    private static var Alice: IDChainEntity!
    private static var Bob: IDChainEntity!
    private static var Carol: IDChainEntity!
    private static var Dave: IDChainEntity!
    private static var Erin: IDChainEntity!
    private static var Frank: IDChainEntity!
    private static var Grace: IDChainEntity!

    private static var foo1: DID!
    private static var foo2: DID!
    
    private static var bar1: DID!
    private static var bar2: DID!
    private static var bar3: DID!
    ///private static DID baz1, baz2, baz3

    private static var foo1Vc: DIDURL! /// self-proclaimed VC
    private static var foo2Vc: DIDURL!
    
    private static var bar1Vc: DIDURL! /// KYC VC
    private static var bar2Vc: DIDURL! /// KYC VC
    private static var bar3Vc: DIDURL! /// KYC VC
    
    override class func setUp() {
        print("111")
        IDChainOperationsTest2.adapter = SimulatedIDChainAdapter("http://localhost:\(DEFAULT_PORT)/")
//        IDChainOperationsTest2.adapter = Web3Adapter(rpcEndpoint, contractAddress, walletPath, walletPassword)
        try! DIDBackend.initialize(IDChainOperationsTest2.adapter!)

        IDChainOperationsTest2.Alice = IDChainEntity("Alice")
        persons.append(IDChainOperationsTest2.Alice)

        IDChainOperationsTest2.Bob = IDChainEntity("Bob")
        persons.append(IDChainOperationsTest2.Bob)

        IDChainOperationsTest2.Carol = IDChainEntity("Carol")
        persons.append(IDChainOperationsTest2.Carol)

        IDChainOperationsTest2.Dave = IDChainEntity("Dave")
        persons.append(IDChainOperationsTest2.Dave)

        IDChainOperationsTest2.Erin = IDChainEntity("Erin")
        persons.append(IDChainOperationsTest2.Erin)

        IDChainOperationsTest2.Frank = IDChainEntity("Frank")
        persons.append(IDChainOperationsTest2.Frank)

        IDChainOperationsTest2.Grace = IDChainEntity("Grace")
        persons.append(IDChainOperationsTest2.Grace)
    }
    
    override func setUp() {
        print("333")
        waitForWalletAvaliable()
    }
    
    override func tearDown() {
//        IDChainOperationsTest.testData.cleanup()
    }
    
    func waitForWalletAvaliable() {
        while true {
            Thread.sleep(forTimeInterval: 1)
            break
//            if IDChainOperationsTest2.adapter!.isAvailable() {
//                print("OK")
//                break
//            }
//            else {
//                print(".")
//            }
            Thread.sleep(forTimeInterval: 0)
        }
    }

    func test_01CreateCustomizedDid() {
        do {
            for person in IDChainOperationsTest2.persons {
                try XCTAssertNotNil(person.did?.resolve())
                
                let doc = try person.getDocument()
                let timeStamp = Date().milliStamp
                let customizedDid = try DID("did:elastos:" + person.name + "Z" + "\(timeStamp)" + "ZZ" + "\(timeStamp)")
                let customizedDoc = try doc!.newCustomizedDid(withId: customizedDid, person.storepass)
                XCTAssertNotNil(customizedDid)
                
                try customizedDoc.publish(using: person.storepass)
                waitForWalletAvaliable()
                
                let resolvedDoc = try customizedDid.resolve()
                XCTAssertNotNil(resolvedDoc)
                XCTAssertEqual(customizedDid, resolvedDoc?.subject)
                XCTAssertEqual(1, resolvedDoc?.controllerCount())
                XCTAssertEqual(person.did, resolvedDoc?.controller)
                XCTAssertEqual(customizedDoc.proof.signature,
                               resolvedDoc?.proof.signature)
                
                try XCTAssertTrue(resolvedDoc!.isValid())
                
                person.setCustomizedDid(customizedDid)
            }
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_02CreateMultisigCustomizedDid_1of2() throws {
        do {
            let timeStamp = Date().milliStamp

            let customizedDid = try DID("did:elastos:foo1" + "Z" + timeStamp)

            // Alice create initially
            let customizedDoc = try IDChainOperationsTest2.Alice.getDocument()!.newCustomizedDid(withId: customizedDid,
                                                                                                 [IDChainOperationsTest2.Bob.did!], 1, IDChainOperationsTest2.Alice.storepass)
            try XCTAssertTrue(customizedDoc.isValid())

            // Bob publishx
            try IDChainOperationsTest2.Bob.store!.storeDid(using: customizedDoc)
            try customizedDoc.setEffectiveController(IDChainOperationsTest2.Bob.did!)
            try customizedDoc.publish(using: IDChainOperationsTest2.Bob.storepass)
            waitForWalletAvaliable()

            let resolvedDoc = try customizedDid.resolve()
            XCTAssertNotNil(resolvedDoc)

            XCTAssertEqual(customizedDid, resolvedDoc?.subject)
            XCTAssertEqual(2, resolvedDoc?.controllerCount())
            XCTAssertEqual("1:2", resolvedDoc?.multiSignature?.description)
            var ctrls: [DID] = []
            ctrls.append(IDChainOperationsTest2.Alice.did!)
            ctrls.append(IDChainOperationsTest2.Bob.did!)
//            Collections.sort(ctrls)
            XCTAssertEqual(resolvedDoc?.controllerCount(), ctrls.count)
            XCTAssertEqual(customizedDoc.proof.signature,
                    resolvedDoc?.proof.signature)

            try XCTAssertTrue(resolvedDoc!.isValid())

            IDChainOperationsTest2.foo1 = customizedDid
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_03CreateMultisigCustomizedDid_2of2() {
        do {
            let timeStamp = Date().milliStamp
            let customizedDid = try DID("did:elastos:foo2" + "Z" + timeStamp)

            // Alice create initially
            var customizedDoc = try IDChainOperationsTest2.Alice.getDocument()!.newCustomizedDid(withId: customizedDid, [IDChainOperationsTest2.Bob.did!], 2, IDChainOperationsTest2.Alice.storepass)
            XCTAssertFalse(try customizedDoc.isValid())

            // Bob sign
            customizedDoc = try IDChainOperationsTest2.Bob.getDocument()!.sign(with: customizedDoc, using: IDChainOperationsTest2.Bob.storepass)
            XCTAssertTrue(try customizedDoc.isValid())

            // Bob publish
            try IDChainOperationsTest2.Bob.store!.storeDid(using: customizedDoc)
            try customizedDoc.setEffectiveController(IDChainOperationsTest2.Bob.did)
            try customizedDoc.publish(using: IDChainOperationsTest2.Bob.storepass)
            waitForWalletAvaliable()
            
            let resolvedDoc = try customizedDid.resolve()
            XCTAssertNotNil(resolvedDoc)

            XCTAssertEqual(customizedDid, resolvedDoc?.subject)
            XCTAssertEqual(2, resolvedDoc?.controllerCount())
            XCTAssertEqual("2:2", resolvedDoc?.multiSignature?.description)
            var ctrls: [DID] = []
            ctrls.append(IDChainOperationsTest2.Alice.did!)
            ctrls.append(IDChainOperationsTest2.Bob.did!)
//            Collections.sort(ctrls)
            XCTAssertEqual(resolvedDoc?.controllerCount(), ctrls.count)
            XCTAssertEqual(customizedDoc.proof.signature,
                           resolvedDoc?.proof.signature)

            XCTAssertTrue(try resolvedDoc!.isValid())

            IDChainOperationsTest2.foo2 = customizedDid
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_04CreateMultisigCustomizedDid_1of3() {
        do {
            let timeStamp = Date().milliStamp
            let customizedDid = try DID("did:elastos:bar1" + "Z" + timeStamp)

            // Alice create initially
            let customizedDoc = try IDChainOperationsTest2.Alice.getDocument()!.newCustomizedDid(withId: customizedDid, [IDChainOperationsTest2.Bob.did!, IDChainOperationsTest2.Carol.did!], 1, IDChainOperationsTest2.Alice.storepass)
            XCTAssertTrue(try customizedDoc.isValid())

            // Alice publish
            try customizedDoc.setEffectiveController(IDChainOperationsTest2.Alice.did)
            try customizedDoc.publish(using: IDChainOperationsTest2.Alice.storepass)
            waitForWalletAvaliable()
            
            let resolvedDoc = try customizedDid.resolve()
            XCTAssertNotNil(resolvedDoc)

            XCTAssertEqual(customizedDid, resolvedDoc?.subject)
            XCTAssertEqual(3, resolvedDoc?.controllerCount())
            XCTAssertEqual("1:3", resolvedDoc?.multiSignature?.description)
            var ctrls: [DID] = [ ]
            ctrls.append(IDChainOperationsTest2.Alice.did!)
            ctrls.append(IDChainOperationsTest2.Bob.did!)
            ctrls.append(IDChainOperationsTest2.Carol.did!)
//            Collections.sort(ctrls)
            XCTAssertEqual(resolvedDoc?.controllerCount(), ctrls.count)
            XCTAssertEqual(customizedDoc.proof.signature,
                    resolvedDoc?.proof.signature)

            XCTAssertTrue(try resolvedDoc!.isValid())

            IDChainOperationsTest2.bar1 = customizedDid
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_05CreateMultisigCustomizedDid_2of3() {
        do {
            let timeStamp = Date().milliStamp

            let customizedDid = try DID("did:elastos:bar2" + "Z" + timeStamp)

            // Alice create initially
            var customizedDoc = try IDChainOperationsTest2.Alice.getDocument()!.newCustomizedDid(withId: customizedDid, [IDChainOperationsTest2.Bob.did!, IDChainOperationsTest2.Carol.did!]
                                                                                                 , 2, IDChainOperationsTest2.Alice.storepass)
            XCTAssertFalse(try customizedDoc.isValid())

            // Bob sign
            customizedDoc = try IDChainOperationsTest2.Bob.getDocument()!.sign(with: customizedDoc, using: IDChainOperationsTest2.Bob.storepass)
            XCTAssertTrue(try customizedDoc.isValid())

            // Carol publish
            try IDChainOperationsTest2.Carol.store!.storeDid(using: customizedDoc)
            try customizedDoc.setEffectiveController(IDChainOperationsTest2.Carol.did)
            try customizedDoc.publish(using: IDChainOperationsTest2.Carol.storepass)
            waitForWalletAvaliable()
            
            let resolvedDoc = try customizedDid.resolve()
            XCTAssertNotNil(resolvedDoc)

            XCTAssertEqual(customizedDid, resolvedDoc?.subject)
            XCTAssertEqual(3, resolvedDoc?.controllerCount())
            XCTAssertEqual("2:3", resolvedDoc?.multiSignature?.description)
            var ctrls: [DID] = []
            ctrls.append(IDChainOperationsTest2.Alice.did!)
            ctrls.append(IDChainOperationsTest2.Bob.did!)
            ctrls.append(IDChainOperationsTest2.Carol.did!)
//            Collections.sort(ctrls)
            XCTAssertEqual(resolvedDoc?.controllerCount(), ctrls.count)
            XCTAssertEqual(customizedDoc.proof.signature,
                    resolvedDoc?.proof.signature)

            XCTAssertTrue(try resolvedDoc!.isValid())

            IDChainOperationsTest2.bar2 = customizedDid
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_06CreateMultisigCustomizedDid_3of3() {
        do {
            let timeStamp = Date().milliStamp
            let customizedDid = try DID("did:elastos:bar3" + "Z" + timeStamp)

            // Alice create initially
            var customizedDoc = try IDChainOperationsTest2.Alice.getDocument()!.newCustomizedDid(withId: customizedDid, [IDChainOperationsTest2.Bob.did!, IDChainOperationsTest2.Carol.did!]
                                                                                                 , 3, IDChainOperationsTest2.Alice.storepass)
            XCTAssertFalse(try customizedDoc.isValid())

            // Bob sign
            customizedDoc = try IDChainOperationsTest2.Bob.getDocument()!.sign(with: customizedDoc, using: IDChainOperationsTest2.Bob.storepass)
            XCTAssertFalse(try customizedDoc.isValid())

            // Bob sign
            customizedDoc = try IDChainOperationsTest2.Carol.getDocument()!.sign(with: customizedDoc, using: IDChainOperationsTest2.Carol.storepass)
            XCTAssertTrue(try customizedDoc.isValid())

            // Carol publish
            try IDChainOperationsTest2.Carol.store?.storeDid(using: customizedDoc)
            try customizedDoc.setEffectiveController(IDChainOperationsTest2.Carol.did!)
            try customizedDoc.publish(using: IDChainOperationsTest2.Carol.storepass)
            waitForWalletAvaliable()
            
            let resolvedDoc = try customizedDid.resolve()
            XCTAssertNotNil(resolvedDoc)

            XCTAssertEqual(customizedDid, resolvedDoc?.subject)
            XCTAssertEqual(3, resolvedDoc?.controllerCount())
            XCTAssertEqual("3:3", resolvedDoc?.multiSignature?.description)
            var ctrls: [DID] = [ ]
            ctrls.append(IDChainOperationsTest2.Alice.did!)
            ctrls.append(IDChainOperationsTest2.Bob.did!)
            ctrls.append(IDChainOperationsTest2.Carol.did!)
//            Collections.sort(ctrls)
            XCTAssertEqual(resolvedDoc?.controllerCount(), ctrls.count)
            XCTAssertEqual(customizedDoc.proof.signature,
                    resolvedDoc?.proof.signature)

            XCTAssertTrue(try resolvedDoc!.isValid())

            IDChainOperationsTest2.bar3 = customizedDid
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_07UpdateMultisigCustomizedDid_1of2() {
        do {
            let customizedDid = IDChainOperationsTest2.foo1
            let newKey = try TestData.generateKeypair()

            var customizedDoc = try customizedDid!.resolve()

            // Bob edit the doc
            try IDChainOperationsTest2.Bob.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Bob.did!)
            var db = try customizedDoc?.editing()

            // add a new authentication key
            let keyId = try DIDURL(customizedDid!, "#signKey")
            try db!.appendAuthenticationKey(with: keyId, keyBase58: newKey.getPublicKeyBase58())
            try IDChainOperationsTest2.Bob.store!.storePrivateKey(for: keyId, privateKey: newKey.serialize(), using: IDChainOperationsTest2.Bob.storepass)

            // add a self-proclaimed credential
            var props: [String: String] = [: ]
            props["name"] = "Foo1"
            props["gender"] = "Male"
            props["nationality"] = "Singapore"
            props["email"] = "foo1@example.com"

            db = try db!.appendCredential(with: "#profile",
                                types: ["https://ns.elastos.org/credentials/profile/v1#ProfileCredential",
                                        "https://ns.elastos.org/credentials/v1#SelfProclaimedCredential"],
                                     subject: props, using: IDChainOperationsTest2.Bob.storepass)

            customizedDoc = try db!.seal(using: IDChainOperationsTest2.Bob.storepass)
            XCTAssertTrue(try customizedDoc!.isValid())

            // Bob publish
            try IDChainOperationsTest2.Bob.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Bob.did)
            try customizedDoc!.publish(using: IDChainOperationsTest2.Bob.storepass)
            waitForWalletAvaliable()
            
            let resolvedDoc = try customizedDid!.resolve()
            XCTAssertNotNil(resolvedDoc)

            XCTAssertEqual(customizedDid, resolvedDoc?.subject)
            XCTAssertEqual(2, resolvedDoc?.controllerCount())
            XCTAssertEqual("1:2", resolvedDoc?.multiSignature?.description)
            var ctrls: [DID] = []
            ctrls.append(IDChainOperationsTest2.Alice.did!)
            ctrls.append(IDChainOperationsTest2.Bob.did!)
//            Collections.sort(ctrls)
            XCTAssertEqual(resolvedDoc?.controllerCount(), ctrls.count)
            XCTAssertEqual(customizedDoc?.proof.signature,
                    resolvedDoc?.proof.signature)

            XCTAssertTrue(try resolvedDoc!.isValid())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_08UpdateMultisigCustomizedDid_2of2() {
        do {
            let customizedDid = IDChainOperationsTest2.foo2
            let newKey = try TestData.generateKeypair()

            var customizedDoc = try customizedDid!.resolve()

            // Bob edit the doc
            try IDChainOperationsTest2.Bob.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Bob.did)
            var db = try customizedDoc?.editing()

            // add a new authentication key
            let keyId = try DIDURL(customizedDid!, "#signKey")
            try db!.appendAuthenticationKey(with: keyId, keyBase58: newKey.getPublicKeyBase58())
            try IDChainOperationsTest2.Bob.store!.storePrivateKey(for: keyId, privateKey: newKey.serialize(), using: IDChainOperationsTest2.Bob.storepass)

            // add a self-proclaimed credential
            var props: [String: String] = [: ]
            props["name"] = "Foo2"
            props["gender"] = "Male"
            props["nationality"] = "Singapore"
            props["email"] = "foo2@example.com"

            db = try db!.appendCredential(with: "#profile",
                                types: ["https://ns.elastos.org/credentials/profile/v1#ProfileCredential",
                                        "https://ns.elastos.org/credentials/v1#SelfProclaimedCredential"],
                                     subject: props, using: IDChainOperationsTest2.Bob.storepass)

            customizedDoc = try db!.seal(using: IDChainOperationsTest2.Bob.storepass)
            XCTAssertFalse(try customizedDoc!.isValid())

            // Alice sign
            customizedDoc = try IDChainOperationsTest2.Alice.getDocument()!.sign(with: customizedDoc!, using: IDChainOperationsTest2.Alice.storepass)
            XCTAssertTrue(try customizedDoc!.isValid())

            // Alice publish
            try IDChainOperationsTest2.Alice.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Alice.did)
            try customizedDoc!.publish(using: IDChainOperationsTest2.Alice.storepass)
            waitForWalletAvaliable()
            
            let resolvedDoc = try customizedDid!.resolve()
            XCTAssertNotNil(resolvedDoc)

            XCTAssertEqual(customizedDid, resolvedDoc?.subject)
            XCTAssertEqual(2, resolvedDoc?.controllerCount())
            XCTAssertEqual("2:2", resolvedDoc?.multiSignature?.description)
            var ctrls: [DID] = [ ]
            ctrls.append(IDChainOperationsTest2.Alice.did!)
            ctrls.append(IDChainOperationsTest2.Bob.did!)
//            Collections.sort(ctrls);
            XCTAssertEqual(resolvedDoc?.controllerCount(), ctrls.count)
            XCTAssertEqual(customizedDoc?.proof.signature,
                    resolvedDoc?.proof.signature)

            XCTAssertTrue(try resolvedDoc!.isValid())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_09UpdateMultisigCustomizedDid_1of3() {
        do {
            let customizedDid = IDChainOperationsTest2.bar1
            let newKey = try TestData.generateKeypair()

            var customizedDoc = try customizedDid!.resolve()

            // Carol edit the doc
            try IDChainOperationsTest2.Carol.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Carol.did)
            var db = try customizedDoc?.editing()

            // add a new authentication key
            let keyId = try DIDURL(customizedDid!, "#signKey")
            try db!.appendAuthenticationKey(with: keyId, keyBase58: newKey.getPublicKeyBase58())
            try IDChainOperationsTest2.Carol.store!.storePrivateKey(for: keyId, privateKey: newKey.serialize(), using: IDChainOperationsTest2.Carol.storepass)

            // add a self-proclaimed credential
            var props: [String: String] = [: ]
            props["name"] = "Bar1"
            props["gender"] = "Male"
            props["nationality"] = "Singapore"
            props["email"] = "bar1@example.com"

            db = try db!.appendCredential(with: "#profile",
                                types: ["https://ns.elastos.org/credentials/profile/v1#ProfileCredential",
                                        "https://ns.elastos.org/credentials/v1#SelfProclaimedCredential"],
                                     subject: props, using: IDChainOperationsTest2.Carol.storepass)

            customizedDoc = try db!.seal(using: IDChainOperationsTest2.Carol.storepass)
            XCTAssertTrue(try customizedDoc!.isValid())

            // Bob publish
            try IDChainOperationsTest2.Bob.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Bob.did)
            try customizedDoc!.publish(using: IDChainOperationsTest2.Bob.storepass)
            waitForWalletAvaliable()
            
            let resolvedDoc = try customizedDid!.resolve()
            XCTAssertNotNil(resolvedDoc)

            XCTAssertEqual(customizedDid, resolvedDoc?.subject)
            XCTAssertEqual(3, resolvedDoc?.controllerCount())
            XCTAssertEqual("1:3", resolvedDoc?.multiSignature?.description)
            var ctrls: [DID] = []
            ctrls.append(IDChainOperationsTest2.Alice.did!)
            ctrls.append(IDChainOperationsTest2.Bob.did!)
            ctrls.append(IDChainOperationsTest2.Carol.did!)
//            Collections.sort(ctrls)
            XCTAssertEqual(resolvedDoc?.controllerCount(), ctrls.count)
            XCTAssertEqual(customizedDoc?.proof.signature,
                    resolvedDoc?.proof.signature)

            XCTAssertTrue(try resolvedDoc!.isValid())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_10UpdateMultisigCustomizedDid_2of3() {
        do {
            let customizedDid = IDChainOperationsTest2.bar2
            let newKey = try TestData.generateKeypair()

            var customizedDoc = try customizedDid!.resolve()

            // Carol edit the doc
            try IDChainOperationsTest2.Carol.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Carol.did)
            var db = try customizedDoc?.editing()

            // add a new authentication key
            let keyId = try DIDURL(customizedDid!, "#signKey")
            try db!.appendAuthenticationKey(with: keyId, keyBase58: newKey.getPublicKeyBase58())
            try IDChainOperationsTest2.Carol.store!.storePrivateKey(for: keyId, privateKey: newKey.serialize(), using: IDChainOperationsTest2.Carol.storepass)

            // add a self-proclaimed credential
            var props: [String: String] = [: ]
            props["name"] = "Bar1"
            props["gender"] = "Male"
            props["nationality"] = "Singapore"
            props["email"] = "bar1@example.com"

            db = try db!.appendCredential(with: "#profile",
                                types: ["https://ns.elastos.org/credentials/profile/v1#ProfileCredential",
                                        "https://ns.elastos.org/credentials/v1#SelfProclaimedCredential"],
                                     subject: props, using: IDChainOperationsTest2.Carol.storepass)

            customizedDoc = try db!.seal(using: IDChainOperationsTest2.Carol.storepass)
            XCTAssertFalse(try customizedDoc!.isValid())

            // Alice sign
            customizedDoc = try IDChainOperationsTest2.Alice.getDocument()!.sign(with: customizedDoc!, using: IDChainOperationsTest2.Alice.storepass)
            XCTAssertTrue(try customizedDoc!.isValid())

            // Bob publish
            try IDChainOperationsTest2.Bob.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Bob.did!)
            try customizedDoc!.publish(using: IDChainOperationsTest2.Bob.storepass)
            waitForWalletAvaliable()
            
            let resolvedDoc = try customizedDid!.resolve()
            XCTAssertNotNil(resolvedDoc)

            XCTAssertEqual(customizedDid, resolvedDoc?.subject)
            XCTAssertEqual(3, resolvedDoc?.controllerCount())
            XCTAssertEqual("2:3", resolvedDoc?.multiSignature?.description)
            var ctrls: [DID] = []
            ctrls.append(IDChainOperationsTest2.Alice.did!)
            ctrls.append(IDChainOperationsTest2.Bob.did!)
            ctrls.append(IDChainOperationsTest2.Carol.did!)
//            Collections.sort(ctrls)
            XCTAssertEqual(resolvedDoc?.controllerCount(), ctrls.count)
            XCTAssertEqual(customizedDoc?.proof.signature,
                    resolvedDoc?.proof.signature)

            XCTAssertTrue(try resolvedDoc!.isValid())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_11UpdateMultisigCustomizedDid_3of3() {
        do {
            
            let customizedDid = IDChainOperationsTest2.bar3
            let newKey = try TestData.generateKeypair()
            
            var customizedDoc = try customizedDid!.resolve()
            
            // Carol edit the doc
            try IDChainOperationsTest2.Carol.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Carol.did!)
            let db = try customizedDoc?.editing()
            
            // add a new authentication key
            let keyId = try DIDURL(customizedDid!, "#signKey")
            try db!.appendAuthenticationKey(with: keyId, keyBase58: newKey.getPublicKeyBase58())
            try IDChainOperationsTest2.Carol.store!.storePrivateKey(for: keyId, privateKey: newKey.serialize(), using: IDChainOperationsTest2.Carol.storepass)
            
            // add a self-proclaimed credential
            var props: [String: String] = [: ]
            props["name"] = "Bar1"
            props["gender"] = "Male"
            props["nationality"] = "Singapore"
            props["email"] = "bar1@example.com"
            
            try db!.appendCredential(with: "#profile",
                                types: ["https://ns.elastos.org/credentials/profile/v1#ProfileCredential",
                                        "https://ns.elastos.org/credentials/v1#SelfProclaimedCredential"],
                                     subject: props, using: IDChainOperationsTest2.Carol.storepass)
            
            customizedDoc = try db!.seal(using: IDChainOperationsTest2.Carol.storepass)
            XCTAssertFalse(try customizedDoc!.isValid())
            
            // Alice sign
            customizedDoc = try IDChainOperationsTest2.Alice.getDocument()!.sign(with: customizedDoc!, using: IDChainOperationsTest2.Alice.storepass)
            XCTAssertFalse(try customizedDoc!.isValid())
            
            // Bob sign
            customizedDoc = try IDChainOperationsTest2.Bob.getDocument()!.sign(with: customizedDoc!, using: IDChainOperationsTest2.Bob.storepass)
            XCTAssertTrue(try customizedDoc!.isValid())
            
            // Bob publish
            try IDChainOperationsTest2.Bob.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Bob.did!)
            try customizedDoc!.publish(using: IDChainOperationsTest2.Bob.storepass)
            waitForWalletAvaliable()
            
            let resolvedDoc = try customizedDid!.resolve()
            XCTAssertNotNil(resolvedDoc)
            
            XCTAssertEqual(customizedDid, resolvedDoc?.subject)
            XCTAssertEqual(3, resolvedDoc?.controllerCount())
            XCTAssertEqual("3:3", resolvedDoc?.multiSignature?.description)
            var ctrls: [DID] = [ ]
            ctrls.append(IDChainOperationsTest2.Alice.did!)
            ctrls.append(IDChainOperationsTest2.Bob.did!)
            ctrls.append(IDChainOperationsTest2.Carol.did!)
//            Collections.sort(ctrls);
            XCTAssertEqual(resolvedDoc?.controllerCount(), ctrls.count)
            XCTAssertEqual(customizedDoc?.proof.signature,
                         resolvedDoc?.proof.signature)
            
            XCTAssertTrue(try resolvedDoc!.isValid())
        }
        catch {
            print(error)
            XCTFail()
        }
    }

    func test_12ChangeControllersWithUpdate_1of2() {
        do {
            
            let customizedDid = IDChainOperationsTest2.foo1
            
            var customizedDoc = try customizedDid!.resolve()
            
            // Bob edit the doc
            try IDChainOperationsTest2.Bob.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Bob.did)
            let db = try customizedDoc?.editing()
            
            // Change the controllers
            try db!.removeController(IDChainOperationsTest2.Alice.did!)
            try db!.appendController(with: IDChainOperationsTest2.Carol.did!)
            try db!.setMultiSignature(1)
            
            customizedDoc = try db!.seal(using: IDChainOperationsTest2.Bob.storepass)
            XCTAssertTrue(try customizedDoc!.isValid())
            
            // Bob publish
            try IDChainOperationsTest2.Bob.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Bob.did!)
            
            // Should failed because the controllers changed
            // Here the exception raised from the SDK
            let doc = customizedDoc
            //TODO
//            assertThrows(DIDControllersChangedException.class, () -> {
//                doc.publish(Bob.getStorePassword());
//            });
            
            // TODO: how to verify the behavior of the ID chain
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_13ChangeControllersWithUpdate_2of2() {
        do {
            let customizedDid = IDChainOperationsTest2.foo2

            var customizedDoc = try customizedDid!.resolve()

            // Bob edit the doc
            try IDChainOperationsTest2.Bob.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Bob.did!)
            let db = try customizedDoc?.editing()

            // Change the controllers
            try db!.removeController(IDChainOperationsTest2.Alice.did!)
            try db!.appendController(with: IDChainOperationsTest2.Carol.did!)
            try db!.setMultiSignature(2)

            customizedDoc = try db!.seal(using: IDChainOperationsTest2.Bob.storepass)
            XCTAssertFalse(try customizedDoc!.isValid())

            // Carol sign
            customizedDoc = try IDChainOperationsTest2.Carol.getDocument()!.sign(with: customizedDoc!, using: IDChainOperationsTest2.Carol.storepass)
            XCTAssertTrue(try customizedDoc!.isValid())

            // Carol publish
            try IDChainOperationsTest2.Carol.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Carol.did!)

            // Should failed because the controllers changed
            // Here the exception raised from the SDK
            let doc = customizedDoc
//            assertThrows(DIDControllersChangedException.class, () -> {
//                doc.publish(Carol.getStorePassword());
//            });

            // TODO: how to verify the behavior of the ID chain
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_14ChangeControllersWithUpdate_1of3() {
        do {
            let customizedDid = IDChainOperationsTest2.bar1

            var customizedDoc = try customizedDid!.resolve()

            // Alice edit the doc
            try IDChainOperationsTest2.Alice.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Alice.did)
            let db = try customizedDoc?.editing()

            // Change the controllers
            try db!.removeController(IDChainOperationsTest2.Bob.did!)
            try db!.appendController(with: IDChainOperationsTest2.Dave.did!)
            try db!.setMultiSignature(1)

            customizedDoc = try db!.seal(using: IDChainOperationsTest2.Alice.storepass)
            XCTAssertTrue(try customizedDoc!.isValid())

            // Carol publish
            try IDChainOperationsTest2.Carol.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Carol.did!)

            // Should failed because the controllers changed
            // Here the exception raised from the SDK
            let doc = customizedDoc
//            assertThrows(DIDControllersChangedException.class, () -> {
//                doc.publish(Carol.getStorePassword());
//            });

            // TODO: how to verify the behavior of the ID chain
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_15ChangeControllersWithUpdate_2of3() {
        do {
            let customizedDid = IDChainOperationsTest2.bar2

            var customizedDoc = try customizedDid!.resolve()

            // Alice edit the doc
            try IDChainOperationsTest2.Alice.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Alice.did!)
            let db = try customizedDoc?.editing()

            // Change the controllers
            try db!.removeController(IDChainOperationsTest2.Bob.did!)
            try db!.appendController(with: IDChainOperationsTest2.Dave.did!)
            try db!.setMultiSignature(2)

            customizedDoc = try db!.seal(using: IDChainOperationsTest2.Alice.storepass)
            XCTAssertFalse(try customizedDoc!.isValid())

            // Carol sign
            customizedDoc = try IDChainOperationsTest2.Carol.getDocument()!.sign(with: customizedDoc!, using: IDChainOperationsTest2.Carol.storepass)
            XCTAssertTrue(try customizedDoc!.isValid())

            // Carol publish
            try IDChainOperationsTest2.Carol.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Carol.did!)

            // Should failed because the controllers changed
            // Here the exception raised from the SDK
            let doc = customizedDoc
//            assertThrows(DIDControllersChangedException.class, () -> {
//                doc.publish(Carol.getStorePassword());
//            });

            // TODO: how to verify the behavior of the ID chain
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_16ChangeControllersWithUpdate_3of3() {
        do {
            let customizedDid = IDChainOperationsTest2.bar3

            var customizedDoc = try customizedDid!.resolve()

            // Alice edit the doc
            try IDChainOperationsTest2.Alice.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Alice.did!)
            let db = try customizedDoc?.editing()

            // Change the controllers
            try db!.removeController(IDChainOperationsTest2.Bob.did!)
            try db!.appendController(with: IDChainOperationsTest2.Dave.did!)
            try db!.setMultiSignature(3)

            customizedDoc = try db!.seal(using: IDChainOperationsTest2.Alice.storepass)
            XCTAssertFalse(try customizedDoc!.isValid())

            // Carol sign
            customizedDoc = try IDChainOperationsTest2.Carol.getDocument()!.sign(with: customizedDoc!, using: IDChainOperationsTest2.Carol.storepass)
            XCTAssertFalse(try customizedDoc!.isValid())

            // Dave sign
            customizedDoc = try IDChainOperationsTest2.Dave.getDocument()!.sign(with: customizedDoc!, using: IDChainOperationsTest2.Dave.storepass)
            XCTAssertTrue(try customizedDoc!.isValid())

            // Dave publish
            try IDChainOperationsTest2.Dave.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Dave.did!)

            // Should failed because the controllers changed
            // Here the exception raised from the SDK
            let doc = customizedDoc
//            assertThrows(DIDControllersChangedException.class, () -> {
//                doc.publish(Carol.getStorePassword());
//            });

            // TODO: how to verify the behavior of the ID chain
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_17TransferCustomizedDid_1to1() {
        do {
            // Alice create a customized did: baz1
            var doc = try IDChainOperationsTest2.Alice.getDocument()
            let timeStamp = Date().milliStamp

            let customizedDid = try DID("did:elastos:baz1" + "Z" + timeStamp)
            var customizedDoc = try doc!.newCustomizedDid(withId: customizedDid, IDChainOperationsTest2.Alice.storepass)
            XCTAssertNotNil(customizedDoc)

            try customizedDoc.publish(using: IDChainOperationsTest2.Alice.storepass)
            waitForWalletAvaliable()
            
            var resolvedDoc = try customizedDid.resolve()
            XCTAssertNotNil(resolvedDoc)
            XCTAssertEqual(customizedDid, resolvedDoc?.subject)
            XCTAssertEqual(1, resolvedDoc?.controllerCount())
            XCTAssertEqual(IDChainOperationsTest2.Alice.did, resolvedDoc?.controller)
            XCTAssertEqual(customizedDoc.proof.signature,
                    resolvedDoc?.proof.signature)

            XCTAssertTrue(try resolvedDoc!.isValid())

            // Alice prepare to transfer to Bob
            try customizedDoc.setEffectiveController(IDChainOperationsTest2.Alice.did!)
            let ticket = try customizedDoc.createTransferTicket(to: IDChainOperationsTest2.Bob.did!, using: IDChainOperationsTest2.Alice.storepass)

            // Bob create the new document
            doc = try IDChainOperationsTest2.Bob.getDocument()

            customizedDoc = try doc!.newCustomizedDid(withId: customizedDid, true, IDChainOperationsTest2.Bob.storepass)
            XCTAssertNotNil(customizedDoc)

            // Bob publish the DID and take the ownership
            try customizedDoc.publish(with: ticket, using: IDChainOperationsTest2.Bob.storepass)

            resolvedDoc = try customizedDid.resolve()
            XCTAssertNotNil(resolvedDoc)
            XCTAssertEqual(customizedDid, resolvedDoc?.subject)
            XCTAssertEqual(1, resolvedDoc?.controllerCount())
            XCTAssertEqual(IDChainOperationsTest2.Bob.did, resolvedDoc?.controller)
            XCTAssertEqual(customizedDoc.proof.signature,
                    resolvedDoc?.proof.signature)

            XCTAssertTrue(try resolvedDoc!.isValid())

            // baz1 = customizedDid;
        }
        catch {
            print(error)
            XCTFail()
        }
    }

func test_18TransferCustomizedDid_1to2() {
    do {
        // Alice create a customized did: baz2
        var doc = try IDChainOperationsTest2.Alice.getDocument()
        let timeStamp = Date().milliStamp

        let customizedDid = try DID("did:elastos:baz2" + "Z" + timeStamp)
        var customizedDoc = try doc!.newCustomizedDid(withId: customizedDid, IDChainOperationsTest2.Alice.storepass)
        XCTAssertNotNil(customizedDoc)

        try customizedDoc.publish(using: IDChainOperationsTest2.Alice.storepass)
        waitForWalletAvaliable()
        
        var resolvedDoc = try customizedDid.resolve()
        XCTAssertNotNil(resolvedDoc)
        XCTAssertEqual(customizedDid, resolvedDoc?.subject)
        XCTAssertEqual(1, resolvedDoc?.controllerCount())
        XCTAssertEqual(IDChainOperationsTest2.Alice.did, resolvedDoc?.controller)
        XCTAssertEqual(customizedDoc.proof.signature,
                resolvedDoc?.proof.signature)

        XCTAssertTrue(try resolvedDoc!.isValid())

        // Alice prepare to transfer to Bob, Carol...
        try customizedDoc.setEffectiveController(IDChainOperationsTest2.Alice.did)
        let ticket = try customizedDoc.createTransferTicket(to: IDChainOperationsTest2.Bob.did!, using: IDChainOperationsTest2.Alice.storepass)

        // Bob create the new document
        doc = try IDChainOperationsTest2.Bob.getDocument()

        customizedDoc = try doc!.newCustomizedDid(withId: customizedDid,
                                                  [IDChainOperationsTest2.Bob.did!, IDChainOperationsTest2.Carol.did!], 1,
                                                  true, IDChainOperationsTest2.Bob.storepass)
        XCTAssertNotNil(customizedDoc)

        // Bob publish the DID and take the ownership
        try customizedDoc.publish(with: ticket, using: IDChainOperationsTest2.Bob.storepass)

        resolvedDoc = try customizedDid.resolve()
        XCTAssertNotNil(resolvedDoc)
        XCTAssertEqual(customizedDid, resolvedDoc?.subject)
        XCTAssertEqual(2, resolvedDoc?.controllerCount())
        XCTAssertEqual("1:2", resolvedDoc?.multiSignature?.description)
        var ctrls: [ DID ] = []
        ctrls.append(IDChainOperationsTest2.Bob.did!)
        ctrls.append(IDChainOperationsTest2.Carol.did!)
//        Collections.sort(ctrls)
        XCTAssertEqual(resolvedDoc?.controllerCount(), ctrls.count)
        XCTAssertEqual(customizedDoc.proof.signature,
                resolvedDoc?.proof.signature)

        XCTAssertTrue(try resolvedDoc!.isValid())

        // baz2 = customizedDid;
    }
    catch {
        print(error)
        XCTFail()
    }
}
    func test_19TransferCustomizedDid_1to3_WithoutRequiredSig() {
        do {
            // Alice create a customized did: baz3
            var doc = try IDChainOperationsTest2.Alice.getDocument()
            let timeStamp = Date().milliStamp

            let customizedDid = try DID("did:elastos:baz3" + "Z" + timeStamp)
            var customizedDoc = try doc!.newCustomizedDid(withId: customizedDid, IDChainOperationsTest2.Alice.storepass)
            XCTAssertNotNil(customizedDoc)

            try customizedDoc.publish(using: IDChainOperationsTest2.Alice.storepass)
            waitForWalletAvaliable()
            
            let resolvedDoc = try customizedDid.resolve()
            XCTAssertNotNil(resolvedDoc)
            XCTAssertEqual(customizedDid, resolvedDoc?.subject)
            XCTAssertEqual(1, resolvedDoc?.controllerCount())
            XCTAssertEqual(IDChainOperationsTest2.Alice.did, resolvedDoc?.controller)
            XCTAssertEqual(customizedDoc.proof.signature,
                           resolvedDoc?.proof.signature)

            XCTAssertTrue(try resolvedDoc!.isValid())

            // Alice prepare to transfer to Bob, Carol...
            try customizedDoc.setEffectiveController(IDChainOperationsTest2.Alice.did)
            let ticket = try customizedDoc.createTransferTicket(to: IDChainOperationsTest2.Bob.did!, using: IDChainOperationsTest2.Alice.storepass)

            // Carol create the new document
            doc = try IDChainOperationsTest2.Carol.getDocument()

            customizedDoc = try doc!.newCustomizedDid(withId: customizedDid,
                                                      [IDChainOperationsTest2.Bob.did!, IDChainOperationsTest2.Carol.did!, IDChainOperationsTest2.Dave.did!], 2,
                                                      true, IDChainOperationsTest2.Carol.storepass)
            XCTAssertNotNil(customizedDoc)
            XCTAssertFalse(try customizedDoc.isValid())

            // Dave sign
            customizedDoc = try IDChainOperationsTest2.Dave.getDocument()!.sign(with: customizedDoc, using: IDChainOperationsTest2.Dave.storepass)
            XCTAssertTrue(try customizedDoc.isValid())

            // Dave publish the DID and take the ownership
            try IDChainOperationsTest2.Dave.store!.storeDid(using: customizedDoc)
            try customizedDoc.setEffectiveController(IDChainOperationsTest2.Dave.did)

            // Should failed because of missing Bob's signature
            // Here the exception raised from the SDK
            let d = customizedDoc
//            Exception e = assertThrows(IllegalArgumentException.class, () -> {
//                d.publish(ticket, Dave.getStorePassword());
//            });
//            XCTAssertEqual("Document not signed by: " + Bob.did!, e.getMessage());

            // TODO: how to verify the behavior of the ID chain

            // baz3 = customizedDid;
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_20TransferCustomizedDid_2to1() {
        do {
            let customizedDid = IDChainOperationsTest2.foo1
            var customizedDoc = try customizedDid!.resolve()
            XCTAssertNotNil(customizedDoc)

            // Bob prepare to transfer to Carol
            try IDChainOperationsTest2.Bob.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Bob.did)
            let ticket = try customizedDoc!.createTransferTicket(to: IDChainOperationsTest2.Carol.did!, using: IDChainOperationsTest2.Bob.storepass)

            // Carol create the new document
            let doc = try IDChainOperationsTest2.Carol.getDocument()

            customizedDoc = try doc!.newCustomizedDid(withId: customizedDid!, true, IDChainOperationsTest2.Carol.storepass)
            XCTAssertTrue(try customizedDoc!.isValid())

            // Carol publish the DID and take the ownership
            try customizedDoc!.publish(with: ticket, using: IDChainOperationsTest2.Carol.storepass)

            let resolvedDoc = try customizedDid!.resolve()
            XCTAssertNotNil(resolvedDoc)
            XCTAssertEqual(customizedDid, resolvedDoc?.subject)
            XCTAssertEqual(1, resolvedDoc?.controllerCount())
            XCTAssertEqual(IDChainOperationsTest2.Carol.did, resolvedDoc?.controller)
            XCTAssertEqual(customizedDoc?.proof.signature,
                    resolvedDoc?.proof.signature)

            XCTAssertTrue(try resolvedDoc!.isValid())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_21TransferCustomizedDid_2to2() {
        do {
            let customizedDid = IDChainOperationsTest2.foo2
            var customizedDoc = try customizedDid!.resolve()
            XCTAssertNotNil(customizedDoc)

            // Alice prepare to transfer to Carol
            try IDChainOperationsTest2.Alice.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Alice.did)
            var ticket = try customizedDoc!.createTransferTicket(to: IDChainOperationsTest2.Carol.did!, using: IDChainOperationsTest2.Alice.storepass)
            XCTAssertFalse(try ticket.isValid())

            // Bob sign the ticket
            ticket = try IDChainOperationsTest2.Bob.getDocument()!.sign(with: ticket, using: IDChainOperationsTest2.Bob.storepass)
            XCTAssertTrue(try ticket.isValid())

            // Carol create the new document
            let doc = try IDChainOperationsTest2.Carol.getDocument()

            customizedDoc = try doc!.newCustomizedDid(withId: customizedDid!,
                                                      [IDChainOperationsTest2.Carol.did!, IDChainOperationsTest2.Dave.did!],
                                                      2, true, IDChainOperationsTest2.Carol.storepass)
            XCTAssertFalse(try customizedDoc!.isValid())

            // Dave sign the doc
            customizedDoc = try IDChainOperationsTest2.Dave.getDocument()!.sign(with: customizedDoc!, using: IDChainOperationsTest2.Dave.storepass)
            XCTAssertTrue(try customizedDoc!.isValid())

            // Dave publish the DID
            try IDChainOperationsTest2.Dave.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Dave.did!)
            try customizedDoc!.publish(with: ticket, using: IDChainOperationsTest2.Dave.storepass)

            let resolvedDoc = try customizedDid!.resolve()
            XCTAssertNotNil(resolvedDoc);
            XCTAssertEqual(customizedDid, resolvedDoc?.subject)
            XCTAssertEqual(2, resolvedDoc?.controllerCount())
            XCTAssertEqual("2:2", resolvedDoc?.multiSignature?.description)
            var ctrls: [DID] = []
            ctrls.append(IDChainOperationsTest2.Carol.did!)
            ctrls.append(IDChainOperationsTest2.Dave.did!)
//            Collections.sort(ctrls)
            XCTAssertEqual(resolvedDoc?.controllerCount(), ctrls.count)
            XCTAssertEqual(customizedDoc?.proof.signature,
                    resolvedDoc?.proof.signature)

            XCTAssertTrue(try resolvedDoc!.isValid())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_22TransferCustomizedDid_3to1() {
        do {
            let customizedDid = IDChainOperationsTest2.bar1
            var customizedDoc = try customizedDid!.resolve()
            XCTAssertNotNil(customizedDoc)

            // Carol prepare to transfer to Dave
            try IDChainOperationsTest2.Carol.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Carol.did)
            let ticket = try customizedDoc!.createTransferTicket(to: IDChainOperationsTest2.Dave.did!, using: IDChainOperationsTest2.Carol.storepass)

            // Dave create the new document
            let doc = try IDChainOperationsTest2.Dave.getDocument()

            customizedDoc = try doc!.newCustomizedDid(withId: customizedDid!, true, IDChainOperationsTest2.Dave.storepass)
            XCTAssertTrue(try customizedDoc!.isValid())

            // Dave publish the DID and take the ownership
            try customizedDoc!.publish(with: ticket, using: IDChainOperationsTest2.Dave.storepass)

            let resolvedDoc = try customizedDid!.resolve()
            XCTAssertNotNil(resolvedDoc)
            XCTAssertEqual(customizedDid, resolvedDoc?.subject)
            XCTAssertEqual(1, resolvedDoc?.controllerCount())
            XCTAssertEqual(IDChainOperationsTest2.Dave.did, resolvedDoc?.controller)
            XCTAssertEqual(customizedDoc?.proof.signature,
                    resolvedDoc?.proof.signature)

            XCTAssertTrue(try resolvedDoc!.isValid())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_23TransferCustomizedDid_3to2() {
        do {
            let customizedDid = IDChainOperationsTest2.bar2
            var customizedDoc = try customizedDid!.resolve()
            XCTAssertNotNil(customizedDoc)

            // Alice prepare to transfer to Dave
            try IDChainOperationsTest2.Alice.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Alice.did)
            var ticket = try customizedDoc!.createTransferTicket(to: IDChainOperationsTest2.Dave.did!, using: IDChainOperationsTest2.Alice.storepass)
            XCTAssertFalse(try ticket.isValid())

            // Carol sign the ticket
            ticket = try IDChainOperationsTest2.Carol.getDocument()!.sign(with: ticket, using: IDChainOperationsTest2.Carol.storepass)
            XCTAssertTrue(try ticket.isValid())

            // Dave create the new document
            let doc = try IDChainOperationsTest2.Dave.getDocument()

            customizedDoc = try doc!.newCustomizedDid(withId: customizedDid!,
                                                      [IDChainOperationsTest2.Dave.did!, IDChainOperationsTest2.Erin.did!],
                                                      2, true, IDChainOperationsTest2.Dave.storepass)
            XCTAssertFalse(try customizedDoc!.isValid())

            // Erin sign the doc
            customizedDoc = try IDChainOperationsTest2.Erin.getDocument()!.sign(with: customizedDoc!, using: IDChainOperationsTest2.Erin.storepass)
            XCTAssertTrue(try customizedDoc!.isValid())

            // Erin publish the DID
            try IDChainOperationsTest2.Erin.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Erin.did)
            try customizedDoc!.publish(with: ticket, using: IDChainOperationsTest2.Erin.storepass)

            let resolvedDoc = try customizedDid!.resolve()
            XCTAssertNotNil(resolvedDoc)
            XCTAssertEqual(customizedDid, resolvedDoc?.subject)
            XCTAssertEqual(2, resolvedDoc?.controllerCount())
            XCTAssertEqual("2:2", resolvedDoc?.multiSignature?.description)
            var ctrls: [DID] = []
            ctrls.append(IDChainOperationsTest2.Erin.did!)
            ctrls.append(IDChainOperationsTest2.Dave.did!)
//            Collections.sort(ctrls)
            XCTAssertEqual(resolvedDoc?.controllerCount(), ctrls.count)
            XCTAssertEqual(customizedDoc?.proof.signature,
                    resolvedDoc?.proof.signature)

            XCTAssertTrue(try resolvedDoc!.isValid())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_24TransferCustomizedDid_3to3() {
        do {
            let customizedDid = IDChainOperationsTest2.bar3
            var customizedDoc = try customizedDid!.resolve()
            XCTAssertNotNil(customizedDoc)

            // Alice prepare to transfer to Dave
            try IDChainOperationsTest2.Alice.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Alice.did)
            var ticket = try customizedDoc!.createTransferTicket(to: IDChainOperationsTest2.Dave.did!, using: IDChainOperationsTest2.Alice.storepass)
            XCTAssertFalse(try ticket.isValid())

            // Bob sign the ticket
            ticket = try IDChainOperationsTest2.Bob.getDocument()!.sign(with: ticket, using: IDChainOperationsTest2.Bob.storepass)
            XCTAssertFalse(try ticket.isValid())

            // Carol sign the ticket
            ticket = try IDChainOperationsTest2.Carol.getDocument()!.sign(with: ticket, using: IDChainOperationsTest2.Carol.storepass)
            XCTAssertTrue(try ticket.isValid())

            // Erin create the new document
            let doc = try IDChainOperationsTest2.Erin.getDocument()

            customizedDoc = try doc!.newCustomizedDid(withId: customizedDid!,
                                                      [ IDChainOperationsTest2.Dave.did!, IDChainOperationsTest2.Erin.did!, IDChainOperationsTest2.Frank.did! ],
                                                      2, true, IDChainOperationsTest2.Erin.storepass)
            XCTAssertFalse(try customizedDoc!.isValid())

            // Dave sign the doc
            customizedDoc = try IDChainOperationsTest2.Dave.getDocument()!.sign(with: customizedDoc!, using: IDChainOperationsTest2.Dave.storepass)
            XCTAssertTrue(try customizedDoc!.isValid())

            // Frank publish the DID
            try IDChainOperationsTest2.Frank.store!.storeDid(using: customizedDoc!)
            try customizedDoc!.setEffectiveController(IDChainOperationsTest2.Frank.did!)
            try customizedDoc!.publish(with: ticket, using: IDChainOperationsTest2.Frank.storepass)
            waitForWalletAvaliable()
            
            let resolvedDoc = try customizedDid!.resolve()
            XCTAssertNotNil(resolvedDoc)
            XCTAssertEqual(customizedDid, resolvedDoc?.subject)
            XCTAssertEqual(3, resolvedDoc?.controllerCount())
            XCTAssertEqual("2:3", resolvedDoc?.multiSignature?.description)
            var ctrls: [DID] = []
            ctrls.append(IDChainOperationsTest2.Dave.did!)
            ctrls.append(IDChainOperationsTest2.Erin.did!)
            ctrls.append(IDChainOperationsTest2.Frank.did!)
//            Collections.sort(ctrls)
            XCTAssertEqual(resolvedDoc?.controllerCount(), ctrls.count)
            XCTAssertEqual(customizedDoc?.proof.signature,
                    resolvedDoc?.proof.signature)

            XCTAssertTrue(try resolvedDoc!.isValid())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_25_100DeclareSelfProclaimedCredential() {
        do {
            
            for person in IDChainOperationsTest2.persons {
                
                let timeStamp = Date().milliStamp

                let doc = try person.getDocument()

                // add a self-proclaimed credential
                var props: [String: String] = [: ]
                props["name"] = person.name
                props["gender"] = "Male"
                props["nationality"] = "Singapore"
                props["email"] = person.name + "@example.com"

                let id = try DIDURL(doc!.subject, "#profile" + timeStamp)

                var vc = try VerifiableCredential.resolve(id)
                XCTAssertNil(vc)

                let cb = try VerifiableCredentialIssuer(doc!).editingVerifiableCredentialFor(did: doc!.subject)
                vc = try cb.withId(id)
                    .withType("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
                    .withType("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
                    .withProperties(props)
                    .seal(using: person.storepass)

                try person.store!.storeCredential(using: vc!)
                try vc!.declare(person.storepass)
                let vcs = try VerifiableCredential.list(IDChainOperationsTest2.Alice.did!)
                print(vcs)
                waitForWalletAvaliable()
                
                let resolvedVc = try VerifiableCredential.resolve(id)
                XCTAssertNotNil(resolvedVc)
                XCTAssertEqual(id, resolvedVc?.id)
                let types = resolvedVc!.getTypes
                XCTAssertTrue(resolvedVc!.getTypes().contains("ProfileCredential"))
                XCTAssertTrue(resolvedVc!.getTypes().contains("SelfProclaimedCredential"))
                XCTAssertEqual(doc?.subject, resolvedVc?.subject?.did)
                XCTAssertEqual(vc?.proof?.signature,
                        resolvedVc?.proof?.signature)

                XCTAssertTrue(try resolvedVc!.isValid())

                try person.addSelfProclaimedCredential(vc!.getId()!)
            }
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_26_101DeclareSelfProclaimedCredentialForCid() {
        do {
            for person in IDChainOperationsTest2.persons {
                let doc = try person.getCustomizedDocument()
                let timeStamp = Date().milliStamp

                // add a self-proclaimed credential
                var props: [String: String] = [: ]
                props["name"] = person.name
                props["gender"] = "Male"
                props["nationality"] = "Singapore"
                props["email"] = person.name + "@example.com"

                let id = try DIDURL(doc!.subject, "#profile-" + timeStamp)

                var vc = try VerifiableCredential.resolve(id)
                XCTAssertNil(vc)

                let cb = try VerifiableCredentialIssuer(doc!).editingVerifiableCredentialFor(did: doc!.subject)
                vc = try cb.withId(id)
                    .withType("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
                    .withType("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
                    .withProperties(props)
                    .seal(using: person.storepass)

                try person.store!.storeCredential(using: vc!)
                try vc!.declare(person.storepass)
                waitForWalletAvaliable()
                
                let resolvedVc = try VerifiableCredential.resolve(id)
                XCTAssertNotNil(resolvedVc)
                XCTAssertEqual(id, resolvedVc!.getId())
                XCTAssertTrue(resolvedVc!.getTypes().contains("ProfileCredential"))
                XCTAssertTrue(resolvedVc!.getTypes().contains("SelfProclaimedCredential"))
                XCTAssertEqual(doc?.subject, resolvedVc?.subject?.did)
                XCTAssertEqual(vc?.proof?.signature,
                        resolvedVc?.proof?.signature)

                XCTAssertTrue(try resolvedVc!.isValid())

                try person.addSelfProclaimedCredential(vc!.getId()!)
            }
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_27_102DeclareSelfProclaimedCredentialForFoo1() {
        do {
            let doc = try IDChainOperationsTest2.foo1.resolve()
            try IDChainOperationsTest2.Carol.store!.storeDid(using: doc!)
            try doc!.setEffectiveController(IDChainOperationsTest2.Carol.did)

            // add a self-proclaimed credential
            var props: [String: String] = [: ]
            props["name"] = "Foo1"
            props["gender"] = "Male"
            props["nationality"] = "Singapore"
            props["email"] = "foo1@example.com"

            // VC for the normal DID
            let timeStamp = Date().milliStamp
            let id = try DIDURL(doc!.subject, "#profile-" + timeStamp)
            let cb =  try VerifiableCredentialIssuer(doc!).editingVerifiableCredentialFor(did: doc!.subject)
            let vc = try cb.withId(id)
                .withType("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
                .withType("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
                .withProperties(props)
                .seal(using: IDChainOperationsTest2.Carol.storepass)

            try IDChainOperationsTest2.Carol.store!.storeCredential(using: vc)
            try vc.declare(IDChainOperationsTest2.Carol.storepass)
            waitForWalletAvaliable()
            
            let resolvedVc = try VerifiableCredential.resolve(id)
            XCTAssertNotNil(resolvedVc)
            XCTAssertEqual(id, resolvedVc?.id)
            XCTAssertTrue(resolvedVc!.getTypes().contains("ProfileCredential"));
            XCTAssertTrue(resolvedVc!.getTypes().contains("SelfProclaimedCredential"));
            XCTAssertEqual(doc?.subject, resolvedVc?.subject?.did)
            XCTAssertEqual(vc.proof?.signature,
                    resolvedVc?.proof?.signature)

            XCTAssertTrue(try resolvedVc!.isValid())

            IDChainOperationsTest2.foo1Vc = vc.getId()!
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_28_103DeclareSelfProclaimedCredentialForFoo2() {
        do {
            let doc = try IDChainOperationsTest2.foo2.resolve()
            try IDChainOperationsTest2.Dave.store!.storeDid(using: doc!)
            try doc!.setEffectiveController(IDChainOperationsTest2.Dave.did)

            // add a self-proclaimed credential
            var props: [String: String] = [: ]
            props["name"] = "Foo2"
            props["gender"] = "Male"
            props["nationality"] = "Singapore"
            props["email"] = "foo2@example.com"

            // VC for the normal DID
            let timeStamp = Date().milliStamp
            let id = try DIDURL(doc!.subject, "#profile-" + timeStamp)
            let cb =  try VerifiableCredentialIssuer(doc!).editingVerifiableCredentialFor(did: doc!.subject)
            let vc = try cb.withId(id)
                .withType("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
                .withType("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
                .withProperties(props)
                .seal(using: IDChainOperationsTest2.Dave.storepass)

            try IDChainOperationsTest2.Dave.store!.storeCredential(using: vc)
            try vc.declare(IDChainOperationsTest2.Dave.storepass)
            waitForWalletAvaliable()
            
            let resolvedVc = try VerifiableCredential.resolve(id)
            XCTAssertNotNil(resolvedVc)
            XCTAssertEqual(id, resolvedVc!.getId())
            XCTAssertTrue(resolvedVc!.getTypes().contains("ProfileCredential"));
            XCTAssertTrue(resolvedVc!.getTypes().contains("SelfProclaimedCredential"));
            XCTAssertEqual(doc?.subject, resolvedVc?.subject?.did)
            XCTAssertEqual(vc.proof?.signature,
                    resolvedVc?.proof?.signature)

            XCTAssertTrue(try resolvedVc!.isValid())

            IDChainOperationsTest2.foo2Vc = vc.id!
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_29_104DeclareKycCredential_p2p() {
        do {
            let issuer = try VerifiableCredentialIssuer(IDChainOperationsTest2.Grace.getDocument()!)

            for person in IDChainOperationsTest2.persons {
                // add a KYC credential
                var props: [String: String] = [: ]
                props["name"] = person.name
                props["gender"] = "Male"
                props["nationality"] = "Singapore"
                props["email"] = person.name + "@example.com"
                let timeStamp = Date().milliStamp

                let id = try DIDURL(person.did!, "#profile-" + timeStamp)
                let cb = try issuer.editingVerifiableCredentialFor(did: person.did!)
                let vc = try cb.withId(id)
                    .withType("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
                    .withType("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
                    .withProperties(props)
                    .seal(using: IDChainOperationsTest2.Grace.storepass)

                try person.store!.storeCredential(using: vc)
                try vc.declare(person.storepass)
                let vcs = try VerifiableCredential.list(IDChainOperationsTest2.Alice.did!)
                print(vcs)
                waitForWalletAvaliable()
                
                let resolvedVc = try VerifiableCredential.resolve(id)
                XCTAssertNotNil(resolvedVc)
                XCTAssertEqual(id, resolvedVc?.id)
                XCTAssertTrue(resolvedVc!.getTypes().contains("ProfileCredential"));
                XCTAssertTrue(resolvedVc!.getType().contains("SelfProclaimedCredential"));
                XCTAssertEqual(person.did, resolvedVc!.subject?.did)
                XCTAssertEqual(IDChainOperationsTest2.Grace.did, resolvedVc!.issuer)
                XCTAssertEqual(vc.proof?.signature,
                        resolvedVc?.proof?.signature)

                XCTAssertTrue(try resolvedVc!.isValid())

                try person.addKycCredential(vc.getId()!)
            }
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    
    func test_30_105DeclareKycCredential_p2c() {
        do {
            let issuer = try VerifiableCredentialIssuer(IDChainOperationsTest2.Grace.getDocument()!)

            for person in IDChainOperationsTest2.persons {
                // add a KYC credential
                var props: [String: String] = [: ]
                props["name"] = person.name
                props["gender"] = "Male"
                props["nationality"] = "Singapore"
                props["email"] = person.name + "@example.com"
                let timeStamp = Date().milliStamp

                let id = try DIDURL(person.customizedDid!, "#profile-" + timeStamp)
                let cb = try issuer.editingVerifiableCredentialFor(did: person.customizedDid!)
                let vc = try cb.withId(id)
                    .withType("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
                    .withType("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
                    .withProperties(props)
                    .seal(using: IDChainOperationsTest2.Grace.storepass)

                try person.store!.storeCredential(using: vc)
                try vc.declare(person.storepass)
                waitForWalletAvaliable()
                
                let resolvedVc = try VerifiableCredential.resolve(id)
                XCTAssertNotNil(resolvedVc)
                XCTAssertEqual(id, resolvedVc!.getId())
                XCTAssertTrue(resolvedVc!.getType().contains("ProfileCredential"))
                XCTAssertTrue(resolvedVc!.getType().contains("SelfProclaimedCredential"))
                XCTAssertEqual(person.customizedDid, resolvedVc?.subject?.did)
                XCTAssertEqual(IDChainOperationsTest2.Grace.did, resolvedVc?.issuer)
                XCTAssertEqual(vc.proof?.signature,
                        resolvedVc?.proof?.signature)

                XCTAssertTrue(try resolvedVc!.isValid())

                try person.addKycCredential(vc.id!)
            }
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_31_106DeclareKycCredential_c2p() {
        do {
            let issuer = try VerifiableCredentialIssuer(IDChainOperationsTest2.Grace.getCustomizedDocument()!)

            for person in IDChainOperationsTest2.persons {
                // add a KYC credential
                var props: [String: String] = [: ]
                props["name"] = person.name
                props["gender"] = "Male"
                props["nationality"] = "Singapore"
                props["email"] = person.name + "@example.com"
                let timeStamp = Date().milliStamp

                let id = try DIDURL(person.did!, "#profile-" + timeStamp)
                let cb = try issuer.editingVerifiableCredentialFor(did: person.did!)
                let vc = try cb.withId(id)
                    .withType("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
                    .withType("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
                    .withProperties(props)
                    .seal(using: IDChainOperationsTest2.Grace.storepass)

                try person.store!.storeCredential(using: vc)
                try vc.declare(person.storepass)
                waitForWalletAvaliable()
                
                let resolvedVc = try VerifiableCredential.resolve(id)
                XCTAssertNotNil(resolvedVc)
                XCTAssertEqual(id, resolvedVc!.getId())
                XCTAssertTrue(resolvedVc!.getTypes().contains("ProfileCredential"));
                XCTAssertTrue(resolvedVc!.getTypes().contains("SelfProclaimedCredential"));
                XCTAssertEqual(person.did, resolvedVc?.subject?.did)
                XCTAssertEqual(IDChainOperationsTest2.Grace.customizedDid, resolvedVc?.issuer)
                XCTAssertEqual(vc.proof?.signature,
                        resolvedVc?.proof?.signature)

                XCTAssertTrue(try resolvedVc!.isValid())

                try person.addKycCredential(vc.id!)
            }
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_32_107DeclareKycCredential_c2c() {
        do {
            let issuer = try VerifiableCredentialIssuer(IDChainOperationsTest2.Grace.getCustomizedDocument()!)

            for person in IDChainOperationsTest2.persons {
                // add a KYC credential
                var props: [String: String] = [: ]
                props["name"] = person.name
                props["gender"] = "Male"
                props["nationality"] = "Singapore"
                props["email"] = person.name + "@example.com"
                let timeStamp = Date().milliStamp

                let id = try DIDURL(person.customizedDid!, "#profile-" + timeStamp)
                let cb = try issuer.editingVerifiableCredentialFor(did: person.customizedDid!)
                let vc = try cb.withId(id)
                    .withType("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
                    .withType("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
                    .withProperties(props)
                    .seal(using: IDChainOperationsTest2.Grace.storepass)

                try person.store!.storeCredential(using: vc)
                try vc.declare(person.storepass)
                waitForWalletAvaliable()
                
                let resolvedVc = try VerifiableCredential.resolve(id)
                XCTAssertNotNil(resolvedVc)
                XCTAssertEqual(id, resolvedVc?.id)
                XCTAssertTrue(resolvedVc!.getTypes().contains("ProfileCredential"))
                XCTAssertTrue(resolvedVc!.getTypes().contains("SelfProclaimedCredential"))
                XCTAssertEqual(person.customizedDid, resolvedVc?.subject?.did)
                XCTAssertEqual(IDChainOperationsTest2.Grace.customizedDid, resolvedVc?.issuer)
                XCTAssertEqual(vc.proof?.signature,
                        resolvedVc?.proof?.signature)

                XCTAssertTrue(try resolvedVc!.isValid())

                try person.addKycCredential(vc.getId()!)
            }
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_33_108DeclareKycCredentialForBar1_p() {
        do {
            let issuer = try VerifiableCredentialIssuer(IDChainOperationsTest2.Grace.getDocument()!)

            // add a KYC credential
            var props: [String: String] = [: ]
            props["name"] = "Bar1"
            props["gender"] = "Male"
            props["nationality"] = "Singapore"
            props["email"] = "bar2@example.com"

            // VC for the normal DID
            let timeStamp = Date().milliStamp
            let id = try DIDURL(IDChainOperationsTest2.bar1, "#profile-" + timeStamp)
            let cb = try issuer.editingVerifiableCredentialFor(did: IDChainOperationsTest2.bar1)
            let vc = try cb.withId(id)
                .withType("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
                .withType("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
                .withProperties(props)
                .seal(using: IDChainOperationsTest2.Grace.storepass)

            try IDChainOperationsTest2.Dave.store!.storeCredential(using: vc)
            try vc.declare(IDChainOperationsTest2.Dave.storepass)
            waitForWalletAvaliable()
            
            let resolvedVc = try VerifiableCredential.resolve(id)
            XCTAssertNotNil(resolvedVc)
            XCTAssertEqual(id, resolvedVc!.getId())
            XCTAssertTrue(resolvedVc!.getTypes().contains("ProfileCredential"))
            XCTAssertTrue(resolvedVc!.getTypes().contains("SelfProclaimedCredential"))
            XCTAssertEqual(IDChainOperationsTest2.bar1, resolvedVc?.subject?.did)
            XCTAssertEqual(IDChainOperationsTest2.Grace.did, resolvedVc?.issuer)
            XCTAssertEqual(vc.proof?.signature,
                    resolvedVc?.proof?.signature)

            XCTAssertTrue(try resolvedVc!.isValid())

            IDChainOperationsTest2.bar1Vc = vc.id!
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_34_109DeclareKycCredentialForBar2_c() {
        do {
            let issuer = try VerifiableCredentialIssuer(IDChainOperationsTest2.Grace.getCustomizedDocument()!)

            // add a KYC credential
            var props: [String: String] = [: ]
            props["name"] = "Bar2"
            props["gender"] = "Male"
            props["nationality"] = "Singapore"
            props["email"] = "bar2@example.com"

            // VC for the normal DID
            let timeStamp = Date().milliStamp
            let id = try DIDURL(IDChainOperationsTest2.bar2, "#profile-" + timeStamp)
            let cb = try issuer.editingVerifiableCredentialFor(did: IDChainOperationsTest2.bar2)
            let vc = try cb.withId(id)
                .withType("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
                .withType("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
                .withProperties(props)
                .seal(using: IDChainOperationsTest2.Grace.storepass)

            try IDChainOperationsTest2.Erin.store!.storeCredential(using: vc)
            try vc.declare(IDChainOperationsTest2.Erin.storepass)
            waitForWalletAvaliable()
            
            let resolvedVc = try VerifiableCredential.resolve(id)
            XCTAssertNotNil(resolvedVc)
            XCTAssertEqual(id, resolvedVc!.getId())
            XCTAssertTrue(resolvedVc!.getTypes().contains("ProfileCredential"));
            XCTAssertTrue(resolvedVc!.getTypes().contains("SelfProclaimedCredential"));
            XCTAssertEqual(IDChainOperationsTest2.bar2, resolvedVc?.subject?.did)
            XCTAssertEqual(IDChainOperationsTest2.Grace.customizedDid, resolvedVc?.issuer)
            XCTAssertEqual(vc.proof?.signature,
                           resolvedVc?.proof?.signature)

            XCTAssertTrue(try resolvedVc!.isValid())

            IDChainOperationsTest2.bar2Vc = vc.id!
        }
        catch {
            print(error)
            XCTFail()
        }
    }
   
    func test_35_110DeclareKycCredentialForBar3_c() {
        do {
            let issuer = try VerifiableCredentialIssuer(IDChainOperationsTest2.Grace.getCustomizedDocument()!)

            // add a KYC credential
            var props: [String: String] = [: ]
            props["name"] = "Bar3"
            props["gender"] = "Male"
            props["nationality"] = "Singapore"
            props["email"] = "bar3@example.com"

            // VC for the normal DID
            let timeStamp = Date().milliStamp
            let id = try DIDURL(IDChainOperationsTest2.bar3, "#profile-" + timeStamp)
            let cb = try issuer.editingVerifiableCredentialFor(did: IDChainOperationsTest2.bar3)
            let vc = try cb.withId(id)
                .withType("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
                .withType("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
                .withProperties(props)
                .seal(using: IDChainOperationsTest2.Grace.storepass)

            try IDChainOperationsTest2.Frank.store!.storeCredential(using: vc)
            try vc.declare(IDChainOperationsTest2.Frank.storepass)
            waitForWalletAvaliable()
            
            let resolvedVc = try VerifiableCredential.resolve(id)
            XCTAssertNotNil(resolvedVc)
            XCTAssertEqual(id, resolvedVc!.getId())
            XCTAssertTrue(resolvedVc!.getTypes().contains("ProfileCredential"))
            XCTAssertTrue(resolvedVc!.getTypes().contains("SelfProclaimedCredential"))
            XCTAssertEqual(IDChainOperationsTest2.bar3, resolvedVc?.subject?.did)
            XCTAssertEqual(IDChainOperationsTest2.Grace.customizedDid, resolvedVc?.issuer)
            XCTAssertEqual(vc.proof?.signature,
                    resolvedVc?.proof?.signature)

            XCTAssertTrue(try resolvedVc!.isValid())

            IDChainOperationsTest2.bar3Vc = vc.id!
        }
        catch {
            print(error)
            XCTFail()
        }
    }
     
    func test_36_200ListVcForAlice_p() {
        do {
            let vcs = try VerifiableCredential.list(IDChainOperationsTest2.Alice.did!)

            XCTAssertEqual(3, vcs.count)

            for id in vcs {
                let vc = try VerifiableCredential.resolve(id)
                XCTAssertNotNil(vc)
                XCTAssertEqual(id, vc!.getId())
                XCTAssertEqual(IDChainOperationsTest2.Alice.did, vc?.subject?.did)
            }
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_37_201ListVcForAlice_c() {
        do {
            var vcs = try VerifiableCredential.list(IDChainOperationsTest2.Alice.customizedDid!)

            XCTAssertEqual(3, vcs.count)

            for id in vcs {
                let vc = try VerifiableCredential.resolve(id)
                XCTAssertNotNil(vc)
                XCTAssertEqual(id, vc?.id)
                XCTAssertEqual(IDChainOperationsTest2.Alice.customizedDid, vc?.subject?.did)
            }
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_38_202ListVcForFoo1() {
        do {
            let vcs = try VerifiableCredential.list(IDChainOperationsTest2.foo1)

            XCTAssertEqual(1, vcs.count)

            for id in vcs {
                let vc = try VerifiableCredential.resolve(id)
                XCTAssertNotNil(vc)
                XCTAssertEqual(id, vc?.id)
                XCTAssertEqual(IDChainOperationsTest2.foo1, vc?.subject?.did)
            }
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_39_203ListVcForBar3() {
        do {
            let vcs = try VerifiableCredential.list(IDChainOperationsTest2.bar3)

            XCTAssertEqual(1, vcs.count)

            for id in vcs {
                let vc = try VerifiableCredential.resolve(id)
                XCTAssertNotNil(vc)
                XCTAssertEqual(id, vc?.id)
                XCTAssertEqual(IDChainOperationsTest2.bar3, vc?.subject?.did)
            }
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_40_204ListPagination() {
        do {
            let issuer = try VerifiableCredentialIssuer(IDChainOperationsTest2.Grace.getCustomizedDocument()!)

            let nobody = IDChainEntity("nobody")
            // Create a bunch of vcs
            for i in 0...270 {
                let vc = try issuer.editingVerifiableCredentialFor(did: nobody.did!)
                        .withId("#test" + "\(i)")
                        .withType("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
                        .withProperties("index", "\(i)")
                        .seal(using: IDChainOperationsTest2.Grace.storepass)

                try nobody.store!.storeCredential(using: vc)
                try vc.declare(nobody.storepass)
                waitForWalletAvaliable()
                
                XCTAssertTrue(try vc.wasDeclared())
            }

            // Default page size
            var index = 271
            var ids = try VerifiableCredential.list(nobody.did!)
            XCTAssertNotNil(ids)
            XCTAssertEqual(CredentialList.DEFAULT_SIZE, ids.count)
               for id in ids {
                   let ref = try DIDURL(nobody.did!, "#test" + "\(index - 1)")
                   XCTAssertEqual(ref, id)

                   let vc = try VerifiableCredential.resolve(id)

                   XCTAssertNotNil(vc)
                   XCTAssertEqual(ref, vc!.getId())
                   XCTAssertTrue(try vc!.wasDeclared())
               }

               // Max page size
            index = 271;
            ids = try VerifiableCredential.list(nobody.did!, 500)
            XCTAssertNotNil(ids)
            XCTAssertEqual(CredentialList.MAX_SIZE, ids.count)
               for id in ids {
                   let ref = try DIDURL(nobody.did!, "#test" + "\(index - 1)")
                   XCTAssertEqual(ref, id)

                   let vc = try VerifiableCredential.resolve(id)

                   XCTAssertNotNil(vc)
                   XCTAssertEqual(ref, vc?.id)
                   XCTAssertTrue(try vc!.wasDeclared())
               }

               // out of boundary
            ids = try VerifiableCredential.list(nobody.did!, 300, 100)
            XCTAssertNil(ids)

            // list all with default page size
            var skip = 0
            var limit = CredentialList.DEFAULT_SIZE
            index = 271
            while (true) {
                var resultSize = index >= limit ? limit : index
                ids = try VerifiableCredential.list(nobody.did!, skip, limit)
                if (ids.count == 0) {
                    break
                }

                XCTAssertEqual(resultSize, ids.count)
                   for id in ids {
                       let ref = try DIDURL(nobody.did!, "#test" + "\(index - 1)")
                       XCTAssertEqual(ref, id)

                       let vc = try VerifiableCredential.resolve(id)

                       XCTAssertNotNil(vc)
                       XCTAssertEqual(ref, vc?.id)
                       XCTAssertTrue(try vc!.wasDeclared())
                   }

                   skip += ids.count
            }
            XCTAssertEqual(0, index)

            // list with specific page size and start position
            skip = 100
            limit = 100
            index = 171
            while (true) {
                var resultSize = index >= limit ? limit : index
                ids = try VerifiableCredential.list(nobody.did!, skip, limit)
                if (ids.count == 0) {
                    break
                }

                XCTAssertEqual(resultSize, ids.count)
                   for id in ids {
                       let ref = try DIDURL(nobody.did!, "#test" + "\(index - 1)")
                       XCTAssertEqual(ref, id)

                       let vc = try VerifiableCredential.resolve(id)

                       XCTAssertNotNil(vc)
                       XCTAssertEqual(ref, vc?.id)
                       XCTAssertTrue(try vc!.wasDeclared())
                   }

                   skip += ids.count
            }
            XCTAssertEqual(0, index)
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_41_300RevokeSelfProclaimedVcFromNobody_p() {
        do {
            // Frank' self-proclaimed credential
            let id = IDChainOperationsTest2.Frank.getSelfProclaimedCredential(IDChainOperationsTest2.Frank.did!)[0]

            // Alice try to revoke
//            assertThrows(Exception.class, () -> {
//                VerifiableCredential.revoke(id, Alice.getDocument(), Alice.storepass())
//            })

            var vcs = try VerifiableCredential.list(IDChainOperationsTest2.Frank.did!)
            XCTAssertEqual(3, vcs.count)
            XCTAssertTrue(vcs.contains(id))

            let vc = try VerifiableCredential.resolve(id)
            XCTAssertFalse(try vc!.isRevoked())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_42_301RevokeSelfProclaimedVcFromNobody_c() {
        do {
            // Frank' self-proclaimed credential
            let id = IDChainOperationsTest2.Frank.getSelfProclaimedCredential(IDChainOperationsTest2.Frank.customizedDid!)[0]

            // Alice try to revoke
//            assertThrows(Exception.class, () -> {
//                VerifiableCredential.revoke(id, Alice.getDocument(), Alice.storepass)
//            })

            let vcs = try VerifiableCredential.list(IDChainOperationsTest2.Frank.customizedDid!)
            XCTAssertEqual(3, vcs.count)
            XCTAssertTrue(vcs.contains(id))

            let vc = try VerifiableCredential.resolve(id)
            XCTAssertFalse(try vc!.isRevoked())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_43_302RevokeSelfProclaimedVc_p1() {
        do {
            // Frank' self-proclaimed credential
            let id = IDChainOperationsTest2.Frank.getSelfProclaimedCredential(IDChainOperationsTest2.Frank.did!)[0]

            try VerifiableCredential.revoke(id, IDChainOperationsTest2.Frank.getDocument()!, IDChainOperationsTest2.Frank.storepass)
            waitForWalletAvaliable()
            
            let vcs = try VerifiableCredential.list(IDChainOperationsTest2.Frank.did!)
            XCTAssertEqual(3, vcs.count)
            XCTAssertTrue(vcs.contains(id))

            let vc = try VerifiableCredential.resolve(id)
            XCTAssertTrue(try vc!.isRevoked())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_44_303RevokeSelfProclaimedVc_c1() {
        do {
            // Frank' self-proclaimed credential
            let id = IDChainOperationsTest2.Frank.getSelfProclaimedCredential(IDChainOperationsTest2.Frank.customizedDid!)[0]

            let doc = try IDChainOperationsTest2.Frank.getCustomizedDocument()
            try doc!.setEffectiveController(IDChainOperationsTest2.Frank.did!)

            try VerifiableCredential.revoke(id, doc!, IDChainOperationsTest2.Frank.storepass)
            waitForWalletAvaliable()
            
            var vcs = try VerifiableCredential.list(IDChainOperationsTest2.Frank.customizedDid!)
            XCTAssertEqual(3, vcs.count)
            XCTAssertTrue(vcs.contains(id))

            let vc = try VerifiableCredential.resolve(id)
            XCTAssertTrue(try vc!.isRevoked())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_45_304RevokeSelfProclaimedVc_p2() {
        do {
            // Erin' self-proclaimed credential
            let id = IDChainOperationsTest2.Erin.getSelfProclaimedCredential(IDChainOperationsTest2.Erin.did!)[0]

            var vc = try VerifiableCredential.resolve(id)
            XCTAssertFalse(try vc!.isRevoked())

            try vc!.revoke(IDChainOperationsTest2.Erin.getDocument()!, IDChainOperationsTest2.Erin.storepass)
            waitForWalletAvaliable()
            
            let vcs = try VerifiableCredential.list(IDChainOperationsTest2.Erin.did!)
            XCTAssertEqual(3, vcs.count)
            XCTAssertTrue(vcs.contains(id))

            vc = try VerifiableCredential.resolve(id)
            XCTAssertTrue(try vc!.isRevoked())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_46_305RevokeSelfProclaimedVc_c2() {
        do {
            // Erin' self-proclaimed credential
            let id = IDChainOperationsTest2.Erin.getSelfProclaimedCredential(IDChainOperationsTest2.Erin.customizedDid!)[0]

            var vc = try VerifiableCredential.resolve(id)
            XCTAssertFalse(try vc!.isRevoked())

            let doc = try IDChainOperationsTest2.Erin.getCustomizedDocument()
            try doc!.setEffectiveController(IDChainOperationsTest2.Erin.did!)

            try vc!.revoke(doc!, IDChainOperationsTest2.Erin.storepass)
            waitForWalletAvaliable()
            
            let vcs = try VerifiableCredential.list(IDChainOperationsTest2.Erin.customizedDid!)
            XCTAssertEqual(3, vcs.count)
            XCTAssertTrue(vcs.contains(id))

            vc = try VerifiableCredential.resolve(id)
            XCTAssertTrue(try vc!.isRevoked())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_47_306RevokeKycVc_p1() {
        do {
            // Frank' KYC credential
            let id = IDChainOperationsTest2.Frank.getKycCredential(IDChainOperationsTest2.Frank.did!)[0]

            try VerifiableCredential.revoke(id, IDChainOperationsTest2.Frank.getDocument()!, IDChainOperationsTest2.Frank.storepass)
            waitForWalletAvaliable()
            
            let vcs = try VerifiableCredential.list(IDChainOperationsTest2.Frank.did!)
            XCTAssertEqual(3, vcs.count)
            XCTAssertTrue(vcs.contains(id))

            let vc = try VerifiableCredential.resolve(id)
            XCTAssertTrue(try vc!.isRevoked())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_48_307RevokeKycVc_c1() {
        do {
            // Frank' KYC credential
            let id = IDChainOperationsTest2.Frank.getKycCredential(IDChainOperationsTest2.Frank.customizedDid!)[0]

            let doc = try IDChainOperationsTest2.Frank.getCustomizedDocument()
            try doc!.setEffectiveController(IDChainOperationsTest2.Frank.did)

            try VerifiableCredential.revoke(id, doc!, IDChainOperationsTest2.Frank.storepass)
            waitForWalletAvaliable()
            
            let vcs = try VerifiableCredential.list(IDChainOperationsTest2.Frank.customizedDid!)
            XCTAssertEqual(3, vcs.count)
            XCTAssertTrue(vcs.contains(id))

            let vc = try VerifiableCredential.resolve(id)
            XCTAssertTrue(try vc!.isRevoked())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_49_308RevokeKycVc_p2() {
        do {
            // Erin' KYC credential
            let id = IDChainOperationsTest2.Erin.getKycCredential(IDChainOperationsTest2.Erin.did!)[0]

            var vc = try VerifiableCredential.resolve(id)
            XCTAssertFalse(try vc!.isRevoked())

            try vc!.revoke(IDChainOperationsTest2.Erin.getDocument()!, IDChainOperationsTest2.Erin.storepass)
            waitForWalletAvaliable()
            
            let vcs = try VerifiableCredential.list(IDChainOperationsTest2.Erin.did!)
            XCTAssertEqual(3, vcs.count)
            XCTAssertTrue(vcs.contains(id))

            vc = try VerifiableCredential.resolve(id)
            XCTAssertTrue(try vc!.isRevoked())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_50_309RevokeKycVc_c2() {
        do {
            // Erin' KYC credential
            let id = IDChainOperationsTest2.Erin.getKycCredential(IDChainOperationsTest2.Erin.customizedDid!)[0]

            var vc = try VerifiableCredential.resolve(id)
            XCTAssertFalse(try vc!.isRevoked())

            let doc = try IDChainOperationsTest2.Erin.getCustomizedDocument()
            try doc!.setEffectiveController(IDChainOperationsTest2.Erin.did)

            try vc!.revoke(doc!, IDChainOperationsTest2.Erin.storepass)
            waitForWalletAvaliable()
            
            let vcs = try VerifiableCredential.list(IDChainOperationsTest2.Erin.customizedDid!)
            XCTAssertEqual(3, vcs.count)
            XCTAssertTrue(vcs.contains(id))

            vc = try VerifiableCredential.resolve(id)
            XCTAssertTrue(try vc!.isRevoked())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_51_310RevokeFoo1Vc() {
        do {
            var vc = try VerifiableCredential.resolve(IDChainOperationsTest2.foo1Vc)
            XCTAssertFalse(try vc!.isRevoked())

            let doc = try IDChainOperationsTest2.foo1.resolve()
            try IDChainOperationsTest2.Carol.store!.storeDid(using: doc!)
            try doc!.setEffectiveController(IDChainOperationsTest2.Carol.did)

            try vc!.revoke(doc!, IDChainOperationsTest2.Carol.storepass)
            waitForWalletAvaliable()
            
            let vcs = try VerifiableCredential.list(IDChainOperationsTest2.foo1)
            XCTAssertEqual(1, vcs.count)
            XCTAssertTrue(vcs.contains(IDChainOperationsTest2.foo1Vc))

            vc = try VerifiableCredential.resolve(IDChainOperationsTest2.foo1Vc)
            XCTAssertTrue(try vc!.isRevoked())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_52_311RevokeFoo2Vc() {
        do {
            var vc = try VerifiableCredential.resolve(IDChainOperationsTest2.foo2Vc)
            XCTAssertFalse(try vc!.isRevoked())

            let doc = try IDChainOperationsTest2.foo2.resolve()
            try IDChainOperationsTest2.Dave.store!.storeDid(using: doc!)
            try doc!.setEffectiveController(IDChainOperationsTest2.Dave.did)

            try vc!.revoke(doc!, IDChainOperationsTest2.Dave.storepass)
            waitForWalletAvaliable()
            
            let vcs = try VerifiableCredential.list(IDChainOperationsTest2.foo2)
            XCTAssertEqual(1, vcs.count)
            XCTAssertTrue(vcs.contains(IDChainOperationsTest2.foo2Vc))

            vc = try VerifiableCredential.resolve(IDChainOperationsTest2.foo2Vc)
            XCTAssertTrue(try vc!.isRevoked())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_53_312RevokeBar1VcFromNobody() {
        do {
            let vc = try VerifiableCredential.resolve(IDChainOperationsTest2.bar1Vc)
            XCTAssertFalse(try vc!.isRevoked())

            let doc = try IDChainOperationsTest2.Alice.getDocument()

//            assertThrows(Exception.class, () -> {
//                vc.revoke(doc, Alice.storepass)
//            })

            let vcs = try VerifiableCredential.list(IDChainOperationsTest2.bar1)
            XCTAssertEqual(1, vcs.count)
            XCTAssertTrue(vcs.contains(IDChainOperationsTest2.bar1Vc))

            let resolved = try VerifiableCredential.resolve(IDChainOperationsTest2.bar1Vc)
            XCTAssertFalse(try resolved!.isRevoked())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_54_313RevokeBar2VcFromNobody() {
        do {
            let vc = try VerifiableCredential.resolve(IDChainOperationsTest2.bar2Vc)
            XCTAssertFalse(try vc!.isRevoked())

            let doc = try IDChainOperationsTest2.Alice.getDocument()

//            assertThrows(Exception.class, () -> {
//                vc.revoke(doc, Alice.storepass)
//            })

            let vcs = try VerifiableCredential.list(IDChainOperationsTest2.bar2)
            XCTAssertEqual(1, vcs.count)
            XCTAssertTrue(vcs.contains(IDChainOperationsTest2.bar2Vc))

            let resolved = try VerifiableCredential.resolve(IDChainOperationsTest2.bar2Vc)
            XCTAssertFalse(try resolved!.isRevoked())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_55_314RevokeBar1VcFromController() {
        do {
            var vc = try VerifiableCredential.resolve(IDChainOperationsTest2.bar1Vc)
            XCTAssertFalse(try vc!.isRevoked())

            let doc = try IDChainOperationsTest2.bar1.resolve()
            try IDChainOperationsTest2.Dave.store!.storeDid(using: doc!)
            try doc!.setEffectiveController(IDChainOperationsTest2.Dave.did)

            try vc!.revoke(doc!, IDChainOperationsTest2.Dave.storepass)
            waitForWalletAvaliable()
            
            let vcs = try VerifiableCredential.list(IDChainOperationsTest2.bar1)
            XCTAssertEqual(1, vcs.count)
            XCTAssertTrue(vcs.contains(IDChainOperationsTest2.bar1Vc))

            vc = try VerifiableCredential.resolve(IDChainOperationsTest2.bar1Vc)
            XCTAssertTrue(try vc!.isRevoked())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_56_315RevokeBar2VcFromIssuer() {
        do {
            var vc = try VerifiableCredential.resolve(IDChainOperationsTest2.bar2Vc)
            XCTAssertFalse(try vc!.isRevoked())

            let doc = try IDChainOperationsTest2.Grace.getCustomizedDocument()
            try doc!.setEffectiveController(IDChainOperationsTest2.Grace.did)

            try vc!.revoke(doc!, IDChainOperationsTest2.Grace.storepass)
            waitForWalletAvaliable()
            
            let vcs = try VerifiableCredential.list(IDChainOperationsTest2.bar2)
            XCTAssertEqual(1, vcs.count)
            XCTAssertTrue(vcs.contains(IDChainOperationsTest2.bar2Vc))

            vc = try VerifiableCredential.resolve(IDChainOperationsTest2.bar2Vc)
            XCTAssertTrue(try vc!.isRevoked())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_57_316RevokeBar3VcFromIssuer() {
        do {
            var vc = try VerifiableCredential.resolve(IDChainOperationsTest2.bar3Vc)
            XCTAssertFalse(try vc!.isRevoked())

            let doc = try IDChainOperationsTest2.Grace.getCustomizedDocument()
            try doc!.setEffectiveController(IDChainOperationsTest2.Grace.did)

            try VerifiableCredential.revoke(IDChainOperationsTest2.bar3Vc, doc!, IDChainOperationsTest2.Grace.storepass)
            waitForWalletAvaliable()
            
            let vcs = try VerifiableCredential.list(IDChainOperationsTest2.bar3)
            XCTAssertEqual(1, vcs.count)
            XCTAssertTrue(vcs.contains(IDChainOperationsTest2.bar3Vc))

            vc = try VerifiableCredential.resolve(IDChainOperationsTest2.bar3Vc)
            XCTAssertTrue(try vc!.isRevoked())
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_58_400DeactivateFoo1() {
        do {
            var doc = try IDChainOperationsTest2.foo1.resolve()
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc!.isValid())

            try IDChainOperationsTest2.Carol.store!.storeDid(using: doc!)
            try doc!.setEffectiveController(IDChainOperationsTest2.Carol.did)
            try doc!.deactivate(using: IDChainOperationsTest2.Carol.storepass)
            waitForWalletAvaliable()
            
            doc = try IDChainOperationsTest2.foo1.resolve()
            XCTAssertTrue(doc!.isDeactivated)
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_59_401DeactivateFoo2() {
        do {
            var doc = try IDChainOperationsTest2.foo2.resolve()
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc!.isValid())

            try IDChainOperationsTest2.Dave.getDocument()!.deactivate(with: IDChainOperationsTest2.foo2, using: IDChainOperationsTest2.Dave.storepass)
            waitForWalletAvaliable()
            
            doc = try IDChainOperationsTest2.foo1.resolve()
            XCTAssertTrue(doc!.isDeactivated)
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_60_402DeactivateBar1() {
        do {
            var doc = try IDChainOperationsTest2.bar1.resolve()
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc!.isValid())

            try IDChainOperationsTest2.Dave.getDocument()!.deactivate(with: IDChainOperationsTest2.bar1, using: IDChainOperationsTest2.Dave.storepass)
            waitForWalletAvaliable()
            
            doc = try IDChainOperationsTest2.bar1.resolve()
            XCTAssertTrue(doc!.isDeactivated)
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_61_403DeactivateBar2() {
        do {
            var doc = try IDChainOperationsTest2.bar2.resolve()
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc!.isValid())

            try IDChainOperationsTest2.Erin.store!.storeDid(using: doc!)
            try doc!.setEffectiveController(IDChainOperationsTest2.Erin.did)
            try doc!.deactivate(using: IDChainOperationsTest2.Erin.storepass)
            waitForWalletAvaliable()
            
            doc = try IDChainOperationsTest2.bar2.resolve()
            XCTAssertTrue(doc!.isDeactivated)
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_62_404DeactivateBar3() {
        do {
            var doc = try IDChainOperationsTest2.bar3.resolve()
            XCTAssertNotNil(doc)
            

            try IDChainOperationsTest2.Frank.store!.storeDid(using: doc!)
            try doc!.setEffectiveController(IDChainOperationsTest2.Frank.did)
            try doc!.deactivate(using: IDChainOperationsTest2.Frank.storepass)
            waitForWalletAvaliable()
            
            doc = try IDChainOperationsTest2.bar3.resolve()
            XCTAssertTrue(doc!.isDeactivated)
        }
        catch {
            print(error)
            XCTFail()
        }
    }
    func test_63_405DeactivatePersonsCid() {
        do {
            for person in IDChainOperationsTest2.persons {
                var doc = try person.customizedDid!.resolve()
                XCTAssertNotNil(doc)
                XCTAssertTrue(try doc!.isValid())

                doc = try person.getCustomizedDocument()
                try doc!.deactivate(using: person.storepass)
                waitForWalletAvaliable()
                
                doc = try person.customizedDid!.resolve()
                XCTAssertTrue(doc!.isDeactivated)
            }
        }
        catch {
            print(error)
            XCTFail()
        }
    }

    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}

extension Date {
    /// 获取当前 毫秒级 时间戳 - 13位
    var milliStamp : String {
        let timeInterval: TimeInterval = self.timeIntervalSince1970
        let millisecond = CLongLong(round(timeInterval*1000))
        return "\(millisecond)"
    }
}

class IDChainEntity {
    // Mnemonic passphrase and the store password should set by the end user.
    let passphrase = ""  // Default is an empty string, or any user defined word
    let storepass = "mypassword"

    // The entity name
    var name: String = ""

    var store: DIDStore?
    var did: DID?
    var customizedDid: DID?

    var selfProclaimedVcs: [DIDURL] = [ ]
    var kycVcs: [DIDURL] = [ ]

    var cidSelfProclaimedVcs: [DIDURL] = [ ]
    var cidKycVcs: [DIDURL] = [ ]

    init(_ name: String) {
        self.name = name
        try! initRootIdentity()
        try! initDid()
    }
    
    func initRootIdentity() throws {
        
        let storePath = "\(NSHomeDirectory())/Library/Caches/data/didCache/" + name + ".store"
        print("storePath: \(storePath)")
        store = try DIDStore.open(atPath: storePath)
        
        // Check the store whether contains the root private identity.
        if (try store!.containsRootIdentities()) {
            return // Already exists
        }
        
        let mnemonic = try! Mnemonic.generate(Mnemonic.DID_ENGLISH)
        print("Please write down your mnemonic and passwords:")
        print("  Mnemonic: \(mnemonic)")
        print("  Mnemonic passphrase: \(passphrase)")
        print("  Store password: \(storepass)")
        let identity = try RootIdentity.create(mnemonic, passphrase, store!, storepass)
        let re = try identity.synchronize(0)
        print(re)
    }
    
    func initDid() throws {
        
        let dids = try! store!.listDids()
        if (dids.count > 0) {
            self.did = dids[0]
            return
        }
        let identity = try! store!.loadRootIdentity()
        let doc = try identity!.newDid(storepass)
        self.did = doc.subject
        doc.getMetadata().setAlias("swift-me")
        print("My new DID created: ", name, did!.description)
        try! doc.publish(using: storepass)
    }
    
    func getDocument() throws -> DIDDocument? {
        return try store!.loadDid(did!)
    }
    
    func setCustomizedDid(_ did: DID) {
        self.customizedDid = did
    }
    
    func getCustomizedDocument() throws -> DIDDocument? {
        return try store!.loadDid(customizedDid!)
    }
    
    func addSelfProclaimedCredential(_ id: DIDURL) throws {
        if id.did == did {
            selfProclaimedVcs.append(id)
        }
        else if id.did == customizedDid {
            cidSelfProclaimedVcs.append(id)
        }
        else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalArgumentError("Invalid credential")
        }
    }
    
    func getSelfProclaimedCredential(_ did: DID) -> [DIDURL] {
        if did == self.did {
            return selfProclaimedVcs
        }
        else if did == customizedDid {
            return cidSelfProclaimedVcs
        }
        else {
            return [ ]
        }
    }
    
    func addKycCredential(_ id: DIDURL) throws {
        if id.did == self.did {
            kycVcs.append(id)
        }
        else if id.did == customizedDid {
            cidKycVcs.append(id)
        }
        else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalArgumentError("Invalid credential")
        }
    }
    
    func getKycCredential(_ did: DID) -> [DIDURL] {
        if did == self.did {
            return kycVcs
        }
        else if did == customizedDid {
            return cidKycVcs
        }
        else {
            return [ ]
        }
    }

}

