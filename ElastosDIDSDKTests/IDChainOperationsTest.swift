import XCTest
@testable import ElastosDIDSDK
import PromiseKit

class IDChainOperationsTest: XCTestCase {
    static let testData: TestData = TestData()
    static var dids: [DID] = []
    var store:  DIDStore?
    var mnemonic: String = ""
    var identity: RootIdentity?
    var adapter: Web3Adapter?
    var debug = TestEventListener()

    override func setUp() {
        adapter = Web3Adapter(rpcEndpoint, contractAddress, walletPath, walletPassword)
        try! DIDBackend.initialize(adapter!)

        store = IDChainOperationsTest.testData.store
        print(self.store as Any)
        identity = try! IDChainOperationsTest.testData.getRootIdentity()
        mnemonic = IDChainOperationsTest.testData.mnemonic
    }
    
    override func tearDown() {
//        IDChainOperationsTest.testData.cleanup()
    }
    
    func waitForWalletAvaliable() {
        while true {
            Thread.sleep(forTimeInterval: 20)
            if adapter!.isAvailable() {
                print("OK")
                break
            }
            else {
                print(".")
            }
            Thread.sleep(forTimeInterval: 60)
        }
    }
    
    /*
     mnemonic = carry season material labor popular patient radio orient aerobic shed cash alcohol
     passphrase = pwd
     did = iqwLG4NchEeMyFsbfQ3tyLrLwnYbCKA2wS
     
     mnemonic = extend verb milk code angle inform reform noble will grass arrow smoke
     did = igMPopmKyBTgJKaqRGmSiR3TusC7X2MPwa
     */

    func testmnemonic() {
        do {
            
            mnemonic = "carry season material labor popular patient radio orient aerobic shed cash alcohol"
            let identity = try RootIdentity.create(mnemonic, "pwd", true, store!, storePassword)
            let did = try DID("did:elastos:iqwLG4NchEeMyFsbfQ3tyLrLwnYbCKA2wS")
            let doc = try did.resolve()
            let doc1 = try! DIDBackend.sharedInstance().resolveUntrustedDid(did, true)
//            try doc?.publishUntrusted(nil, "pwd", nil)
            print(doc)
        } catch {
            print(error)
        }
    }
    
    func testDID() {
        do {
            var doc = try identity!.newDid(storePassword)
            let db = try doc.editing()
            var json = "{\"twitter\":\"@foobar\"}"
//            _ = try db.appendCredential(with: "#twitter", json: json, using: storePassword)
            _ = try db.appendCredential(with: "#twitter", types: ["twitter", "SelfProclaimedCredential", "TestCredential"], json: json, using: storePassword)
            json = "{\"facebook\":\"@facebook123\"}"
//            _ = try db.appendCredential(with: "#facebook", json: json, using: storePassword)
            _ = try db.appendCredential(with: "#facebook", types: ["facebook", "SelfProclaimedCredential"], json: json, using: storePassword)
            json = "{\"email\":\"@email123\"}"
//            _ = try db.appendCredential(with: "#email", json: json, using: storePassword)
            _ = try db.appendCredential(with: "#email", types: ["email", "test", "FooBar"], json: json, using: storePassword)
            json = "{\"QQ\":\"@4887000\"}"
//            _ = try db.appendCredential(with: "#QQ", json: json, using: storePassword)
            _ = try db.appendCredential(with: "#QQ", types: ["test", "QQ", "SelfProclaimedCredential"], json: json, using: storePassword)

            doc = try db.seal(using: storePassword)
            print(doc)
        } catch {
            print(error)
        }
    }
    
    func test_00CreateAndResolve() {
        do {
            // Create new DID and publish to ID sidechain.
            let doc = try identity!.newDid(storePassword)
            let did = doc.subject
            
            print("Publishing new DID \(did.toString())...")
            try doc.publish(using: storePassword)
            print("Publish new DID \(did.toString())...OK({}s)")
            
            waitForWalletAvaliable()
            let resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertTrue(try resolved!.isValid())
            XCTAssertEqual(doc.toString(true), resolved!.toString(true))
            
            IDChainOperationsTest.dids.append(did) // 0
            print(IDChainOperationsTest.dids)
            
        } catch {
            XCTFail()
        }
    }
    
    func test_01CreateAndResolveAsync() {
        do {
            // Create new DID and publish to ID sidechain.
            let doc = try identity!.newDid(storePassword)
            let did = doc.subject
            
            print("Publishing new DID \(did)...")
            var lock = XCTestExpectation()
            doc.publishAsync(using: storePassword).done{ _ in
                print("Publish new DID \(did)...OK({}s)")
                XCTAssertTrue(true)
                lock.fulfill()
            }
            .catch{ error in
                XCTFail()
                lock.fulfill()
            }
            wait(for: [lock], timeout: 1000)
            lock = XCTestExpectation()
            waitForWalletAvaliable()
            did.resolveAsync(true).done { resolved in
                XCTAssertEqual(did, resolved!.subject)
                XCTAssertTrue(try resolved!.isValid())
                XCTAssertEqual(doc.toString(true), resolved!.toString(true))
                lock.fulfill()
            }
            .catch { error in
                XCTFail()
                lock.fulfill()
            }
            wait(for: [lock], timeout: 1000)
            
            IDChainOperationsTest.dids.append(did) // 1
        } catch {
            XCTFail()
        }
    }
    
    func test_02CreateAndResolveAsync2() {
        do {
            // Create new DID and publish to ID sidechain.
            let doc = try identity!.newDid(storePassword)
            let did = doc.subject
            let lock = XCTestExpectation()
            print("Publishing new DID and resolve \(did)...")
            
            doc.publishAsync(using: storePassword).then{ [self] _ -> Promise<DIDDocument?> in
                waitForWalletAvaliable()
                return did.resolveAsync(true)
            }.done{ resolved in
                print("Publish new DID and resolve \(did)...OK({}s)")
                
                XCTAssertEqual(did, resolved!.subject)
                XCTAssertTrue(try resolved!.isValid())
                XCTAssertEqual(doc.toString(true), resolved!.toString(true))
                
                lock.fulfill()
            }.catch{ error in
                lock.fulfill()
                XCTFail()
            }
            wait(for: [lock], timeout: 1000)
            
            IDChainOperationsTest.dids.append(did) // 2
        } catch {
            XCTFail()
        }
    }
    
    func test_03UpdateAndResolve() {
        do {
            // User the DID that created in previous case(1)
//            did:elastos:iYsRKjWMmUayNJPWqgTQHqN3hFF4KvgA6i
//            IDChainOperationsTest.dids.append(try DID("did:elastos:iYsRKjWMmUayNJPWqgTQHqN3hFF4KvgA6i"))
            var doc = try store!.loadDid(IDChainOperationsTest.dids[0])
            XCTAssertNotNil(doc)
            let did = doc!.subject
            
            var resolved = try did.resolve()
            XCTAssertEqual(did, resolved!.subject)
            XCTAssertTrue(try resolved!.isValid())
            XCTAssertEqual(doc?.proof.signature, resolved?.proof.signature)
            var lastTxid = resolved?.getMetadata().transactionId
            print("Last transaction id \(String(describing: lastTxid))")
            
            // Update
            let db = try doc!.editing()
            let key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db.seal(using: storePassword)
            XCTAssertEqual(2, doc?.publicKeyCount)
            XCTAssertEqual(2, doc!.authenticationKeyCount)
            try store?.storeDid(using: doc!)
            
            print("Updating DID \(did)...")
            try doc!.publish(using: storePassword)
            print("Update DID \(did)...OK({}s)")
            
            waitForWalletAvaliable()
            resolved = try did.resolve()
            XCTAssertNotEqual(lastTxid, resolved?.getMetadata().transactionId)
            XCTAssertEqual(did, resolved!.subject)
            XCTAssertTrue(try resolved!.isValid())
            XCTAssertEqual(doc!.toString(true), resolved!.toString(true))
            
            lastTxid = resolved?.getMetadata().transactionId
            print("Last transaction id \(String(describing: lastTxid))")
            
            let rr = try did.resolveBiography()
            XCTAssertNotNil(rr)
            XCTAssertEqual(did, rr?.did)
            XCTAssertEqual(DIDBiographyStatus.STATUS_VALID, rr?.status)
            XCTAssertEqual(2, rr?.count)
            let txs = rr?.getAllTransactions()
            XCTAssertNotNil(txs)
            XCTAssertEqual(2, txs?.count)
            
            var tx = txs![0]
            XCTAssertEqual(did, tx.did)
            XCTAssertEqual(IDChainRequestOperation.UPDATE, tx.request.operation)
            XCTAssertTrue(try tx.request.isValid())
            
            tx = txs![1]
            XCTAssertEqual(did, tx.did)
            XCTAssertEqual(IDChainRequestOperation.CREATE, tx.request.operation)
            XCTAssertTrue(try tx.request.isValid())
            
        } catch {
            XCTFail()
        }
    }
    
    func test_04UpdateAndResolveAgain() {
        do {
            // User the DID that created in previous case(1)
            var doc = try store!.loadDid(IDChainOperationsTest.dids[0])
            XCTAssertNotNil(doc)
            let did = doc!.subject
            
            var resolved = try did.resolve()
            XCTAssertEqual(did, resolved!.subject)
            XCTAssertTrue(try resolved!.isValid())
            XCTAssertEqual(doc?.proof.signature, resolved?.proof.signature)
            var lastTxid = resolved?.getMetadata().transactionId
            print("Last transaction id \(String(describing: lastTxid))")
            
            // Update again
            let db = try doc?.editing()
            let key = try TestData.generateKeypair()
            _ = try db!.appendAuthenticationKey(with: "#key2", keyBase58: key.getPublicKeyBase58())
            doc = try db?.seal(using: storePassword)
            XCTAssertEqual(3, doc?.publicKeyCount)
            XCTAssertEqual(3, doc!.authenticationKeyCount)
            try store!.storeDid(using: doc!)
            
            print("Updating DID \(did)...")
            try doc!.publish(using: storePassword)
            
            print("Update DID \(did)...OK({}s)" )
            
            waitForWalletAvaliable()
            resolved = try did.resolve()
            XCTAssertNotEqual(lastTxid, resolved!.getMetadata().transactionId)
            XCTAssertEqual(did, resolved!.subject)
            XCTAssertTrue(try resolved!.isValid())
            XCTAssertEqual(doc!.toString(true), resolved!.toString(true))
            
            lastTxid = resolved!.getMetadata().transactionId
            print("Last transaction id \(String(describing: lastTxid))")
            
            let rr = try did.resolveBiography()
            XCTAssertNotNil(rr)
            XCTAssertEqual(did, rr?.did)
            XCTAssertEqual(DIDBiographyStatus.STATUS_VALID, rr?.status)
            XCTAssertEqual(3, rr?.count)
            let txs = rr?.getAllTransactions()
            XCTAssertNotNil(txs)
            XCTAssertEqual(3, txs?.count)
            
            var tx = txs![0]
            XCTAssertEqual(did, tx.did)
            XCTAssertEqual(IDChainRequestOperation.UPDATE, tx.request.operation)
            XCTAssertTrue(try tx.request.isValid())
            
            tx = txs![1]
            XCTAssertEqual(did, tx.did)
            XCTAssertEqual(IDChainRequestOperation.UPDATE, tx.request.operation)
            XCTAssertTrue(try tx.request.isValid())
            
            tx = txs![2]
            XCTAssertEqual(did, tx.did)
            XCTAssertEqual(IDChainRequestOperation.CREATE, tx.request.operation)
            XCTAssertTrue(try tx.request.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func test_05UpdateAndResolveAsync() {
        do {
            // User the DID that created in previous case(2)
            var doc = try store!.loadDid(IDChainOperationsTest.dids[1])
            XCTAssertNotNil(doc)
            let did = doc!.subject
            
            var resolved: DIDDocument?
            var lock = XCTestExpectation()
            did.resolveAsync(true).done { doc in
                resolved = doc
                lock.fulfill()
            }.catch { error in
                XCTFail()
                lock.fulfill()
            }
            wait(for: [lock], timeout: 10000)
            XCTAssertEqual(did, resolved!.subject)
            XCTAssertTrue(try resolved!.isValid())
            XCTAssertEqual(doc?.proof.signature, resolved?.proof.signature)
            var lastTxid = resolved?.getMetadata().transactionId
            print("Last transaction id \(String(describing: lastTxid))")
            
            // Update
            let db = try doc?.editing()
            let key = try TestData.generateKeypair()
            _ = try! db!.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db?.seal(using: storePassword)
            XCTAssertEqual(2, doc!.publicKeyCount)
            XCTAssertEqual(2, doc!.authenticationKeyCount)
            try store!.storeDid(using: doc!)
            
            print("Updating DID \(did)...")
            lock = XCTestExpectation()
            doc!.publishAsync(using: storePassword).then{ [self] _ -> Promise<DIDDocument?> in
                print("Update DID \(did)...OK({}s)")
                waitForWalletAvaliable()
                return did.resolveAsync(true)
            }.done{ doc in
                resolved = doc
                lock.fulfill()
            }.catch{ error in
                XCTFail()
                lock.fulfill()
            }
            wait(for: [lock], timeout: 1000)
            
            XCTAssertNotEqual(lastTxid, resolved?.getMetadata().transactionId)
            XCTAssertEqual(did, resolved!.subject)
            XCTAssertTrue(try resolved!.isValid())
            XCTAssertEqual(doc!.toString(true), resolved!.toString(true))
            lastTxid = resolved!.getMetadata().transactionId
            print("Last transaction id \(String(describing: lastTxid))")
            lock = XCTestExpectation()
            var rr: DIDBiography?
            _ = try did.resolveBiographyAsync().done { bio in
                rr = bio
                lock.fulfill()
            }.catch { error in
                XCTFail()
                lock.fulfill()
            }
            wait(for: [lock], timeout: 1000)
            XCTAssertNotNil(rr)
            XCTAssertEqual(did, rr?.did)
            XCTAssertEqual(DIDBiographyStatus.STATUS_VALID, rr?.status)
            XCTAssertEqual(2, rr!.count)
            let txs = rr!.getAllTransactions()
            XCTAssertNotNil(txs)
            XCTAssertEqual(2, txs.count)
            
            var tx = txs[0]
            XCTAssertEqual(did, tx.did)
            XCTAssertEqual(IDChainRequestOperation.UPDATE, tx.request.operation)
            XCTAssertTrue(try tx.request.isValid())
            
            tx = txs[1]
            XCTAssertEqual(did, tx.did)
            XCTAssertEqual(IDChainRequestOperation.CREATE, tx.request.operation)
            XCTAssertTrue(try tx.request.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func test_06UpdateAndResolveAsyncAgain() {
        do {
            // User the DID that created in previous case(2)
            var doc = try store!.loadDid(IDChainOperationsTest.dids[1])
            XCTAssertNotNil(doc)
            let did = doc!.subject
            var resolved: DIDDocument?
            var lock = XCTestExpectation()
            _ = did.resolveAsync(true).done { doc in
                resolved = doc
                lock.fulfill()
            }.catch { error in
                XCTFail()
                lock.fulfill()
            }
            wait(for: [lock], timeout: 1000)
            
            XCTAssertEqual(did, resolved!.subject)
            XCTAssertTrue(try resolved!.isValid())
            XCTAssertEqual(doc?.proof.signature, resolved?.proof.signature)
            var lastTxid = resolved!.getMetadata().transactionId
            print("Last transaction id \(String(describing: lastTxid))")
            
            // Update again
            let db = try doc?.editing()
            let key = try TestData.generateKeypair()
            _ = try! db!.appendAuthenticationKey(with: "#key2", keyBase58: key.getPublicKeyBase58())
            doc = try db?.seal(using: storePassword)
            XCTAssertEqual(3, doc!.publicKeyCount)
            XCTAssertEqual(3, doc!.authenticationKeyCount)
            try store!.storeDid(using: doc!)
            
            print("Updating DID \(did)...")
            lock = XCTestExpectation()
            doc!.publishAsync(using: storePassword).then{ [self] _ -> Promise<DIDDocument?> in
                waitForWalletAvaliable()
                return did.resolveAsync(true)
            }
            .done{ doc in
                resolved = doc
                print("Update DID \(did)...OK({}s)")
                lock.fulfill()
            }
            .catch{ error in
                XCTFail()
                lock.fulfill()
            }
            wait(for: [lock], timeout: 1000)
            
            XCTAssertNotEqual(lastTxid, resolved?.getMetadata().transactionId)
            XCTAssertEqual(did, resolved!.subject)
            XCTAssertTrue(try resolved!.isValid())
            XCTAssertEqual(doc!.toString(true), resolved!.toString(true))
            
            lastTxid = resolved?.getMetadata().transactionId
            print("Last transaction id \(String(describing: lastTxid))")
            
            let rr = try did.resolveBiography()
            XCTAssertNotNil(rr)
            XCTAssertEqual(did, rr?.did)
            XCTAssertEqual(DIDBiographyStatus.STATUS_VALID, rr?.status)
            XCTAssertEqual(3, rr?.count)
            let txs = rr?.getAllTransactions()
            XCTAssertNotNil(txs)
            XCTAssertEqual(3, txs?.count)
            
            var tx = txs![0]
            XCTAssertEqual(did, tx.did)
            XCTAssertEqual(IDChainRequestOperation.UPDATE, tx.request.operation)
            XCTAssertTrue(try tx.request.isValid())
            
            tx = txs![1]
            XCTAssertEqual(did, tx.did)
            XCTAssertEqual(IDChainRequestOperation.UPDATE, tx.request.operation)
            XCTAssertTrue(try tx.request.isValid())
            
            tx = txs![2]
            XCTAssertEqual(did, tx.did)
            XCTAssertEqual(IDChainRequestOperation.CREATE, tx.request.operation)
            XCTAssertTrue(try tx.request.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func test_07CreateAndResolveWithCredentials() {
        do {
            // Create new DID and publish to ID sidechain.
            var doc = try identity!.newDid(storePassword)
            let did = doc.subject
            
            let selfIssuer = try VerifiableCredentialIssuer(doc)
            let cb = try selfIssuer.editingVerifiableCredentialFor(did: did)
            
            let props = ["name": "John",
                         "gender": "Male",
                         "nationality": "Singapore",
                         "language": "English",
                         "email": "john@example.com",
                         "twitter": "@john"]
            
            let vc = try cb.withId("#profile")
                .withType("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
                .withType("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
                .withType("EmailCredential", "https://ns.elastos.org/credentials/email/v1")
                .withType("SocialCredential", "https://ns.elastos.org/credentials/social/v1")
                .withProperties(props)
                .seal(using: storePassword)
            XCTAssertNotNil(vc)
            
            let db = try doc.editing()
            _ = try db.appendCredential(with: vc)
            doc = try db.seal(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertEqual(1, doc.credentialCount)
            try store!.storeDid(using: doc)
            
            print("Publishing new DID \(did)...")
            try doc.publish(using: storePassword)
            print("Publish new DID \(did)...OK({}s)")
            
            waitForWalletAvaliable()
            let resolved = try did.resolve()
            XCTAssertEqual(did, resolved!.subject)
            XCTAssertTrue(try resolved!.isValid())
            XCTAssertEqual(doc.toString(true), resolved!.toString(true))
            
            let lastTxid = resolved!.getMetadata().transactionId
            print("Last transaction id \(String(describing: lastTxid))")
            
            IDChainOperationsTest.dids.append(did) // 3
        } catch {
            XCTFail()
        }
    }
    
    func test_08UpdateAndResolveWithCredentials() {
        
        do {
            // User the DID that created in previous case(8)
            var doc = try store!.loadDid(IDChainOperationsTest.dids[3])
            XCTAssertNotNil(doc)
            let did = doc!.subject
            
            var resolved = try did.resolve()
            XCTAssertEqual(did, resolved!.subject)
            XCTAssertTrue(try resolved!.isValid())
            XCTAssertEqual(doc?.proof.signature, resolved?.proof.signature)
            var lastTxid = resolved!.getMetadata().transactionId
            print("Last transaction id \(String(describing: lastTxid))")
            
            let selfIssuer = try VerifiableCredentialIssuer(doc!)
            let cb = try selfIssuer.editingVerifiableCredentialFor(did: did)
            
            let props = ["nationality": "Singapore",
                         "passport": "S653258Z07"]
            
            let vc = try cb.withId("#passport")
                .withType("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
                .withProperties(props)
                .seal(using: storePassword)
            XCTAssertNotNil(vc)
            
            let db = try doc?.editing()
            _ = try db!.appendCredential(with: vc)
            doc = try db?.seal(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertEqual(2, doc!.credentialCount)
            try store!.storeDid(using: doc!)
            
            print("Updating DID {}...", did)
            try doc!.publish(using: storePassword)
            print("Update DID \(did)...OK({}s)")
            
            waitForWalletAvaliable()
            resolved = try did.resolve()
            XCTAssertNotEqual(lastTxid, resolved!.getMetadata().transactionId)
            XCTAssertEqual(did, resolved!.subject)
            XCTAssertTrue(try resolved!.isValid())
            XCTAssertEqual(doc!.toString(true), resolved!.toString(true))
            
            lastTxid = resolved!.getMetadata().transactionId
            print("Last transaction id \(String(describing: lastTxid))")
            
            let rr = try did.resolveBiography()
            XCTAssertNotNil(rr)
            XCTAssertEqual(did, rr?.did)
            XCTAssertEqual(DIDBiographyStatus.STATUS_VALID, rr?.status)
            XCTAssertEqual(2, rr?.count)
            let txs = rr?.getAllTransactions()
            XCTAssertNotNil(txs)
            XCTAssertEqual(2, txs!.count)
            
            var tx = txs![0]
            XCTAssertEqual(did, tx.did)
            XCTAssertEqual(IDChainRequestOperation.UPDATE, tx.request.operation)
            XCTAssertTrue(try tx.request.isValid())
            
            tx = txs![1]
            XCTAssertEqual(did, tx.did)
            XCTAssertEqual(IDChainRequestOperation.CREATE, tx.request.operation)
            XCTAssertTrue(try tx.request.isValid())
            
        } catch {
            XCTFail()
        }
    }
    
    func test_09UpdateAndResolveWithCredentialsAgain() {
        do {
            // User the DID that created in previous case(8)
            var doc = try store!.loadDid(IDChainOperationsTest.dids[3])
            XCTAssertNotNil(doc)
            let did = doc!.subject
            
            var resolved = try did.resolve()
            XCTAssertEqual(did, resolved!.subject)
            XCTAssertTrue(try resolved!.isValid())
            XCTAssertEqual(doc?.proof.signature, resolved?.proof.signature)
            var lastTxid = resolved!.getMetadata().transactionId
            print("Last transaction id \(String(describing: lastTxid))")
            
            // Update again
            let selfIssuer = try VerifiableCredentialIssuer(doc!)
            let cb = try selfIssuer.editingVerifiableCredentialFor(did: did)
            
            let props = ["Abc": "Abc",
                         "abc": "abc",
                         "Foobar": "Foobar",
                         "foobar": "foobar",
                         "zoo": "zoo",
                         "Zoo": "Zoo"]
            
            let vc = try cb.withId("#test")
                .withType("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
                .withProperties(props)
                .seal(using: storePassword)
            XCTAssertNotNil(vc)
            
            let db = try doc?.editing()
            _ = try db!.appendCredential(with: vc)
            doc = try! db?.seal(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertEqual(3, doc!.credentialCount)
            try store!.storeDid(using: doc!)
            
            print("Updating DID \(did)...")
            try doc!.publish(using: storePassword)
            print("Update DID \(did)...OK({}s)")
            
            waitForWalletAvaliable()
            resolved = try did.resolve()
            XCTAssertNotEqual(lastTxid, resolved!.getMetadata().transactionId)
            XCTAssertEqual(did, resolved!.subject)
            XCTAssertTrue(try resolved!.isValid())
            XCTAssertEqual(doc!.toString(true), resolved!.toString(true))
            
            lastTxid = resolved!.getMetadata().transactionId
            print("Last transaction id \(String(describing: lastTxid))")
            
            let rr = try did.resolveBiography()
            XCTAssertNotNil(rr)
            XCTAssertEqual(did, rr?.did)
            XCTAssertEqual(DIDBiographyStatus.STATUS_VALID, rr?.status)
            XCTAssertEqual(3, rr?.count)
            let txs = rr?.getAllTransactions()
            XCTAssertNotNil(txs)
            XCTAssertEqual(3, txs!.count)
            
            var tx = txs![0]
            XCTAssertEqual(did, tx.did)
            XCTAssertEqual(IDChainRequestOperation.UPDATE, tx.request.operation)
            XCTAssertTrue(try tx.request.isValid())
            
            tx = txs![1]
            XCTAssertEqual(did, tx.did)
            XCTAssertEqual(IDChainRequestOperation.UPDATE, tx.request.operation)
            XCTAssertTrue(try tx.request.isValid())
            
            tx = txs![2]
            XCTAssertEqual(did, tx.did)
            XCTAssertEqual(IDChainRequestOperation.CREATE, tx.request.operation)
            XCTAssertTrue(try tx.request.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func test_10CreateAndResolveWithCredentialsAsync() {
        do {
            // Create new DID and publish to ID sidechain.
            var doc = try identity!.newDid(storePassword)
            let did = doc.subject
            
            let selfIssuer = try VerifiableCredentialIssuer(doc)
            let cb = try selfIssuer.editingVerifiableCredentialFor(did: did)
            
            let props = ["name": "John",
                         "gender": "Male",
                         "nationality": "Singapore",
                         "language": "English",
                         "email": "john@example.com",
                         "twitter": "@john"]
            
            let vc = try cb.withId("#profile")
                .withType("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
                .withType("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
                .withType("EmailCredential", "https://ns.elastos.org/credentials/email/v1")
                .withType("SocialCredential", "https://ns.elastos.org/credentials/social/v1")
                .withProperties(props)
                .seal(using: storePassword)
            XCTAssertNotNil(vc)
            
            let db = try doc.editing()
            _ = try! db.appendCredential(with: vc)
            doc = try! db.seal(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertEqual(1, doc.credentialCount)
            try! store!.storeDid(using: doc)
            
            print("Publishing new DID \(did)...")
            var resolved: DIDDocument?
            let lock = XCTestExpectation()
            doc.publishAsync(using: storePassword).then{ [self] _ -> Promise<DIDDocument?> in
                print("Publish new DID \(did)...OK({}s)")
                waitForWalletAvaliable()
                return did.resolveAsync(true)
            }.done{ doc in
                resolved = doc
                lock.fulfill()
            }
            .catch{ error in
                XCTFail()
                lock.fulfill()
            }
            wait(for: [lock], timeout: 1000)
            
            XCTAssertEqual(did, resolved!.subject)
            XCTAssertTrue(try resolved!.isValid())
            XCTAssertEqual(doc.toString(true), resolved!.toString(true))
            
            let lastTxid = resolved!.getMetadata().transactionId
            print("Last transaction id \(String(describing: lastTxid))")
            
            IDChainOperationsTest.dids.append(did) // 4
        } catch {
            XCTFail()
        }
    }
    
    func test_11UpdateAndResolveWithCredentialsAsync() {
        do {
            // User the DID that created in previous case(11)
            var doc = try store!.loadDid(IDChainOperationsTest.dids[4])
            XCTAssertNotNil(doc)
            let did = doc!.subject
            var resolved: DIDDocument?
            var lock = XCTestExpectation()
            _ = did.resolveAsync(true).done { doc in
                resolved = doc
                lock.fulfill()
            }
            .catch { error in
                XCTFail()
                lock.fulfill()
            }
            wait(for: [lock], timeout: 1000)
            
            XCTAssertEqual(did, resolved!.subject)
            XCTAssertTrue(try resolved!.isValid())
            XCTAssertEqual(doc?.proof.signature, resolved?.proof.signature)
            var lastTxid = resolved?.getMetadata().transactionId
            print("Last transaction id \(String(describing: lastTxid))")
            
            // Update
            let selfIssuer = try! VerifiableCredentialIssuer(doc!)
            let cb = try selfIssuer.editingVerifiableCredentialFor(did: did)
            
            let props = ["nationality": "Singapore",
                         "passport": "S653258Z07"]
            
            let vc = try cb.withId("#passport")
                .withType("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
                .withProperties(props)
                .seal(using: storePassword)
            XCTAssertNotNil(vc)
            
            let db = try doc?.editing()
            _ = try db!.appendCredential(with: vc)
            doc = try db?.seal(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertEqual(2, doc!.credentialCount)
            try store!.storeDid(using: doc!)
            
            print("Updating DID \(did)...")
            lock = XCTestExpectation()
            doc!.publishAsync(using: storePassword).then{ [self] _ -> Promise<DIDDocument?> in
                print("Update DID \(did)...OK({}s)")
                waitForWalletAvaliable()
                return did.resolveAsync(true)
            }.done { doc in
                resolved = doc
                lock.fulfill()
            }
            .catch { error in
                XCTFail()
                lock.fulfill()
            }
            wait(for: [lock], timeout: 1000)
            
            XCTAssertNotEqual(lastTxid, resolved?.getMetadata().transactionId)
            XCTAssertEqual(did, resolved!.subject)
            XCTAssertTrue(try resolved!.isValid())
            XCTAssertEqual(doc!.toString(true), resolved!.toString(true))
            
            lastTxid = resolved?.getMetadata().transactionId
            print("Last transaction id {}", lastTxid as Any)
        } catch {
            XCTFail()
        }
    }
    
    func test_12UpdateAndResolveWithCredentialsAsyncAgain() {
        do {
            // User the DID that created in previous case(11)
            var doc = try store!.loadDid(IDChainOperationsTest.dids[4])
            XCTAssertNotNil(doc)
            let did = doc!.subject
            var lock = XCTestExpectation()
            var resolved: DIDDocument?
            did.resolveAsync(true).done { doc in
                resolved = doc
                lock.fulfill()
            }
            .catch { error in
                XCTFail()
                lock.fulfill()
            }
            wait(for: [lock], timeout: 1000)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertTrue(try resolved!.isValid())
            XCTAssertEqual(doc?.proof.signature, resolved?.proof.signature)
            var lastTxid = resolved?.getMetadata().transactionId
            print("Last transaction id \(String(describing: lastTxid))")
            
            // Update again
            let selfIssuer = try VerifiableCredentialIssuer(doc!)
            let cb = try selfIssuer.editingVerifiableCredentialFor(did: did)
            
            let props = ["Abc": "Abc",
                         "abc": "abc",
                         "Foobar": "Foobar",
                         "foobar": "foobar",
                         "zoo": "zoo",
                         "Zoo": "Zoo"]
            
            let vc = try cb.withId("#test")
                .withType("SelfProclaimedCredential", "https://elastos.org/credentials/v1")
                .withProperties(props)
                .seal(using: storePassword)
            XCTAssertNotNil(vc)
            
            let db = try doc?.editing()
            _ = try db!.appendCredential(with: vc)
            doc = try db?.seal(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertEqual(3, doc!.credentialCount)
            try store!.storeDid(using: doc!)
            
            print("Updating DID \(did)...")
            lock = XCTestExpectation()
            doc!.publishAsync(using: storePassword).then{ [self] _ -> Promise<DIDDocument?> in
                print("Update DID \(did)...OK({}s)")
                waitForWalletAvaliable()
                return did.resolveAsync(true)
            }.done{ doc in
                resolved = doc
                lock.fulfill()
            }.catch{ error in
                XCTFail()
                lock.fulfill()
            }
            wait(for: [lock], timeout: 1000)
            
            XCTAssertNotEqual(lastTxid, resolved?.getMetadata().transactionId)
            XCTAssertEqual(did, resolved!.subject)
            XCTAssertTrue(try resolved!.isValid())
            XCTAssertEqual(doc!.toString(true), resolved!.toString(true))
            
            lastTxid = resolved?.getMetadata().transactionId
            print("Last transaction id \(String(describing: lastTxid))")
            
            let rr = try did.resolveBiography()
            XCTAssertNotNil(rr)
            XCTAssertEqual(did, rr?.did)
            XCTAssertEqual(DIDBiographyStatus.STATUS_VALID, rr?.status)
            XCTAssertEqual(3, rr?.count)
            let txs = rr?.getAllTransactions()
            XCTAssertNotNil(txs)
            XCTAssertEqual(3, txs?.count)
            
            var tx = txs![0]
            XCTAssertEqual(did, tx.did)
            XCTAssertEqual(IDChainRequestOperation.UPDATE, tx.request.operation)
            XCTAssertTrue(try tx.request.isValid())
            
            tx = txs![1]
            XCTAssertEqual(did, tx.did)
            XCTAssertEqual(IDChainRequestOperation.UPDATE, tx.request.operation)
            XCTAssertTrue(try tx.request.isValid())
            
            tx = txs![2]
            XCTAssertEqual(did, tx.did)
            XCTAssertEqual(IDChainRequestOperation.CREATE, tx.request.operation)
            XCTAssertTrue(try tx.request.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func test_13SyncRootIdentityClean() {
        do {
            let path = tempDir + "/cleanstore"
            TestData.deleteFile(path)
            
            let cleanStore = try DIDStore.open(atPath: path)
            let rootIdentity = try RootIdentity.create(mnemonic,
                                                       passphrase, true, cleanStore, storePassword)
            
            print("Synchronizing from IDChain...")
            try rootIdentity.synchronize()
            print("Synchronize from IDChain...OK({}s)")
            
            let restoredDids = try cleanStore.listDids()
            XCTAssertEqual(5, restoredDids.count)
            
            _ = IDChainOperationsTest.dids
            //create a credential for testing lazy private key
            let did = restoredDids[0]
            let issuer = try VerifiableCredentialIssuer(did, cleanStore)
            
            let props = ["name": "John", "gender": "Male"]
            let cb = try issuer.editingVerifiableCredentialFor(did: did)
            let vc = try cb.withId("#selfCredential")
                .withType("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
                .withProperties(props)
                .seal(using: storePassword)
            let result = vc.subject!.getPropertyAsString(ofName: "name")
            print(result)
            XCTAssertEqual("John", result)
            
            let originalDids = IDChainOperationsTest.dids
            
            XCTAssertEqual(originalDids[0], restoredDids[0])
        } catch {
            XCTFail()
        }
    }
    
    func test_14SyncRootIdentityCleanAsync() {
        do {
            let path = tempDir + "/cleanstore"
            TestData.deleteFile(path)
            
            let cleanStore = try DIDStore.open(atPath: path)
            let rootIdentity = try RootIdentity.create(mnemonic,
                                                       passphrase, true, cleanStore, storePassword)
            
            print("Synchronizing from IDChain...")
            let lock = XCTestExpectation()
            _ = rootIdentity.synchronizeAsync().done{ _ in
                print("Synchronize from IDChain...OK({}s)")
                lock.fulfill()
            }.catch{ error in
                XCTFail()
                lock.fulfill()
            }
            wait(for: [lock], timeout: 1000)
            
            let restoredDids = try cleanStore.listDids()
            XCTAssertEqual(5, restoredDids.count)

            _ = IDChainOperationsTest.dids
        } catch {
            XCTFail()
        }
    }
    
    func test_15SyncRootIdentityWithoutModification() {
        do {
            print("Synchronizing from IDChain...")
            try identity?.synchronize({ (c, l) -> DIDDocument in
                XCTAssertEqual(l.proof.signature, c.proof.signature)
                XCTAssertEqual(l.lastModified, c.lastModified)
                
                l.getMetadata().setPublishTime(c.getMetadata().publishTime!)
                l.getMetadata().setSignature(c.getMetadata().signature!)
                return l
            })
            
            print("Synchronize from IDChain...OK({}s)")
            
            let restoredDids = try store!.listDids()
            XCTAssertEqual(5, restoredDids.count)
            
            _ = IDChainOperationsTest.dids
        } catch {
            XCTFail()
        }
    }
   
    func test_16SyncRootIdentityWithoutModificationAsync() {
        do {
        
             print("Synchronizing from IDChain...")
             
            try identity?.synchronize({ (c, l) -> DIDDocument in
                XCTAssertEqual(l.proof.signature, c.proof.signature)
                XCTAssertEqual(l.lastModified, c.lastModified)
                
                l.getMetadata().setPublishTime(c.getMetadata().publishTime!)
                l.getMetadata().setSignature(c.getMetadata().signature!)
                return l
            })
            
            _ = identity!.synchronizeAsync { (c, l) -> DIDDocument in
                print("Synchronize from IDChain...OK({}s)")

                return c
            }
             
            let restoredDids = try store!.listDids()
             XCTAssertEqual(5, restoredDids.count)
             
            let originalDids = IDChainOperationsTest.dids
             
            XCTAssertEqual(originalDids.count, restoredDids.count)
             
        } catch {
            XCTFail()
        }
    }
    
    func test_17SyncRootIdentityWithLocalModification1() {
        do {
            // Sync to a clean store first
            let path = tempDir + "/cleanstore"
            TestData.deleteFile(path)
            
            let cleanStore = try DIDStore.open(atPath: path)
            let rootIdentity = try RootIdentity.create(mnemonic,
                                                       passphrase, true, cleanStore, storePassword)
            
            print("Synchronizing from IDChain...")
            try rootIdentity.synchronize()
            print("Synchronize from IDChain...OK({}s)")
            
            var restoredDids = try cleanStore.listDids()
            XCTAssertEqual(5, restoredDids.count)
            
            var originalDids = IDChainOperationsTest.dids
            
            // Modify a DID document
            let modifiedDid = IDChainOperationsTest.dids[0]
            var doc = try cleanStore.loadDid(modifiedDid)
            let db = try doc?.editing()
            _ = try db!.appendService(with: "#test1", type: "TestType", endpoint: "http://test.com/")
            doc = try db?.seal(using: storePassword)
            try cleanStore.storeDid(using: doc!)
            let modifiedSignature = doc?.proof.signature
            
            print("Synchronizing again from IDChain...")
            try rootIdentity.synchronize()
            print("Synchronize again from IDChain...OK({}s)")
            
            restoredDids = try cleanStore.listDids()
            XCTAssertEqual(5, restoredDids.count)
            
            originalDids = IDChainOperationsTest.dids
            
            // Should keep the local modified copy after sync
            doc = try cleanStore.loadDid(modifiedDid)
            XCTAssertEqual(modifiedSignature, doc?.proof.signature)
        } catch {
            XCTFail()
        }
     }
        
    func test_18SyncRootIdentityWithLocalModification2() {
        do {
            // Sync to a clean store first
            let path = tempDir + "/cleanstore"
            TestData.deleteFile(path)
            
            let cleanStore = try DIDStore.open(atPath: path)
            let rootIdentity = try RootIdentity.create(mnemonic,
                                                       passphrase, true, cleanStore, storePassword)
            
            print("Synchronizing from IDChain...")
            try rootIdentity.synchronize()
            print("Synchronize from IDChain...OK({}s)")
            
            var restoredDids = try cleanStore.listDids().sorted(by: { (d1, d2) -> Bool in
                return try! d1.compareTo(d2) == ComparisonResult.orderedAscending
            })
            
            XCTAssertEqual(5, restoredDids.count)
            
            var originalDids = IDChainOperationsTest.dids.sorted(by: { (d1, d2) -> Bool in
                return try! d1.compareTo(d2) == ComparisonResult.orderedAscending
            })
            
            // Modify a DID document
            let modifiedDid = IDChainOperationsTest.dids[0]
            var doc = try cleanStore.loadDid(modifiedDid)
            
            let db = try doc?.editing()
            _ = try db?.appendService(with: "#test1", type: "TestType", endpoint: "http://test.com/")
            doc = try db?.seal(using: storePassword)
            try cleanStore.storeDid(using: doc!)
            let modifiedSignature = doc?.signature

            print("Synchronizing again from IDChain...")
            _ = rootIdentity.synchronizeAsync { (c, l) -> DIDDocument in
                return c
            }
            print("Synchronize again from IDChain...OK({}s)")
            
            restoredDids = try cleanStore.listDids().sorted(by: { (d1, d2) -> Bool in
                return try! d1.compareTo(d2) == ComparisonResult.orderedAscending
            })
            XCTAssertEqual(5, restoredDids.count)
            
            originalDids = IDChainOperationsTest.dids.sorted(by: { (d1, d2) -> Bool in
                return try! d1.compareTo(d2) == ComparisonResult.orderedAscending
            })
            
            // Should overwrite the local modified copy with chain copy after sync
            doc = try cleanStore.loadDid(modifiedDid)
            XCTAssertEqual(modifiedSignature, doc?.signature)
        } catch {
            XCTFail()
        }
    }
    
    func test_19SyncRootIdentityWithLocalModificationAsync() {
        do {
            // Sync to a clean store first
            let path = tempDir + "/cleanstore"
            TestData.deleteFile(path)
            
            let cleanStore = try DIDStore.open(atPath: path)
            let rootIdentity = try RootIdentity.create(mnemonic,
                                                       passphrase, true, cleanStore, storePassword)
            
            print("Synchronizing from IDChain...")
            var lock = XCTestExpectation(description: "")
            rootIdentity.synchronizeAsync().done{ _ in
                print("Synchronize from IDChain...OK({}s)")
                lock.fulfill()
            }
            .catch { error in
                XCTFail()
                lock.fulfill()
            }
            wait(for: [lock], timeout: 10000)
            var restoredDids = try cleanStore.listDids()
            XCTAssertEqual(5, restoredDids.count)
            
            var originalDids = IDChainOperationsTest.dids
            
            // Modify a DID document
            let modifiedDid = IDChainOperationsTest.dids[0]
            var doc = try cleanStore.loadDid(modifiedDid)
            let originalSignature = doc?.signature
            
            let db = try doc?.editing()
            _ = try db!.appendService(with: "#test1", type: "TestType", endpoint: "http://test.com/")
            doc = try db?.seal(using: storePassword)
            try cleanStore.storeDid(using: doc!)
            
            print("Synchronizing again from IDChain...")
            
            _ = rootIdentity.synchronizeAsync { (c, l) -> DIDDocument in
                print("Synchronize again from IDChain...OK({}s)")
                return c
            }
            Thread.sleep(forTimeInterval: 60)
            restoredDids = try cleanStore.listDids()
            XCTAssertEqual(5, restoredDids.count)
            
            originalDids = IDChainOperationsTest.dids
            
            //            XCTAssertEqual(originalDids[DID[0]], restoredDids[DID[0]])
            
            // Should overwrite the local modified copy with chain copy after sync
            doc = try cleanStore.loadDid(modifiedDid)
            XCTAssertEqual(originalSignature, doc?.signature)
        } catch {
            XCTFail()
        }
    }
    //    customized DID(create, update, transfer, deactivate), credential(declare, revoke, list)

    func test_20CustomizedWithCreataAndResolve() {
        do {
            // Create normal DID first
            let controller = try identity!.newDid(storePassword)
            XCTAssertTrue(try controller.isValid(debug))

            var resolved = try controller.subject.resolve()
            XCTAssertNil(resolved)

            try controller.publish(using: storePassword);
            waitForWalletAvaliable()
            
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
            waitForWalletAvaliable()

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(controller.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)
        }
        catch {
            print(error)
        }
    }
    
    func test_21CreateMultisigCustomizedDid() {
            do {
                // Create normal DID first
                let ctrl1 = try identity!.newDid(storePassword)
                
                try ctrl1.publish(using: storePassword)
                waitForWalletAvaliable()

                var resolved = try ctrl1.subject.resolve()
                XCTAssertNotNil(resolved)
                XCTAssertEqual(ctrl1.subject, resolved?.subject)
                XCTAssertEqual(ctrl1.proof.signature,
                               resolved?.proof.signature)

                XCTAssertTrue(try resolved!.isValid(debug))

                let ctrl2 = try identity!.newDid(storePassword)
                XCTAssertTrue(try ctrl2.isValid(debug))
                try ctrl2.publish(using: storePassword)
                waitForWalletAvaliable()

                resolved = try ctrl2.subject.resolve()
                XCTAssertNotNil(resolved)
                XCTAssertEqual(ctrl2.subject, resolved?.subject)
                XCTAssertEqual(ctrl2.proof.signature,
                        resolved?.proof.signature)

                XCTAssertTrue(try resolved!.isValid(debug))

                let ctrl3 = try identity!.newDid(storePassword)
                XCTAssertTrue(try ctrl3.isValid(debug))
                try ctrl3.publish(using: storePassword)
                waitForWalletAvaliable()

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
                waitForWalletAvaliable()

                resolved = try did.resolve()
    
        }
        catch {
            print(error)
        }
    }
    
    func test_22UpdateCustomizedDid() {
        do {
            // Create normal DID first
            let controller = try identity!.newDid(storePassword)
            XCTAssertTrue(try controller.isValid(debug))

            var resolved = try controller.subject.resolve();
            XCTAssertNil(resolved)

            try controller.publish(using: storePassword)
            waitForWalletAvaliable()

            resolved = try controller.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(controller.subject, resolved!.subject)
            XCTAssertEqual(controller.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Create customized DID
            let did = try DID("did:elastos:helloworld123")
            var doc = try controller.newCustomizedDid(withId: did, storePassword)
            XCTAssertTrue(try doc.isValid(debug))

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(controller.subject, doc.controller)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.publish(using: storePassword)
            waitForWalletAvaliable()

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
            waitForWalletAvaliable()

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
            waitForWalletAvaliable()

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_23UpdateMultisigCustomizedDid() {
        do {
            // Create normal DID first
            let ctrl1 = try identity!.newDid(storePassword)
            XCTAssertTrue(try ctrl1.isValid(debug))
            try ctrl1.publish(using: storePassword)
            waitForWalletAvaliable()

            var resolved = try ctrl1.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl1.subject, resolved?.subject)
            XCTAssertEqual(ctrl1.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            let ctrl2 = try identity!.newDid(storePassword)
            XCTAssertTrue(try ctrl2.isValid(debug))
            try ctrl2.publish(using: storePassword)
            waitForWalletAvaliable()

            resolved = try ctrl2.subject.resolve();
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl2.subject, resolved?.subject)
            XCTAssertEqual(ctrl2.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            let ctrl3 = try identity!.newDid(storePassword)
            XCTAssertTrue(try ctrl3.isValid(debug))
            try ctrl3.publish(using: storePassword)
            waitForWalletAvaliable()

            resolved = try ctrl3.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl3.subject, resolved?.subject)
            XCTAssertEqual(ctrl3.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Create customized DID
            let did = try DID("did:elastos:helloworld321")
            var doc = try ctrl1.newCustomizedDid(withId: did, [ctrl2.subject, ctrl3.subject],
                    2, storePassword)
            XCTAssertFalse(try doc.isValid(debug))

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
            waitForWalletAvaliable()

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
            waitForWalletAvaliable()

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
            waitForWalletAvaliable()

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())
            XCTAssertEqual(5, resolved?.publicKeyCount)
            XCTAssertEqual(5, resolved?.authenticationKeyCount)
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_24TransferCustomizedDidAfterCreate() {
        do {
            // Create normal DID first
            let controller = try identity!.newDid(storePassword)
            XCTAssertTrue(try controller.isValid(debug))

            var resolved = try controller.subject.resolve()
            XCTAssertNil(resolved)

            try controller.publish(using: storePassword)
            waitForWalletAvaliable()

            resolved = try controller.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(controller.subject, resolved?.subject)
            XCTAssertEqual(controller.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Create customized DID
            let did = try DID("did:elastos:helloworld1234")
            var doc = try controller.newCustomizedDid(withId: did, storePassword)
            XCTAssertTrue(try doc.isValid(debug))

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(controller.subject, doc.controller)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.publish(using: storePassword);
            waitForWalletAvaliable()

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(controller.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // create new controller
            let newController = try identity!.newDid(storePassword)
            XCTAssertTrue(try controller.isValid(debug))

            resolved = try newController.subject.resolve()
            XCTAssertNil(resolved)

            try newController.publish(using: storePassword)
            waitForWalletAvaliable()

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
            waitForWalletAvaliable()

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(newController.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func test_25TransferCustomizedDidAfterUpdate() {
        do {
            // Create normal DID first
            let controller = try identity!.newDid(storePassword)
            XCTAssertTrue(try controller.isValid(debug))

            var resolved = try controller.subject.resolve()
            XCTAssertNil(resolved)

            try controller.publish(using: storePassword)
            waitForWalletAvaliable()

            resolved = try controller.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(controller.subject, resolved?.subject)
            XCTAssertEqual(controller.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Create customized DID
            let did = try DID("did:elastos:helloworld98")
            var doc = try controller.newCustomizedDid(withId: did, storePassword)
            XCTAssertTrue(try doc.isValid(debug))

            XCTAssertEqual(did, doc.subject)
            XCTAssertEqual(controller.subject, doc.controller)

            resolved = try did.resolve()
            XCTAssertNil(resolved)

            try doc.publish(using: storePassword)
            waitForWalletAvaliable()

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
            waitForWalletAvaliable()

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())

            // create new controller
            let newController = try identity!.newDid(storePassword)
            XCTAssertTrue(try controller.isValid(debug))

            resolved = try newController.subject.resolve()
            XCTAssertNil(resolved)

            try newController.publish(using: storePassword)
            waitForWalletAvaliable()

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
            waitForWalletAvaliable()

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(newController.subject, resolved?.controller)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))
        } catch {
            print(error)
            XCTFail()
        }
    }
   
    func test_27TransferMultisigCustomizedDidAfterUpdate() {
        do {
            // Create normal DID first
            let ctrl1 = try identity!.newDid(storePassword)
            XCTAssertTrue(try ctrl1.isValid(debug))
            try ctrl1.publish(using: storePassword)
            waitForWalletAvaliable()

            var resolved = try ctrl1.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl1.subject, resolved?.subject)
            XCTAssertEqual(ctrl1.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            let ctrl2 = try identity!.newDid(storePassword)
            XCTAssertTrue(try ctrl2.isValid(debug))
            try  ctrl2.publish(using: storePassword)
            waitForWalletAvaliable()

            resolved = try ctrl2.subject.resolve()
            XCTAssertNotNil(resolved);
            XCTAssertEqual(ctrl2.subject, resolved?.subject)
            XCTAssertEqual(ctrl2.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

               let ctrl3 = try identity!.newDid(storePassword)
            XCTAssertTrue(try ctrl3.isValid(debug))
            try ctrl3.publish(using: storePassword)
            waitForWalletAvaliable()

            resolved = try ctrl3.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(ctrl3.subject, resolved?.subject)
            XCTAssertEqual(ctrl3.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))

            // Create customized DID
            let did = try DID("did:elastos:helloworld3781")
            var doc = try ctrl1.newCustomizedDid(withId: did, [ctrl2.subject, ctrl3.subject], 2, storePassword)
            XCTAssertFalse(try doc.isValid(debug))

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
            waitForWalletAvaliable()

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
            waitForWalletAvaliable()

            resolved = try doc.subject.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(doc.toString(), resolved?.toString())
            XCTAssertEqual(4, resolved?.publicKeyCount)
            XCTAssertEqual(4, resolved?.authenticationKeyCount)

            // new controllers for the did
            let td = IDChainOperationsTest.testData.sharedInstantData()
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
            waitForWalletAvaliable()

            resolved = try did.resolve()
            XCTAssertNotNil(resolved)

            XCTAssertEqual(did, resolved?.subject)
            XCTAssertEqual(doc.proof.signature,
                    resolved?.proof.signature)

            XCTAssertTrue(try resolved!.isValid(debug))
        } catch {
            print(error)
            XCTFail()
        }
    }
}

