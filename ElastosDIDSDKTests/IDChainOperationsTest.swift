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
    
    override func setUp() {
        adapter = Web3Adapter("http://52.80.107.251:1111", "0xEA2256bd30cfeC643203d1a6f36A90A4fD17863E", "", "password")
        try! DIDBackend.initialize(adapter!)

        store = IDChainOperationsTest.testData.store
        print(self.store as Any)
        identity = try! IDChainOperationsTest.testData.getRootIdentity()
        mnemonic = IDChainOperationsTest.testData.mnemonic
        waitForWalletAvaliable()
    }
    
    override func tearDown() {
//        IDChainOperationsTest.testData.cleanup()
    }
    
    func waitForWalletAvaliable() {
        while true {
            Thread.sleep(forTimeInterval: 30)
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

    func test_00CreateAndResolve() {
        do {
            // Create new DID and publish to ID sidechain.
            let doc = try identity!.newDid(storePassword)
            let did = doc.subject
            
            print("Publishing new DID \(did.toString())...")
            try doc.publish(storePassword)
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
            doc.publishAsync(storePassword).done{ _ in
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
            
            doc.publishAsync(storePassword).then{ [self] _ -> Promise<DIDDocument?> in
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
            doc = try db.sealed(using: storePassword)
            XCTAssertEqual(2, doc?.publicKeyCount)
            XCTAssertEqual(2, doc!.authenticationKeyCount)
            try store?.storeDid(using: doc!)
            
            print("Updating DID \(did)...")
            try doc!.publish(storePassword)
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
            doc = try db?.sealed(using: storePassword)
            XCTAssertEqual(3, doc?.publicKeyCount)
            XCTAssertEqual(3, doc!.authenticationKeyCount)
            try store!.storeDid(using: doc!)
            
            print("Updating DID \(did)...")
            try doc!.publish(storePassword)
            
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
            let rf = did.resolveAsync(true).done { doc in
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
            var lastTxid = resolved?.getMetadata().transactionId
            print("Last transaction id \(String(describing: lastTxid))")
            
            // Update
            let db = try doc?.editing()
            let key = try TestData.generateKeypair()
            _ = try! db!.appendAuthenticationKey(with: "#key1", keyBase58: key.getPublicKeyBase58())
            doc = try db?.sealed(using: storePassword)
            XCTAssertEqual(2, doc!.publicKeyCount)
            XCTAssertEqual(2, doc!.authenticationKeyCount)
            try store!.storeDid(using: doc!)
            
            print("Updating DID \(did)...")
            lock = XCTestExpectation()
            doc!.publishAsync(storePassword).then{ [self] _ -> Promise<DIDDocument?> in
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
            doc = try db?.sealed(using: storePassword)
            XCTAssertEqual(3, doc!.publicKeyCount)
            XCTAssertEqual(3, doc!.authenticationKeyCount)
            try store!.storeDid(using: doc!)
            
            print("Updating DID \(did)...")
            lock = XCTestExpectation()
            doc!.publishAsync(storePassword).then{ [self] _ -> Promise<DIDDocument?> in
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
            let cb = selfIssuer.editingVerifiableCredentialFor(did: did)
            
            let props = ["name": "John",
                         "gender": "Male",
                         "nation": "Singapore",
                         "language": "English",
                         "email": "john@example.com",
                         "twitter": "@john"]
            
            let vc = try cb.withId("#profile")
                .withTypes("BasicProfileCredential", "SelfProclaimedCredential")
                .withProperties(props)
                .sealed(using: storePassword)
            XCTAssertNotNil(vc)
            
            let db = try doc.editing()
            _ = try db.appendCredential(with: vc)
            doc = try db.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertEqual(1, doc.credentialCount)
            try store!.storeDid(using: doc)
            
            print("Publishing new DID \(did)...")
            try doc.publish(storePassword)
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
            let cb = selfIssuer.editingVerifiableCredentialFor(did: did)
            
            let props = ["nation": "Singapore",
                         "passport": "S653258Z07"]
            
            let vc = try cb.withId("#passport")
                .withTypes("BasicProfileCredential", "SelfProclaimedCredential")
                .withProperties(props)
                .sealed(using: storePassword)
            XCTAssertNotNil(vc)
            
            let db = try doc?.editing()
            _ = try db!.appendCredential(with: vc)
            doc = try db?.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertEqual(2, doc!.credentialCount)
            try store!.storeDid(using: doc!)
            
            print("Updating DID {}...", did)
            try doc!.publish(storePassword)
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
            let cb = selfIssuer.editingVerifiableCredentialFor(did: did)
            
            let props = ["Abc": "Abc",
                         "abc": "abc",
                         "Foobar": "Foobar",
                         "foobar": "foobar",
                         "zoo": "zoo",
                         "Zoo": "Zoo"]
            
            let vc = try cb.withId("#test")
                .withTypes("TestCredential", "SelfProclaimedCredential")
                .withProperties(props)
                .sealed(using: storePassword)
            XCTAssertNotNil(vc)
            
            let db = try doc?.editing()
            _ = try db!.appendCredential(with: vc)
            doc = try! db?.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertEqual(3, doc!.credentialCount)
            try store!.storeDid(using: doc!)
            
            print("Updating DID \(did)...")
            try doc!.publish(storePassword)
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
            let cb = selfIssuer.editingVerifiableCredentialFor(did: did)
            
            let props = ["name": "John",
                         "gender": "Male",
                         "nation": "Singapore",
                         "language": "English",
                         "email": "john@example.com",
                         "twitter": "@john"]
            
            let vc = try cb.withId("#profile")
                .withTypes("BasicProfileCredential", "SelfProclaimedCredential")
                .withProperties(props)
                .sealed(using: storePassword)
            XCTAssertNotNil(vc)
            
            let db = try doc.editing()
            _ = try! db.appendCredential(with: vc)
            doc = try! db.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertEqual(1, doc.credentialCount)
            try! store!.storeDid(using: doc)
            
            print("Publishing new DID \(did)...")
            var resolved: DIDDocument?
            let lock = XCTestExpectation()
            doc.publishAsync(storePassword).then{ [self] _ -> Promise<DIDDocument?> in
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
            let cb = selfIssuer.editingVerifiableCredentialFor(did: did)
            
            let props = ["nation": "Singapore",
                         "passport": "S653258Z07"]
            
            let vc = try cb.withId("#passport")
                .withTypes("BasicProfileCredential", "SelfProclaimedCredential")
                .withProperties(props)
                .sealed(using: storePassword)
            XCTAssertNotNil(vc)
            
            let db = try doc?.editing()
            _ = try db!.appendCredential(with: vc)
            doc = try db?.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertEqual(2, doc!.credentialCount)
            try store!.storeDid(using: doc!)
            
            print("Updating DID \(did)...")
            lock = XCTestExpectation()
            doc!.publishAsync(storePassword).then{ [self] _ -> Promise<DIDDocument?> in
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
            let cb = selfIssuer.editingVerifiableCredentialFor(did: did)
            
            let props = ["Abc": "Abc",
                         "abc": "abc",
                         "Foobar": "Foobar",
                         "foobar": "foobar",
                         "zoo": "zoo",
                         "Zoo": "Zoo"]
            
            let vc = try cb.withId("#test")
                .withTypes("TestCredential", "SelfProclaimedCredential")
                .withProperties(props)
                .sealed(using: storePassword)
            XCTAssertNotNil(vc)
            
            let db = try doc?.editing()
            _ = try db!.appendCredential(with: vc)
            doc = try db?.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertEqual(3, doc!.credentialCount)
            try store!.storeDid(using: doc!)
            
            print("Updating DID \(did)...")
            lock = XCTestExpectation()
            doc!.publishAsync(storePassword).then{ [self] _ -> Promise<DIDDocument?> in
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
            doc = try db?.sealed(using: storePassword)
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
            
            var restoredDids = try cleanStore.listDids()
            XCTAssertEqual(5, restoredDids.count)
            
            var originalDids = IDChainOperationsTest.dids
            
            // Modify a DID document
            let modifiedDid = IDChainOperationsTest.dids[0]
            var doc = try cleanStore.loadDid(modifiedDid)
            let originalSignature = doc?.signature
            
            let db = try doc?.editing()
            _ = try db?.appendService(with: "#Stest1", type: "TestType", endpoint: "http://test.com/")
            doc = try db?.sealed(using: storePassword)
            try cleanStore.storeDid(using: doc!)
            
            print("Synchronizing again from IDChain...")
            _ = rootIdentity.synchronizeAsync { (c, l) -> DIDDocument in
                return c
            }
            print("Synchronize again from IDChain...OK({}s)")
            
            restoredDids = try cleanStore.listDids()
            XCTAssertEqual(5, restoredDids.count)
            
            originalDids = IDChainOperationsTest.dids

            // Should overwrite the local modified copy with chain copy after sync
            doc = try cleanStore.loadDid(modifiedDid)
            XCTAssertEqual(originalSignature, doc?.signature)
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
            rootIdentity.synchronizeAsync().done{ _ in
                print("Synchronize from IDChain...OK({}s)")
            }
            .catch { error in
                XCTFail()
            }
            
            var restoredDids = try cleanStore.listDids()
            XCTAssertEqual(5, restoredDids.count)
            
            var originalDids = IDChainOperationsTest.dids
            
            //            XCTAssertEqual(originalDids[DID[0]], restoredDids[DID[0]])
            
            // Modify a DID document
            let modifiedDid = IDChainOperationsTest.dids[0]
            var doc = try cleanStore.loadDid(modifiedDid)
            let originalSignature = doc?.signature
            
            let db = try doc?.editing()
            _ = try db!.appendService(with: "#test1", type: "TestType", endpoint: "http://test.com/")
            doc = try db?.sealed(using: storePassword)
            try cleanStore.storeDid(using: doc!)
            
            print("Synchronizing again from IDChain...")
            _ = rootIdentity.synchronizeAsync { (c, l) -> DIDDocument in
                print("Synchronize again from IDChain...OK({}s)")
                return c
            }
            
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

}

