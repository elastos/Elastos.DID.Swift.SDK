import XCTest
@testable import ElastosDIDSDK
import PromiseKit

class IDChainOperationsTest: XCTestCase {
    let testData: TestData = TestData()
    var dids: [DID] = []
    
    var store:  DIDStore?
    var mnemonic: String = ""
    var identity: RootIdentity?
    
    override func setUp() {
        store = testData.store
        mnemonic = testData.mnemonic
        identity = try! testData.getRootIdentity()
        
        try! testData.waitForWalletAvaliable()
    }
    
    override func tearDown() {
        testData.cleanup()
    }
    
    func testCreateAndResolve() {
        do {
            // Create new DID and publish to ID sidechain.
            let doc = try identity!.newDid(storePassword)
            let did = doc.subject
            
            print("Publishing new DID \(did.toString())...")
            try doc.publish(storePassword)
            print("Publish new DID \(did.toString())...OK({}s)")
            
            try testData.waitForWalletAvaliable()
            let resolved = try did.resolve()
            XCTAssertNotNil(resolved)
            XCTAssertEqual(did, resolved?.subject)
            XCTAssertTrue(try resolved!.isValid())
            XCTAssertEqual(doc.toString(true), resolved!.toString(true))
            
            dids.append(did) // 0
            
        } catch {
            XCTFail()
        }
    }
    
    func testCreateAndResolveAsync() {
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
            try testData.waitForWalletAvaliable()
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
            
            dids.append(did) // 1
        } catch {
            XCTFail()
        }
    }
    
    func testCreateAndResolveAsync2() {
        do {
            // Create new DID and publish to ID sidechain.
            let doc = try identity!.newDid(storePassword)
            let did = doc.subject
            let lock = XCTestExpectation()
            print("Publishing new DID and resolve \(did)...")
            
            doc.publishAsync(storePassword).then{ [self] _ -> Promise<DIDDocument?> in
                try? testData.waitForWalletAvaliable()
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
            
            dids.append(did) // 2
        } catch {
            XCTFail()
        }
    }
    
    func testUpdateAndResolve() {
        do {
            // User the DID that created in previous case(1)
            var doc = try store!.loadDid(dids[0])
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
            
            try testData.waitForWalletAvaliable()
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
    
    func testUpdateAndResolveAgain() {
        do {
            // User the DID that created in previous case(1)
            var doc = try store!.loadDid(dids[0])
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
            
            try testData.waitForWalletAvaliable()
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
    
    func testUpdateAndResolveAsync() {
        do {
            // User the DID that created in previous case(2)
            var doc = try store!.loadDid(dids[1])
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
                try? testData.waitForWalletAvaliable()
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
    
    func testUpdateAndResolveAsyncAgain() {
        do {
            // User the DID that created in previous case(2)
            var doc = try store!.loadDid(dids[1])
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
                try? testData.waitForWalletAvaliable()
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
    
    func testCreateAndResolveWithCredentials() {
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
            
            try testData.waitForWalletAvaliable()
            let resolved = try did.resolve()
            XCTAssertEqual(did, resolved!.subject)
            XCTAssertTrue(try resolved!.isValid())
            XCTAssertEqual(doc.toString(true), resolved!.toString(true))
            
            let lastTxid = resolved!.getMetadata().transactionId
            print("Last transaction id \(String(describing: lastTxid))")
            
            dids.append(did) // 3
        } catch {
            XCTFail()
        }
    }
    
    func testUpdateAndResolveWithCredentials() {
        
        do {
            // User the DID that created in previous case(8)
            var doc = try store!.loadDid(dids[3])
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
            
            try testData.waitForWalletAvaliable()
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
    
    func testUpdateAndResolveWithCredentialsAgain() {
        do {
            // User the DID that created in previous case(8)
            var doc = try store!.loadDid(dids[3])
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
            
            try testData.waitForWalletAvaliable()
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
    
    func testCreateAndResolveWithCredentialsAsync() {
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
                try? testData.waitForWalletAvaliable()
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
            
            dids.append(did) // 4
        } catch {
            XCTFail()
        }
    }
    
    func testUpdateAndResolveWithCredentialsAsync() {
        do {
            // User the DID that created in previous case(11)
            var doc = try store!.loadDid(dids[4])
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
                try? testData.waitForWalletAvaliable()
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
    
    func testUpdateAndResolveWithCredentialsAsyncAgain() {
        do {
            // User the DID that created in previous case(11)
            var doc = try store!.loadDid(dids[4])
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
                try? testData.waitForWalletAvaliable()
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
    
    func testSyncRootIdentityClean() {
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
            //            Collections.sort(restoredDids)
            
            _ = dids
            //            Collections.sort(originalDids)
            //            XCTAssertEqual(originalDids.toArray(DID[0]), restoredDids.toArray(DID[0]))
        } catch {
            XCTFail()
        }
    }
    
    func testSyncRootIdentityCleanAsync() {
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
            //        Collections.sort(restoredDids)
            
            _ = dids
            //        Collections.sort(originalDids)
            
            //        XCTAssertEqual(originalDids.toArray(DID[0]), restoredDids.toArray(DID[0]))
        } catch {
            XCTFail()
        }
    }
    
    func testSyncRootIdentityWithoutModification() {
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
            //            Collections.sort(restoredDids)
            
            _ = dids
            //            Collections.sort(originalDids)
            
            //            XCTAssertEqual(originalDids.toArray(DID[0]), restoredDids.toArray(DID[0]))
        } catch {
            XCTFail()
        }
    }
    
    func testSyncRootIdentityWithoutModificationAsync() {
        do {
            /*
             print("Synchronizing from IDChain...")
             
             let ch: ConflictHandler = (c, l) -> {
             XCTAssertEqual(l.getProof().getSignature(), c.getProof().getSignature())
             XCTAssertEqual(l.getLastModified(), c.getLastModified())
             
             l.getMetadata().setPublishTime(c.getMetadata().getPublishTime())
             l.getMetadata().setSignature(c.getMetadata().getSignature())
             return l
             }
             
             CompletableFuture<Void> f = identity.synchronizeAsync(ch)
             .thenRun(() -> {
             long duration = (System.currentTimeMillis() - start + 500) / 1000
             print("Synchronize from IDChain...OK({}s)", duration)
             })
             
             f.join()
             
             List<DID> restoredDids = new ArrayList<DID>(store.listDids())
             XCTAssertEqual(5, restoredDids.size())
             Collections.sort(restoredDids)
             
             List<DID> originalDids = new ArrayList<DID>(dids)
             Collections.sort(originalDids)
             
             assertArrayEquals(originalDids.toArray(new DID[0]),
             restoredDids.toArray(new DID[0]))
             */
        } catch {
            XCTFail()
        }
    }
    
    func testSyncRootIdentityWithLocalModification1() {
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
            //            Collections.sort(restoredDids)
            
            var originalDids = dids
            //            Collections.sort(originalDids)
            
            //            XCTAssertEqual(originalDids[DID[0]],
            //                              restoredDids[DID[0]])
            
            // Modify a DID document
            let modifiedDid = dids[0]
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
            //            Collections.sort(restoredDids)
            
            originalDids = dids
            //            Collections.sort(originalDids)
            
            //            XCTAssertEqual(originalDids[DID[0]],
            //                              restoredDids[DID[0]])
            
            // Should keep the local modified copy after sync
            doc = try cleanStore.loadDid(modifiedDid)
            XCTAssertEqual(modifiedSignature, doc?.proof.signature)
        } catch {
            XCTFail()
        }
        
        func testSyncRootIdentityWithLocalModification2() {
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
                
                var originalDids = dids
                
                //                assertArrayEquals(originalDids[DID[0],
                //                                  restoredDids[DID[0]])
                
                // Modify a DID document
                let modifiedDid = dids[0]
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
                
                originalDids = dids
                
                //                XCTAssertEqual(originalDids[DID[0]],
                //                                  restoredDids[DID[0]])
                
                // Should overwrite the local modified copy with chain copy after sync
                doc = try cleanStore.loadDid(modifiedDid)
                XCTAssertEqual(originalSignature, doc?.signature)
            } catch {
                XCTFail()
            }
        }
        
        func testSyncRootIdentityWithLocalModificationAsync() {
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
                
                var originalDids = dids
                
                //            XCTAssertEqual(originalDids[DID[0]], restoredDids[DID[0]])
                
                // Modify a DID document
                let modifiedDid = dids[0]
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
                
                originalDids = dids
                
                //            XCTAssertEqual(originalDids[DID[0]], restoredDids[DID[0]])
                
                // Should overwrite the local modified copy with chain copy after sync
                doc = try cleanStore.loadDid(modifiedDid)
                XCTAssertEqual(originalSignature, doc?.signature)
            } catch {
                XCTFail()
            }
        }
    }
}
   
