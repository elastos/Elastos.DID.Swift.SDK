
import XCTest
@testable import ElastosDIDSDK

class DIDStoreTests: XCTestCase {
    var testData: TestData!
    var store: DIDStore?
    var simulatedIDChain: SimulatedIDChain = SimulatedIDChain()

    override func setUp() {
        testData = TestData()
        store = testData.store!
//        try! simulatedIDChain.httpServer.start(in_port_t(DEFAULT_PORT), forceIPv4: true)
//        simulatedIDChain.start()
        let adapter = SimulatedIDChainAdapter("http://localhost:\(DEFAULT_PORT)/")
        try! DIDBackend.initialize(adapter)
    }
    
    override func tearDown() {
        testData.reset()
        testData.cleanup()
    }
    
    func getFile(_ path: String) -> String {
        var relPath = storeRoot
        relPath.append("/")
        relPath.append("data/")
        relPath.append(path)
        
        return relPath
    }
    
    func testSynchronizeStore() {
        do {
            let identity = try testData.getRootIdentity()

            for i in 0...5 {
                let alias = "my did \(i)"
                let doc = try identity.newDid(storePassword)
                doc.getMetadata().setAlias(alias)
                XCTAssertTrue(try doc.isValid())

                var resolved = try doc.subject.resolve()
                XCTAssertNil(resolved)

                try doc.publish(using: storePassword)
                resolved = try doc.subject.resolve()
                XCTAssertNotNil(resolved)
            }

            let store = testData.store
            let dids = try store!.listDids()
            //            Collections.sort(dids);
            for did in dids {
                let success = store!.deleteDid(did)
                XCTAssertTrue(success)
            }

            let empty = try store!.listDids()
            XCTAssertTrue(empty.isEmpty)

            try store!.synchronize()
            let syncedDids = try store!.listDids()
            //            Collections.sort(syncedDids)
            XCTAssertEqual(dids.count, syncedDids.count)
            //            assertArrayEquals(dids.toArray(), syncedDids.toArray());
        } catch {
            XCTFail()
        }
    }

    func testLoadRootIdentityFromEmptyStore() {
        do {
            let file = getFile(".metadata")
            XCTAssertTrue(try file.exists())

            let identity = try store!.loadRootIdentity()
            XCTAssertNil(identity)
        } catch {
            XCTFail()
        }
    }
    
    func testBulkCreate() {
        do {
            var file = getFile(".metadata")
            XCTAssertTrue(try file.exists())

            let identity = try testData.getRootIdentity()

            file = try getFile(("roots/" + identity.getId() + "/mnemonic"))
            XCTAssertTrue(try file.exists())

            file = try getFile("roots/" + identity.getId() + "/private")
            XCTAssertTrue(try file.exists())

            file = try getFile("roots/" + identity.getId() + "/public")
            XCTAssertTrue(try file.exists())

            file = try getFile("roots/" + identity.getId() + "/index")
            XCTAssertTrue(try file.exists())

            file = try getFile("roots/" + identity.getId() + "/.metadata")
            XCTAssertFalse(try file.exists())

            identity.alias = "default"
            file = try getFile("roots/" + identity.getId() + "/.metadata")
            XCTAssertTrue(try file.exists())

            for i in 0..<100 {
                let alias = "my did \(i)"
                let doc = try identity.newDid(storePassword)
                doc.getMetadata().setAlias(alias)
                XCTAssertTrue(try doc.isValid())

                var resolved = try doc.subject.resolve()
                XCTAssertNil(resolved)

                try doc.publish(using: storePassword)

                file = getFile("ids/" + doc.subject.methodSpecificId +  "/document")
                XCTAssertTrue(try file.exists())

                file = getFile("ids/" + doc.subject.methodSpecificId + "/.metadata")
                XCTAssertTrue(try file.exists())

                resolved = try doc.subject.resolve()
                XCTAssertNotNil(resolved)
                try store!.storeDid(using: resolved!)
                XCTAssertEqual(alias, resolved!.getMetadata().getAlias())
                XCTAssertEqual(doc.subject, resolved?.subject)
                XCTAssertEqual(doc.proof.signature,
                        resolved?.proof.signature)

                XCTAssertTrue(try resolved!.isValid())
            }

            let dids = try store!.listDids()
            XCTAssertEqual(100, dids.count)
        } catch {
            XCTFail()
        }
    }
    
    func testDeleteDID() {
        do {
            let identity = try testData.getRootIdentity();
            
            // Create test DIDs
            var dids: [DID] = []
            for i in 0...100 {
                let alias = "my did \(i)"
                let doc = try identity.newDid(storePassword)
                doc.getMetadata().setAlias(alias)
                try doc.publish(using: storePassword)
                 dids.append(doc.subject)
            }

            for i in 0...100  {
                if (i % 5 != 0) {
                    continue
                }

                let did = dids[i]

                var deleted = store!.deleteDid(did)
                XCTAssertTrue(deleted)

                let file = getFile("ids/" + did.methodSpecificId)
                XCTAssertFalse(try file.exists())

                deleted = store!.deleteDid(did)
                XCTAssertFalse(deleted)
            }

            let remains = try store!.listDids()
            XCTAssertEqual(80, remains.count)
        } catch {
            XCTFail()
        }
    }
    
    func testStoreAndLoadDID() {
        do {
            // Store test data into current store
            let issuer = try testData.sharedInstantData().getIssuerDocument()

            var file = getFile("ids/" + issuer.subject.methodSpecificId +
                    "/document")
            XCTAssertTrue(try file.exists())

            file = getFile("ids/" + issuer.subject.methodSpecificId +
                    "/.metadata")
            XCTAssertTrue(try file.exists())

            let test = try testData.sharedInstantData().getUser1Document()

            file = getFile("ids/" + test.subject.methodSpecificId +
                    "/document")
            XCTAssertTrue(try file.exists())

            file = getFile("ids/" + test.subject.methodSpecificId +
                    "/.metadata")
            XCTAssertTrue(try file.exists())

            var doc = try store!.loadDid(issuer.subject)
            XCTAssertEqual(issuer.subject, doc?.subject)
            XCTAssertEqual(issuer.proof.signature, doc?.proof.signature)
            XCTAssertTrue(try doc!.isValid())

            doc = try store!.loadDid(test.subject.toString())
            XCTAssertEqual(test.subject, doc?.subject)
            XCTAssertEqual(test.proof.signature, doc?.proof.signature)
            XCTAssertTrue(try doc!.isValid())

            let dids = try store!.listDids()
            XCTAssertEqual(2, dids.count)
        } catch {
            XCTFail()
        }
    }
    
    func testLoadCredentials() {
        do {
            // Store test data into current store
            _ = try testData.sharedInstantData().getIssuerDocument()
            let user = try testData.sharedInstantData().getUser1Document()

            var vc = try user.credential(ofId: "#profile")
            vc!.getMetadata().setAlias("MyProfile")
            
            var path = "ids/" + vc!.id!.did!.methodSpecificId + "/credentials/#" + vc!.id!.fragment! + "/credential"

            var file = getFile(path)
            XCTAssertTrue(try file.exists())

            path = "ids/" + vc!.id!.did!.methodSpecificId + "/credentials/#" + vc!.id!.fragment! + "/.metadata"
            file = getFile(path)
            XCTAssertTrue(try file.exists())

            vc = try user.credential(ofId: "#email")
              vc!.getMetadata().setAlias("Email")
            
            path = "ids/" + vc!.id!.did!.methodSpecificId + "/credentials/#" + vc!.id!.fragment! + "/credential"
            file = getFile(path)
            XCTAssertTrue(try file.exists())

            path = "ids/" + vc!.id!.did!.methodSpecificId + "/credentials/#" + vc!.id!.fragment! + "/.metadata"

            file = getFile(path)
            XCTAssertTrue(try file.exists())

            vc = try testData.sharedInstantData().getUser1TwitterCredential()
            vc!.getMetadata().setAlias("Twitter")

            path = "ids/" + vc!.id!.did!.methodSpecificId + "/credentials/#" + vc!.id!.fragment! + "/credential"
            file = getFile(path)
            XCTAssertTrue(try file.exists())

            path = "ids/" + vc!.id!.did!.methodSpecificId + "/credentials/#" + vc!.id!.fragment! + "/.metadata"
            file = getFile(path)
            XCTAssertTrue(try file.exists())

            vc = try testData.sharedInstantData().getUser1PassportCredential()
            vc!.getMetadata().setAlias("Passport")

            path = "ids/" + vc!.id!.did!.methodSpecificId + "/credentials/#" + vc!.id!.fragment! + "/credential"
            file = getFile(path)
            XCTAssertTrue(try file.exists())

            path = "ids/" + vc!.id!.did!.methodSpecificId + "/credentials/#" + vc!.id!.fragment! + "/.metadata"
            file = getFile(path)
            XCTAssertTrue(try file.exists())

            var id =  try DIDURL(user.subject, "#profile")
            vc = try store!.loadCredential(byId: id)
            XCTAssertEqual("MyProfile", vc!.getMetadata().getAlias())
            XCTAssertEqual(user.subject, vc!.subject!.did)
            XCTAssertEqual(id, vc!.getId())
            XCTAssertTrue(try vc!.isValid())

            // try with full id string
            vc = try store!.loadCredential(byId: id.toString())
            XCTAssertNotNil(vc)
            XCTAssertEqual("MyProfile", vc?.getMetadata().getAlias())
            XCTAssertEqual(user.subject, vc?.subject?.did)
            XCTAssertEqual(id, vc?.id)
            XCTAssertTrue(try vc!.isValid())

            id = try DIDURL(user.subject, "#twitter")
            vc = try store!.loadCredential(byId: id.toString())
            XCTAssertNotNil(vc)
            XCTAssertEqual("Twitter", vc!.getMetadata().getAlias())
            XCTAssertEqual(user.subject, vc?.subject?.did)
            XCTAssertEqual(id, vc?.id)
            XCTAssertTrue(try vc!.isValid())

            vc = try store!.loadCredential(byId: DIDURL(user.subject, "#notExist"))
            XCTAssertNil(vc)

            id = try DIDURL(user.subject, "#twitter")
            XCTAssertTrue(try store!.containsCredential(id))
            XCTAssertTrue(try store!.containsCredential(id.toString()))
            XCTAssertFalse(try store!.containsCredential(DIDURL(user.subject, "#notExists")))
        } catch {
            XCTFail()
        }
    }
    
    func testListCredentials() {
        do {
            _ = try testData.getRootIdentity()
            
            // Store test data into current store
            _ = try testData.sharedInstantData().getIssuerDocument()
            let user = try testData.sharedInstantData().getUser1Document()
            var vc = try user.credential(ofId: "#profile")
            vc!.getMetadata().setAlias("MyProfile")
            vc = try user.credential(ofId: "#email")
            vc!.getMetadata().setAlias("Email")
            vc = try testData.sharedInstantData().getUser1TwitterCredential()
            vc!.getMetadata().setAlias("Twitter")
            vc = try testData.sharedInstantData().getUser1PassportCredential()
            vc!.getMetadata().setAlias("Passport")
            
            let vcs = try store!.listCredentials(for: user.subject)
            XCTAssertEqual(4, vcs.count)
            
            for id in vcs {
                XCTAssertTrue(id.fragment == "profile"
                                || id.fragment == "email"
                                || id.fragment == "twitter"
                                || id.fragment == "passport")
                
                XCTAssertTrue(id.getMetadata().getAlias() == "MyProfile"
                                || id.getMetadata().getAlias() == "Email"
                                || id.getMetadata().getAlias() == "Twitter"
                                || id.getMetadata().getAlias() == "Passport")
            }
        } catch {
            XCTFail()
        }
    }
    
    func testDeleteCredential() {
        do {
            // Store test data into current store
            _ = try testData.sharedInstantData().getIssuerDocument()
            let user = try testData.sharedInstantData().getUser1Document()
            var vc = try user.credential(ofId: "#profile")
            vc!.getMetadata().setAlias("MyProfile")
            vc = try user.credential(ofId: "#email")
            vc!.getMetadata().setAlias("Email")
            vc = try testData.sharedInstantData().getUser1TwitterCredential()
            vc!.getMetadata().setAlias("Twitter")
            vc = try testData.sharedInstantData().getUser1PassportCredential()
            vc!.getMetadata().setAlias("Passport")


            var path = "ids/" + user.subject.methodSpecificId + "/credentials" + "/#twitter" + "/credential"
            var file = getFile(path)
            XCTAssertTrue(try file.exists())
            
            path = "ids/" + user.subject.methodSpecificId + "/credentials" + "/#twitter" + "/.metadata"
            file = getFile(path)
            XCTAssertTrue(try file.exists())

            path = "ids/" + user.subject.methodSpecificId + "/credentials" + "/#passport" + "/credential"
            file = getFile(path)
            XCTAssertTrue(try file.exists())

            path = "ids/" + user.subject.methodSpecificId + "/credentials" + "/#passport" + "/.metadata"
            file = getFile(path)
            XCTAssertTrue(try file.exists())

            var deleted = store!.deleteCredential(try DIDURL(user.subject, "#twitter"))
            XCTAssertTrue(deleted)

            deleted = try store!.deleteCredential(DIDURL(user.subject, "#passport").toString())
            XCTAssertTrue(deleted)

            deleted = try store!.deleteCredential(user.subject.toString() + "#notExist")
            XCTAssertFalse(deleted)

            path = "ids/" + user.subject.methodSpecificId + "/credentials" + "/#twitter"
            file = getFile(path)
            XCTAssertFalse(try file.exists())

            path = "ids/" + user.subject.methodSpecificId + "/credentials" + "/#passport"
            file = getFile(path)
            XCTAssertFalse(try file.exists())

            XCTAssertTrue(try! store!.containsCredential(DIDURL(user.subject, "#email")))
            XCTAssertTrue(try! store!.containsCredential(user.subject.toString() + "#profile"))

            XCTAssertFalse(try! store!.containsCredential(DIDURL(user.subject, "#twitter")))
            XCTAssertFalse(try! store!.containsCredential(user.subject.toString() + "#passport"))
        } catch {
            XCTFail()
        }
    }
    
    func testChangePassword() {
        do {
            let identity = try testData.getRootIdentity()

            for i in 0..<10{
                let alias = "my did \(i)"
                let doc = try identity.newDid(storePassword)
                doc.getMetadata().setAlias(alias)
                XCTAssertTrue(try doc.isValid())

                var resolved = try doc.subject.resolve()
                XCTAssertNil(resolved)

                try doc.publish(using: storePassword)

                var path = "ids/" + doc.subject.methodSpecificId + "/document"
                var file = getFile(path)
                XCTAssertTrue(try file.exists())

                path = "ids/" + doc.subject.methodSpecificId + "/.metadata"
                file = getFile(path)
                XCTAssertTrue(try file.exists())

                path = "ids/" + doc.subject.methodSpecificId + "/privatekeys" + "/#primary"
                file = getFile(path)
                XCTAssertTrue(try file.exists())

                resolved = try doc.subject.resolve()
                XCTAssertNotNil(resolved)
                try store!.storeDid(using: resolved!)
                XCTAssertEqual(alias, resolved!.getMetadata().getAlias())
                XCTAssertEqual(doc.subject, resolved?.subject)
                XCTAssertEqual(doc.proof.signature,resolved?.proof.signature)

                XCTAssertTrue(try resolved!.isValid())
            }

            var dids = try store!.listDids()
            XCTAssertEqual(10, dids.count)

            try store!.changePassword(storePassword, "newpasswd")

            dids = try store!.listDids()
            XCTAssertEqual(10, dids.count)

            for i in 0..<10 {
                let alias = "my did \(i)"
                let did = try identity.getDid(i)
                let doc = try store!.loadDid(did)
                XCTAssertNotNil(doc)
                XCTAssertTrue(try doc!.isValid())

                var file = getFile("ids/" + did.methodSpecificId + "/document")
                XCTAssertTrue(try file.exists())

                var path = "ids/" + did.methodSpecificId + "/.metadata"
                file = getFile(path)
                XCTAssertTrue(try file.exists())

                path = "ids/" + did.methodSpecificId + "/privatekeys" + "/#primary"
                file = getFile(path)
                XCTAssertTrue(try file.exists())

                XCTAssertEqual(alias, doc!.getMetadata().getAlias())
            }

            let doc = try identity.newDid("newpasswd")
            XCTAssertNotNil(doc)
        } catch {
            XCTFail()
        }
    }
    
    func testChangePasswordWithWrongPassword() {
        do {
            let identity = try testData.getRootIdentity()

            for i in 0..<10 {
                let alias = "my did \(i)"
                let doc = try identity.newDid(storePassword)
                doc.getMetadata().setAlias(alias)
                XCTAssertTrue(try doc.isValid())
            }

            let dids = try store!.listDids()
            XCTAssertEqual(10, dids.count)

            XCTAssertThrowsError(_ = try store!.changePassword("wrongpasswd", "newpasswd")){ error in
                switch error {
                case DIDError.CheckedError.DIDStoreError.DIDStoreError:
                    XCTAssertTrue(true)
                    break
                default:
                    XCTFail()
                }
            }
        } catch {
            XCTFail()
        }
    }
    
    func testCompatibility1() {
        Compatibility(1, "/Users/liaihong/Library/Developer/CoreSimulator/Devices/020AAD07-8674-4D58-AD51-C9EF0B21E155/data/Library/Caches/Resources/v1/teststore")
    }
    func testCompatibility2() {
        Compatibility(2,"/Users/liaihong/Library/Developer/CoreSimulator/Devices/020AAD07-8674-4D58-AD51-C9EF0B21E155/data/Library/Caches/Resources/v2/teststore")
    }
    func Compatibility(_ version: Int, _ path: String) {
        do {
            let data = "Hello World".data(using: .utf8)
            
            let cd = try testData.getCompatibleData(version)
            try cd.loadAll()
            
            let store = try DIDStore.open(atPath: path)
            
            let dids = try store.listDids()
            XCTAssertEqual(version == 2 ? 10 : 4, dids.count)
            
            for did in dids {
                let alias = did.getMetadata().getAlias()
                
                if (alias == "Issuer") {
                    let vcs = try store.listCredentials(for: did)
                    XCTAssertEqual(1, vcs.count)
                    
                    for id in vcs {
                        XCTAssertNotNil(try store.loadCredential(byId: id))
                    }
                }
                else if (alias == "User1") {
                    let vcs = try store.listCredentials(for: did)
                    XCTAssertEqual(version == 2 ? 5 : 4, vcs.count)
                    
                    for id in vcs {
                        XCTAssertNotNil(try store.loadCredential(byId: id))
                    }
                } else if (alias == "User2") {
                    let vcs = try store.listCredentials(for: did)
                    XCTAssertEqual(1, vcs.count)
                    
                    for id in vcs {
                        XCTAssertNotNil(try store.loadCredential(byId: id))
                    }
                } else if (alias == "User3") {
                    let vcs = try store.listCredentials(for: did)
                    XCTAssertEqual(0, vcs.count)
                }
                
                let doc = try store.loadDid(did)
                if (!doc!.isCustomizedDid() || doc!.controllerCount() <= 1) {
                    let sig = try doc!.sign(using: storePassword, for: data!)
                    XCTAssertTrue(try doc!.verify(signature: sig, onto: data!))
                }
            }
        } catch {
            XCTFail()
        }
    }
    
    func testCompatibilityNewDIDWithWrongPass1() {
        CompatibilityNewDIDWithWrongPass(1)
    }
    func testCompatibilityNewDIDWithWrongPass2() {
        CompatibilityNewDIDWithWrongPass(2)
    }
    func CompatibilityNewDIDWithWrongPass(_ version: Int) {
        do {
            
//            let path = try testData.getCompatibleData(version).storePath
            let path = "/Users/liaihong/Library/Developer/CoreSimulator/Devices/020AAD07-8674-4D58-AD51-C9EF0B21E155/data/Library/Caches/Resources/v1/teststore"
            let store = try DIDStore.open(atPath: path)
            let idenitty = try store.loadRootIdentity()
            
            XCTAssertThrowsError(_ = try idenitty!.newDid("wrongpass")){ error in
                switch error {
                case DIDError.CheckedError.DIDStoreError.WrongPasswordError:
                    XCTAssertTrue(true)
                    break
                default:
                    XCTFail()
                }
            }
        } catch {
            XCTFail()
        }
    }
    
    func testCompatibilityNewDIDandGetDID1() {
        CompatibilityNewDIDandGetDID(1)
    }
    func testCompatibilityNewDIDandGetDID2() {
        CompatibilityNewDIDandGetDID(2)
    }
    func CompatibilityNewDIDandGetDID(_ version: Int) {
        do {
            
            let path = "/Users/liaihong/Library/Developer/CoreSimulator/Devices/020AAD07-8674-4D58-AD51-C9EF0B21E155/data/Library/Caches/Resources/v1/teststore"

//            let store = try DIDStore.open(atPath: testData.getCompatibleData(version).storePath)
            let store = try DIDStore.open(atPath: path)

            let identity = try store.loadRootIdentity()
            
            var doc = try identity!.newDid(storePassword)
            XCTAssertNotNil(doc)
            
            _ = store.deleteDid(doc.subject)
            
            let did = try identity!.getDid(1000)
            
            doc = try identity!.newDid(1000, storePassword)
            XCTAssertNotNil(doc)
            XCTAssertEqual(doc.subject, did)
            
            _ = store.deleteDid(doc.subject)
            
        } catch {
            XCTFail()
        }
    }
    
    func createDataForPerformanceTest(_ store: DIDStore)  {
        do {
            let props = ["name": "John",
                         "gender": "Male",
                         "nation": "Singapore",
                         "language": "English",
                         "email": "john@example.com",
                         "twitter": "@john"]
            
            let identity = try store.loadRootIdentity()
            
            for i in 0..<10 {
                let alias = "my did \(i)"
                let doc = try identity!.newDid(storePassword)
                doc.getMetadata().setAlias(alias)
                let issuer = try VerifiableCredentialIssuer(doc)
                let cb = issuer.editingVerifiableCredentialFor(did: doc.subject)
                let vc = try cb.withId("#cred-1")
                    .withTypes("BasicProfileCredential", "SelfProclaimedCredential")
                    .withProperties(props)
                    .sealed(using: storePassword)
                
                try store.storeCredential(using: vc)
            }
        } catch {
            XCTFail()
        }
    }
    
    func testStoreCachePerformance1() {
        StoreCachePerformance(true)
    }
    func testStoreCachePerformance2() {
        StoreCachePerformance(false)
    }
    func StoreCachePerformance(_ cached: Bool) {
        do {
            TestData.deleteFile(storeRoot)
            var store: DIDStore? = nil
            if (cached) {
                store = try DIDStore.open(atPath: storeRoot)
            }
            else {
                store = try DIDStore.open(atPath: storeRoot, initialCacheCapacity: 0, maxCacheCapacity: 0)
            }
            
            let mnemonic =  try Mnemonic.generate(Mnemonic.DID_ENGLISH)
            _ = try RootIdentity.create(mnemonic, passphrase, true, store!, storePassword)
            
            createDataForPerformanceTest(store!)
            
            let dids = try store!.listDids()
            XCTAssertEqual(10, dids.count)
            
            for _ in 0...1000 {
                for did in dids {
                    let doc = try store!.loadDid(did)
                    XCTAssertEqual(did, doc!.subject)
                    
                    let id = try DIDURL(did, "#cred-1")
                    let vc = try store!.loadCredential(byId: id)
                    XCTAssertEqual(id, vc!.getId())
                }
            }
            
            print("Store loading \(cached) cache took {} milliseconds.")
        }
        catch {
            XCTFail()
        }
    }
    
    func testMultipleStore() {
        do {
            var stores: [DIDStore] = []
            var docs: [DIDDocument] = []

            for i in 0..<10{
                TestData.deleteFile(storeRoot + "\(i)")
                stores.insert(try DIDStore.open(atPath: storeRoot + "\(i)"), at: i)
                XCTAssertNotNil(stores[i])
                let mnemonic = try Mnemonic.generate(Mnemonic.DID_ENGLISH)
                _ = try RootIdentity.create(mnemonic, "", stores[i], storePassword)
            }

            for i in 0..<stores.count  {
                docs.insert(try stores[i].loadRootIdentity()!.newDid(storePassword), at: i)
                XCTAssertNotNil(docs[i])
            }

            for i in 0..<stores.count {
                let doc = try stores[i].loadDid(docs[i].subject)
                XCTAssertNotNil(doc)
                XCTAssertEqual(docs[i].toString(true), doc!.toString(true))
            }
        } catch {
            XCTFail()
        }
    }
    
    func testOpenStoreOnExistEmptyFolder() {
        do {
            let emptyFolder = tempDir + "/DIDTest-EmptyStore"
            if (try emptyFolder.exists()) {
                TestData.deleteFile(emptyFolder)
            }

            let store = try DIDStore.open(atPath: emptyFolder)
            XCTAssertNotNil(store)

            store.close()
        } catch {
            XCTFail()
        }
    }
    
    func testExportAndImportDid() {
        do {
            let storeDir = storeRoot

            _ = try testData.sharedInstantData().getIssuerDocument()
            _ = try testData.sharedInstantData().getUser1Document()
            _ = try testData.sharedInstantData().getUser1PassportCredential()
            _ = try testData.sharedInstantData().getUser1TwitterCredential()

            let did = try store!.listDids()[0]

            let exportFile = tempDir + "/didexport.json"
            TestData.deleteFile(exportFile)
            try create(exportFile, forWrite: true)
            let fileHndle: FileHandle = FileHandle(forWritingAtPath: exportFile)!
            try store!.exportDid(did, to: fileHndle, using: "password", storePassword: storePassword)
            let restoreDir = tempDir + "/restore"
            TestData.deleteFile(restoreDir)
            let store2 = try DIDStore.open(atPath: restoreDir)
            let readerHndle = FileHandle(forReadingAtPath: exportFile)
            readerHndle?.seek(toFileOffset: 0)
            try store2.importDid(from: readerHndle!, using: "password", storePassword: storePassword)

            let path = "data" + "/ids/" + did.methodSpecificId
            let didDir = storeDir + "/" + path
            let reDidDir = restoreDir + "/" + path
            XCTAssertTrue(try didDir.exists())
            XCTAssertTrue(try reDidDir.exists())
//            XCTAssertTrue(Utils.equals(reDidDir, didDir))
        } catch {
            XCTFail()
        }
    }
    
    func create(_ path: String, forWrite: Bool) throws {
        if !FileManager.default.fileExists(atPath: path) && forWrite {
            let dirPath: String = path.dirname()
            let fileM = FileManager.default
            let re = fileM.fileExists(atPath: dirPath)
            if !re {
                try fileM.createDirectory(atPath: dirPath, withIntermediateDirectories: true, attributes: nil)
            }
            FileManager.default.createFile(atPath: path, contents: nil, attributes: nil)
        }
    }
    
    func testExportAndImportRootIdentity() {
        do {
           let storeDir = storeRoot
            
            _ = try testData.sharedInstantData().getIssuerDocument()
            _ = try testData.sharedInstantData().getUser1Document()
            _ = try testData.sharedInstantData().getUser1PassportCredential()
            _ = try testData.sharedInstantData().getUser1TwitterCredential()

            let id = try store!.loadRootIdentity()!.getId()

            let exportFile = tempDir + "/idexport.json"
            TestData.deleteFile(exportFile)
            try create(exportFile, forWrite: true)
            let fileHndle: FileHandle = FileHandle(forWritingAtPath: exportFile)!
            try store!.exportRootIdentity(id, to: fileHndle, using: "password", storePassword: storePassword)

            let restoreDir = tempDir + "/restore"
            TestData.deleteFile(restoreDir)
            let store2 = try DIDStore.open(atPath: restoreDir)
            let readerHndle = FileHandle(forReadingAtPath: exportFile)
            readerHndle?.seek(toFileOffset: 0)
            try store2.importRootIdentity(from: readerHndle!, using: "password", storePassword: storePassword)

            let path = "data" + "/" + "roots" + "/" + id
            let privateDir = storeDir + "/" + path
            let rePrivateDir = restoreDir + "/" + path
            XCTAssertTrue(try privateDir.exists())
            XCTAssertTrue(try rePrivateDir.exists())
//            XCTAssertTrue(Utils.equals(rePrivateDir, privateDir))
        } catch {
            XCTFail()
        }
    }
    
    func testExportAndImportStore() {
        do {
            _ = try testData.getRootIdentity()

            // Store test data into current store
            _ = try testData.sharedInstantData().getIssuerDocument()
            let user = try testData.sharedInstantData().getUser1Document()
            var vc = try user.credential(ofId: "#profile")
            vc!.getMetadata().setAlias("MyProfile")
            vc = try user.credential(ofId: "#email")
            vc!.getMetadata().setAlias("Email")
            vc = try testData.sharedInstantData().getUser1TwitterCredential()
            vc!.getMetadata().setAlias("Twitter")
            vc = try testData.sharedInstantData().getUser1PassportCredential()
            vc!.getMetadata().setAlias("Passport")

            let exportFile = tempDir + "/storeexport"
            TestData.deleteFile(exportFile)
            try store!.exportStore(to: exportFile, using: "password", storePassword: storePassword)

            let restoreDir = tempDir + "/restore"
            TestData.deleteFile(restoreDir)
            let store2 = try DIDStore.open(atPath: restoreDir)
            try store2.importStore(from: exportFile, using: "password", storePassword: storePassword)

            let storeDir = storeRoot

            XCTAssertTrue(try storeDir.exists())
            XCTAssertTrue(try restoreDir.exists())
//            XCTAssertTrue(Utils.equals(restoreDir, storeDir))
        } catch {
            XCTFail()
        }
    }
    /*
    func testImportCompatible() {
        do {
            _ = try testData.getRootIdentity()
            
//            let url = "/v2/testdata/store-export"
            let path = "/Users/liaihong/Library/Developer/CoreSimulator/Devices/020AAD07-8674-4D58-AD51-C9EF0B21E155/data/Library/Caches/Resources/v2/testdata/store-export"
            let exportFile =  path
            
            TestData.deleteFile(tempDir)
//            try create(tempDir, forWrite: true)
            let restoreDir = tempDir + "/imported-store"
            TestData.deleteFile(restoreDir)
            print("restoreDir == \(restoreDir)")
            let store2 = try DIDStore.open(atPath: restoreDir)
            try store2.importStore(from: exportFile, using: "password", storePassword: storePassword)
            
            // Root identity
            let ids = try store2.listRootIdentities()
            XCTAssertEqual(1, ids.count)
            XCTAssertEqual("d2f3c0f07eda4e5130cbdc59962426b1", try ids[0].getId())
            XCTAssertEqual(5, ids[0].index)

            // DIDs
            let dids = try store2.listDids()
            XCTAssertEqual(10, dids.count)
            
            // DID: User1
            var did = try DID("did:elastos:iXcRhYB38gMt1phi5JXJMjeXL2TL8cg58y")
            XCTAssertTrue(dids.contains(did))
            var doc = try store2.loadDid(did)
            XCTAssertNotNil(doc)
            XCTAssertEqual("User1", doc?.getMetadata().getAlias())
            try doc!.publish(using: storePassword)
            
            var names = ["email", "json", "passport", "profile", "twitter"]
            
            var vcIds = try store2.listCredentials(for: did)
            XCTAssertEqual(names.count, vcIds.count)
            for id in vcIds {
                let vc = try store2.loadCredential(byId: id)
                XCTAssertNotNil(vc)
                names = names.filter { $0 != vc?.getId()?.fragment}
            }
            XCTAssertEqual(0, names.count)
            
            // DID: User2
            did = try DID("did:elastos:idwuEMccSpsTH4ZqrhuHqg6y8XMVQAsY5g");
            XCTAssertTrue(dids.contains(did))
            doc = try store2.loadDid(did)
            XCTAssertNotNil(doc)
            XCTAssertEqual("User2", doc!.getMetadata().getAlias())
            try doc!.publish(using: storePassword)
            
            vcIds = try store2.listCredentials(for: did)
            XCTAssertEqual(1, vcIds.count)
            XCTAssertEqual("profile", vcIds[0].fragment)
            var vc = try store2.loadCredential(byId: vcIds[0])
            XCTAssertNotNil(vc)
            
            // DID: User3
            did = try DID("did:elastos:igXiyCJEUjGJV1DMsMa4EbWunQqVg97GcS");
            XCTAssertTrue(dids.contains(did))
            doc = try store2.loadDid(did)
            XCTAssertNotNil(doc)
            XCTAssertEqual("User3", doc!.getMetadata().getAlias())
            try doc!.publish(using: storePassword)
            
            vcIds = try store2.listCredentials(for: did)
            XCTAssertEqual(0, vcIds.count)
            
            // DID: User4
            did = try DID("did:elastos:igHbSCez6H3gTuVPzwNZRrdj92GCJ6hD5d")
            XCTAssertTrue(dids.contains(did))
            doc = try store2.loadDid(did)
            XCTAssertNotNil(doc)
            XCTAssertEqual("User4", doc!.getMetadata().getAlias())
            try doc!.publish(using: storePassword)
            
            vcIds = try store2.listCredentials(for: did)
            XCTAssertEqual(0, vcIds.count)
            
            // DID: Issuer
            did = try DID("did:elastos:imUUPBfrZ1yZx6nWXe6LNN59VeX2E6PPKj")
            XCTAssertTrue(dids.contains(did))
            doc = try store2.loadDid(did)
            XCTAssertNotNil(doc)
            XCTAssertEqual("Issuer", doc!.getMetadata().getAlias())
            try doc!.publish(using: storePassword)
            
            vcIds = try store2.listCredentials(for: did)
            XCTAssertEqual(1, vcIds.count)
            XCTAssertEqual("profile", vcIds[0].fragment)
            vc = try store2.loadCredential(byId: vcIds[0])
            XCTAssertNotNil(vc)
            
            // DID: Example
            did = try DID("did:elastos:example")
            XCTAssertTrue(dids.contains(did))
            doc = try store2.loadDid(did)
            XCTAssertNotNil(doc)
            try doc!.publish(using: storePassword)
            
            vcIds = try store2.listCredentials(for: did)
            XCTAssertEqual(1, vcIds.count)
            XCTAssertEqual("profile", vcIds[0].fragment)
            vc = try store2.loadCredential(byId: vcIds[0])
            XCTAssertNotNil(vc)
            
            // DID: Foo
            did = try DID("did:elastos:foo")
            XCTAssertTrue(dids.contains(did))
            doc = try store2.loadDid(did)
            XCTAssertNotNil(doc)
            try doc!.setEffectiveController(try DID("did:elastos:iXcRhYB38gMt1phi5JXJMjeXL2TL8cg58y"))
            try doc!.publish(using: storePassword)
            
            vcIds = try store2.listCredentials(for: did)
            XCTAssertEqual(1, vcIds.count)
            XCTAssertEqual("email", vcIds[0].fragment)
            vc = try store2.loadCredential(byId: vcIds[0])
            XCTAssertNotNil(vc)
            
            // DID: FooBar
            did = try DID("did:elastos:foobar")
            XCTAssertTrue(dids.contains(did))
            doc = try store2.loadDid(did)
            XCTAssertNotNil(doc)
            try doc?.setEffectiveController(try DID("did:elastos:iXcRhYB38gMt1phi5JXJMjeXL2TL8cg58y"))
            try doc!.publish(using: storePassword)
            
            names = ["email", "license", "profile", "services"]
            
            vcIds = try store2.listCredentials(for: did)
            XCTAssertEqual(names.count, vcIds.count)
            for id in vcIds {
                vc = try store2.loadCredential(byId: id)
                XCTAssertNotNil(vc)
                names = names.filter { $0 != vc?.getId()?.fragment}
            }
            XCTAssertEqual(0, names.count)
            
            // DID: Bar
            did = try DID("did:elastos:bar")
            XCTAssertTrue(dids.contains(did))
            doc = try store2.loadDid(did)
            XCTAssertNotNil(doc)
            try doc!.setEffectiveController(try DID("did:elastos:iXcRhYB38gMt1phi5JXJMjeXL2TL8cg58y"))
            try doc!.publish(using: storePassword)
            
            vcIds = try store2.listCredentials(for: did)
            XCTAssertEqual(0, vcIds.count)
            
            // DID: Baz
            did = try DID("did:elastos:baz")
            XCTAssertTrue(dids.contains(did))
            doc = try store2.loadDid(did)
            XCTAssertNotNil(doc)
            try doc!.setEffectiveController(try DID("did:elastos:iXcRhYB38gMt1phi5JXJMjeXL2TL8cg58y"))
            try doc!.publish(using: storePassword)
            
            vcIds = try store2.listCredentials(for: did)
            XCTAssertEqual(0, vcIds.count)
        } catch {
            XCTFail()
        }
    }
 */
}

