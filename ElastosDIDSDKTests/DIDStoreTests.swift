
import XCTest
@testable import ElastosDIDSDK


class DIDStoreTests: XCTestCase {
    let testData: TestData = TestData()
    var store: DIDStore?
    var simulatedIDChain: SimulatedIDChain = SimulatedIDChain()

    override func setUp() {
        store = testData.store!
        try! simulatedIDChain.httpServer.start(in_port_t(DEFAULT_PORT), forceIPv4: true)
        simulatedIDChain.start()
        try! DIDBackend.initialize(simulatedIDChain.getAdapter());
    }
    
    func getFile(_ path: String) -> String {
        var relPath = storeRoot
        relPath.append("/")
        relPath.append("data/")
        relPath.append(path)
        
        return relPath
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
                let alias = "my did " + i
                let doc = try identity.newDid(storePassword)
                doc.getMetadata().setAlias(alias)
                XCTAssertTrue(try doc.isValid())

                var resolved = try doc.subject.resolve()
                XCTAssertNil(resolved)

                try doc.publish(storePassword)

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
                let alias = "my did " + i
                let doc = try identity.newDid(storePassword)
                doc.getMetadata().setAlias(alias)
                try doc.publish(storePassword)
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
            
            path = "ids" + vc!.id!.did!.methodSpecificId + "/credentials/#" + vc!.id!.fragment! + "/credential"
            file = getFile(path)
            XCTAssertTrue(try file.exists())

            path = "ids" + vc!.id!.did!.methodSpecificId + "/credentials/#" + vc!.id!.fragment! + "/.metadata"

            file = getFile(path)
            XCTAssertTrue(try file.exists())

            vc = try testData.sharedInstantData().getUser1TwitterCredential()
            vc!.getMetadata().setAlias("Twitter")

            path = "ids" + vc!.id!.did!.methodSpecificId + "/credentials/#" + vc!.id!.fragment! + "/credential"
            file = getFile(path)
            XCTAssertTrue(try file.exists())

            path = "ids" + vc!.id!.did!.methodSpecificId + "/credentials/#" + vc!.id!.fragment! + "/.metadata"
            file = getFile(path)
            XCTAssertTrue(try file.exists())

            vc = try testData.sharedInstantData().getUser1PassportCredential()
            vc!.getMetadata().setAlias("Passport")

            path = "ids" + vc!.id!.did!.methodSpecificId + "/credentials/#" + vc!.id!.fragment! + "/credential"
            file = getFile(path)
            XCTAssertTrue(try file.exists())

            path = "ids" + vc!.id!.did!.methodSpecificId + "/credentials/#" + vc!.id!.fragment! + "/.metadata"
            file = getFile(path)
            XCTAssertTrue(try file.exists())

            var id =  try DIDURL(user.subject, "#profile")
            vc = try store!.loadCredential(byId: id)
            XCTAssertEqual("MyProfile", vc!.getMetadata().getAlias())
            XCTAssertEqual(user.subject, vc!.subject!.did)
            XCTAssertEqual(id, vc!.getId())
            XCTAssertTrue(vc!.isValid)

            // try with full id string
            vc = try store!.loadCredential(byId: id.toString())
            XCTAssertNotNil(vc)
            XCTAssertEqual("MyProfile", vc?.getMetadata().getAlias())
            XCTAssertEqual(user.subject, vc?.subject?.did)
            XCTAssertEqual(id, vc?.id)
            XCTAssertTrue(vc!.isValid)

            id = try DIDURL(user.subject, "#twitter")
            vc = try store!.loadCredential(byId: id.toString())
            XCTAssertNotNil(vc)
            XCTAssertEqual("Twitter", vc!.getMetadata().getAlias())
            XCTAssertEqual(user.subject, vc?.subject?.did)
            XCTAssertEqual(id, vc?.id)
            XCTAssertTrue(vc!.isValid)

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

            for i in 0...10{
                let alias = "my did " + i
                let doc = try identity.newDid(storePassword)
                doc.getMetadata().setAlias(alias)
                XCTAssertTrue(try doc.isValid())

                var resolved = try doc.subject.resolve()
                XCTAssertNil(resolved)

                try doc.publish(storePassword)

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

            for i in 0...10 {
                let alias = "my did " + i
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

            for i in 0...10 {
                let alias = "my did " + i
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
        Compatibility(1)
    }
    func testCompatibility2() {
        Compatibility(2)
    }
    func Compatibility(_ version: Int) {
        do {
            let data = "Hello World".data(using: .utf8)
            
            let cd = try testData.getCompatibleData(version)
            try cd.loadAll()
            
            let store = try DIDStore.open(atPath: cd.storePath)
            
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
            let store = try DIDStore.open(atPath: testData.getCompatibleData(version).storePath)
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
            let store = try DIDStore.open(atPath: testData.getCompatibleData(version).storePath)
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
            
            for i in 0...10 {
                let alias = "my did " + i
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
                store = try DIDStore.open(atPath: storePassword)
            }
            else {
                store = try DIDStore.open(atPath: storePassword, initialCacheCapacity: 0, maxCacheCapacity: 0)
            }
            
            let mnemonic =  try Mnemonic.generate(Mnemonic.DID_ENGLISH)
            _ = try RootIdentity.create(mnemonic, storePassword, true, store!, storePassword)
            
            createDataForPerformanceTest(store!)
            
            let dids = try store!.listDids()
            XCTAssertEqual(10, dids.count)
            
            for _ in 0...1000 {
                for did in dids {
                    let doc = try store!.loadDid(did)
                    XCTAssertEqual(did, doc!.subject)
                    
                    let id = try DIDURL(did, "#cred-1")
                    let vc = try! store!.loadCredential(byId: id)
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

            for i in 0...stores.count {
                TestData.deleteFile(storeRoot + i)
                stores[i] = try DIDStore.open(atPath: storeRoot + i)
                XCTAssertNotNil(stores[i])
                let mnemonic = try Mnemonic.generate(Mnemonic.DID_ENGLISH)
                _ = try RootIdentity.create(mnemonic, "", stores[i], storePassword)
            }

            for i in 0...stores.count  {
                docs[i] = try stores[i].loadRootIdentity()!.newDid(storePassword)
                XCTAssertNotNil(docs[i])
            }

            for i in 0...stores.count {
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

//            emptyFolder.mkdirs()

            let store = try DIDStore.open(atPath: emptyFolder)
            XCTAssertNotNil(store)

            store.close()
        } catch {
            XCTFail()
        }
    }
}
/*
 @Test
 public void testExportAndImportDid() throws DIDException, IOException {
     File storeDir = new File(TestConfig.storeRoot);

     testData.getInstantData().getIssuerDocument();
     testData.getInstantData().getUser1Document();
     testData.getInstantData().getUser1PassportCredential();
     testData.getInstantData().getUser1TwitterCredential();

     DID did = store.listDids().get(0);

     File tempDir = new File(TestConfig.tempDir);
     tempDir.mkdirs();
     File exportFile = new File(tempDir, "didexport.json");

     store.exportDid(did, exportFile, "password", TestConfig.storePass);

     File restoreDir = new File(tempDir, "restore");
     Utils.deleteFile(restoreDir);
     DIDStore store2 = DIDStore.open(restoreDir.getAbsolutePath());
     store2.importDid(exportFile, "password", TestConfig.storePass);

     String path = "data" + File.separator + "ids" + File.separator + did.getMethodSpecificId();
     File didDir = new File(storeDir, path);
     File reDidDir = new File(restoreDir, path);
     assertTrue(didDir.exists());
     assertTrue(reDidDir.exists());
     assertTrue(Utils.equals(reDidDir, didDir));
 }

 @Test
 public void testExportAndImportRootIdentity() throws DIDException, IOException {
     File storeDir = new File(TestConfig.storeRoot);

     testData.getInstantData().getIssuerDocument();
     testData.getInstantData().getUser1Document();
     testData.getInstantData().getUser1PassportCredential();
     testData.getInstantData().getUser1TwitterCredential();

     String id = store.loadRootIdentity().getId();

     File tempDir = new File(TestConfig.tempDir);
     tempDir.mkdirs();
     File exportFile = new File(tempDir, "idexport.json");

     store.exportRootIdentity(id, exportFile, "password", TestConfig.storePass);

     File restoreDir = new File(tempDir, "restore");
     Utils.deleteFile(restoreDir);
     DIDStore store2 = DIDStore.open(restoreDir.getAbsolutePath());
     store2.importRootIdentity(exportFile, "password", TestConfig.storePass);

     String path = "data" + File.separator + "roots" + File.separator + id;
     File privateDir = new File(storeDir, path);
     File rePrivateDir = new File(restoreDir, path);
     assertTrue(privateDir.exists());
     assertTrue(rePrivateDir.exists());
     assertTrue(Utils.equals(rePrivateDir, privateDir));
 }

 @Test
 public void testExportAndImportStore() throws DIDException, IOException {
     testData.getRootIdentity();

     // Store test data into current store
     testData.getInstantData().getIssuerDocument();
     DIDDocument user = testData.getInstantData().getUser1Document();
     VerifiableCredential vc = user.getCredential("#profile");
     vc.getMetadata().setAlias("MyProfile");
     vc = user.getCredential("#email");
     vc.getMetadata().setAlias("Email");
     vc = testData.getInstantData().getUser1TwitterCredential();
     vc.getMetadata().setAlias("Twitter");
     vc = testData.getInstantData().getUser1PassportCredential();
     vc.getMetadata().setAlias("Passport");

     File tempDir = new File(TestConfig.tempDir);
     tempDir.mkdirs();
     File exportFile = new File(tempDir, "storeexport.zip");

     store.exportStore(exportFile, "password", TestConfig.storePass);

     File restoreDir = new File(tempDir, "restore");
     Utils.deleteFile(restoreDir);
     DIDStore store2 = DIDStore.open(restoreDir.getAbsolutePath());
     store2.importStore(exportFile, "password", TestConfig.storePass);

     File storeDir = new File(TestConfig.storeRoot);

     assertTrue(storeDir.exists());
     assertTrue(restoreDir.exists());
     assertTrue(Utils.equals(restoreDir, storeDir));
 }
 */
