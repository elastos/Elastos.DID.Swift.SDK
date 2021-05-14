
import XCTest
@testable import ElastosDIDSDK
class VerifiableCredentialTest: XCTestCase {
    static var simulatedIDChain: SimulatedIDChain = SimulatedIDChain()
    var testData: TestData?
    
    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
        testData = TestData()
//        try! DIDBackend.initialize(VerifiableCredentialTest.simulatedIDChain.getAdapter())
        let adapter = SimulatedIDChainAdapter("http://localhost:\(DEFAULT_PORT)/")
        try! DIDBackend.initialize(adapter)
    }
    
    override func tearDown() {
        testData?.reset()
        testData?.cleanup()
    }
    
    func testKycCredential1() {
        KycCredential(1)
    }
    
    func testKycCredential2() {
        KycCredential(2)
    }
    
    func KycCredential(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(version)
            
            let issuer = try cd.getDocument("issuer")
            let user = try cd.getDocument("user1")
            
            let vc = try cd.getCredential("user1", "twitter")
            
            XCTAssertEqual(try DIDURL(user.subject, "#twitter"), vc.getId())
            
            XCTAssertTrue(vc.getType().contains("InternetAccountCredential"))
            XCTAssertTrue(vc.getType().contains("TwitterCredential"))
            
            XCTAssertEqual(issuer.subject, vc.getIssuer())
            XCTAssertEqual(user.subject, vc.subject?.did)
            
            XCTAssertEqual("@john", vc.subject?.getProperties()?.get(forKey: "twitter")?.asString())
            
            XCTAssertNotNil(vc.getIssuanceDate())
            XCTAssertNotNil(try vc.getExpirationDate())
            
            XCTAssertFalse(vc.isSelfProclaimed)
            XCTAssertFalse(vc.isExpired)
            XCTAssertTrue(try vc.isGenuine())
            XCTAssertTrue(vc.isValid)
        } catch {
            XCTFail()
        }
    }
    
    func testSelfProclaimedCredential1() {
        SelfProclaimedCredential1(1)
    }
    
    func testSelfProclaimedCredential2() {
        SelfProclaimedCredential1(2)
    }
    
    func SelfProclaimedCredential1(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(version)
            
            let user = try cd.getDocument("user1")
            let vc = try cd.getCredential("user1", "passport")
            
            XCTAssertEqual(try DIDURL(user.subject, "#passport"), vc.getId())
            
            XCTAssertTrue(vc.getType().contains("BasicProfileCredential"))
            XCTAssertTrue(vc.getType().contains("SelfProclaimedCredential"))
            
            XCTAssertEqual(user.subject, vc.getIssuer())
            XCTAssertEqual(user.subject, vc.subject?.did)
            
            XCTAssertEqual("Singapore", vc.subject?.getProperties()?.get(forKey: "nation")?.asString())
            XCTAssertEqual("S653258Z07", vc.subject?.getProperty(ofName: "passport")?.asString())
            
            XCTAssertNotNil(vc.getIssuanceDate())
            XCTAssertNotNil(try vc.getExpirationDate())
            
            XCTAssertTrue(vc.isSelfProclaimed)
            XCTAssertFalse(vc.isExpired)
            XCTAssertTrue(try vc.isGenuine())
            XCTAssertTrue(vc.isValid)
        } catch {
            XCTFail()
        }
    }
    
    func testJsonCredential1() {
        JsonCredential(1)
    }
    
    func testJsonCredential2() {
        JsonCredential(2)
    }
    
    func JsonCredential(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(version)
            
            let issuer = try cd.getDocument("issuer")
            let user = try cd.getDocument("user1")
            let vc = try cd.getCredential("user1", "json")
            
            XCTAssertEqual(try DIDURL(user.subject, "#json"), vc.getId())
            
            XCTAssertTrue(vc.getType().contains("JsonCredential"))
            XCTAssertTrue(vc.getType().contains("TestCredential"))
            
            XCTAssertEqual(issuer.subject, vc.getIssuer())
            XCTAssertEqual(user.subject, vc.subject?.did)
            
            XCTAssertEqual("Technologist", vc.subject?.getProperty(ofName: "Description")?.asString())
            XCTAssertEqual(true, vc.subject?.getProperty(ofName: "booleanValue")?.asBool())
            XCTAssertEqual(1234, vc.subject?.getProperty(ofName: "numberValue")?.asNumber() as? Int)
            
            XCTAssertNotNil(vc.getIssuanceDate())
            XCTAssertNotNil(vc.getExpirationDate)
            
            XCTAssertFalse(vc.isSelfProclaimed)
            XCTAssertFalse(vc.isExpired)
            XCTAssertTrue(try vc.isGenuine())
            XCTAssertTrue(vc.isValid)
        } catch {
            XCTFail()
        }
    }
    
    func testKycCredentialToCid() {
        do {
            let cd = try testData!.getCompatibleData(2)
            try cd.loadAll()
            
            let issuer = try cd.getDocument("issuer")
            let foo = try cd.getDocument("foo")
            
            let vc = try cd.getCredential("foo", "email")
            
            XCTAssertEqual(try DIDURL(foo.subject, "#email"), vc.id)
            
            XCTAssertTrue(vc.getType().contains("InternetAccountCredential"))
            XCTAssertFalse(vc.getType().contains("ProfileCredential"))
            
            XCTAssertEqual(issuer.subject, vc.getIssuer())
            XCTAssertEqual(foo.subject, vc.subject?.did)
            
            XCTAssertEqual("foo@example.com", vc.subject?.getProperty(ofName: "email")?.asString())
            
            XCTAssertNotNil(vc.getIssuanceDate())
            XCTAssertNotNil(try vc.getExpirationDate())
            
            XCTAssertFalse(vc.isSelfProclaimed)
            XCTAssertFalse(vc.isExpired)
            XCTAssertTrue(try vc.isGenuine())
            XCTAssertTrue(vc.isValid)
        } catch {
            XCTFail()
        }
    }
    
    func testKycCredentialFromCid() {
        do {
            let cd = try testData!.getCompatibleData(2)
            try cd.loadAll()
            
            let exampleCorp = try cd.getDocument("examplecorp")
            let foobar = try cd.getDocument("foobar")
            
            let vc = try cd.getCredential("foobar", "license")
            
            XCTAssertEqual(try DIDURL(foobar.subject, "#license"), vc.id)
            
            XCTAssertTrue(vc.getType().contains("LicenseCredential"))
            XCTAssertFalse(vc.getType().contains("ProfileCredential"))
            
            XCTAssertEqual(exampleCorp.subject, vc.getIssuer())
            XCTAssertEqual(foobar.subject, vc.subject?.did)
            
            XCTAssertEqual("20201021C889", vc.subject?.getProperty(ofName: "license-id")?.asString())
            XCTAssertEqual("Consulting", vc.subject?.getProperty(ofName: "scope")?.asString())
            
            XCTAssertNotNil(vc.getIssuanceDate())
            XCTAssertNotNil(try vc.getExpirationDate())
            
            XCTAssertFalse(vc.isSelfProclaimed)
            XCTAssertFalse(vc.isExpired)
            XCTAssertTrue(try vc.isGenuine())
            XCTAssertTrue(vc.isValid)
        } catch {
            XCTFail()
        }
    }
    
    func testSelfProclaimedCredentialFromCid() {
        do {
            let cd = try testData!.getCompatibleData(2)
            try cd.loadAll()
            
            let foobar = try cd.getDocument("foobar")
            
            let vc = try cd.getCredential("foobar", "services")
            
            XCTAssertEqual(try DIDURL(foobar.subject, "#services"), vc.getId())
            
            XCTAssertTrue(vc.getType().contains("SelfProclaimedCredential"))
            XCTAssertTrue(vc.getType().contains("BasicProfileCredential"))
            
            XCTAssertEqual(foobar.subject, vc.getIssuer())
            XCTAssertEqual(foobar.subject, vc.subject?.did)
            
            XCTAssertEqual("https://foobar.com/outsourcing", vc.subject?.getProperty(ofName: "Outsourceing")?.asString())
            XCTAssertEqual("https://foobar.com/consultation", vc.subject?.getProperty(ofName: "consultation")?.asString())
            
            XCTAssertNotNil(vc.getIssuanceDate())
            XCTAssertNotNil(vc.getExpirationDate)
            
            XCTAssertTrue(vc.isSelfProclaimed)
            XCTAssertFalse(vc.isExpired)
            XCTAssertTrue(try vc.isGenuine())
            XCTAssertTrue(vc.isValid)
        } catch {
            XCTFail()
        }
    }
    
    func testParseAndSerializeJsonCredential1() {
        ParseAndSerializeJsonCredential(1, "user1", "twitter")
    }
    func testParseAndSerializeJsonCredential2() {
        ParseAndSerializeJsonCredential(1, "user1", "passport")
    }
    func testParseAndSerializeJsonCredential3() {
        ParseAndSerializeJsonCredential(1, "user1", "json")
    }
    func testParseAndSerializeJsonCredential4() {
        ParseAndSerializeJsonCredential(2, "user1", "twitter")
    }
    func testParseAndSerializeJsonCredential5() {
        ParseAndSerializeJsonCredential(2, "user1", "passport")
    }
    func testParseAndSerializeJsonCredential6() {
        ParseAndSerializeJsonCredential(2, "user1", "json")
    }
    func testParseAndSerializeJsonCredential7() {
        ParseAndSerializeJsonCredential(2, "foobar", "license")
    }
    func testParseAndSerializeJsonCredential8() {
        ParseAndSerializeJsonCredential(2, "foobar", "services")
    }
    func testParseAndSerializeJsonCredential9() {
        ParseAndSerializeJsonCredential(2, "foo", "email")
    }
    
    func ParseAndSerializeJsonCredential(_ version: Int, _ did: String, _ vc: String) {
        do {
            let cd = try testData!.getCompatibleData(version)
            try cd.loadAll()
            
            let normalizedJson = try cd.getCredentialJson(did, vc, "normalized")
            let normalized = try VerifiableCredential.fromJson(normalizedJson)
            
            let compactJson = try cd.getCredentialJson(did, vc, "compact")
            let compact = try VerifiableCredential.fromJson(compactJson)
            
            let credential = try cd.getCredential(did, vc)
            
            XCTAssertFalse(credential.isExpired)
            XCTAssertTrue(try credential.isGenuine())
            XCTAssertTrue(credential.isValid)
            
            XCTAssertEqual(normalizedJson, normalized.toString(true))
            XCTAssertEqual(normalizedJson, compact.toString(true))
            XCTAssertEqual(normalizedJson, credential.toString(true))
            
            // Don't check the compact mode for the old versions
            if (cd.isLatestVersion) {
                XCTAssertEqual(compactJson, normalized.toString(false))
                XCTAssertEqual(compactJson, compact.toString(false))
                XCTAssertEqual(compactJson, credential.toString(false))
            }
        } catch {
            XCTFail()
        }
    }
    
    func testDeclareCrendential1() {
        DeclareCrendential(1, "user1", "twitter")
    }
    func testDeclareCrendential2() {
        DeclareCrendential(1, "user1", "passport")
    }
    func testDeclareCrendential3() {
        DeclareCrendential(1, "user1", "json")
    }
    func testDeclareCrendential4() {
        DeclareCrendential(2, "user1", "twitter")
    }
    func testDeclareCrendential5() {
        DeclareCrendential(2, "user1", "passport")
    }
    func testDeclareCrendential6() {
        DeclareCrendential(2, "user1", "json")
    }
    func testDeclareCrendential7() {
        DeclareCrendential(2, "foobar", "license")
    }
    func testDeclareCrendential8() {
        DeclareCrendential(2, "foobar", "services")
    }
    func testDeclareCrendential9() {
        DeclareCrendential(2, "foo", "email")
    }
    
    func DeclareCrendential(_ version: Int, _ did: String, _ vc: String) {
        do {
            let cd = try testData!.getCompatibleData(version)
            try cd.loadAll()
            
            let credential = try cd.getCredential(did, vc);
            // Sign key for customized DID
            let doc = try credential.subject?.did.resolve()
            var signKey: DIDURL? = nil
            if (doc!.controllerCount() > 1) {
                let rnd = Int(arc4random())
                let index = rnd % doc!.controllerCount()
                signKey = try doc!.controllers()[index].resolve()?.defaultPublicKeyId()
            }
            
            if signKey == nil {
                try credential.declare(storePassword)
            }
            else {
                try credential.declare(signKey!, storePassword)
            }
            
            let id = credential.getId()
            let resolved = try VerifiableCredential.resolve(id!)
            XCTAssertNotNil(resolved)
            
            XCTAssertEqual(credential.toString(), resolved!.toString())
            
            let metadata = resolved!.getMetadata()
            XCTAssertNotNil(metadata)
            XCTAssertNotNil(metadata.getPublishTime())
            XCTAssertNotNil(metadata.getTransactionId())
            XCTAssertFalse(try resolved!.isRevoked())
            
            let bio = try VerifiableCredential.resolveBiography(id!, credential.getIssuer()!)
            XCTAssertNotNil(bio)
            XCTAssertEqual(1, bio?.getAllTransactions().count)
            XCTAssertEqual(IDChainRequestOperation.DECLARE, bio!.getTransaction(0).request.operation)
        } catch {
            XCTFail()
        }
    }
    
    func testDeclareCrendentials() {
        let sd = testData!.sharedInstantData()
        let vcds = [
            [ "user1": "passport" ]]
//        let vcds = [
//            [ "user1": "twitter" ],
//            [ "user1": "passport" ],
//            ["user1": "json" ],
//            [ "user1": "jobposition" ],
//            [ "foobar": "license" ],
//            [ "foobar": "services" ],
//            [ "foo" : "email" ]]
        
        for vcd in vcds {
            do {
                let key = vcd.first!.key
                let vaule = vcd[key]
                let credential = try sd.getCredential(key, vaule!)
                // Sign key for customized DID
                let doc = try credential?.subject?.did.resolve()
                var signKey: DIDURL? = nil
                if (doc!.controllerCount() > 1) {
                    let rnd = Int(arc4random())
                    let index = rnd % doc!.controllerCount()
                    signKey = try doc!.controllers()[index].resolve()?.defaultPublicKeyId()
                }
                if let _ = signKey {
                    try credential!.declare(signKey!, storePassword)
                }
                else {
                    try credential!.declare(storePassword)
                }
                let id = credential!.getId()
                let resolved = try VerifiableCredential.resolve(id!)
                XCTAssertNotNil(resolved)
                
                XCTAssertEqual(credential!.toString(), resolved!.toString())
                
                let metadata = resolved!.getMetadata()
                XCTAssertNotNil(metadata)
                XCTAssertNotNil(metadata.getPublishTime())
                XCTAssertNotNil(metadata.getTransactionId())
                XCTAssertFalse(try resolved!.isRevoked())
                
                let bio = try VerifiableCredential.resolveBiography(id!, credential!.getIssuer()!)
                XCTAssertNotNil(bio)
                XCTAssertEqual(1, bio?.getAllTransactions().count)
                XCTAssertEqual(IDChainRequestOperation.DECLARE, bio!.getTransaction(0).request.operation)
            } catch {
                XCTFail()
            }
        }
    }
    func testRevokeCrendential1() {
        RevokeCrendential(1, "user1", "twitter")
    }
    func testRevokeCrendential2() {
        RevokeCrendential(1, "user1", "passport")
    }
    func testRevokeCrendential3() {
        RevokeCrendential(1, "user1", "json")
    }
    func testRevokeCrendential4() {
        RevokeCrendential(2, "user1", "twitter")
    }
    func testRevokeCrendential5() {
        RevokeCrendential(2, "user1", "passport")
    }
    func testRevokeCrendential6() {
        RevokeCrendential(2, "user1", "json")
    }
    func testRevokeCrendential7() {
        RevokeCrendential(2, "foobar", "license")
    }
    func testRevokeCrendential8() {
        RevokeCrendential(2, "foobar", "services")
    }
    func testRevokeCrendential9() {
        RevokeCrendential(2, "foo", "email")
    }
    
    func RevokeCrendential(_ version: Int, _ did: String, _ vc: String) {
        do {
            let cd = try testData!.getCompatibleData(version)
            try cd.loadAll()
            
            let credential = try cd.getCredential(did, vc)
            XCTAssertFalse(try credential.wasDeclared())
            
            // Sign key for customized DID
            let doc = try credential.subject?.did.resolve()
            var signKey: DIDURL? = nil
            if (doc!.controllerCount() > 1) {
                let rnd = Int(arc4random())
                let index = rnd % doc!.controllerCount()
                signKey = try doc!.controllers()[index].resolve()?.defaultPublicKeyId()
            }
            
            if let _ = signKey {
                try credential.declare(signKey!, storePassword)
            }
            else {
                try credential.declare(storePassword)
            }
            
            let id = credential.getId()
            var resolved = try VerifiableCredential.resolve(id!)
            XCTAssertNotNil(resolved)
            
            XCTAssertEqual(credential.toString(), resolved!.toString())
            
            var metadata = resolved!.getMetadata()
            XCTAssertNotNil(metadata)
            XCTAssertNotNil(metadata.getPublishTime())
            XCTAssertNotNil(metadata.getTransactionId())
            XCTAssertFalse(try resolved!.isRevoked())
            
            XCTAssertTrue(try credential.wasDeclared())
            if let _ = signKey {
                try credential.revoke(signKey!, storePassword)
            }
            else {
                try credential.revoke(storePassword)
            }
            
            resolved = try VerifiableCredential.resolve(id!)
            XCTAssertNotNil(resolved)
            
            XCTAssertEqual(credential.toString(), resolved!.toString())
            
            metadata = resolved!.getMetadata()
            XCTAssertNotNil(metadata)
            XCTAssertNotNil(metadata.getPublishTime())
            XCTAssertNotNil(metadata.getTransactionId())
            XCTAssertTrue(try resolved!.isRevoked())
            
            let bio = try VerifiableCredential.resolveBiography(id!, credential.getIssuer()!)
            XCTAssertNotNil(bio)
            XCTAssertEqual(2, bio?.getAllTransactions().count)
            XCTAssertEqual(IDChainRequestOperation.REVOKE, bio!.getTransaction(0).request.operation)
            XCTAssertEqual(IDChainRequestOperation.DECLARE, bio!.getTransaction(1).request.operation)
        } catch {
            XCTFail()
        }
    }
    
    func testIllegalRevoke1() {
        IllegalRevoke(1, "user1", "twitter")
    }
    func testIllegalRevoke2() {
        IllegalRevoke(1, "user1", "passport")
    }
    func testIllegalRevoke3() {
        IllegalRevoke(1, "user1", "json")
    }
    func testIllegalRevoke4() {
        IllegalRevoke(2, "user1", "twitter")
    }
    func testIllegalRevoke5() {
        IllegalRevoke(2, "user1", "passport")
    }
    func testIllegalRevoke6() {
        IllegalRevoke(2, "user1", "json")
    }
    func testIllegalRevoke7() {
        IllegalRevoke(2, "foobar", "license")
    }
    func testIllegalRevoke8() {
        IllegalRevoke(2, "foobar", "services")
    }
    func testIllegalRevoke9() {
        IllegalRevoke(2, "foo", "email")
    }
    
    func IllegalRevoke(_ version: Int, _ did: String, _ vc: String) {
        do {
            let cd = try testData!.getCompatibleData(version)
            try cd.loadAll()
            
            let credential = try cd.getCredential(did, vc)
            XCTAssertFalse(try credential.wasDeclared())
            
            // Sign key for customized DID
            let doc = try credential.subject?.did.resolve()
            var signKey: DIDURL? = nil
            if (doc!.controllerCount() > 1) {
                let rnd = Int(arc4random())
                let index = rnd % doc!.controllerCount()
                signKey = try doc!.controllers()[index].resolve()?.defaultPublicKeyId()
            }
            if let _ = signKey {
                try credential.declare(signKey!, storePassword)
            }
            else {
                try credential.declare(storePassword)
            }
            
            let id = credential.getId()
            var resolved = try VerifiableCredential.resolve(id!)
            XCTAssertNotNil(resolved)
            
            XCTAssertEqual(credential.toString(), resolved!.toString())
            
            var metadata = resolved!.getMetadata()
            XCTAssertNotNil(metadata)
            XCTAssertNotNil(metadata.getPublishTime())
            XCTAssertNotNil(metadata.getTransactionId())
            XCTAssertFalse(try resolved!.isRevoked())
            
            XCTAssertTrue(try credential.wasDeclared())
            let sd = testData?.sharedInstantData()
            let d = try sd!.getUser1Document()
            
            //TODO:
            XCTAssertThrowsError(_ = try VerifiableCredential.revoke(credential.getId()!, d, storePassword)){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError: break
                default:
                    XCTFail()
                }
            }
            
            resolved = try VerifiableCredential.resolve(id!)
            XCTAssertNotNil(resolved)
            
            XCTAssertEqual(credential.toString(), resolved!.toString())
            
            metadata = resolved!.getMetadata()
            XCTAssertNotNil(metadata)
            XCTAssertNotNil(metadata.getPublishTime())
            XCTAssertNotNil(metadata.getTransactionId())
            XCTAssertFalse(try resolved!.isRevoked())
            
            let bio = try VerifiableCredential.resolveBiography(id!, credential.getIssuer()!)
            XCTAssertNotNil(bio)
            XCTAssertEqual(1, bio?.getAllTransactions().count)
            XCTAssertEqual(IDChainRequestOperation.DECLARE, bio!.getTransaction(0).request.operation)
        } catch {
            XCTFail()
        }
    }
    
    func testRevokeCrendentialWithDifferentKey1() {
        RevokeCrendentialWithDifferentKey(2, "foobar", "license")
    }
    func testRevokeCrendentialWithDifferentKey2() {
        RevokeCrendentialWithDifferentKey(2, "foobar", "services")
    }
    func testRevokeCrendentialWithDifferentKey3() {
        RevokeCrendentialWithDifferentKey(2, "foo", "email")
    }
    
    func RevokeCrendentialWithDifferentKey(_ version: Int, _ did: String, _ vc: String) {
        do {
            let cd = try testData!.getCompatibleData(version)
            try cd.loadAll()
            
            let credential = try cd.getCredential(did, vc)
            XCTAssertFalse(try credential.wasDeclared())
            
            // Sign key for customized DID
            let doc = try credential.subject?.did.resolve()
            var signKey: DIDURL? = nil
            if (doc!.controllerCount() > 1) {
                let rnd = Int(arc4random())
                let index = rnd % doc!.controllerCount()
                signKey = try doc!.controllers()[index].resolve()?.defaultPublicKeyId()
            }
            
            try credential.declare(signKey!, storePassword)
            
            let id = credential.getId()
            var resolved = try VerifiableCredential.resolve(id!)
            XCTAssertNotNil(resolved)
            
            XCTAssertEqual(credential.toString(), resolved!.toString())
            
            var metadata = resolved!.getMetadata()
            XCTAssertNotNil(metadata)
            XCTAssertNotNil(metadata.getPublishTime())
            XCTAssertNotNil(metadata.getTransactionId())
            XCTAssertFalse(try resolved!.isRevoked())
            
            XCTAssertTrue(try credential.wasDeclared())
            
            if (doc!.controllerCount() > 1) {
                let rnd = Int(arc4random())
                let index = rnd % doc!.controllerCount()
                signKey = try doc!.controllers()[index].resolve()?.defaultPublicKeyId()
            }
            
            try credential.revoke(signKey!, storePassword)
            
            resolved = try VerifiableCredential.resolve(id!)
            XCTAssertNotNil(resolved)
            
            XCTAssertEqual(credential.toString(), resolved!.toString())
            
            metadata = resolved!.getMetadata()
            XCTAssertNotNil(metadata)
            XCTAssertNotNil(metadata.getPublishTime())
            XCTAssertNotNil(metadata.getTransactionId())
            XCTAssertTrue(try resolved!.isRevoked())
            
            let bio = try VerifiableCredential.resolveBiography(id!, credential.getIssuer()!)
            XCTAssertNotNil(bio)
            XCTAssertEqual(2, bio?.getAllTransactions().count)
            XCTAssertEqual(IDChainRequestOperation.REVOKE, bio!.getTransaction(0).request.operation)
            XCTAssertEqual(IDChainRequestOperation.DECLARE, bio!.getTransaction(1).request.operation)
        } catch {
            XCTFail()
        }
    }
    
    func testDeclareAfterDeclare1() {
        DeclareAfterDeclare(1, "user1", "twitter")
    }
    func testDeclareAfterDeclare2() {
        DeclareAfterDeclare(1, "user1", "passport")
    }
    func testDeclareAfterDeclare3() {
        DeclareAfterDeclare(1, "user1", "json")
    }
    func testDeclareAfterDeclare4() {
        DeclareAfterDeclare(2, "user1", "twitter")
    }
    func testDeclareAfterDeclare5() {
        DeclareAfterDeclare(2, "user1", "passport")
    }
    func testDeclareAfterDeclare6() {
        DeclareAfterDeclare(2, "user1", "json")
    }
    func testDeclareAfterDeclare7() {
        DeclareAfterDeclare(2, "foobar", "license")
    }
    func testDeclareAfterDeclare8() {
        DeclareAfterDeclare(2, "foobar", "services")
    }
    func testDeclareAfterDeclare9() {
        DeclareAfterDeclare(2, "foo", "email")
    }
    
    func DeclareAfterDeclare(_ version: Int, _ did: String, _ vc: String) {
        do {
            let cd = try testData!.getCompatibleData(version)
            try cd.loadAll()
            
            let credential = try cd.getCredential(did, vc)
            XCTAssertFalse(try credential.wasDeclared())
            XCTAssertFalse(try credential.isRevoked())
            
            // Sign key for customized DID
            let doc = try credential.subject?.did.resolve()
            var signKey: DIDURL? = nil
            if (doc!.controllerCount() > 1) {
                let rnd = Int(arc4random())
                let index = rnd % doc!.controllerCount()
                signKey = try doc!.controllers()[index].resolve()?.defaultPublicKeyId()
            }
            if let _ = signKey {
                try credential.declare(signKey!, storePassword)
            }
            else {
                try credential.declare(storePassword)
            }
            let resolved = try VerifiableCredential.resolve(credential.id!)
            XCTAssertNotNil(resolved)
            XCTAssertTrue(try credential.wasDeclared())
            XCTAssertFalse(try credential.isRevoked())
            
            XCTAssertThrowsError(_ = try credential.declare(storePassword)) { error in
                switch error {
                case DIDError.UncheckedError.IllegalStateError.CredentialAlreadyExistError: break
                default:
                    XCTFail()
                }
            }
            
            let bio = try VerifiableCredential.resolveBiography(credential.getId()!, credential.getIssuer()!)
            XCTAssertNotNil(bio)
            XCTAssertEqual(1, bio?.getAllTransactions().count)
            XCTAssertEqual(IDChainRequestOperation.DECLARE, bio!.getTransaction(0).request.operation)
        } catch {
            XCTFail()
        }
    }
    
    func testDeclareAfterRevoke1() {
        DeclareAfterRevoke(1, "user1", "twitter")
    }
    func testDeclareAfterRevoke2() {
        DeclareAfterRevoke(1, "user1", "passport")
    }
    func testDeclareAfterRevoke3() {
        DeclareAfterRevoke(1, "user1", "json")
    }
    func testDeclareAfterRevoke4() {
        DeclareAfterRevoke(2, "user1", "twitter")
    }
    func testDeclareAfterRevoke5() {
        DeclareAfterRevoke(2, "user1", "passport")
    }
    func testDeclareAfterRevoke6() {
        DeclareAfterRevoke(2, "user1", "json")
    }
    func testDeclareAfterRevoke7() {
        DeclareAfterRevoke(2, "foobar", "license")
    }
    func testDeclareAfterRevoke8() {
        DeclareAfterRevoke(2, "foobar", "services")
    }
    func testDeclareAfterRevoke9() {
        DeclareAfterRevoke(2, "foo", "email")
    }
    
    func DeclareAfterRevoke(_ version: Int, _ did: String, _ vc: String) {
        do {
            let cd = try testData!.getCompatibleData(version)
            try cd.loadAll()
            
            let credential = try cd.getCredential(did, vc)
            XCTAssertFalse(try credential.wasDeclared())
            XCTAssertFalse(try credential.isRevoked())
            
            // Sign key for customized DID
            let doc = try credential.subject?.did.resolve()
            var signKey: DIDURL? = nil
            if (doc!.controllerCount() > 1) {
                let rnd = Int(arc4random())
                let index = rnd % doc!.controllerCount()
                signKey = try doc!.controllers()[index].resolve()?.defaultPublicKeyId()
            }
            if let _ = signKey {
                try credential.revoke(signKey!, storePassword)
            }
            else {
                try credential.revoke(storePassword)
            }
            
            XCTAssertFalse(try credential.wasDeclared())
            XCTAssertTrue(try credential.isRevoked())
            
            let resolved = try VerifiableCredential.resolve(credential.id!)
            XCTAssertNil(resolved)
            
            var _: DIDURL? = signKey
            XCTAssertThrowsError(_ = try credential.declare(storePassword)) { error in
                switch error {
                case DIDError.UncheckedError.IllegalStateError.CredentialRevokedError: break
                default:
                    XCTFail()
                }
            }
            
            let bio = try VerifiableCredential.resolveBiography(credential.id!, credential.issuer!)
            XCTAssertNotNil(bio)
            XCTAssertEqual(1, bio?.getAllTransactions().count)
            XCTAssertEqual(IDChainRequestOperation.REVOKE, bio!.getTransaction(0).request.operation)
        } catch {
            XCTFail()
        }
    }
    
    func testDeclareAfterRevokeWithDifferentKey1() {
        DeclareAfterRevokeWithDifferentKey(2, "foobar", "license")
    }
    func testDeclareAfterRevokeWithDifferentKey2() {
        DeclareAfterRevokeWithDifferentKey(2, "foobar", "services")
    }
    func testDeclareAfterRevokeWithDifferentKey3() {
        DeclareAfterRevokeWithDifferentKey(2, "foo", "email")
    }
    
    func DeclareAfterRevokeWithDifferentKey(_ version: Int, _ did: String, _ vc: String) {
        
        do {
            let cd = try testData!.getCompatibleData(version)
            try cd.loadAll()
            
            let credential = try cd.getCredential(did, vc)
            XCTAssertFalse(try credential.wasDeclared())
            XCTAssertFalse(try credential.isRevoked())
            
            // Sign key for customized DID
            let doc = try credential.subject?.did.resolve()
            var signKey: DIDURL? = nil
            if (doc!.controllerCount() > 1) {
                let rnd = Int(arc4random())
                let index = rnd % doc!.controllerCount()
                signKey = try doc!.controllers()[index].resolve()?.defaultPublicKeyId()
            }
            
            try credential.revoke(signKey!, storePassword)
            
            XCTAssertFalse(try credential.wasDeclared())
            XCTAssertTrue(try credential.isRevoked())
            
            let resolved = try VerifiableCredential.resolve(credential.id!)
            XCTAssertNil(resolved);
            
            if (doc!.controllerCount() > 1) {
                let rnd = Int(arc4random())
                let index = rnd % doc!.controllerCount()
                signKey = try doc!.controllers()[index].resolve()?.defaultPublicKeyId()
            }
            
            let key = signKey
            XCTAssertThrowsError(_ = try credential.declare(key!, storePassword)) { error in
                switch error {
                case DIDError.UncheckedError.IllegalStateError.CredentialRevokedError: break
                default:
                    XCTFail()
                }
            }
            
            let bio = try VerifiableCredential.resolveBiography(credential.getId()!, credential.getIssuer()!)
            XCTAssertNotNil(bio)
            XCTAssertEqual(1, bio!.getAllTransactions().count)
            XCTAssertEqual(IDChainRequestOperation.REVOKE, bio!.getTransaction(0).request.operation)
        } catch {
            XCTFail()
        }
    }
    
    func testDeclareAfterRevokeByIssuer1() {
        DeclareAfterRevokeByIssuer(1, "user1", "twitter")
    }
    func testDeclareAfterRevokeByIssuer2() {
        DeclareAfterRevokeByIssuer(1, "user1", "passport")
    }
    func testDeclareAfterRevokeByIssuer3() {
        DeclareAfterRevokeByIssuer(1, "user1", "json")
    }
    func testDeclareAfterRevokeByIssuer4() {
        DeclareAfterRevokeByIssuer(2, "user1", "twitter")
    }
    func testDeclareAfterRevokeByIssuer5() {
        DeclareAfterRevokeByIssuer(2, "user1", "passport")
    }
    func testDeclareAfterRevokeByIssuer6() {
        DeclareAfterRevokeByIssuer(2, "user1", "json")
    }
    func testDeclareAfterRevokeByIssuer7() {
        DeclareAfterRevokeByIssuer(2, "foobar", "license")
    }
    func testDeclareAfterRevokeByIssuer8() {
        DeclareAfterRevokeByIssuer(2, "foobar", "services")
    }
    func testDeclareAfterRevokeByIssuer9() {
        DeclareAfterRevokeByIssuer(2, "foo", "email")
    }
    
    func DeclareAfterRevokeByIssuer(_ version: Int, _ did: String, _ vc: String) {
        do {
            let cd = try testData!.getCompatibleData(version)
            try cd.loadAll()
            
            let credential = try cd.getCredential(did, vc)
            XCTAssertFalse(try credential.wasDeclared())
            XCTAssertFalse(try credential.isRevoked())
            
            // Sign key for issuer
            let issuer = try credential.getIssuer()!.resolve()
            var signKey: DIDURL? = nil
            if (issuer!.controllerCount() > 1) {
                let rnd = Int(arc4random())
                let index = rnd % issuer!.controllerCount()
                signKey = try issuer!.controllers()[index].resolve()?.defaultPublicKeyId()
            } else {
                signKey = issuer?.defaultPublicKeyId()
            }
            
            try credential.revoke(signKey!, storePassword)
            
            XCTAssertFalse(try credential.wasDeclared())
            XCTAssertTrue(try credential.isRevoked())
            
            let resolved = try VerifiableCredential.resolve(credential.getId()!)
            XCTAssertNil(resolved)
            
            let doc = try credential.subject?.did.resolve()
            if (doc!.controllerCount() > 1) {
                let rnd = Int(arc4random())
                let index = rnd % doc!.controllerCount()
                signKey = try doc!.controllers()[index].resolve()?.defaultPublicKeyId()
            }
            
            var key: DIDURL? = signKey
            
            XCTAssertThrowsError(_ = try credential.declare(key!, storePassword)) { error in
                switch error {
                case DIDError.UncheckedError.IllegalStateError.CredentialRevokedError: break
                default:
                    XCTFail()
                }
            }
            let bio = try VerifiableCredential.resolveBiography(credential.getId()!, credential.getIssuer()!)
            XCTAssertNotNil(bio)
            XCTAssertEqual(1, bio!.getAllTransactions().count)
            XCTAssertEqual(IDChainRequestOperation.REVOKE, bio!.getTransaction(0).request.operation)
        } catch {
            XCTFail()
        }
    }
}

