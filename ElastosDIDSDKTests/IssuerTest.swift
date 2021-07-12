
import XCTest
@testable import ElastosDIDSDK

class IssuerTest: XCTestCase {
    var simulatedIDChain: SimulatedIDChain = SimulatedIDChain()
    var testData: TestData?
    var store: DIDStore?
    var issuerDoc: DIDDocument?
    var testDoc: DIDDocument?

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
        testData = TestData()
        store = testData?.store!

//        try! simulatedIDChain.httpServer.start(in_port_t(DEFAULT_PORT), forceIPv4: true)
//        simulatedIDChain.start()
//        try! DIDBackend.initialize(simulatedIDChain.getAdapter())
        let adapter = SimulatedIDChainAdapter("http://localhost:\(DEFAULT_PORT)/")
        try! DIDBackend.initialize(adapter)
        issuerDoc = try! testData?.sharedInstantData().getIssuerDocument()
        testDoc = try! testData?.instantData!.getUser1Document()
        
    }

    func testNewIssuerTestWithSignKey() {
        do {
            let signKey = issuerDoc?.defaultPublicKeyId()

            let issuer = try VerifiableCredentialIssuer(issuerDoc!.subject, signKey!, store!)

            XCTAssertEqual(issuerDoc?.subject, issuer.did)
            XCTAssertEqual(signKey, issuer.signKey)
        } catch {
            XCTFail()
        }
    }
    
    func testnewIssuerTestWithoutSignKey() {
        do {
            let issuer = try VerifiableCredentialIssuer(issuerDoc!.subject, store!)
            
            XCTAssertEqual(issuerDoc?.subject, issuer.did)
            XCTAssertEqual(issuerDoc?.defaultPublicKeyId(), issuer.signKey)
        } catch {
            XCTFail()
        }
    }
    
    func testnewIssuerTestWithInvalidKey() {
        do {
            let signKey = try DIDURL(issuerDoc!.subject, "#testKey")
            let doc = issuerDoc
            
            XCTAssertThrowsError(_ = try VerifiableCredentialIssuer(doc!, signKey)){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError: break
                default:
                    XCTFail()
                }
            }
        } catch {
            XCTFail()
        }
    }
    
    func testnewIssuerTestWithInvalidKey2() {
        do {
            let signKey = try DIDURL(issuerDoc!.subject, "#recovery")
            let doc = issuerDoc
            XCTAssertThrowsError(_ = try VerifiableCredentialIssuer(doc!, signKey)){ error in
                switch error {
                case DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError: break
                default:
                    XCTFail()
                }
            }
        } catch {
            XCTFail()
        }
    }
    
    func testIssueKycCredentialTest() {
        do {
            let props = ["name": "John",
                         "gender": "Male",
                         "nation": "Singapore",
                         "language": "English",
                         "email": "john@example.com",
                         "twitter": "@john"]

            let issuer = try VerifiableCredentialIssuer(issuerDoc!)

            let cb = issuer.editingVerifiableCredentialFor(did: testDoc!.subject)
            let vc = try cb.withId("#testCredential")
                .withTypes("BasicProfileCredential", "InternetAccountCredential")
                .withProperties(props)
                .sealed(using: storePassword)

            let vcId = try DIDURL(testDoc!.subject, "#testCredential")

            XCTAssertEqual(vcId, vc.id)

            XCTAssertTrue(vc.getType().contains("BasicProfileCredential"))
            XCTAssertTrue(vc.getType().contains("InternetAccountCredential"))
            XCTAssertFalse(vc.getType().contains("SelfProclaimedCredential"))

            XCTAssertEqual(issuerDoc?.subject, vc.issuer)
            XCTAssertEqual(testDoc?.subject, vc.subject?.did)

            XCTAssertEqual("John", vc.subject!.properties()["name"] as? String)
            XCTAssertEqual("Male", vc.subject!.properties()["gender"] as? String)
            XCTAssertEqual("Singapore", vc.subject!.properties()["nation"] as? String)
            XCTAssertEqual("English", vc.subject!.properties()["language"] as? String)
            XCTAssertEqual("john@example.com", vc.subject!.properties()["email"] as? String)
            XCTAssertEqual("@john", vc.subject!.properties()["twitter"] as? String)

            XCTAssertFalse(try vc.isExpired())
            XCTAssertTrue(try vc.isGenuine())
            XCTAssertTrue(try vc.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func testIssueSelfProclaimedCredentialTest() {
        do {
            let props = ["name": "Testing Issuer",
                    "nation": "Singapore",
                    "language": "English",
                    "email": "issuer@example.com",
                    "twitter": "@john"]

            let issuer = try VerifiableCredentialIssuer(issuerDoc!)

            let cb = issuer.editingVerifiableCredentialFor(did: issuerDoc!.subject)
            let vc = try cb.withId("#myCredential")
                .withTypes("BasicProfileCredential", "SelfProclaimedCredential")
                .withProperties(props)
                .sealed(using: storePassword)

            let vcId = try DIDURL(issuerDoc!.subject, "#myCredential")

            XCTAssertEqual(vcId, vc.getId())

            XCTAssertTrue(vc.getType().contains("BasicProfileCredential"))
            XCTAssertTrue(vc.getType().contains("SelfProclaimedCredential"))
            XCTAssertFalse(vc.getType().contains("InternetAccountCredential"))

            XCTAssertEqual(issuerDoc?.subject, vc.issuer)
            XCTAssertEqual(issuerDoc?.subject, vc.subject?.did)

            XCTAssertEqual("Testing Issuer", vc.subject!.properties()["name"] as? String)
            XCTAssertEqual("Singapore", vc.subject!.properties()["nation"] as? String)
            XCTAssertEqual("English", vc.subject!.properties()["language"] as? String)
            XCTAssertEqual("issuer@example.com", vc.subject!.properties()["email"] as? String)

            XCTAssertFalse(try vc.isExpired())
            XCTAssertTrue(try vc.isGenuine())
            XCTAssertTrue(try vc.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func testIssueKycCredentialForCidTest() {
        do {
            let testDoc = try testData!.sharedInstantData().getBazDocument()

            let props = ["name": "John",
                         "gender": "Male",
                         "nation": "Singapore",
                         "language": "English",
                         "email": "john@example.com",
                         "twitter": "@john"]

            let issuer = try VerifiableCredentialIssuer(issuerDoc!)

            let cb = issuer.editingVerifiableCredentialFor(did: testDoc.subject)
            let vc = try cb.withId("#testCredential")
                .withTypes("BasicProfileCredential", "InternetAccountCredential")
                .withProperties(props)
                .sealed(using: storePassword)

            let vcId = try DIDURL(testDoc.subject, "#testCredential")

            XCTAssertEqual(vcId, vc.getId());

            XCTAssertTrue(vc.getType().contains("BasicProfileCredential"))
            XCTAssertTrue(vc.getType().contains("InternetAccountCredential"))
            XCTAssertFalse(vc.getType().contains("SelfProclaimedCredential"))

            XCTAssertEqual(issuerDoc?.subject, vc.issuer)
            XCTAssertEqual(testDoc.subject, vc.subject?.did)

            XCTAssertEqual("John", vc.subject!.properties()["name"] as? String)
            XCTAssertEqual("Male", vc.subject!.properties()["gender"] as? String)
            XCTAssertEqual("Singapore", vc.subject!.properties()["nation"] as? String)
            XCTAssertEqual("English", vc.subject!.properties()["language"] as? String)
            XCTAssertEqual("john@example.com", vc.subject!.properties()["email"] as? String)
            XCTAssertEqual("@john", vc.subject!.properties()["twitter"] as? String)

            XCTAssertFalse(try vc.isExpired())
            XCTAssertTrue(try vc.isGenuine())
            XCTAssertTrue(try vc.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func testIssueKycCredentialFromCidTest() {
        do {
            issuerDoc = try testData?.sharedInstantData().getExampleCorpDocument()

            let props = ["name": "John",
                         "gender": "Male",
                         "nation": "Singapore",
                         "language": "English",
                         "email": "john@example.com",
                         "twitter": "@john"]

            let issuer = try VerifiableCredentialIssuer(issuerDoc!)

            let cb = issuer.editingVerifiableCredentialFor(did: testDoc!.subject)
            let vc = try cb.withId("#testCredential")
                .withTypes("BasicProfileCredential", "InternetAccountCredential")
                .withProperties(props)
                .sealed(using: storePassword)

            let vcId = try DIDURL(testDoc!.subject, "#testCredential")

            XCTAssertEqual(vcId, vc.id)

            XCTAssertTrue(vc.getType().contains("BasicProfileCredential"))
            XCTAssertTrue(vc.getType().contains("InternetAccountCredential"))
            XCTAssertFalse(vc.getType().contains("SelfProclaimedCredential"))

            XCTAssertEqual(issuerDoc?.subject, vc.issuer)
            XCTAssertEqual(testDoc?.subject, vc.subject?.did)

            XCTAssertEqual("John", vc.subject!.properties()["name"] as? String)
            XCTAssertEqual("Male", vc.subject!.properties()["gender"] as? String)
            XCTAssertEqual("Singapore", vc.subject!.properties()["nation"] as? String)
            XCTAssertEqual("English", vc.subject!.properties()["language"] as? String)
            XCTAssertEqual("john@example.com", vc.subject!.properties()["email"] as? String)
            XCTAssertEqual("@john", vc.subject!.properties()["twitter"] as? String)

            XCTAssertFalse(try vc.isExpired())
            XCTAssertTrue(try vc.isGenuine())
            XCTAssertTrue(try vc.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func testIssueSelfProclaimedCredentialFromCidTest() {
        do {
            let issuerDoc = try testData?.sharedInstantData().getExampleCorpDocument()

            let props = ["name": "Testing Issuer",
                        "nation": "Singapore",
                        "language": "English",
                        "email": "issuer@example.com"]
            let issuer = try VerifiableCredentialIssuer(issuerDoc!)

            let cb = issuer.editingVerifiableCredentialFor(did: issuerDoc!.subject)
            let vc = try cb.withId("#myCredential")
                .withTypes("BasicProfileCredential", "SelfProclaimedCredential")
                .withProperties(props)
                .sealed(using: storePassword)

            let vcId = try DIDURL(issuerDoc!.subject, "#myCredential")

            XCTAssertEqual(vcId, vc.id)

            XCTAssertTrue(vc.getType().contains("BasicProfileCredential"))
            XCTAssertTrue(vc.getType().contains("SelfProclaimedCredential"))
            XCTAssertFalse(vc.getType().contains("InternetAccountCredential"))

            
            XCTAssertEqual(issuerDoc?.subject, vc.issuer)
            XCTAssertEqual(issuerDoc?.subject, vc.subject?.did)

            XCTAssertEqual("Testing Issuer", vc.subject!.properties()["name"] as? String)
            XCTAssertEqual("Singapore", vc.subject!.properties()["nation"] as? String)
            XCTAssertEqual("English", vc.subject!.properties()["language"] as? String)
            XCTAssertEqual("issuer@example.com", vc.subject!.properties()["email"] as? String)

            XCTAssertFalse(try vc.isExpired())
            XCTAssertTrue(try vc.isGenuine())
            XCTAssertTrue(try vc.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func testIssueJsonPropsCredentialTest() {
        do {
            let props = "{\"name\":\"Jay Holtslander\",\"alternateName\":\"Jason Holtslander\",\"booleanValue\":true,\"numberValue\":1234,\"doubleValue\":9.5,\"nationality\":\"Canadian\",\"birthPlace\":{\"type\":\"Place\",\"address\":{\"type\":\"PostalAddress\",\"addressLocality\":\"Vancouver\",\"addressRegion\":\"BC\",\"addressCountry\":\"Canada\"}},\"affiliation\":[{\"type\":\"Organization\",\"name\":\"Futurpreneur\",\"sameAs\":[\"https://twitter.com/futurpreneur\",\"https://www.facebook.com/futurpreneur/\",\"https://www.linkedin.com/company-beta/100369/\",\"https://www.youtube.com/user/CYBF\"]}],\"alumniOf\":[{\"type\":\"CollegeOrUniversity\",\"name\":\"Vancouver Film School\",\"sameAs\":\"https://en.wikipedia.org/wiki/Vancouver_Film_School\",\"year\":2000},{\"type\":\"CollegeOrUniversity\",\"name\":\"CodeCore Bootcamp\"}],\"gender\":\"Male\",\"Description\":\"Technologist\",\"disambiguatingDescription\":\"Co-founder of CodeCore Bootcamp\",\"jobTitle\":\"Technical Director\",\"worksFor\":[{\"type\":\"Organization\",\"name\":\"Skunkworks Creative Group Inc.\",\"sameAs\":[\"https://twitter.com/skunkworks_ca\",\"https://www.facebook.com/skunkworks.ca\",\"https://www.linkedin.com/company/skunkworks-creative-group-inc-\",\"https://plus.google.com/+SkunkworksCa\"]}],\"url\":\"https://jay.holtslander.ca\",\"image\":\"https://s.gravatar.com/avatar/961997eb7fd5c22b3e12fb3c8ca14e11?s=512&r=g\",\"address\":{\"type\":\"PostalAddress\",\"addressLocality\":\"Vancouver\",\"addressRegion\":\"BC\",\"addressCountry\":\"Canada\"},\"sameAs\":[\"https://twitter.com/j_holtslander\",\"https://pinterest.com/j_holtslander\",\"https://instagram.com/j_holtslander\",\"https://www.facebook.com/jay.holtslander\",\"https://ca.linkedin.com/in/holtslander/en\",\"https://plus.google.com/+JayHoltslander\",\"https://www.youtube.com/user/jasonh1234\",\"https://github.com/JayHoltslander\",\"https://profiles.wordpress.org/jasonh1234\",\"https://angel.co/j_holtslander\",\"https://www.foursquare.com/user/184843\",\"https://jholtslander.yelp.ca\",\"https://codepen.io/j_holtslander/\",\"https://stackoverflow.com/users/751570/jay\",\"https://dribbble.com/j_holtslander\",\"http://jasonh1234.deviantart.com/\",\"https://www.behance.net/j_holtslander\",\"https://www.flickr.com/people/jasonh1234/\",\"https://medium.com/@j_holtslander\"]}";

            let issuer = try VerifiableCredentialIssuer(issuerDoc!)

            let cb = issuer.editingVerifiableCredentialFor(did: issuerDoc!.subject)
            let vc = try cb.withId("#myCredential")
                .withTypes("BasicProfileCredential", "SelfProclaimedCredential")
                .withProperties(props)
                .sealed(using: storePassword)

            let vcId = try DIDURL(issuerDoc!.subject, "#myCredential")

            XCTAssertEqual(vcId, vc.getId())
            
            XCTAssertTrue(vc.getType().contains("BasicProfileCredential"))
            XCTAssertTrue(vc.getType().contains("SelfProclaimedCredential"))
            XCTAssertFalse(vc.getType().contains("InternetAccountCredential"))

            
            XCTAssertEqual(issuerDoc?.subject, vc.issuer)
            XCTAssertEqual(issuerDoc?.subject, vc.subject?.did)
            //TODO:
            XCTAssertEqual("Technologist", vc.subject!.getProperties()!.get(forKey: "Description")!.asString())
            XCTAssertEqual("Jason Holtslander", vc.subject!.getProperties()!.get(forKey: "alternateName")!.asString())
            XCTAssertEqual(1234, vc.subject!.getProperties()!.get(forKey: "numberValue")!.asNumber() as? Int)
            XCTAssertEqual(9.5, vc.subject!.getProperties()!.get(forKey: "doubleValue")!.asNumber() as? Double)
            XCTAssertNotNil(vc.subject?.properties())
            
            XCTAssertFalse(try vc.isExpired())
            XCTAssertTrue(try vc.isGenuine())
            XCTAssertTrue(try vc.isValid())
        } catch {
            XCTFail()
        }
    }
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        simulatedIDChain.httpServer.stop()
        testData?.cleanup()
        testData?.reset()
    }
}
