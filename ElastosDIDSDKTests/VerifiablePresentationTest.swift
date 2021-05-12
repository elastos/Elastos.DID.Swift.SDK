
import XCTest
@testable import ElastosDIDSDK

class VerifiablePresentationTest: XCTestCase {
    var simulatedIDChain: SimulatedIDChain = SimulatedIDChain()
    var testData: TestData?
    var store: DIDStore?

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
        testData = TestData()
        store = testData?.store!

//        try! simulatedIDChain.httpServer.start(in_port_t(DEFAULT_PORT), forceIPv4: true)
//        simulatedIDChain.start()
//        try! DIDBackend.initialize(simulatedIDChain.getAdapter())
        let adapter = SimulatedIDChainAdapter("http://localhost:\(DEFAULT_PORT)/")
        try! DIDBackend.initialize(adapter)
        testData?.reset()
    }
    
    override func tearDown() {
        testData?.reset()
        testData?.cleanup()
    }
    
    func testReadPresentationNonempty1() {
        ReadPresentationNonempty(1)
    }
    
    func testReadPresentationNonempty2() {
        ReadPresentationNonempty(2)
    }
    
    func ReadPresentationNonempty(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(version)

            // For integrity check
            _ = try cd.getDocument("issuer")
            let user = try cd.getDocument("user1");
            let vp = try cd.getPresentation("user1", "nonempty");
            
            XCTAssertNil(vp.id)
            XCTAssertEqual(1, vp.types.count)
            XCTAssertEqual("VerifiablePresentation", vp.types[0])
            XCTAssertEqual(user.subject, vp.holder)
            
            XCTAssertEqual(4, vp.credentialCount)
            let vcs = vp.credentials
            for vc in vcs {
                XCTAssertEqual(user.subject, vc.subject?.did)

                let re = vc.id?.fragment == "profile" || vc.id?.fragment == "email" || vc.id?.fragment == "twitter" || vc.id?.fragment == "passport"
                XCTAssertTrue(re)
            }


            XCTAssertNotNil(try vp.credential(ofId: try DIDURL(vp.holder!, "#profile")))
            XCTAssertNotNil(try vp.credential(ofId: try DIDURL(vp.holder!, "#email")))
            XCTAssertNotNil(try vp.credential(ofId: try DIDURL(vp.holder!, "#twitter")))
            XCTAssertNotNil(try vp.credential(ofId: try DIDURL(vp.holder!, "#passport")))
            XCTAssertNil(try vp.credential(ofId: try DIDURL(vp.holder!, "#notExist")))
            XCTAssertTrue(try vp.isGenuine())
            XCTAssertTrue(try vp.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func testReadPresentationEmpty1() {
        ReadPresentationEmpty(1)
    }
    
    func testReadPresentationEmpty2() {
        ReadPresentationEmpty(2)
    }
    
    func ReadPresentationEmpty(_ version: Int) {
        do {
            let cd = try testData!.getCompatibleData(version)

           // For integrity check
            _ = try cd.getDocument("issuer")
            let user = try cd.getDocument("user1")
            let vp = try cd.getPresentation("user1", "empty")

           XCTAssertNil(vp.id)
           XCTAssertEqual(1, vp.types.count)
            XCTAssertEqual(Constants.DEFAULT_PRESENTATION_TYPE, vp.types[0])
            XCTAssertEqual(user.subject, vp.holder)

            XCTAssertEqual(0, vp.credentials.count)
            XCTAssertNil(try vp.credential(ofId: try DIDURL(vp.holder!, "#notExist")))

            XCTAssertTrue(try vp.isGenuine())
            XCTAssertTrue(try vp.isValid())
        } catch {
        
        }
    }
    func testParseAndSerializeNonempty1() {
        ParseAndSerializeNonempty(1, "user1", "empty")
    }
    
    func testParseAndSerializeNonempty2() {
        ParseAndSerializeNonempty(1, "user1", "nonempty")
    }
    func testParseAndSerializeNonempty3() {
        ParseAndSerializeNonempty(2, "user1", "empty")
    }
    func testParseAndSerializeNonempty4() {
        ParseAndSerializeNonempty(2, "user1", "nonempty")
    }
    func testParseAndSerializeNonempty5() {
        ParseAndSerializeNonempty(2, "user1", "optionalattrs")
    }
    func testParseAndSerializeNonempty6() {
        ParseAndSerializeNonempty(2, "foobar", "empty")
    }
    func testParseAndSerializeNonempty7() {
        ParseAndSerializeNonempty(2, "foobar", "nonempty")
    }
    func testParseAndSerializeNonempty8() {
        ParseAndSerializeNonempty(2, "foobar", "optionalattrs")
    }
    func ParseAndSerializeNonempty(_ version: Int, _ did: String, _ presentation: String) {
        do {
            let cd = try testData!.getCompatibleData(version)
           // For integrity check
            try cd.loadAll()

            let vp = try cd.getPresentation(did, presentation)

           XCTAssertNotNil(vp)
            XCTAssertTrue(try vp.isGenuine())
            XCTAssertTrue(try vp.isValid())

            let normalizedJson = try cd.getPresentationJson(did, presentation, "normalized")

           let normalized = try VerifiablePresentation.fromJson(normalizedJson)
            XCTAssertNotNil(normalized)
            XCTAssertTrue(try normalized.isGenuine())
            XCTAssertTrue(try normalized.isValid())

           XCTAssertEqual(normalizedJson, normalized.toString())
            XCTAssertEqual(normalizedJson, vp.toString())
        } catch {
            XCTFail()
        }
    }
    
    func testBuildNonempty() {
        do {
            let td = testData!.sharedInstantData()
            let doc = try td.getUser1Document()

            let pb = try VerifiablePresentation.editingVerifiablePresentation(for: doc.subject, using: store!)
            let vp = try pb
                .withCredentials(try doc.credential(ofId: "#profile")!, doc.credential(ofId: "#email")!, td.getUser1TwitterCredential(), td.getUser1PassportCredential())
                .withRealm("https://example.com/")
                .withNonce("873172f58701a9ee686f0630204fee59")
                .sealed(using: storePassword)
            
            XCTAssertNotNil(vp)

            XCTAssertNil(vp.id)
            XCTAssertEqual(1, vp.types.count)
            XCTAssertEqual(Constants.DEFAULT_PRESENTATION_TYPE, vp.types[0])
            XCTAssertEqual(doc.subject, vp.holder)

            XCTAssertEqual(4, vp.credentialCount)
            let vcs = vp.credentials
            for vc in vcs {
                XCTAssertEqual(doc.subject, vc.subject?.did)
                let re = vc.id?.fragment == "profile" || vc.id?.fragment == "email" || vc.id?.fragment == "twitter" || vc.id?.fragment == "passport" || vc.id?.fragment == "notExist"
                XCTAssertTrue(re)
            }

            XCTAssertNotNil(try vp.credential(ofId: try DIDURL(vp.holder!, "#profile")))
            XCTAssertNotNil(try vp.credential(ofId: try DIDURL(vp.holder!, "#email")))
            XCTAssertNotNil(try vp.credential(ofId: try DIDURL(vp.holder!, "#twitter")))
            XCTAssertNotNil(try vp.credential(ofId: try DIDURL(vp.holder!, "#passport")))
            XCTAssertNil(try vp.credential(ofId: try DIDURL(vp.holder!, "#notExist")))

            XCTAssertTrue(try vp.isGenuine())
            XCTAssertTrue(try vp.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func testBuildNonemptyWithOptionalAttrs() {
        do {
            let td = testData!.sharedInstantData()
            let doc = try td.getUser1Document()

            let pb = try VerifiablePresentation.editingVerifiablePresentation(for: doc.subject, using: store!)
            let vp = try pb
                .withId("#test-vp")
                .withTypes("Trail", "TestPresentation")
                .withCredentials(try doc.credential(ofId: "#profile")!, doc.credential(ofId: "#email")!, td.getUser1TwitterCredential(), td.getUser1PassportCredential())
                .withRealm("https://example.com/")
                .withNonce("873172f58701a9ee686f0630204fee59")
                .sealed(using: storePassword)
            
            XCTAssertNotNil(vp)

            XCTAssertEqual(try DIDURL(doc.subject, "#test-vp"), vp.id)
            XCTAssertEqual(2, vp.types.count)
            XCTAssertEqual("TestPresentation", vp.types[0])
            XCTAssertEqual("Trail", vp.types[1])
            XCTAssertEqual(doc.subject, vp.holder)

            XCTAssertEqual(4, vp.credentials.count)
            let vcs = vp.credentials
            for vc in vcs {
                XCTAssertEqual(doc.subject, vc.subject?.did)
                let re = vc.id?.fragment == "profile" || vc.id?.fragment == "email" || vc.id?.fragment == "twitter" || vc.id?.fragment == "passport"
                XCTAssertTrue(re)
            }

            XCTAssertNotNil(try vp.credential(ofId: try DIDURL(vp.holder!, "#profile")))
            XCTAssertNotNil(try vp.credential(ofId: try DIDURL(vp.holder!, "#email")))
            XCTAssertNotNil(try vp.credential(ofId: try DIDURL(vp.holder!, "#twitter")))
            XCTAssertNotNil(try vp.credential(ofId: try DIDURL(vp.holder!, "#passport")))
            XCTAssertNil(try vp.credential(ofId: try DIDURL(vp.holder!, "#notExist")))

            XCTAssertTrue(try vp.isGenuine())
            XCTAssertTrue(try vp.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func testBuildEmpty() {
        do {
            let doc = try testData!.sharedInstantData().getUser1Document()

            let pb = try VerifiablePresentation.editingVerifiablePresentation(for: doc.subject, using: store!)
            let vp = try pb
                    .withRealm("https://example.com/")
                    .withNonce("873172f58701a9ee686f0630204fee59")
                    .sealed(using: storePassword)

            XCTAssertNotNil(vp)

            XCTAssertNil(vp.id)
            XCTAssertEqual(1, vp.types.count)
            XCTAssertEqual(Constants.DEFAULT_PRESENTATION_TYPE, vp.types[0])
            XCTAssertEqual(doc.subject, vp.holder)

            XCTAssertEqual(0, vp.credentials.count)
            XCTAssertNil(try vp.credential(ofId: try DIDURL(vp.holder!, "#notExist")))

            XCTAssertTrue(try vp.isGenuine())
            XCTAssertTrue(try vp.isValid())
        } catch {
            XCTFail()
        }
    }
    
    func testBuildEmptyWithOptionsAttrs() {
        do {
            let doc = try testData!.sharedInstantData().getUser1Document()

            let pb = try VerifiablePresentation.editingVerifiablePresentation(for: doc.subject, using: store!)
            let vp = try pb
                    .withId("#test-vp")
                    .withTypes("HelloWorld", "FooBar", "Baz")
                    .withRealm("https://example.com/")
                    .withNonce("873172f58701a9ee686f0630204fee59")
                    .sealed(using: storePassword)

            XCTAssertNotNil(vp)

            XCTAssertEqual(try DIDURL(doc.subject, "#test-vp"), vp.id)
            XCTAssertEqual(3, vp.types.count)
            XCTAssertEqual("Baz", vp.types[0])
            XCTAssertEqual("FooBar", vp.types[1])
            XCTAssertEqual("HelloWorld", vp.types[2])
            XCTAssertEqual(doc.subject, vp.holder)

            XCTAssertEqual(0, vp.credentials.count)
            XCTAssertNil(try vp.credential(ofId: try DIDURL(vp.holder!, "#notExist")))

            XCTAssertTrue(try vp.isGenuine())
            XCTAssertTrue(try vp.isValid())
        } catch {
            XCTFail()
        }
    }
}
