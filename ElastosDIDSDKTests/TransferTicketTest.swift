import XCTest
@testable import ElastosDIDSDK

class TransferTicketTest: XCTestCase {
    var testData: TestData!
    var adapter: SimulatedIDChainAdapter = SimulatedIDChainAdapter("http://localhost:\(DEFAULT_PORT)/")

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
        testData = TestData()
        try! DIDBackend.initialize(adapter)
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        testData.cleanup()
    }
    
    func testMultiSignatureTicket2() {
        MultiSignatureTicket(2)
    }
    func testMultiSignatureTicket3() {
        MultiSignatureTicket(3)
    }
    func MultiSignatureTicket(_ version: Int) {
        do {
            let cd = try testData.getCompatibleData(version)
            try cd.loadAll()

            let tt = try cd.getTransferTicket("foobar")

            XCTAssertEqual(try DID("did:elastos:foobar"), tt.subject)
            XCTAssertEqual(try DID("did:elastos:igHbSCez6H3gTuVPzwNZRrdj92GCJ6hD5d"), tt.getTo)
//            XCTAssertEqual("4184a30d785a3579e944fd48e40e3cdf", tt.transactionId)
            XCTAssertEqual(2, tt.proofs.count)
            XCTAssertTrue(try tt.isGenuine())
            XCTAssertTrue(try tt.isGenuine())
            XCTAssertTrue(try tt.isGenuine())
            XCTAssertTrue(try tt.isGenuine())
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func testTicket2() {
        Ticket(2)
    }
    func testTicket3() {
        Ticket(3)
    }
    func Ticket(_ version: Int) {
        do {
            let cd = try testData.getCompatibleData(version)
            try cd.loadAll()

            let tt = try cd.getTransferTicket("baz")

            XCTAssertEqual(try DID("did:elastos:baz"), tt.subject)
            XCTAssertEqual(try DID("did:elastos:igHbSCez6H3gTuVPzwNZRrdj92GCJ6hD5d"), tt.getTo)
//            XCTAssertEqual("f54c02fd7dcdd2be48a6353998a04811", tt.transactionId)
            XCTAssertEqual(1, tt.proofs.count)
            XCTAssertTrue(try tt.isGenuine())
        } catch {
            XCTFail()
        }
    }
}
