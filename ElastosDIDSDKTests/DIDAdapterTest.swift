
import XCTest
@testable import ElastosDIDSDK

class DIDAdapterTest: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testExample() throws {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        // Any test you write for XCTest can be annotated as throws and async.
        // Mark your test throws to produce an unexpected failure when your test encounters an uncaught error.
        // Mark your test async to allow awaiting for asynchronous code to complete. Check the results with assertions afterwards.
    }

    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

    func testRedirect() {
        let adapter = DefaultDIDAdapter("https://httpstat.us/")
        
        let expected = try! adapter.httpGet("https://httpstat.us/")
        let expectedString = String(data: expected!, encoding: .utf8)!
        
        let resultFor301 = try! adapter.httpGet("https://httpstat.us/301")
        let resultFor301String = String(data: resultFor301!, encoding: .utf8)!
        assert(expectedString == resultFor301String)

        let resultFor302 = try! adapter.httpGet("https://httpstat.us/302")
        let resultFor302String = String(data: resultFor302!, encoding: .utf8)!
        assert(expectedString == resultFor302String)

        let resultFor303 = try! adapter.httpGet("https://httpstat.us/303")
        let resultFor303String = String(data: resultFor303!, encoding: .utf8)!
        assert(expectedString == resultFor303String)

        let resultFor307 = try! adapter.httpGet("https://httpstat.us/307")
        let resultFor307String = String(data: resultFor307!, encoding: .utf8)!
        assert(expectedString == resultFor307String)
    }
}

