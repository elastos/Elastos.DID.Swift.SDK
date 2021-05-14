
import XCTest
@testable import ElastosDIDSDK

class MnemonicTest: XCTestCase {
    var testData: TestData?

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
        testData = TestData()
    }
    
    func testBuiltinWordList() {
        do {
            let langs = [
                Mnemonic.DID_ENGLISH,
                Mnemonic.DID_SPANISH,
                Mnemonic.DID_FRENCH,
                Mnemonic.DID_CZECH,
                Mnemonic.DID_ITALIAN,
                Mnemonic.DID_CHINESE_SIMPLIFIED,
                Mnemonic.DID_CHINESE_TRADITIONAL,
                Mnemonic.DID_JAPANESE,
                Mnemonic.DID_KOREAN
            ]
            for lang in langs {
                var mnemonic = try Mnemonic.generate(lang)
                XCTAssertTrue(try Mnemonic.isValid(lang, mnemonic))
                
                let store = testData?.store
                _ = try RootIdentity.create(mnemonic, passphrase, true, store!, storePassword)
                mnemonic = mnemonic + "z"
                XCTAssertFalse(try Mnemonic.isValid(lang, mnemonic))
            }
        } catch {
            XCTFail()
        }
    }
    
    func testFrenchMnemonic() {
        do {
            let mnemonic = "remarque séduire massif boire horde céleste exact dribbler pulpe prouesse vagabond opale"
            let mc = try Mnemonic.generate(Mnemonic.DID_FRENCH)
            XCTAssertTrue(try Mnemonic.isValid(Mnemonic.DID_FRENCH, mc))
            XCTAssertTrue(try Mnemonic.isValid(Mnemonic.DID_FRENCH, mnemonic))

        } catch {
            XCTFail()
        }
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testExample() throws {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
    }

    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
