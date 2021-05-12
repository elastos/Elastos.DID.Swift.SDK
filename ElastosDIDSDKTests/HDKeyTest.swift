
import XCTest
@testable import ElastosDIDSDK

class HDKeyTest: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    // Test HD key algorithm, keep compatible with SPV.
    func test0() {
        do {
            let expectedIDString = "iY4Ghz9tCuWvB5rNwvn4ngWvthZMNzEA7U"
            let mnemonic = "cloth always junk crash fun exist stumble shift over benefit fun toe"
            let root = DIDHDKey.init(mnemonic, "", Mnemonic.DID_ENGLISH)
            let key = try root.derive(DIDHDKey.DID_DERIVE_PATH_PREFIX + "0")

            XCTAssertEqual(expectedIDString, key.getAddress())

            let sk = DIDHDKey.paddingToExtendedPrivateKey(key.getPrivateKeyData())
            let rk = DIDHDKey.deserialize(sk)
            XCTAssertEqual(key.getPublicKeyBase58(), rk.getPublicKeyBase58())
            XCTAssertEqual(key.getPrivateKeyBase58(), rk.getPrivateKeyBase58())
        } catch {
            XCTFail()
        }
    }

    func test1() {
        do {
            let expectedIDString = "iW3HU8fTmwkENeVT9UCEvvg3ddUD5oCxYA"
            let mnemonic = "service illegal blossom voice three eagle grace agent service average knock round"
            let root = DIDHDKey.init(mnemonic, "", Mnemonic.DID_ENGLISH)
            let key = try root.derive(DIDHDKey.DID_DERIVE_PATH_PREFIX + "0")

            XCTAssertEqual(expectedIDString, key.getAddress())

            let sk = DIDHDKey.paddingToExtendedPrivateKey(key.getPrivateKeyData())
            let rk = DIDHDKey.deserialize(sk)
            XCTAssertEqual(key.getPublicKeyBase58(), rk.getPublicKeyBase58())
            XCTAssertEqual(key.getPrivateKeyBase58(), rk.getPrivateKeyBase58())
        } catch {
            XCTFail()
        }
    }

    func test2() {
        do {
            let mnemonic = "pact reject sick voyage foster fence warm luggage cabbage any subject carbon"
            let passphrase = "helloworld"
            let key = "xprv9s21ZrQH143K4biiQbUq8369meTb1R8KnstYFAKtfwk3vF8uvFd1EC2s49bMQsbdbmdJxUWRkuC48CXPutFfynYFVGnoeq8LJZhfd9QjvUt"

            var root = DIDHDKey.init(mnemonic, passphrase, Mnemonic.DID_ENGLISH)

            XCTAssertEqual(key, root.serializeBase58())

            let keyBytes = try root.serialize()
            root = DIDHDKey.deserializeBase58(key)
            XCTAssertEqual(key, root.serializeBase58())
            XCTAssertEqual(keyBytes, try root.serialize())
        } catch {
            XCTFail()
        }
    }

    func testDerivePublicOnly() {
        do {
            let mnemonic = "pact reject sick voyage foster fence warm luggage cabbage any subject carbon"
            let passphrase = "helloworld"

            let root = DIDHDKey.init(mnemonic, passphrase, Mnemonic.DID_ENGLISH)
            let preDerivedKey = try root.derive(DIDHDKey.DID_PRE_DERIVED_PUBLICKEY_PATH)
            let preDerivedPubBase58 = try preDerivedKey.serializePublicKeyBase58()
            let preDerivedPub = DIDHDKey.deserializeBase58(preDerivedPubBase58)

            for i in 0...1000 {
                let path = DIDHDKey.DID_DERIVE_PATH_PREFIX + "\(i)"
                let key = try root.derive(path)

                let keyPubOnly = try preDerivedPub.derive("0/" + "\(i)")
                XCTAssertEqual(key.getPublicKeyBase58(), keyPubOnly.getPublicKeyBase58())
                XCTAssertEqual(key.getAddress(), keyPubOnly.getAddress())
            }
        } catch {
            XCTFail()
        }
    }

    func testJWTCompatible() {
        do {
            let input = "The quick brown fox jumps over the lazy dog."
            for i in 0...1000 {
                let key = try TestData.generateKeypair()
            }
        } catch {
            XCTFail()
        }
    }
}

