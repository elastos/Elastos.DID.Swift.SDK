
import XCTest
@testable import ElastosDIDSDK

class DIDDoucumentTests: XCTestCase {
    
    var store: DIDStore!
    var compactPath: String!
    var documentPath: String!
    var normalizedPath: String!

    func test0Payload() {
        let payload = "eyJpZCI6ImRpZDplbGFzdG9zOmlqNUIyVE02NzVRazlSdVFVOXVHUnFNMTQ0SzRMUktNblIiLCJwdWJsaWNLZXkiOlt7ImlkIjoiI3ByaW1hcnkiLCJwdWJsaWNLZXlCYXNlNTgiOiIyN1JOMkNySlpxS21aMjFHMko1VWdNWG14aUVkbTFwYWVMZG5CU1BGd3hZR0MifV0sImF1dGhlbnRpY2F0aW9uIjpbIiNwcmltYXJ5Il0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbeyJpZCI6IiNuYW1lIiwidHlwZSI6WyJCYXNpY1Byb2ZpbGVDcmVkZW50aWFsIiwiU2VsZlByb2NsYWltZWRDcmVkZW50aWFsIl0sImlzc3VhbmNlRGF0ZSI6IjIwMjAtMDMtMDNUMTI6MjA6MDhaIiwiZXhwaXJhdGlvbkRhdGUiOiIyMDIwLTAzLTE4VDEyOjIwOjA4WiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7Im5hbWUiOiLmiZjlsJTmlq_ms7AifSwicHJvb2YiOnsidmVyaWZpY2F0aW9uTWV0aG9kIjoiI3ByaW1hcnkiLCJzaWduYXR1cmUiOiJrSmVZVE5weEt4NjR5X3hYME5xdmFNVlF2TWxiY2xxTkJpYzJHUnYyMXo0dVZsMnRuNFVCZkNJbVR6ZHlGVUV3c3NEbkFCM21ub0xNYWhDckpWU19XdyJ9fV0sImV4cGlyZXMiOiIyMDI1LTAzLTAzVDEyOjIwOjA3WiIsInByb29mIjp7ImNyZWF0ZWQiOiIyMDIwLTEyLTA1VDAyOjAxOjMxWiIsInNpZ25hdHVyZVZhbHVlIjoiZmc1Sm5Hc3kyeS1XaVpvYlZIMDV0V3hod3QyMHZQcUd3UzBnZnRWU0dhT2dHdmxRSWJKVlc3cFhxY2d4VWdxYTB4WDAyVy1wS1MxdHNyRkJ6aEs2b0EifX0"
        let capacity = payload.count * 3
        let buffer: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
        let cp = payload.toUnsafePointerInt8()
        let c = base64_url_decode(buffer, cp)
        buffer[c] = 0
        let json: String = String(cString: buffer)
        print("json == \(json)")
        do {
            let doc = try DIDDocument.convertToDIDDocument(fromJson: json)
            let vc = try doc.credential(ofId: "did:elastos:ij5B2TM675Qk9RuQU9uGRqM144K4LRKMnR#name")
            let dataString = vc!.toJson(true, true)
            print("doc === \(doc.description)")
            print("vcstring====\(dataString)")
            let publicKeyBase58 = "27RN2CrJZqKmZ21G2J5UgMXmxiEdm1paeLdnBSPFwxYGC"
            let pks = Base58.bytesFromBase58(publicKeyBase58)
            var pkData = Data(bytes: pks, count: pks.count)
            let cpk = pkData.withUnsafeMutableBytes { (pk: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> in
                return pk
            }
            // vc 验签
            let signature = "kJeYTNpxKx64y_xX0NqvaMVQvMlbclqNBic2GRv21z4uVl2tn4UBfCImTzdyFUEwssDnAB3mnoLMahCrJVS_Ww"
            let digest = sha256Digest([dataString.data(using: .utf8)!])
            let cdigest = digest.toPointer()
            let size: Int = digest.count
            let csignature = signature.toUnsafeMutablePointerInt8()
            let re = ecdsa_verify_base64(csignature, cpk, UnsafeMutablePointer(mutating: cdigest), size)
            print("vcre==\(re)")
            
            // doc 验签
            let dataString1 = doc.toString(true, forSign: true)
            let signature1 = "fg5JnGsy2y-WiZobVH05tWxhwt20vPqGwS0gftVSGaOgGvlQIbJVW7pXqcgxUgqa0xX02W-pKS1tsrFBzhK6oA"
            let digest1 = sha256Digest([dataString1.data(using: .utf8)!])
            let cdigest1 = digest1.toPointer()
            let size1: Int = digest1.count
            let csignature1 = signature1.toUnsafeMutablePointerInt8()
            let docRe = ecdsa_verify_base64(csignature1, cpk, UnsafeMutablePointer(mutating: cdigest1), size1)
            print("docRe==\(docRe)")
            
            let json = doc.toString()
            let capacity = json.count * 3

            // payload
            let cInput = json.toUnsafePointerUInt8()
            let cPayload = UnsafeMutablePointer<CChar>.allocate(capacity: capacity)
            let rePayload = base64_url_encode(cPayload, cInput, json.lengthOfBytes(using: .utf8))
            cPayload[rePayload] = 0
            let payload = String(cString: cPayload)
            print(payload)
            
        } catch {
        print("error=====\(error)")
        }
    }

    private func sha256Digest(_ data: [Data]) -> Data {
        var cinputs: [CVarArg] = []
        var capacity: Int = 0
        data.forEach { data in
            let json = String(data: data, encoding: .utf8)
            if json != "" {
                let cjson = json!.toUnsafePointerInt8()!
                cinputs.append(cjson)
                cinputs.append(json!.lengthOfBytes(using: .utf8))
                capacity += json!.count * 3
            }
        }

        let c_inputs = getVaList(cinputs)
        let count = cinputs.count / 2
        
        // digest
        let cdigest = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
        let size = sha256v_digest(cdigest, Int32(count), c_inputs)
        let cdigestPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: cdigest, count: size)

        return Data(buffer: cdigestPointerToArry)
    }
    
    func getDictionaryFromJSONString(_ jsonString: String) -> Dictionary<String, Any> {
     
        let jsonData:Data = jsonString.data(using: .utf8)!
     
        let dict = try? JSONSerialization.jsonObject(with: jsonData, options: .mutableContainers)
        if dict != nil {
            return dict as! [String: Any]
        }
        return [: ]
    }
    
    func testGetPublicKey() {
        do {
            let time = DateHelper.currentDate()
            let timestr = DateHelper.formateDate(time)
            print("timestr=== \(timestr)")
            
            let timester2 = DateHelper.getTimeStampForString(time)
            print("timester2 === \(timester2)")
            
            let maxExpirationDate = DateHelper.maxExpirationDate()
            let maxExpirationDateStr = DateHelper.formateDate(maxExpirationDate)
            print("maxExpirationDateStr == \(maxExpirationDateStr)")
            
            let date = DateFormatter.convertToUTCDateFromString("1612510747")
            let dateSTR = DateHelper.formateDate(date!)

            print("dateSTR == \(dateSTR)")
            
            let ss = DateFormatter.convertToUTCStringFromDate(maxExpirationDate)
            print("ss ===== \(ss)")
            
            let testData: TestData = TestData()
            _ = try testData.setup(true)
            
            let doc: DIDDocument = try testData.loadTestDocument()
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            // Count and list.
            XCTAssertEqual(4, doc.publicKeyCount)
            var pks:Array<PublicKey> = doc.publicKeys()
            XCTAssertEqual(4, pks.count)
            
            for pk in pks {
                XCTAssertEqual(doc.subject, pk.getId().did)
                XCTAssertEqual("ECDSAsecp256r1", pk.getType())
                
                if (pk.getId().fragment == "recovery") {
                    XCTAssertNotEqual(doc.subject, pk.controller)
                }
                else {
                    XCTAssertEqual(doc.subject, pk.controller)
                }
                
                let re = pk.getId().fragment == "primary" || pk.getId().fragment == "key2" || pk.getId().fragment == "key3" || pk.getId().fragment == "recovery"
                XCTAssertTrue(re)
            }

            // PublicKey getter.
            var pk = try doc.publicKey(ofId: "primary")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "primary"), pk!.getId())
            
            var id: DIDURL = try DIDURL(doc.subject, "key2")
            pk = doc.publicKey(ofId: id)
            XCTAssertNotNil(pk)
            XCTAssertEqual(id, pk!.getId())
            
            id = doc.defaultPublicKey
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "primary"), id)
            
            // Key not exist, should fail.
            pk = try doc.publicKey(ofId: "notExist")
            XCTAssertNil(pk)
            id = try DIDURL(doc.subject, "notExist")
            pk = doc.publicKey(ofId: id)
            XCTAssertNil(pk)
            
            // Selector
            id = doc.defaultPublicKey
            pks = doc.selectPublicKeys(byId: id, andType: "ECDSAsecp256r1")
            XCTAssertEqual(1, pks.count);
            XCTAssertEqual(try DIDURL(doc.subject, "primary"), pks[0].getId())
            
            pks = doc.selectPublicKeys(byId: id, andType: nil)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.subject, "primary"), pks[0].getId())

            pks = doc.selectPublicKeys(byType: "ECDSAsecp256r1")
            XCTAssertEqual(4, pks.count)
            
            pks = try doc.selectPublicKeys(byId: "key2", andType: "ECDSAsecp256r1")
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.subject, "key2"), pks[0].getId())
            
            pks = try doc.selectPublicKeys(byId: "key3", andType: nil)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.subject, "key3"), pks[0].getId())
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func testAddPublicKey() {
        do {
            let testData: TestData = TestData()
            _ = try testData.setup(true)
            _ = try testData.initIdentity()
            var doc = try testData.loadTestDocument()
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            var db: DIDDocumentBuilder = doc.editing()

            // Add 2 public keys
            let id = try DIDURL(doc.subject, "test1")
            var key = try TestData.generateKeypair()
            db = try db.appendPublicKey(id, doc.subject, key.getPublicKeyBase58())

            key = try TestData.generateKeypair()
            db = try db.appendPublicKey(with: "test2", controller: doc.subject.toString(),
                                        keyBase58: key.getPublicKeyBase58())
            
            doc = try db.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)

            // Check existence
            var pk: PublicKey = try doc.publicKey(ofId: "test1")!
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "test1"), pk.getId())
            
            pk = try doc.publicKey(ofId: "test2")!
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "test2"), pk.getId())
            
            // Check the final count.
            XCTAssertEqual(6, doc.publicKeyCount)
            XCTAssertEqual(3, doc.authenticationKeyCount)
            XCTAssertEqual(1, doc.authorizationKeyCount)
            
        } catch  {
            print(error)
            XCTFail()
        }
    }
    
    func testRemovePublicKey() {
        do {
            let testData: TestData = TestData()
            _ = try testData.setup(true)
            _ = try testData.initIdentity()
            
            var doc: DIDDocument = try testData.loadTestDocument()
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            let db: DIDDocumentBuilder = doc.editing()
            
            // recovery used by authorization, should failed.
            let id = try DIDURL(doc.subject, "recovery")
            XCTAssertThrowsError(try db.removePublicKey(with: id)) { (error) in
                switch error {
                case DIDError.illegalArgument: break
                    //everything is fine
                default:
                    XCTFail("Unexpected error thrown")
                }
            }

            // force remove public key, should success
            _ = try db.removePublicKey(with: id, true)
            
            _ = try db.removePublicKey(with: "key2", true)
            
            // Key not exist, should fail.
            XCTAssertThrowsError(try db.removePublicKey(with: "notExistKey", true)) { (error) in
                switch error {
                case DIDError.illegalArgument: break
                    //everything is fine
                default:
                    XCTFail("Unexpected error thrown")
                }
            }

            XCTAssertThrowsError(try db.removePublicKey(with: doc.defaultPublicKey, true)) { (error) in
                switch error {
                case DIDError.illegalArgument: break
                    //everything is fine
                default:
                    XCTFail("Unexpected error thrown")
                }
            }

            doc = try db.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            // Check existence
            var pk = try doc.publicKey(ofId: "recovery")
            XCTAssertNil(pk)
            
            pk = try doc.publicKey(ofId: "key2")
            XCTAssertNil(pk)
            
            // Check the final count.
            XCTAssertEqual(2, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            XCTAssertEqual(0, doc.authorizationKeyCount)
        } catch {
            print(error)
            XCTFail()
        }
        
    }
    
    func testGetAuthenticationKey() {
        do {
            let testData: TestData = TestData()
            _ = try testData.setup(true)
            _ = try testData.initIdentity()
            
            let doc: DIDDocument = try testData.loadTestDocument()
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            // Count and list.
            XCTAssertEqual(3, doc.authenticationKeyCount)
            
            var pks: Array<PublicKey> = doc.authenticationKeys()
            XCTAssertEqual(3, pks.count)
            
            for pk in pks {
                XCTAssertEqual(doc.subject, pk.getId().did)
                XCTAssertEqual("ECDSAsecp256r1", pk.getType())
                XCTAssertEqual(doc.subject, pk.controller)
                let re = pk.getId().fragment == "primary" || pk.getId().fragment == "key2" || pk.getId().fragment == "key3"
                XCTAssertTrue(re)
            }
            
            // AuthenticationKey getter
            var pk = try doc.authenticationKey(ofId: "primary")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "primary"), pk!.getId())
            
            var id: DIDURL = try DIDURL(doc.subject, "key3")
            pk = doc.authenticationKey(ofId: id)
            XCTAssertNotNil(pk)
            XCTAssertEqual(id, pk!.getId())
            
            // Key not exist, should fail.
            pk = try doc.authenticationKey(ofId: "notExist")
            XCTAssertNil(pk)
            id = try DIDURL(doc.subject, "notExist")
            pk = doc.authenticationKey(ofId: id)
            XCTAssertNil(pk)
            
            // selector
            id = try DIDURL(doc.subject, "key3")
            pks = doc.selectAuthenticationKeys(byId: id, andType: "ECDSAsecp256r1")
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(id, pks[0].getId())
            pks = doc.selectAuthenticationKeys(byId: id, andType: nil)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(id, pks[0].getId())

            pks = doc.selectAuthenticationKeys(byType: "ECDSAsecp256r1")
            XCTAssertEqual(3, pks.count)
            
            pks = try doc.selectAuthenticationKeys(byId: "key2", andType: "ECDSAsecp256r1")
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.subject, "key2"), pks[0].getId())
            
            pks = try doc.selectAuthenticationKeys(byId: "key2", andType: nil)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(try DIDURL(doc.subject, "key2"), pks[0].getId())
        } catch {
            print(error)
            XCTFail()
        }
        
    }
    
    func testAddAuthenticationKey() {
        do {
            let testData: TestData = TestData()
            _ = try testData.setup(true)
            _ = try testData.initIdentity()
            
            var doc: DIDDocument = try testData.loadTestDocument()
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            let db: DIDDocumentBuilder = doc.editing()
            
            // Add 2 public keys for test.
            let id: DIDURL = try DIDURL(doc.subject, "test1")
            var key = try TestData.generateKeypair()
            _ = try db.appendPublicKey(with: id, controller: doc.subject.toString(),
                                       keyBase58: key.getPublicKeyBase58())
            key = try TestData.generateKeypair()
            _ = try db.appendPublicKey(with: "test2", controller: doc.subject.toString(), keyBase58: key.getPublicKeyBase58())
            
            // Add by reference
            _ = try db.appendAuthenticationKey(with: DIDURL(doc.subject, "test1"))
            
            _ = try db.appendAuthenticationKey(with: "test2")
            
            // Add new keys
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: DIDURL(doc.subject, "test3"),
                                               keyBase58: key.getPublicKeyBase58())
            
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "test4", keyBase58: key.getPublicKeyBase58())
            
            // Try to add a non existing key, should fail.
            XCTAssertThrowsError(try db.appendAuthenticationKey(with: "notExistKey")) { (error) in
                switch error {
                case DIDError.illegalArgument: break
                    //everything is fine
                default:
                    XCTFail("Unexpected error thrown")
                }
            }

            // Try to add a key not owned by self, should fail.
            XCTAssertThrowsError(try db.appendAuthenticationKey(with: "recovery")) { (error) in
                switch error {
                case DIDError.illegalArgument: break
                    //everything is fine
                default:
                    XCTFail("Unexpected error thrown")
                }
            }
            
            doc = try db.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            // Check existence
            var pk = try doc.authenticationKey(ofId: "test1")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "test1"), pk!.getId())
            
            pk = try doc.authenticationKey(ofId: "test2")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "test2"), pk!.getId())
            
            pk = try doc.authenticationKey(ofId: "test3")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "test3"), pk!.getId())
            
            pk = try doc.authenticationKey(ofId: "test4")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "test4"), pk!.getId())
            
            // Check the final count.
            XCTAssertEqual(8, doc.publicKeyCount)
            XCTAssertEqual(7, doc.authenticationKeyCount)
            XCTAssertEqual(1, doc.authorizationKeyCount)
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func testRemoveAuthenticationKey() {
        do {
            let testData: TestData = TestData()
            _ = try testData.setup(true)
            _ = try testData.initIdentity()
            
        
            var doc: DIDDocument = try testData.loadTestDocument()
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            let db: DIDDocumentBuilder = doc.editing()
            
            // Add 2 public keys for test
            var key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(
                with: try DIDURL(doc.subject, "test1"), keyBase58: key.getPublicKeyBase58())
            
            key = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "test2", keyBase58: key.getPublicKeyBase58())
            
            // Remote keys
            _ = try db.removeAuthenticationKey(with: try DIDURL(doc.subject, "test1"))
            
            _ = try db.removeAuthenticationKey(with: "test2")
            
            _ = try db.removeAuthenticationKey(with: "key2")
            
            // Key not exist, should fail.
            XCTAssertThrowsError(try db.removeAuthenticationKey(with: "notExistKey")) { (error) in
                switch error {
                case DIDError.illegalArgument: break
                    //everything is fine
                default:
                    XCTFail("Unexpected error thrown")
                }
            }
            
            // Default publickey, can not remove, should fail.
            XCTAssertThrowsError(try db.removeAuthenticationKey(with: doc.defaultPublicKey)) { (error) in
                switch error {
                case DIDError.illegalArgument: break
                    //everything is fine
                default:
                    XCTFail("Unexpected error thrown")
                }
            }
            doc = try db.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            // Check existence
            var pk = try doc.authenticationKey(ofId: "test1")
            XCTAssertNil(pk)
            
            pk = try doc.authenticationKey(ofId: "test2")
            XCTAssertNil(pk)
            
            pk = try doc.authenticationKey(ofId: "key2")
            XCTAssertNil(pk)
            
            // Check the final count.
            XCTAssertEqual(6, doc.publicKeyCount)
            XCTAssertEqual(2, doc.authenticationKeyCount)
            XCTAssertEqual(1, doc.authorizationKeyCount)
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func testGetAuthorizationKey() {
        do {
            let testData: TestData = TestData()
            _ = try testData.setup(true)
            _ = try testData.initIdentity()
            
            let doc: DIDDocument = try testData.loadTestDocument()
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            // Count and list.
            XCTAssertEqual(1, doc.authorizationKeyCount)
            
            var pks: Array<PublicKey> = doc.authorizationKeys()
            XCTAssertEqual(1, pks.count)
            
            for pk in pks {
                XCTAssertEqual(doc.subject, pk.getId().did)
                XCTAssertEqual("ECDSAsecp256r1", pk.getType())
                
                XCTAssertNotEqual(doc.subject, pk.controller)
                XCTAssertTrue(pk.getId().fragment == "recovery")
            }
            
            // AuthorizationKey getter
            var pk = try doc.authorizationKey(ofId: "recovery")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "recovery"), pk!.getId())
            
            var id: DIDURL = try DIDURL(doc.subject, "recovery")
            pk = doc.authorizationKey(ofId: id)
            XCTAssertNotNil(pk)
            XCTAssertEqual(id, pk!.getId())
            
            // Key not exist, should fail.
            pk = try doc.authorizationKey(ofId: "notExistKey")
            XCTAssertNil(pk)
            id = try DIDURL(doc.subject, "notExistKey")
            pk = doc.authorizationKey(ofId: id)
            XCTAssertNil(pk)
            
            // Selector
            id = try DIDURL(doc.subject, "recovery")
            pks = doc.selectAuthorizationKeys(byId: id, andType: "ECDSAsecp256r1")
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(id, pks[0].getId())
            
            pks = doc.selectAuthorizationKeys(byId: id, andType: nil)
            XCTAssertEqual(1, pks.count)
            XCTAssertEqual(id, pks[0].getId())

            pks = doc.selectAuthorizationKeys(byType: "ECDSAsecp256r1")
            XCTAssertEqual(1, pks.count)
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func testAddAuthorizationKey() {
        do {
            let testData: TestData = TestData()
            store = try testData.setup(true)
            _ = try testData.initIdentity()
            
            var doc: DIDDocument = try testData.loadTestDocument()
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            let db: DIDDocumentBuilder = doc.editing()
            
            // Add 2 public keys for test.
            let id: DIDURL = try DIDURL(doc.subject, "test1")
            var key = try TestData.generateKeypair()
            let did = DID(DID.METHOD, key.getAddress())
            _ = try db.appendPublicKey(with: id, controller: did.toString(), keyBase58: key.getPublicKeyBase58())
            
            key = try TestData.generateKeypair()
            _ = try db.appendPublicKey(with: "test2", controller: did.toString(), keyBase58: key.getPublicKeyBase58())
            
            // Add by reference
            _ = try db.appendAuthorizationKey(with: DIDURL(doc.subject, "test1"))
            
            _ = try db.appendAuthorizationKey(with: "test2")
            
            // Add new keys
            key = try TestData.generateKeypair()
            _ = try db.appendAuthorizationKey(try DIDURL(doc.subject, "test3"),
                                                  did, key.getPublicKeyBase58())
            
            key = try TestData.generateKeypair()
            _ = try db.appendAuthorizationKey(with: "test4", controller: did.toString(), keyBase58: key.getPublicKeyBase58())
            
            // Try to add a non existing key, should fail.
            XCTAssertThrowsError(try db.appendAuthorizationKey(with: "notExistKey")) { (error) in
                switch error {
                case DIDError.illegalArgument: break
                    //everything is fine
                default:
                    XCTFail("Unexpected error thrown")
                }
            }
            
            // Try to add key owned by self, should fail.
            XCTAssertThrowsError(try db.appendAuthorizationKey(with: "key2")) { (error) in
                switch error {
                case DIDError.illegalArgument: break
                    //everything is fine
                default:
                    XCTFail("Unexpected error thrown")
                }
            }
            
            doc = try db.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            var pk = try doc.authorizationKey(ofId: "test1")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "test1"), pk!.getId())
            pk = try doc.authorizationKey(ofId: "test2")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "test2"), pk!.getId())
            pk = try doc.authorizationKey(ofId: "test3")
            
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "test3"), pk!.getId())
            
            pk = try doc.authorizationKey(ofId: "test4")
            XCTAssertNotNil(pk)
            XCTAssertEqual(try DIDURL(doc.subject, "test4"), pk!.getId())
            
            // Check the final key count.
            XCTAssertEqual(8, doc.publicKeyCount)
            XCTAssertEqual(3, doc.authenticationKeyCount)
            XCTAssertEqual(5, doc.authorizationKeyCount)
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func testRemoveAuthorizationKey() {
        do {
            let testData: TestData = TestData()
            _ = try testData.setup(true)
            _ = try testData.initIdentity()
            
            var doc: DIDDocument = try testData.loadTestDocument()
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            let db: DIDDocumentBuilder = doc.editing()
            
            // Add 2 keys for test.
            let id: DIDURL = try DIDURL(doc.subject, "test1")
            var key = try TestData.generateKeypair()
            let did = DID(DID.METHOD, key.getAddress())
            _ = try db.appendAuthorizationKey(id, did, key.getPublicKeyBase58())
            
            key = try TestData.generateKeypair()
            _ = try db.appendAuthorizationKey(with: "test2", controller: did.toString(), keyBase58: key.getPublicKeyBase58())
            
            // Remove keys.
            _ = try db.removeAuthorizationKey(with: try DIDURL(doc.subject, "test1"))
            
            _ = try db.removeAuthorizationKey(with: "recovery")
            
            // Key not exist, should fail.
            XCTAssertThrowsError(try db.removeAuthorizationKey(with: "notExistKey")) { (error) in
                switch error {
                case DIDError.illegalArgument: break
                    //everything is fine
                default:
                    XCTFail("Unexpected error thrown")
                }
            }
            
            doc = try db.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            // Check existence
            var pk = try doc.authorizationKey(ofId: "test1")
            XCTAssertNil(pk)
            
            pk = try doc.authorizationKey(ofId: "test2")
            XCTAssertNotNil(pk)
            
            pk = try doc.authorizationKey(ofId: "recovery")
            XCTAssertNil(pk)
            
            // Check the final count.
            XCTAssertEqual(6, doc.publicKeyCount)
            XCTAssertEqual(3, doc.authenticationKeyCount)
            XCTAssertEqual(1, doc.authorizationKeyCount)
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func testGetCredential() {
        do {
            let testData: TestData = TestData()
            _ = try testData.setup(true)
            _ = try testData.initIdentity()
            
            let doc: DIDDocument = try testData.loadTestDocument()
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            // Count and list.
            XCTAssertEqual(2, doc.credentialCount)
            var vcs: Array<VerifiableCredential> = doc.credentials()
            XCTAssertEqual(2, vcs.count)
            
            for vc in vcs {
                XCTAssertEqual(doc.subject, vc.getId().did)
                XCTAssertEqual(doc.subject, vc.subject.did)
                let re = vc.getId().fragment == "profile" || vc.getId().fragment == "email"
                XCTAssertTrue(re)
            }
            // Credential getter.
            var vc = try doc.credential(ofId: "profile")
            XCTAssertNotNil(vc)
            XCTAssertEqual(try DIDURL(doc.subject, "profile"), vc!.getId())
            
            vc = try doc.credential(ofId: DIDURL(doc.subject, "email"))
            XCTAssertNotNil(vc)
            XCTAssertEqual(try DIDURL(doc.subject, "email"), vc!.getId())
            
            // Credential not exist.
            vc = try doc.credential(ofId: "notExistVc")
            XCTAssertNil(vc)
            
            // Credential selector.
            vcs = try doc.selectCredentials(byId: DIDURL(doc.subject, "profile"), andType: "SelfProclaimedCredential")
            XCTAssertEqual(1, vcs.count)
            XCTAssertEqual(try DIDURL(doc.subject, "profile"), vcs[0].getId())
            
            vcs = try doc.selectCredentials(byId: DIDURL(doc.subject, "profile"), andType: nil)
            XCTAssertEqual(1, vcs.count)
            XCTAssertEqual(try DIDURL(doc.subject, "profile"), vcs[0].getId())

            vcs = doc.selectCredentials(byType: "SelfProclaimedCredential")
            XCTAssertEqual(1, vcs.count)
            XCTAssertEqual(try DIDURL(doc.subject, "profile"), vcs[0].getId())

            vcs = doc.selectCredentials(byType: "TestingCredential")
            XCTAssertEqual(0, vcs.count)
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func testAddCredential() {
        do {
            let testData: TestData = TestData()
            _ = try testData.setup(true)
            _ = try testData.initIdentity()
            
            var doc: DIDDocument = try testData.loadTestDocument()
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            let db: DIDDocumentBuilder = doc.editing()
            
            // Add credentials.
            var vc = try testData.loadPassportCredential()
            _ = try db.appendCredential(with: vc!)
            
            vc = try testData.loadTwitterCredential()
            _ = try db.appendCredential(with: vc!)

            
            // Credential already exist, should fail.
            XCTAssertThrowsError(try db.appendCredential(with: vc!)) { (error) in
                switch error {
                case DIDError.illegalArgument: break
                    //everything is fine
                default:
                    XCTFail("Unexpected error thrown")
                }
            }
            
            doc = try db.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            // Check new added credential.
            vc = try doc.credential(ofId: "passport")
            XCTAssertNotNil(vc)
            XCTAssertEqual(try DIDURL(doc.subject, "passport"), vc!.getId())
            
            let id: DIDURL = try DIDURL(doc.subject, "twitter")
            vc = doc.credential(ofId: id)
            XCTAssertNotNil(vc)
            XCTAssertEqual(id, vc!.getId())
            
            // Should contains 3 credentials.
            XCTAssertEqual(4, doc.credentialCount)
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func testAddSelfClaimedCredential() {
        do {
            let testData = TestData()
            _ = try testData.setup(true)
            _ = try testData.initIdentity()

            var doc: DIDDocument = try testData.loadTestDocument()
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)

            let db = doc.editing()
            // Add credentials.
            var subject: [String: String] = [: ]
            subject["passport"] = "S653258Z07"
            _ = try db.appendCredential(with: "passport", subject: subject, using: storePassword)

            let subjectjson = "{\"name\":\"Jay Holtslander\",\"alternateName\":\"Jason Holtslander\"}"
            _ = try db.appendCredential(with: "name", json: subjectjson, using: storePassword)
            let json = "{\"twitter\":\"@john\"}"
            let jsonDict = try JSONSerialization.jsonObject(with: json.data(using: .utf8)!, options: []) as? [String: String]
            _ = try db.appendCredential(with: "twitter", subject: jsonDict!, using: storePassword)

            doc = try db.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)

            // Check new added credential.
            var vc = try doc.credential(ofId: "passport")
            XCTAssertNotNil(vc)
            XCTAssertEqual(try DIDURL(doc.subject, "passport"), vc!.getId())
            XCTAssertTrue(vc!.isSelfProclaimed())

            var id = try DIDURL(doc.subject, "name")
            vc = doc.credential(ofId: id)
            XCTAssertNotNil(vc)
            XCTAssertEqual(id, vc!.getId())
            XCTAssertTrue(vc!.isSelfProclaimed())

            id = try DIDURL(doc.subject, "twitter")
            vc = doc.credential(ofId: id)
            XCTAssertNotNil(vc)
            XCTAssertEqual(id, vc!.getId())
            XCTAssertTrue(vc!.isSelfProclaimed())

            // Should contains 3 credentials.
            XCTAssertEqual(5, doc.credentialCount)
        } catch {
            XCTFail()
        }
    }

    func testRemoveCredential() {
        do {
            let testData: TestData = TestData()
            _ = try testData.setup(true)
            _ = try testData.initIdentity()
            
            var doc: DIDDocument = try testData.loadTestDocument()
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            let db: DIDDocumentBuilder = doc.editing()
            
            // Add test credentials.
            var vc = try testData.loadPassportCredential()
            _ = try db.appendCredential(with: vc!)
            
            vc = try testData.loadTwitterCredential()
            _ = try db.appendCredential(with: vc!)
            
            // Remove credentials
            _ = try db.removeCredential(with: "profile")
            
            _ = try db.removeCredential(with: try DIDURL(doc.subject, "twitter"))
            
            // Credential not exist, should fail.
            XCTAssertThrowsError(try db.removeCredential(with: "notExistCredential")) { (error) in
                switch error {
                case DIDError.illegalArgument: break
                //everything is fine
                default:
                    XCTFail("Unexpected error thrown")
                }
            }
            XCTAssertThrowsError(
                try db.removeCredential(with:
                    try DIDURL(doc.subject,
                               "notExistCredential"))) { (error) in
                                switch error {
                                case DIDError.illegalArgument: break
                                //everything is fine
                                default:
                                    XCTFail("Unexpected error thrown")
                                }
            }

            doc = try db.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            // Check existence
            vc = try doc.credential(ofId: "profile")
            XCTAssertNil(vc)
            vc = doc.credential(ofId: try DIDURL(doc.subject, "twitter"))
            XCTAssertNil(vc)
            
            // Check the final count.
            XCTAssertEqual(2, doc.credentialCount)
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func testGetService() {
        do {
            let testData: TestData = TestData()
            _ = try testData.setup(true)
            _ = try testData.initIdentity()
            
            let doc: DIDDocument = try testData.loadTestDocument()
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            // Count and list
            XCTAssertEqual(3, doc.serviceCount)
            var svcs: Array<Service> = doc.services()
            XCTAssertEqual(3, svcs.count)
            
            for svc in svcs {
                XCTAssertEqual(doc.subject, svc.getId().did)
                let re = svc.getId().fragment == "openid" || svc.getId().fragment == "vcr" || svc.getId().fragment == "carrier"
                XCTAssertTrue(re)
            }
            
            // Service getter, should success.
            var svc = try doc.service(ofId: "openid")
            XCTAssertNotNil(svc)
            XCTAssertEqual(try DIDURL(doc.subject, "openid"), svc!.getId())
            XCTAssertEqual("OpenIdConnectVersion1.0Service", svc!.getType())
            XCTAssertEqual("https://openid.example.com/", svc!.endpoint)
            
            svc = try doc.service(ofId: DIDURL(doc.subject, "vcr"))!
            XCTAssertNotNil(svc)
            XCTAssertEqual(try DIDURL(doc.subject, "vcr"), svc!.getId())
            
            // Service not exist, should fail.
            svc = try doc.service(ofId: "notExistService")
            XCTAssertNil(svc)
            
            // Service selector.
            svcs = try doc.selectServices(byId: "vcr", andType: "CredentialRepositoryService")
            XCTAssertEqual(1, svcs.count)
            XCTAssertEqual(try DIDURL(doc.subject, "vcr"), svcs[0].getId())
            
            svcs = try doc.selectServices(byId: DIDURL(doc.subject, "openid"), andType: nil)
            XCTAssertEqual(1, svcs.count)
            XCTAssertEqual(try DIDURL(doc.subject, "openid"), svcs[0].getId())

            svcs = doc.selectServices(byType: "CarrierAddress")
            XCTAssertEqual(1, svcs.count)
            XCTAssertEqual(try DIDURL(doc.subject, "carrier"), svcs[0].getId())
            
            // Service not exist, should return a empty list.
            svcs = try doc.selectServices(byId: "notExistService", andType: "CredentialRepositoryService")
            XCTAssertEqual(0, svcs.count)

            svcs = doc.selectServices(byType: "notExistType")
            XCTAssertEqual(0, svcs.count)
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func testAddService() {
        do {
            let testData: TestData = TestData()
            _ = try testData.setup(true)
            _ = try testData.initIdentity()
            
            var doc: DIDDocument = try testData.loadTestDocument()
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            let db: DIDDocumentBuilder = doc.editing()
            
            // Add services
            _ = try db.appendService(with: "test-svc-1",
                                     type: "Service.Testing", endpoint: "https://www.elastos.org/testing1")
            
            _ = try db.appendService(with: DIDURL(doc.subject, "test-svc-2"),
                                     type: "Service.Testing", endpoint: "https://www.elastos.org/testing2")
            
            // Service id already exist, should failed.
            _ = try db.appendService(with: "vcr", type: "test", endpoint: "https://www.elastos.org/test")
            
            doc = try db.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            // Check the final count
            XCTAssertEqual(5, doc.serviceCount)
            
            // Try to select new added 2 services
            let svcs: Array<Service> = doc.selectServices(byType: "Service.Testing")
            XCTAssertEqual(2, svcs.count)
            XCTAssertEqual("Service.Testing", svcs[0].getType())
            XCTAssertEqual("Service.Testing", svcs[0].getType())
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func testRemoveService() {
        do {
            let testData: TestData = TestData()
            _ = try testData.setup(true)
            _ = try testData.initIdentity()
            
            var doc: DIDDocument = try testData.loadTestDocument()
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            let db: DIDDocumentBuilder = doc.editing()
            
            // remove services
            _ = try db.removeService(with: "openid")
            
            _ = try db.removeService(with: try DIDURL(doc.subject, "vcr"))
            
            // Service not exist, should fail.
            XCTAssertThrowsError(try db.removeService(with: "notExistService")) { (error) in
                switch error {
                case DIDError.illegalArgument: break
                //everything is fine
                default:
                XCTFail("Unexpected error thrown")
                }
            }
            
            doc = try db.sealed(using: storePassword)
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            var svc = try doc.service(ofId: "openid")
            XCTAssertNil(svc)
            
            svc = try doc.service(ofId: DIDURL(doc.subject, "vcr"))
            XCTAssertNil(svc)
            
            // Check the final count
            XCTAssertEqual(1, doc.serviceCount)
        } catch {
            XCTFail()
        }
    }
    
    func testParseAndSerializeDocument() {
        do {
            let testData: TestData = TestData()
            _ = try testData.setup(true)
            _ = try testData.initIdentity()
            
            let compact = try DIDDocument.convertToDIDDocument(fromJson: try testData.loadTestCompactJson())
            XCTAssertNotNil(compact)
            XCTAssertTrue(compact.isValid)
            
            XCTAssertEqual(4, compact.publicKeyCount)
            
            XCTAssertEqual(3, compact.authenticationKeyCount)
            XCTAssertEqual(1, compact.authorizationKeyCount)
            XCTAssertEqual(2, compact.credentialCount)
            XCTAssertEqual(3, compact.serviceCount)
            
            let normalized = try DIDDocument.convertToDIDDocument(fromJson: try testData.loadTestCompactJson())
            XCTAssertNotNil(normalized);
            XCTAssertTrue(normalized.isValid)
            
            XCTAssertEqual(4, normalized.publicKeyCount)
            
            XCTAssertEqual(3, normalized.authenticationKeyCount)
            XCTAssertEqual(1, normalized.authorizationKeyCount)
            XCTAssertEqual(2, normalized.credentialCount)
            XCTAssertEqual(3, normalized.serviceCount)
            
            let doc: DIDDocument = try testData.loadTestDocument()
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            XCTAssertEqual(try testData.loadTestNormalizedJson(), compact.toString(true))
            XCTAssertEqual(try testData.loadTestNormalizedJson(), normalized.toString(true))
            XCTAssertEqual(try testData.loadTestNormalizedJson(), doc.toString(true))
            
            XCTAssertEqual(try testData.loadTestCompactJson(), compact.toString(false))
            XCTAssertEqual(try testData.loadTestCompactJson(), normalized.toString(false))
            XCTAssertEqual(try testData.loadTestCompactJson(), doc.toString(false))
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    func testSignAndVerify() {
        do {
            let testData: TestData = TestData()
            _ = try testData.setup(true)
            _ = try testData.initIdentity()
            
            let doc: DIDDocument = try testData.loadTestDocument()

            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            let pkid: DIDURL = try DIDURL(doc.subject, "primary")
            
            for _ in 0..<10 {
                var json = doc.toString(false)
                var sig: String = try doc.sign(withId: pkid, using: storePassword, for: json.data(using: .utf8)!)
                
                var result: Bool = try doc.verify(withId: pkid, using: sig, onto: json.data(using: .utf8)!)
                XCTAssertTrue(result)
                
                json = String(json.suffix(json.count - 1))
                result = try doc.verify(withId: pkid, using: sig, onto: json.data(using: .utf8)!)
                XCTAssertFalse(result)
                
                sig = try doc.sign(using: storePassword, for: json.data(using: .utf8)!)
                result = try doc.verify(signature: sig, onto: json.data(using: .utf8)!)
                XCTAssertTrue(result)
                
                json = String(json.suffix(json.count - 1))
                result = try doc.verify(signature: sig, onto: json.data(using: .utf8)!)
                XCTAssertFalse(result)
            }
        } catch {
            print(error)
            XCTFail()
        }
    }

    func testSignAndVerifyNew() {

        do {
            let testData: TestData = TestData()
            _ = try testData.setup(true)
            _ = try testData.initIdentity()
            
            let doc: DIDDocument = try testData.loadTestDocument()
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)
            
            let pkid: DIDURL = try DIDURL(doc.subject, "primary")
            
            for i in 0..<10 {
                var data: [String]  = Array(repeating: String(i), count: 1024)
                var json = data.joined(separator: "")
                
                var sig: String = try doc.sign(withId: pkid, using: storePassword, for: json.data(using: .utf8)!)
                var result: Bool = try doc.verify(signature: sig, onto: json.data(using: .utf8)!)
                XCTAssertTrue(result)
                
                data[0] = String(i + 1)
                json = data.joined(separator: "")
                result = try doc.verify(signature: sig, onto: json.data(using: .utf8)!)
                XCTAssertFalse(result)

                sig = try doc.sign(using: storePassword, for: json.data(using: .utf8)!)
                result = try doc.verify(signature: sig, onto: json.data(using: .utf8)!)
                XCTAssertTrue(result)
                
                data[0] = String(i + 2)
                json = data.joined(separator: "")
                result = try doc.verify(signature: sig, onto: json.data(using: .utf8)!)
                XCTAssertFalse(result)
            }
            
        } catch {
            print(error)
            XCTFail()
        }
    }

    func testDeriveFromIdentifier() {
        do {
            let identifier = "org.elastos.did.test"
            let testData: TestData = TestData()
            _ = try testData.setup(true)
            _ = try testData.initIdentity()

            let doc: DIDDocument = try testData.loadTestDocument()
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)

            for i in -100..<100 {
                let strKey = try doc.derive(identifier, i, storePassword)
                let key = DIDHDKey.deserializeBase58(strKey)

                let binKey = Base58.bytesFromBase58(strKey)
                let sk = Array(binKey[46..<78])
                XCTAssertEqual(key.getPrivateKeyBytes().count, sk.count)
                XCTAssertEqual(key.getPrivateKeyBytes(), sk)
            }
        } catch {
            print(error)
            XCTFail()
        }
    }
}
