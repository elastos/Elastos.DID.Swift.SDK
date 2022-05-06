
import XCTest
@testable import ElastosDIDSDK

class JwtTest: XCTestCase {
    var testData: TestData!
    var doc: DIDDocument!

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
//        let toks = token.split(separator: ".")
//        let str  = "\(toks[0]).\(toks[1])"
//        _ = try doc!.verify(signature: "\(toks[2])", onto: str.data(using: String.Encoding.utf8)!)
        do {
            let adapter = SimulatedIDChainAdapter("http://localhost:\(DEFAULT_PORT)/")
            try! DIDBackend.initialize(adapter)
            testData = TestData()
            let identity = try testData.getRootIdentity()
            doc = try identity.newDid(storePassword)
            
            let key = try TestData.generateKeypair()
            let db = try doc.editing()
            let id = try DIDURL(doc.subject, "#key2")
            _ = try db.appendAuthenticationKey(with: id, keyBase58: key.getPublicKeyBase58())

            try testData.store!.storePrivateKey(for: id, privateKey: key.serialize(), using: storePassword)
            doc = try db.seal(using: storePassword)
            try testData.store!.storeDid(using: doc)
            try doc.publish(using: storePassword)
        }
        catch {
          print("JwtTest ERROR: \(error)")
        }
    }
    
    func testjwt() {
        do {
            var h = JwtBuilder.createHeader()
            _ = h.setType("JWT")
                .setContentType("json")
                .setValue(key: "library", value: "Elastos DID")
                .setValue(key: "version", value: "1.0")

            var c = JwtBuilder.createClaims()
            let userCalendar = Calendar.current
            var components = DateComponents()
            components.year = 2020
            components.month = 9
            components.day = 14
            components.minute = 21
            components.hour = 21
            components.second = 41
            let iat = userCalendar.date(from: components)

            let exp = iat! + 100000000000
            let nbf = iat! - 10
            _ = c.setSubject(subject: "JwtTest")
                .setId(id: "0")
                .setAudience(audience: "Test cases")
                .setExpiration(expiration: exp)
                .setIssuedAt(issuedAt: iat!)
                .setNotBefore(notBefore: nbf)
                .setValue(key: "foo", value: "bar")

            let token = try doc.jwtBuilder()
                .setHeader(h)
                .setClaims(c)
                .compact()
            print(token)

            let jp: JwtParser = try doc.jwtParserBuilder().build()
            let jwt: JWT = try jp.parseClaimsJwt(token)
            XCTAssertNotNil(jwt)
            h = jwt.header
            XCTAssertNotNil(h)
            XCTAssertEqual("json", h.getContentType())
            XCTAssertEqual("JWT", h.getType())
            XCTAssertEqual("Elastos DID", h.getValue(key: "library") as! String)

            c = jwt.claims

            XCTAssertEqual("JwtTest", c.getSubject())
            XCTAssertEqual("0", c.getId())
            XCTAssertEqual(doc.subject.description, c.getIssuer())
            XCTAssertEqual("Test cases", c.getAudience())
            XCTAssertEqual(iat, c.getIssuedAt())
            XCTAssertEqual(exp, c.getExpiration())
            XCTAssertEqual(nbf, c.getNotBefore())
            XCTAssertEqual("bar", c.get(key: "foo") as! String)
            
            let jp0 = try JwtParserBuilder().setAllwedClockSkewSeconds(30).build()
            let jwt0 = try jp0.parseClaimsJwt(token)
            print("jwt0")
        }
        catch {
            print(error)
            XCTFail()
        }
    }

    func testSignWithDefaultKey() {
        do {
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            var h = JwtBuilder.createHeader()
            h = h.setType(Header.JWT_TYPE)
                .setContentType("json")
                .setValue(key: "library", value: "Elastos DID")
                .setValue(key: "version", value: "1.0")
            let userCalendar = Calendar.current
            var components = DateComponents()
            components.year = 2020
            components.month = 9
            components.day = 14
            components.minute = 21
            components.hour = 21
            components.second = 41
            let iat = userCalendar.date(from: components)

            let exp = iat! + 100000000000
            let nbf = iat! - 10

            var c = JwtBuilder.createClaims()
            c = c.setSubject(subject: "JwtTest")
                .setId(id: "0")
                .setAudience(audience: "Test cases")
                .setIssuedAt(issuedAt: iat!)
                .setExpiration(expiration: exp)
                .setNotBefore(notBefore: nbf)
                .setValue(key: "foo", value: "bar")

            let token = try doc.jwtBuilder()
                            .setHeader(h)
                            .setClaims(c)
                            .sign(using: storePassword)
                            .compact()
            XCTAssertNotNil(token)

            let jp = try doc.jwtParserBuilder().build()
            let jwt = try jp.parseClaimsJwt(token)
            XCTAssertNotNil(jwt)

            h = jwt.header
            XCTAssertNotNil(h)
            XCTAssertEqual("json", h.getContentType())
            XCTAssertEqual(Header.JWT_TYPE, h.getType())
            XCTAssertEqual("Elastos DID", h.getValue(key: "library") as? String)
            XCTAssertEqual("1.0", h.getValue(key: "version") as? String)

            c = jwt.claims
            XCTAssertNotNil(c)
            XCTAssertEqual("JwtTest", c.getSubject())
            XCTAssertEqual("0", c.getId())
            XCTAssertEqual(doc.subject.description, c.getIssuer())
            XCTAssertEqual("Test cases", c.getAudience())
            XCTAssertEqual(iat, c.getIssuedAt())
            XCTAssertEqual(exp, c.getExpiration())
            XCTAssertEqual(nbf, c.getNotBefore())
            XCTAssertEqual("bar", c.get(key: "foo") as! String)

            let s = jwt.signature
            XCTAssertNotNil(s)
        } catch {
            XCTFail()
        }
    }

    func testSignWithSpecificKey() {
        do {
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            let userCalendar = Calendar.current
            var components = DateComponents()
            components.year = 2020
            components.month = 9
            components.day = 14
            components.minute = 21
            components.hour = 21
            components.second = 41
            let iat = userCalendar.date(from: components)

            let exp = iat! + 100000000000
            let nbf = iat! - 10

            let token = try doc.jwtBuilder()
                .addHeader(key: Header.TYPE, value: Header.JWT_TYPE)
                .addHeader(key: Header.CONTENT_TYPE, value: "json")
                .addHeader(key: "library", value: "Elastos DID")
                .addHeader(key: "version", value: "1.0")
                .setSubject(sub: "JwtTest")
                .setId(id: "0")
                .setAudience(audience: "Test cases")
                .setIssuedAt(issuedAt: iat!)
                .setExpiration(expiration: exp)
                .setNotBefore(nbf: nbf)
                .claim(name: "foo", value: "bar")
                .sign(withKey: "#key2", using: storePassword)
                .compact()
            XCTAssertNotNil(token)

            let jp = try JwtParserBuilder("#key2").build()
            let jwt = try jp.parseClaimsJwt(token)
            XCTAssertNotNil(jwt)

            let h = jwt.header
            XCTAssertNotNil(h)
            XCTAssertEqual("json", h.getContentType())
            XCTAssertEqual(Header.JWT_TYPE, h.getType())
            XCTAssertEqual("Elastos DID", h.getValue(key: "library") as? String)
            XCTAssertEqual("1.0", h.getValue(key: "version") as? String)

            let c = jwt.claims
            XCTAssertNotNil(c)
            XCTAssertEqual("JwtTest", c.getSubject())
            XCTAssertEqual("0", c.getId())
            XCTAssertEqual(doc.subject.description, c.getIssuer())
            XCTAssertEqual("Test cases", c.getAudience())
            XCTAssertEqual(iat, c.getIssuedAt())
            XCTAssertEqual(exp, c.getExpiration())
            XCTAssertEqual(nbf, c.getNotBefore())
            XCTAssertEqual("bar", c.get(key: "foo") as? String)
            let s = jwt.signature
            XCTAssertNotNil(s)
        } catch {
            XCTFail()
        }
    }

    func testAutoVerify() {
        do {
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            let userCalendar = Calendar.current
            var components = DateComponents()
            components.year = 2020
            components.month = 9
            components.day = 14
            components.minute = 21
            components.hour = 21
            components.second = 41
            let iat = userCalendar.date(from: components)

            let exp = iat! + 100000000000
            let nbf = iat! - 10

            let token = try doc.jwtBuilder()
                    .addHeader(key: Header.TYPE, value: Header.JWT_TYPE)
                    .addHeader(key: Header.CONTENT_TYPE, value: "json")
                    .addHeader(key: "library", value: "Elastos DID")
                    .addHeader(key: "version", value: "1.0")
                    .setSubject(sub: "JwtTest")
                    .setId(id: "0")
                    .setAudience(audience: "Test cases")
                    .setIssuedAt(issuedAt: iat!)
                    .setExpiration(expiration: exp)
                    .setNotBefore(nbf: nbf)
                    .claim(name: "foo", value: "bar")
                    .sign(withKey: "#key2", using: storePassword)
                    .compact()

            XCTAssertNotNil(token)

            // The JWT parser not related with a DID document
            let jp = try JwtParserBuilder("#key2").build()
            let jwt = try jp.parseClaimsJwt(token)
            XCTAssertNotNil(jwt)

            let h = jwt.header
            XCTAssertNotNil(h)
            XCTAssertEqual("json", h.getContentType())
            XCTAssertEqual(Header.JWT_TYPE, h.getType())
            XCTAssertEqual("Elastos DID", h.getValue(key: "library") as? String)
            XCTAssertEqual("1.0", h.getValue(key: "version") as? String)

            let c = jwt.claims
            XCTAssertNotNil(c)
            XCTAssertEqual("JwtTest", c.getSubject())
            XCTAssertEqual("0", c.getId())
            XCTAssertEqual(doc.subject.description, c.getIssuer())
            XCTAssertEqual("Test cases", c.getAudience())
            XCTAssertEqual(iat, c.getIssuedAt())
            XCTAssertEqual(exp, c.getExpiration())
            XCTAssertEqual(nbf, c.getNotBefore())
            XCTAssertEqual("bar", c.get(key: "foo") as? String)
            let s = jwt.signature
            XCTAssertNotNil(s)
        } catch {
            XCTFail()
        }
    }

    func testClaimJsonNode() {
        do {
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            let userCalendar = Calendar.current
            var components = DateComponents()
            components.year = 2020
            components.month = 9
            components.day = 14
            components.minute = 21
            components.hour = 21
            components.second = 41
            let iat = userCalendar.date(from: components)

            let exp = iat! + 100000000000
            let nbf = iat! - 10
            let vcEmail = try testData.sharedInstantData().getUser1Document().credential(ofId: "#email")
            let dic: [String: Any]? = try JSONSerialization.jsonObject(with: vcEmail!.toString(true).data(using: .utf8)!, options: []) as? [String: Any]

            let token = try doc.jwtBuilder()
                .addHeader(key: Header.TYPE, value: Header.JWT_TYPE)
                .addHeader(key: Header.CONTENT_TYPE, value: "json")
                .addHeader(key: "library", value: "Elastos DID")
                .addHeader(key: "version", value: "1.0")
                .setSubject(sub: "JwtTest")
                .setId(id: "0")
                .setAudience(audience: "Test cases")
                .setIssuedAt(issuedAt: iat!)
                .setExpiration(expiration: exp)
                .setNotBefore(nbf: nbf)
                .claim(name: "foo", value: "bar")
                .claim(name: "vc", value: dic as Any)
                .sign(withKey: "#key2", using: storePassword)
                .compact()
            XCTAssertNotNil(token)

            // The JWT parser not related with a DID document
            let jp = try JwtParserBuilder("#key2").build()
            let jwt = try jp.parseClaimsJwt(token)
            XCTAssertNotNil(jwt)

            let h = jwt.header
            XCTAssertNotNil(h)
            XCTAssertEqual("json", h.getContentType())
            XCTAssertEqual(Header.JWT_TYPE, h.getType())
            XCTAssertEqual("Elastos DID", h.getValue(key: "library") as? String)
            XCTAssertEqual("1.0", h.getValue(key: "version") as? String)

            let c = jwt.claims
            XCTAssertNotNil(c)
            XCTAssertEqual("JwtTest", c.getSubject())
            XCTAssertEqual("0", c.getId())
            XCTAssertEqual(doc.subject.description, c.getIssuer())
            XCTAssertEqual("Test cases", c.getAudience())
            XCTAssertEqual(iat, c.getIssuedAt())
            XCTAssertEqual(exp, c.getExpiration())
            XCTAssertEqual(nbf, c.getNotBefore())
            XCTAssertEqual("bar", c.get(key: "foo") as? String)
            let s = jwt.signature
            XCTAssertNotNil(s)
            let d = c.get(key: "vc") as? [String: Any]
            XCTAssertNotNil(d)
        } catch {
            XCTFail()
        }
    }

    func testClaimJsonText() {
        do {
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            let userCalendar = Calendar.current
            var components = DateComponents()
            components.year = 2020
            components.month = 9
            components.day = 14
            components.minute = 21
            components.hour = 21
            components.second = 41
            let iat = userCalendar.date(from: components)

            let exp = iat! + 100000000000
            let nbf = iat! - 10

            let vcPassport = try testData.sharedInstantData().getUser1PassportCredential()
            let jsonValue = vcPassport.toString(true)
            let token = try doc.jwtBuilder()
                    .addHeader(key: Header.TYPE, value: Header.JWT_TYPE)
                    .addHeader(key: Header.CONTENT_TYPE, value: "json")
                    .addHeader(key: "library", value: "Elastos DID")
                    .addHeader(key: "version", value: "1.0")
                    .setSubject(sub: "JwtTest")
                    .setId(id: "0")
                    .setAudience(audience: "Test cases")
                    .setIssuedAt(issuedAt: iat!)
                    .setExpiration(expiration: exp)
                    .setNotBefore(nbf: nbf)
                    .claim(name: "foo", value: "bar")
                    .claimWithJson(name: "vc", jsonValue: jsonValue)
                    .sign(withKey: "#key2", using: storePassword)
                    .compact()
            XCTAssertNotNil(token)

            let jp = try JwtParserBuilder("#key2").build()
            let jwt = try jp.parseClaimsJwt(token)
            XCTAssertNotNil(jwt)

            let h = jwt.header
            XCTAssertNotNil(h)
            XCTAssertEqual("json", h.getContentType())
            XCTAssertEqual(Header.JWT_TYPE, h.getType())
            XCTAssertEqual("Elastos DID", h.getValue(key: "library") as? String)
            XCTAssertEqual("1.0", h.getValue(key: "version") as? String)

            let c = jwt.claims
            XCTAssertNotNil(c)
            XCTAssertEqual("JwtTest", c.getSubject())
            XCTAssertEqual("0", c.getId())
            XCTAssertEqual(doc.subject.description, c.getIssuer())
            XCTAssertEqual("Test cases", c.getAudience())
            XCTAssertEqual(iat, c.getIssuedAt())
            XCTAssertEqual(exp, c.getExpiration())
            XCTAssertEqual(nbf, c.getNotBefore())
            XCTAssertEqual("bar", c.get(key: "foo") as? String)
            let s = jwt.signature
            XCTAssertNotNil(s)
            let d = c.get(key: "vc") as? [String: Any]
            XCTAssertNotNil(d)
        } catch {
            XCTFail()
        }
    }

    func testSignSetClaimWithJsonNode() {
        do {
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            let userCalendar = Calendar.current
            var components = DateComponents()
            components.year = 2020
            components.month = 9
            components.day = 14
            components.minute = 21
            components.hour = 21
            components.second = 41
            let iat = userCalendar.date(from: components)

            let exp = iat! + 100000000000
            let nbf = iat! - 10

            let json = "{\n" +
                    "  \"sub\":\"JwtTest\",\n" +
                    "  \"jti\":\"0\",\n" +
                    "  \"aud\":\"Test cases\",\n" +
                    "  \"foo\":\"bar\",\n" +
                    "  \"object\":{\n" +
                    "    \"hello\":\"world\",\n" +
                    "    \"test\":true\n" +
                    "  }\n" +
                    "}"
            let jsonNode = JsonNode(json)
            let token = try doc.jwtBuilder()
                    .addHeader(key: Header.TYPE, value: Header.JWT_TYPE)
                    .addHeader(key: Header.CONTENT_TYPE, value: "json")
                    .addHeader(key: "library", value: "Elastos DID")
                    .addHeader(key: "version", value: "1.0")
                    .setClaims(claims: jsonNode)
                    .setIssuedAt(issuedAt: iat!)
                    .setExpiration(expiration: exp)
                    .setNotBefore(nbf: nbf)
                    .sign(withKey: "#key2", using: storePassword)
                    .compact()
            XCTAssertNotNil(token)

            // The JWT parser not related with a DID document
            let jp = try JwtParserBuilder("#key2").build()
            let jwt = try jp.parseClaimsJwt(token)
            XCTAssertNotNil(jwt)

            let h = jwt.header
            XCTAssertNotNil(h)
            XCTAssertEqual("json", h.getContentType())
            XCTAssertEqual(Header.JWT_TYPE, h.getType())
            XCTAssertEqual("Elastos DID", h.getValue(key: "library") as? String)
            XCTAssertEqual("1.0", h.getValue(key: "version") as? String)

            let c = jwt.claims
            XCTAssertNotNil(c)
            XCTAssertEqual("JwtTest", c.getSubject())
            XCTAssertEqual("0", c.getId())
            XCTAssertEqual(doc.subject.description, c.getIssuer())
            XCTAssertEqual("Test cases", c.getAudience())
            XCTAssertEqual(iat, c.getIssuedAt())
            XCTAssertEqual(exp, c.getExpiration())
            XCTAssertEqual(nbf, c.getNotBefore())
            XCTAssertEqual("bar", c.get(key: "foo") as? String)
            let s = jwt.signature
            XCTAssertNotNil(s)
        } catch {
            XCTFail()
        }
    }

    func testSetClaimWithJsonText() {
        do {
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            let userCalendar = Calendar.current
            var components = DateComponents()
            components.year = 2020
            components.month = 9
            components.day = 14
            components.minute = 21
            components.hour = 21
            components.second = 41
            let iat = userCalendar.date(from: components)

            let exp = iat! + 100000000000
            let nbf = iat! - 10

            let json = "{\n" +
                    "  \"sub\":\"JwtTest\",\n" +
                    "  \"jti\":\"0\",\n" +
                    "  \"aud\":\"Test cases\",\n" +
                    "  \"foo\":\"bar\",\n" +
                    "  \"object\":{\n" +
                    "    \"hello\":\"world\",\n" +
                    "    \"test\":true\n" +
                    "  }\n" +
                    "}"
            let token = try doc.jwtBuilder()
                    .addHeader(key: Header.TYPE, value: Header.JWT_TYPE)
                    .addHeader(key: Header.CONTENT_TYPE, value: "json")
                    .addHeader(key: "library", value: "Elastos DID")
                    .addHeader(key: "version", value: "1.0")
                    .setClaimsWithJson(value: json)
                    .setIssuedAt(issuedAt: iat!)
                    .setExpiration(expiration: exp)
                    .setNotBefore(nbf: nbf)
                    .sign(withKey: "#key2", using: storePassword)
                    .compact()
            XCTAssertNotNil(token)

            // The JWT parser not related with a DID document
            let jp = try JwtParserBuilder("#key2").build()
            let jwt = try jp.parseClaimsJwt(token)
            XCTAssertNotNil(jwt)

            let h = jwt.header
            XCTAssertNotNil(h)
            XCTAssertEqual("json", h.getContentType())
            XCTAssertEqual(Header.JWT_TYPE, h.getType())
            XCTAssertEqual("Elastos DID", h.getValue(key: "library") as? String)
            XCTAssertEqual("1.0", h.getValue(key: "version") as? String)

            let c = jwt.claims
            XCTAssertNotNil(c)
            XCTAssertEqual("JwtTest", c.getSubject())
            XCTAssertEqual("0", c.getId())
            XCTAssertEqual(doc.subject.description, c.getIssuer())
            XCTAssertEqual("Test cases", c.getAudience())
            XCTAssertEqual(iat, c.getIssuedAt())
            XCTAssertEqual(exp, c.getExpiration())
            XCTAssertEqual(nbf, c.getNotBefore())
            XCTAssertEqual("bar", c.get(key: "foo") as? String)
            let s = jwt.signature
            XCTAssertNotNil(s)

        } catch {
            XCTFail()
        }
    }

    func testAddClaimWithJsonNode() {
        do {
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            let userCalendar = Calendar.current
            var components = DateComponents()
            components.year = 2020
            components.month = 9
            components.day = 14
            components.minute = 21
            components.hour = 21
            components.second = 41
            let iat = userCalendar.date(from: components)

            let exp = iat! + 100000000000
            let nbf = iat! - 10
            let json = "{\n" +
                    "  \"sub\":\"JwtTest\",\n" +
                    "  \"jti\":\"0\",\n" +
                    "  \"aud\":\"Test cases\",\n" +
                    "  \"foo\":\"bar\",\n" +
                    "  \"object\":{\n" +
                    "    \"hello\":\"world\",\n" +
                    "    \"test\":true\n" +
                    "  }\n" +
                    "}"
            let node = JsonNode(json)
            let token = try doc.jwtBuilder()
                    .addHeader(key: Header.TYPE, value: Header.JWT_TYPE)
                    .addHeader(key: Header.CONTENT_TYPE, value: "json")
                    .addHeader(key: "library", value: "Elastos DID")
                    .addHeader(key: "version", value: "1.0")
                    .setIssuedAt(issuedAt: iat!)
                    .setExpiration(expiration: exp)
                    .setNotBefore(nbf: nbf)
                    .addClaims(claims: node)
                    .sign(withKey: "#key2", using: storePassword)
                    .compact()
            XCTAssertNotNil(token)

            // The JWT parser not related with a DID document
            let jp = try JwtParserBuilder("#key2").build()
            let jwt = try jp.parseClaimsJwt(token)
            XCTAssertNotNil(jwt)

            let h = jwt.header
            XCTAssertNotNil(h)
            XCTAssertEqual("json", h.getContentType())
            XCTAssertEqual(Header.JWT_TYPE, h.getType())
            XCTAssertEqual("Elastos DID", h.getValue(key: "library") as? String)
            XCTAssertEqual("1.0", h.getValue(key: "version") as? String)

            let c = jwt.claims
            XCTAssertNotNil(c)
            XCTAssertEqual("JwtTest", c.getSubject())
            XCTAssertEqual("0", c.getId())
            XCTAssertEqual(doc.subject.description, c.getIssuer())
            XCTAssertEqual("Test cases", c.getAudience())
            XCTAssertEqual(iat, c.getIssuedAt())
            XCTAssertEqual(exp, c.getExpiration())
            XCTAssertEqual(nbf, c.getNotBefore())
            XCTAssertEqual("bar", c.get(key: "foo") as? String)
            let s = jwt.signature
            XCTAssertNotNil(s)
        } catch {
            XCTFail()
        }
    }

    func testAddClaimWithJsonText() {
        do {
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())

            let userCalendar = Calendar.current
            var components = DateComponents()
            components.year = 2020
            components.month = 9
            components.day = 14
            components.minute = 21
            components.hour = 21
            components.second = 41
            let iat = userCalendar.date(from: components)

            let exp = iat! + 100000000000
            let nbf = iat! - 10
            let json = "{\n" +
                    "  \"sub\":\"JwtTest\",\n" +
                    "  \"jti\":\"0\",\n" +
                    "  \"aud\":\"Test cases\",\n" +
                    "  \"foo\":\"bar\",\n" +
                    "  \"object\":{\n" +
                    "    \"hello\":\"world\",\n" +
                    "    \"test\":true\n" +
                    "  }\n" +
                    "}"
            let token = try doc.jwtBuilder()
                    .addHeader(key: Header.TYPE, value: Header.JWT_TYPE)
                    .addHeader(key: Header.CONTENT_TYPE, value: "json")
                    .addHeader(key: "library", value: "Elastos DID")
                    .addHeader(key: "version", value: "1.0")
                    .setIssuedAt(issuedAt: iat!)
                    .setExpiration(expiration: exp)
                    .setNotBefore(nbf: nbf)
                    .addClaimsWithJson(jsonClaims: json)
                    .sign(withKey: "#key2", using: storePassword)
                    .compact()
            XCTAssertNotNil(token)

            // The JWT parser not related with a DID document
            let jp = try JwtParserBuilder("#key2").build()
            let jwt = try jp.parseClaimsJwt(token)
            XCTAssertNotNil(jwt)

            let h = jwt.header
            XCTAssertNotNil(h)
            XCTAssertEqual("json", h.getContentType())
            XCTAssertEqual(Header.JWT_TYPE, h.getType())
            XCTAssertEqual("Elastos DID", h.getValue(key: "library") as? String)
            XCTAssertEqual("1.0", h.getValue(key: "version") as? String)

            let c = jwt.claims
            XCTAssertNotNil(c)
            XCTAssertEqual("JwtTest", c.getSubject())
            XCTAssertEqual("0", c.getId())
            XCTAssertEqual(doc.subject.description, c.getIssuer())
            XCTAssertEqual("Test cases", c.getAudience())
            XCTAssertEqual(iat, c.getIssuedAt())
            XCTAssertEqual(exp, c.getExpiration())
            XCTAssertEqual(nbf, c.getNotBefore())
            XCTAssertEqual("bar", c.get(key: "foo") as? String)
            let s = jwt.signature
            XCTAssertNotNil(s)
        } catch {
            XCTFail()
        }
    }

    func testExpiration() {
        do {
            XCTAssertNotNil(doc)
            XCTAssertTrue(try doc.isValid())
            let userCalendar = Calendar.current
            var components = DateComponents()
            components.year = 2020
            components.month = 9
            components.day = 14
            components.minute = 21
            components.hour = 21
            components.second = 41
            let iat = userCalendar.date(from: components)

            let exp = iat! + 10000
            let nbf = iat! - 10

            let token = try doc.jwtBuilder()
                .addHeader(key: Header.TYPE, value: Header.JWT_TYPE)
                .addHeader(key: Header.CONTENT_TYPE, value: "json")
                .addHeader(key: "library", value: "Elastos DID")
                .addHeader(key: "version", value: "1.0")
                .setSubject(sub: "JwtTest").setId(id: "0")
                .setAudience(audience: "Test cases")
                .setIssuedAt(issuedAt: iat!)
                .setExpiration(expiration: exp)
                .setNotBefore(nbf: nbf)
                .claim(name: "foo", value: "bar")
                .sign(withKey: "#key2", using: storePassword)
                .compact()
            XCTAssertNotNil(token)
            print(token)

            // The JWT token is expired
            let jp = try JwtParserBuilder("#key2").build()
            XCTAssertThrowsError(try jp.parseClaimsJwt(token)){ error in
                switch error {
                case JWTError.expiredJwtTime: break
                default:
                    XCTFail()
                }
            }
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
