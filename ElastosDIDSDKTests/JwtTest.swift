
import XCTest
import ElastosDIDSDK

class JwtTest: XCTestCase {

    func testJWT() {
        do {
            let testData = TestData()
            _ = try testData.setupStore(true)
            _ = try testData.initIdentity()

            let doc = try testData.loadTestDocument()
            XCTAssertNotNil(doc)
            XCTAssertTrue(doc.isValid)

            let h = JwtBuilder.createHeader()
            _ = h.setType(h.typ)
                 .setContentType("json")
                 .setValue(key: "library", value: "Elastos DID")
                 .setValue(key: "version", value: "1.0")

            let c = JwtBuilder.createClaims()
            _ = c.setSubject(subject: "JwtTest")
                 .setId(id: "0")
                 .setAudience(audience: "Test cases")
                 .setExpiration(expiration: Date() + 1000)
                 .setIssuedAt(issuedAt: Date())
                 .setNotBefore(notBefore: Date() + 100)
                 .setValue(key: "foo", value: "bar")

            let jwt = try doc.jwtBuilder()
                .setHeader(h)
                .setClaims(c)
            let token = try jwt.sign(using: storePass)
            print(token)

        } catch {
            print(error)
            XCTFail()
        }
/*
         Calendar cal = Calendar.getInstance();
         cal.set(Calendar.MILLISECOND, 0);
         Date iat = cal.getTime();
         cal.add(Calendar.MONTH, -1);
         Date nbf = cal.getTime();
         cal.add(Calendar.MONTH, 4);
         Date exp = cal.getTime();

         Claims b = JwtBuilder.createClaims();
         b.setSubject("JwtTest")
             .setId("0")
             .setAudience("Test cases")
             .setIssuedAt(iat)
             .setExpiration(exp)
             .setNotBefore(nbf)
             .put("foo", "bar");

         String token = doc.jwtBuilder()
                 .setHeader(h)
                 .setClaims(b)
                 .compact();

         assertNotNull(token);
         printJwt(token);

         JwtParser jp = doc.jwtParserBuilder().build();
         Jwt<Claims> jwt = jp.parseClaimsJwt(token);
         assertNotNull(jwt);

         h = jwt.getHeader();
         assertNotNull(h);
         assertEquals("json", h.getContentType());
         assertEquals(Header.JWT_TYPE, h.getType());
         assertEquals("Elastos DID", h.get("library"));
         assertEquals("1.0", h.get("version"));

         Claims c = jwt.getBody();
         assertNotNull(c);
         assertEquals("JwtTest", c.getSubject());
         assertEquals("0", c.getId());
         assertEquals(doc.getSubject().toString(), c.getIssuer());
         assertEquals("Test cases", c.getAudience());
         assertEquals(iat, c.getIssuedAt());
         assertEquals(exp, c.getExpiration());
         assertEquals(nbf, c.getNotBefore());
         assertEquals("bar", c.get("foo", String.class));
         */
    }


    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
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
