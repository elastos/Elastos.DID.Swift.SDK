
import XCTest
@testable import ElastosDIDSDK

let testDID: String = "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN"
let params: String = "elastos:foo=testvalue;bar=123;keyonly;elastos:foobar=12345"
let path: String = "/path/to/the/resource"
let query: String = "qkey=qvalue&qkeyonly&test=true"
let fragment: String = "testfragment"
let testURL: String = testDID + ";" + params + path + "?" + query + "#" + fragment

class DIDURLTest: XCTestCase {
    static let TEST_DID = "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN"
    static let TEST_PATH = "/path/to/the/test-%E6%B5%8B%E8%AF%95-2020/resource"
    static let TEST_QUERY = "?qkey=qvalue&qkeyonly&hello=%E4%BD%A0%E5%A5%BD&test=true&a=%E5%95%8A"
    static let TEST_FRAGMENT = "#testfragment"
    
    static let WITH_DID = 0x01
    static let WITH_PATH = 0x02
    static let WITH_QUERY = 0x04
    static let WITH_FRAGMENT = 0x08
    
    override func setUp() {
        
    }
    
    public static func provideDIDURLs() -> Array<[Any]> {
        return [
            [TEST_DID, WITH_DID],
            [TEST_DID + TEST_PATH, WITH_DID | WITH_PATH],
            [TEST_DID + TEST_QUERY, WITH_DID | WITH_QUERY],
            [TEST_DID + TEST_FRAGMENT, WITH_DID | WITH_FRAGMENT],
            [TEST_DID + TEST_PATH + TEST_FRAGMENT, WITH_DID | WITH_PATH | WITH_FRAGMENT],
            [TEST_DID + TEST_QUERY + TEST_FRAGMENT, WITH_DID | WITH_QUERY | WITH_FRAGMENT],
            [TEST_DID + TEST_PATH + TEST_QUERY, WITH_DID | WITH_PATH | WITH_QUERY],
            [TEST_DID + TEST_PATH + TEST_QUERY + TEST_FRAGMENT, WITH_DID | WITH_PATH | WITH_QUERY | WITH_FRAGMENT],
            [TEST_PATH, WITH_PATH],
            [TEST_QUERY, WITH_QUERY],
            [TEST_FRAGMENT, WITH_FRAGMENT],
            [TEST_PATH + TEST_FRAGMENT, WITH_PATH | WITH_FRAGMENT],
            [TEST_QUERY + TEST_FRAGMENT, WITH_QUERY | WITH_FRAGMENT],
            [TEST_PATH + TEST_QUERY, WITH_PATH | WITH_QUERY],
            [TEST_PATH + TEST_QUERY + TEST_FRAGMENT, WITH_PATH | WITH_QUERY | WITH_FRAGMENT],
            ["  \n \t " + TEST_DID + "\t    \n", WITH_DID],
            ["\t   \n" + TEST_DID + TEST_PATH + "  \n \t", WITH_DID | WITH_PATH],
            ["   " + TEST_DID + TEST_QUERY + "\n", WITH_DID | WITH_QUERY],
            ["\n" + TEST_DID + TEST_FRAGMENT + "      ", WITH_DID | WITH_FRAGMENT],
            ["\t" + TEST_DID + TEST_PATH + TEST_FRAGMENT + "  \n", WITH_DID | WITH_PATH | WITH_FRAGMENT],
            [" " + TEST_DID + TEST_QUERY + TEST_FRAGMENT + "\t", WITH_DID | WITH_QUERY | WITH_FRAGMENT],
            ["   " + TEST_DID + TEST_PATH + TEST_QUERY, WITH_DID | WITH_PATH | WITH_QUERY],
            [TEST_DID + TEST_PATH + TEST_QUERY + TEST_FRAGMENT + "      ", WITH_DID | WITH_PATH | WITH_QUERY | WITH_FRAGMENT],

            ["  \t" + TEST_PATH + "    ", WITH_PATH],
            [" \n \t " + TEST_QUERY + "   \n", WITH_QUERY],
            ["   " + TEST_FRAGMENT + "\t", WITH_FRAGMENT],
            [" " + TEST_PATH + TEST_FRAGMENT + "    ", WITH_PATH | WITH_FRAGMENT],
            ["   " + TEST_QUERY + TEST_FRAGMENT, WITH_QUERY | WITH_FRAGMENT],
            [TEST_PATH + TEST_QUERY + "  \n \t  ", WITH_PATH | WITH_QUERY],
            ["   " + TEST_PATH + TEST_QUERY + TEST_FRAGMENT + " \n\t\t\n  ", WITH_PATH | WITH_QUERY | WITH_FRAGMENT],
        ]
    }
    
    public func testDIDURL() {
        for item in DIDURLTest.provideDIDURLs() {
            self.testDIDURLWithParams(item[0] as! String, item[1] as! Int)
        }
    }
    
    private func testDIDURLWithParams(_ spec: String, _ parts: Int) {
        do {
            print("spec = \(spec), parts = \(parts)")
            let url = try DIDURL(spec)
            var urlBuilder = ""
            
            // getDid()
            if ((parts & DIDURLTest.WITH_DID) == DIDURLTest.WITH_DID) {
                XCTAssertEqual(try DID(DIDURLTest.TEST_DID), url.did)
                XCTAssertEqual(DIDURLTest.TEST_DID, url.did!.toString())
                
                urlBuilder.append(DIDURLTest.TEST_DID)
            } else {
                XCTAssertNil(url.did)
            }
            
            // getPath()
            if ((parts & DIDURLTest.WITH_PATH) == DIDURLTest.WITH_PATH) {
                XCTAssertEqual(DIDURLTest.TEST_PATH, url.path)
                
                urlBuilder.append(DIDURLTest.TEST_PATH)
            } else {
                XCTAssertNil(url.path)
            }
            
            // getQuery(), getQueryString(), getQueryParameter(), hasQueryParameter()
            if ((parts & DIDURLTest.WITH_QUERY) == DIDURLTest.WITH_QUERY) {
                //                XCTAssertEqual(DIDURLTest.TEST_QUERY.suffix(1), url.queryString)
                
                XCTAssertEqual(5, url._queryParameters.count)
                
                XCTAssertEqual("qvalue", url.queryParameter(ofKey: "qkey"))
                XCTAssertEqual("true", url.queryParameter(ofKey: "test"))
                XCTAssertEqual("你好", url.queryParameter(ofKey:"hello")?.removingPercentEncoding)
                XCTAssertEqual("啊", url.queryParameter(ofKey:"a")?.removingPercentEncoding)
                XCTAssertEqual("", url.queryParameter(ofKey:"qkeyonly"))
                
                XCTAssertTrue(url.containsQueryParameter(forKey: "qkeyonly"))
                XCTAssertTrue(url.containsQueryParameter(forKey: "qkey"))
                XCTAssertTrue(url.containsQueryParameter(forKey: "test"))
                XCTAssertTrue(url.containsQueryParameter(forKey: "hello"))
                XCTAssertTrue(url.containsQueryParameter(forKey: "a"))
                
                XCTAssertFalse(url.containsQueryParameter(forKey: "notexist"))
                
                urlBuilder.append(DIDURLTest.TEST_QUERY)
            } else {
                XCTAssertEqual(url.queryString, "")
                XCTAssertEqual(0, url._queryParameters.count)
                
                XCTAssertNil(url.queryParameter(ofKey: "qkey"))
                XCTAssertFalse(url.containsQueryParameter(forKey: "qkey"))
            }
            
            // getFragment()
            if ((parts & DIDURLTest.WITH_FRAGMENT) == DIDURLTest.WITH_FRAGMENT) {
                //                        XCTAssertEqual(TEST_FRAGMENT.suffix(1), url.fragment)
                urlBuilder.append(DIDURLTest.TEST_FRAGMENT)
            } else {
                XCTAssertNil(url.fragment)
            }
            
            let refURLString = urlBuilder
            let refURL = try DIDURL(refURLString)
            
            // toString()
            XCTAssertEqual(refURLString, url.toString())
            
            // toString(DID)
            let pos = (parts & DIDURLTest.WITH_DID) == DIDURLTest.WITH_DID ? DIDURLTest.TEST_DID.count : 0
            //            XCTAssertEqual(refURLString.suffix(pos), url.toString(DID.valueOf(DIDURLTest.TEST_DID)))
            let u = url.toString(try DID.valueOf("did:elastos:abc")!)
            XCTAssertEqual(refURLString, u)
            
            // equals()
            XCTAssertTrue(url == refURL)
            XCTAssertTrue(url.toString() == refURLString)
            
            let difURLString = refURLString + "_abc"
            let difURL = try DIDURL(difURLString)
            XCTAssertFalse(url == difURL)
            XCTAssertFalse(url.toString() == difURLString)
            
            // hashCode()
            XCTAssertEqual(refURL.hashValue, url.hashValue)
            XCTAssertNotEqual(difURL.hashValue, url.hashValue)
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    public func testDIDURLWithContext() {
        for item in DIDURLTest.provideDIDURLs() {
            self.testDIDURLWithContextParams(item[0] as! String, item[1] as! Int)
        }
    }
    
    private func testDIDURLWithContextParams(_ spec: String, _ parts: Int) {
        do {
            print("spec = \(spec), parts = \(parts)")
            let context = try DID("did:elastos:foobar")
            
            let url = try DIDURL(context, spec)
            var urlBuilder = ""
            
            // getDid()
            if ((parts & DIDURLTest.WITH_DID) == DIDURLTest.WITH_DID) {
                XCTAssertEqual( try DID(DIDURLTest.TEST_DID), url.did)
                XCTAssertEqual(DIDURLTest.TEST_DID, url.did!.toString())
                
                urlBuilder.append(DIDURLTest.TEST_DID)
            } else {
                XCTAssertEqual(context, url.did)
                XCTAssertEqual(context.toString(), url.did!.toString())
                
                urlBuilder.append(context.toString())
            }
            
            // getPath()
            if ((parts & DIDURLTest.WITH_PATH) == DIDURLTest.WITH_PATH) {
                XCTAssertEqual(DIDURLTest.TEST_PATH, url.path)
                
                urlBuilder.append(DIDURLTest.TEST_PATH)
            } else {
                XCTAssertNil(url.path)
            }
            
            // getQuery(), getQueryString(), getQueryParameter(), hasQueryParameter()
            if ((parts & DIDURLTest.WITH_QUERY) == DIDURLTest.WITH_QUERY) {
                //                        XCTAssertEqual(TEST_QUERY.suffix(1), url.queryString)
                
                XCTAssertEqual(5, url.queryParameters().count)
                
                XCTAssertEqual("qvalue", url.queryParameter(ofKey: "qkey"))
                XCTAssertEqual("true", url.queryParameter(ofKey: "test"))
                XCTAssertEqual("你好", url.queryParameter(ofKey: "hello")?.removingPercentEncoding)
                XCTAssertEqual("啊", url.queryParameter(ofKey: "a")?.removingPercentEncoding)
                XCTAssertEqual("", url.queryParameter(ofKey: "qkeyonly"))
                
                XCTAssertTrue(url.containsQueryParameter(forKey: "qkeyonly"))
                XCTAssertTrue(url.containsQueryParameter(forKey: "qkey"))
                XCTAssertTrue(url.containsQueryParameter(forKey: "test"))
                XCTAssertTrue(url.containsQueryParameter(forKey: "hello"))
                XCTAssertTrue(url.containsQueryParameter(forKey: "a"))
                
                XCTAssertFalse(url.containsQueryParameter(forKey: "notexist"))
                
                urlBuilder.append(DIDURLTest.TEST_QUERY)
            } else {
                XCTAssertEqual("", url.queryString)
                XCTAssertEqual(0, url.queryParameters().count)
                
                XCTAssertNil(url.queryParameter(ofKey: "qkey"))
                XCTAssertFalse((url.queryParameter(ofKey: "qkey") == ""))
            }
            
            // getFragment()
            if ((parts & DIDURLTest.WITH_FRAGMENT) == DIDURLTest.WITH_FRAGMENT) {
                //                        XCTAssertEqual(TEST_FRAGMENT.suffix(1), url.fragment)
                urlBuilder.append(DIDURLTest.TEST_FRAGMENT)
            } else {
                XCTAssertEqual(url.fragment, nil)
            }
            
            let refURLString = urlBuilder
            let refURL = try DIDURL(refURLString)
            
            // toString()
            XCTAssertEqual(refURLString, url.toString())
            
            // toString(DID)
            if ((parts & DIDURLTest.WITH_DID) == DIDURLTest.WITH_DID) {
               let r = refURLString[refURLString.index(refURLString.startIndex, offsetBy: DIDURLTest.TEST_DID.count)...]
                XCTAssertEqual(String(r),
                               url.toString(try DID.valueOf(DIDURLTest.TEST_DID)!))
                XCTAssertEqual(refURLString, url.toString(context))
            } else {
                let r = refURLString[refURLString.index(refURLString.startIndex, offsetBy: context.toString().count)...]
                XCTAssertEqual(String(r),
                               url.toString(context))
                XCTAssertEqual(refURLString, url.toString(try DID.valueOf(DIDURLTest.TEST_DID)!))
            }
            
            // equals()
            XCTAssertTrue(url == (refURL))
            XCTAssertTrue(url.toString() == (refURLString))
            
            let difURLString = refURLString + "_abc"
            let difURL = try DIDURL(difURLString)
            XCTAssertFalse(url == (difURL))
            XCTAssertFalse(url.toString() == (difURLString))
            
            // hashCode()
            XCTAssertEqual(refURL.hashValue, url.hashValue)
            XCTAssertNotEqual(difURL.hashValue, url.hashValue)
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    public func testCompatibleWithPlainFragment() {
        do {
            let testURL = DIDURLTest.TEST_DID + "#test"
            
            let url1 = try DIDURL(testURL)
            XCTAssertEqual(testURL, url1.toString())
            XCTAssertEqual("test", url1.fragment)
            XCTAssertTrue(url1.toString() == (testURL))
            
            let url2 = try DIDURL(DID.valueOf(DIDURLTest.TEST_DID)!, "test")
            XCTAssertEqual(testURL, url2.toString())
            XCTAssertEqual("test", url2.fragment)
            XCTAssertTrue(url2.toString() == (testURL))
            
            XCTAssertTrue(url1 == (url2))
            
            let url = try DIDURL("test")
            XCTAssertEqual("test", url.fragment)
            XCTAssertEqual("#test", url.toString())
            XCTAssertTrue(url.toString() == ("#test"))
        } catch {
            print(error)
            XCTFail()
        }
    }
    
    public static func CsvSource() -> Array<String> {
        return [
            "did:elastos:foobar/path/to/resource?test=true&key=value&name=foobar#helloworld",
            "did:elastos:foobar/p.a_t-h/to-/resource_?te_st=tr_ue&ke.y=va_lue&na_me=foobar#helloworld_",
            "did:elastos:foobar/path_/to./resource_?test-=true.&ke.y_=va_lue.&name_=foobar.#helloworld_-.",
            "did:elastos:foobar/pa...th/to.../resource_-_?test-__.=true...&ke...y_---=va_lue.&name_=foo...bar.#helloworld_-.",
            "did:elastos:foobar/path/to/resou___rce?test=tr----ue&key=va----lue&name=foobar#hello....---world__",
        ]
    }
    
    private func trim(_ str: String) -> String {
        var start = 0
        var limit = str.count

        // trim the leading and trailing spaces
        while ((limit > 0) && (str.charAt(limit - 1) <= " ")) {
            limit = limit - 1        //eliminate trailing whitespace
        }

        while ((start < limit) && (str.charAt(start) <= " ")) {
            start = start + 1        // eliminate leading whitespace
        }
        
        let r = String(str[start..<limit])
        
        return r
    }
    
    public func testParseUrlWithSpecialChars() {
        for value in DIDURLTest.CsvSource() {
            do {
                let url = try DIDURL(value)
                
                XCTAssertTrue(url.did == (DID(DID.METHOD, "foobar")))
                
                let urlString = trim(value)
                XCTAssertEqual(urlString, url.toString())
                XCTAssertTrue(url.toString() == (urlString))
            } catch {
                print(error)
                XCTFail()
            }
        }
    }
    
    public func testDataForTestParseWrongUrl() -> Array<String> {
        return [
            "did1:elastos:foobar/path/to/resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 4",
            "did:unknown:foobar/path/to/resource?test=true&key=value&name=foobar#helloworld | Invalid did at: 0",
            "did:elastos:foobar:/path/to/resource?test=true&key=value&name=foobar#helloworld | Invalid did at: 0",
            "did:elastos:foobar/-path/to/resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 19",
            "did:elastos:foobar/._path/to/resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 19",
            "did:elastos:foobar/-._path/to/resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 19",
            "did:elastos:foobar/path/-to/resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 24",
            "did:elastos:foobar/path/.to/resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 24",
            "did:elastos:foobar/path/_to/resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 24",
            "did:elastos:foobar/path/*to/resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 24",
            "did:elastos:foobar/path/$to/resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 24",
            "did:elastos:foobar/path./$to/resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 25",
            "did:elastos:foobar/path/%to/resource?test=true&key=value&name=foobar#helloworld | Invalid hex char at: 25",
            "did:elastos:foobar/path/to//resource?test=true&key=value&name=foobar#helloworld | Invalid char at: 27",
            "did:elastos:foobar/path/to/resource?test=true&&&key=value&name=foobar#helloworld | Invalid char at: 46",
            "did:elastos:foobar/path/to/resource?test=true&_key=value&name=foobar#helloworld | Invalid char at: 46",
            "did:elastos:foobar/path/to/resource?test=true&*key=value&name=foobar#helloworld | Invalid char at: 46",
            "did:elastos:foobar/path/to/resource?test=true&-key=value&name=foobar#helloworld | Invalid char at: 46",
            "did:elastos:foobar/path/to/resource?test=true.&-key=value&name=foobar#helloworld | Invalid char at: 47",
            "did:elastos:foobar/path/to/resource%20?test=true.&-key=value&name=foobar#helloworld | Invalid char at: 50",
            "did:elastos:foobar/path/to/resource?test=true&key=value&name==foobar#helloworld | Invalid char at: 61",
            "did:elastos:foobar/path/to/resource?test=true&key=value&name%=foobar#helloworld | Invalid hex char at: 61",
            "did:elastos:foobar/path/to/resource?test=true&key=va--lue&name%=foobar#helloworld | Invalid hex char at: 63",
            "did:elastos:foobar/path/to/resource?test=t.rue&ke.y=val_ue&nam-e=^foobar#helloworld | Invalid char at: 65",
            "did:elastos:foobar/path/to/resource?test=true&key=value&name=foobar*#helloworld | Invalid char at: 67",
            "did:elastos:foobar/path/to/resource?test=true&key=value&name=foobar?#helloworld | Invalid char at: 67",
            "did:elastos:foobar/path/to/resource?test=true&key=value&name=foobar##helloworld | Invalid char at: 68",
            "did:elastos:foobar/path/to/resource?test=true&key=value&name=foobar#helloworld* | Invalid char at: 78",
            "did:elastos:foobar/path/to/resource?test=true&key=value&name=foobar#helloworld& | Invalid char at: 78",
            "did:elastos:foobar/path/to/resource?test=true&key=value&name=foobar#helloworld% | Invalid char at: 78",
        ]
    }

    public func testParseWrongUrl() {
        for value in testDataForTestParseWrongUrl() {
            let params: Array = value.components(separatedBy: " | ")
            let spec = params[0]
            let targetError = params[1]
            
            do {
               _ = try DIDURL(spec)
            } catch {
                XCTAssertTrue(error.localizedDescription == targetError)
            }
        }
        
    }

    public func testParseWrongUrlWithPadding() {
        do {
            _ = try DIDURL("       \t did:elastos:foobar/-path/to/resource?test=true&key=value&name=foobar#helloworld")
        } catch {
            XCTAssertTrue(error.localizedDescription == "Invalid char at: 28")
        }
    }
    
    public func testParseEmptyAndNull() {
        do {
            _ = try DIDURL("")
            _ = try DIDURL("           ")
        } catch {
            XCTAssertTrue(error.localizedDescription == "empty DIDURL string")
        }
    }
    
    override func tearDown() {
        
    }
}
