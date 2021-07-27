/*
 * Copyright (c) 2020 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import Foundation

/* =========================================================================
 *
 * DID and DIDURL syntax definition
 *
 * did:elastos:method-specific-string[;params][/path][?query][#fragment]
 *
 * didurl
 *   : did? ('/' path)? ('?' query)? ('#' fragment)? SPACE?
 *   ;
 *
 * did
 *   : 'did' ':' method ':' methodSpecificString
 *   ;
 *
 * method
 *   : STRING
 *   ;
 *
 * methodSpecificString
 *   : STRING
 *   ;
 *
 * path
 *   : STRING ('/' STRING)*
 *   ;
 *
 * query
 *   : queryParam ('&' queryParam)*
 *   ;
 *
 * queryParam
 *   : queryParamName ('=' queryParamValue)?
 *   ;
 *
 * queryParamName
 *   : STRING
 *   ;
 *
 * queryParamValue
 *   : STRING
 *   ;
 *
 * fragment
 *   : STRING
 *   ;
 *
 * STRING
 *   : ([a-zA-Z~0-9] | HEX) ([a-zA-Z0-9._\-] | HEX)*
 *   ;
 *
 * HEX
 *   : ('%' [a-fA-F0-9] [a-fA-F0-9])+
 *   ;
 *
 * SPACE
 *   : [ \t\n\r]+
 *   ;
 *
 =========================================================================*/
class DIDURLParser: NSObject {
    public let SCHEMA = "did"
    public let METHOD = "elastos"
    public var didurl: DIDURL
    
    init(_ didurl: DIDURL) {
        self.didurl = didurl
    }
    
    private func isHexChar(_ ch: String) -> Bool {
        if (ch >= "A" && ch <= "F") || (ch >= "a" && ch <= "f") || (ch >= "0" && ch <= "9") {
            return true
        }
        
       return false
    }
 
    private func isTokenChar(_ ch: String, _ start: Bool) -> Bool {
        if (ch >= "A" && ch <= "Z") || (ch >= "a" && ch <= "z") || (ch >= "0" && ch <= "9") {
            return true
        }
        
        if start {
            return false
        }
        else {
            return ch  == "." || ch == "_" || ch == "-"
        }
    }
    
    private func scanNextPart(_ url: String, _ start: Int, _ limit: Int, _ partSeps: String, _ tokenSeps: String?) throws -> Int {
        var nextPart = limit
        var tokenStart = true
        for i in start...limit {
            let ch = url.charAt(i)
            let c = Character.init(ch)
            if partSeps.index(of: c) != nil {
                 nextPart = i
                break
            }
            
            if (tokenSeps?.index(of: c) != nil) {
                if tokenStart {
                    throw DIDError.UncheckedError.IllegalArgumentErrors.MalformedDIDURLError("Invalid char at: \(i)")
                }
                tokenStart = true
                continue
            }
            
            if isTokenChar(String(ch), tokenStart) {
                tokenStart = false
                continue
            }
            
            if ch == "%" {
                if i + 2 >= limit {
                    throw DIDError.UncheckedError.IllegalArgumentErrors.MalformedDIDURLError("Invalid char at: \(i)")
                }
                var seq = url.charAt(i + 1)
                if !isHexChar(seq) {
                    throw DIDError.UncheckedError.IllegalArgumentErrors.MalformedDIDURLError("Invalid hex char at: \(i)")
                }
                seq = url.charAt(i + 1)
                if !isHexChar(seq) {
                    throw DIDError.UncheckedError.IllegalArgumentErrors.MalformedDIDURLError("Invalid hex char at:\(i)")
                }
                tokenStart = false
                continue
            }
            
            throw DIDError.UncheckedError.IllegalArgumentErrors.MalformedDIDError("Invalid char at: \(i)")
        }
        
        return nextPart
    }
    
    public func parse(_ url: String) throws {
        try parse(context: nil, url)
    }
    
    public func parse(_ context: DID, _ url: String) throws {
        try parse(context: context, url)
    }
    
    private func parse(context: DID?, _ url: String) throws {
        if context != nil {
            self.didurl.setDid(context!)
        }
        
        var start = 0
        var limit = url.count
        var nextPart: Int = 0
        
        // trim the leading and trailing spaces
        while (limit > 0) && (url.charAt(limit - 1) <= " ") {
            limit = limit - 1        //eliminate trailing whitespace
        }
        while (start < limit) && (url.charAt(start) <= " ") {
            start = start + 1        // eliminate leading whitespace
        }
        if start == limit { // empty url string
            throw DIDError.UncheckedError.IllegalArgumentErrors.MalformedDIDURLError("empty DIDURL string")
        }
        var pos: Int = start
        
        // DID
        if pos < limit || url.regionMatches(pos, "did:", 0, 4) {
            nextPart = try scanNextPart(url, pos, limit, "/?#", ":")
            do {
                let d = try DID(url, pos, nextPart)
                self.didurl.setDid(d)
            } catch {
                throw DIDError.UncheckedError.IllegalArgumentErrors.MalformedDIDError("Invalid did at: \(pos) error: \(error.localizedDescription)")
            }
            
            pos = nextPart
        }
        
        // path
        if pos < limit && url.charAt(pos) == "/" {
            nextPart = try scanNextPart(url, pos + 1, limit, "?#", "/")
            self.didurl.setPath(url[pos...nextPart])
            pos = nextPart
        }
        
        // query
        if (pos < limit && url.charAt(pos) == "?") {
            nextPart = try scanNextPart(url, pos + 1, limit, "#", "&=")
            let queryString = url[pos + 1...nextPart]
            pos = nextPart
            
            if (!queryString.isEmpty) {
                var query: OrderedDictionary<String, String> = OrderedDictionary()
                
                let pairs = queryString.split(separator: "&")
                for pair in pairs {
                    let parts = pair.split(separator: "=")
                    if (parts.count > 0 && !parts[0].isEmpty) {
                        let name = parts[0]
                        let value = parts.count == 2 ? parts[1] : nil
                        query[String(name)] = String(value!)
                    }
                }
                
                self.didurl._queryParameters = query
            }
        } else {
            self.didurl._queryParameters = OrderedDictionary()
        }
        // fragment
        // condition: pos == start
        //    Compatible with v1, support fragment without leading '#'
        if ((pos < limit && url.charAt(pos) == "#") || (pos == start)) {
            if url.charAt(pos) == "#" {
                pos = pos + 1
            }
            nextPart = try scanNextPart(url, pos, limit, "", nil)
            let fragment = url[pos...nextPart]
            if (!fragment.isEmpty) {
                self.didurl.setFragment(fragment)
            }
        }
    }
}
