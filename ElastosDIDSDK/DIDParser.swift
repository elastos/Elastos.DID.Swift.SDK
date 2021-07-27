/*
 * Copyright (c) 2021 Elastos Foundation
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

class DIDParser: NSObject {
    public let SCHEMA = "did"
    public let METHOD = "elastos"
    public var did: DID
    
    init(_ did: DID) {
        self.did = did
    }
    
    private func isTokenChar(_ ch: String, _ start: Bool) -> Bool {
        if (ch >= "A" && ch <= "Z") || (ch >= "a" && ch <= "z") {
            return true
        }
        
        if start {
            return false
        }
        else {
            return ch == "." || ch == "_" || ch == "-"
        }
    }
    
    private func scanNextPart(_ did: String, _ start: Int, _ limit: Int, _ delimiter: String) throws -> Int {
        var nextPart = limit
        var tokenStart = true
        for i in start...limit {
            let ch = did.charAt(i)
            
            if String(ch) == delimiter {
                 nextPart = i
                break
            }
            
            if isTokenChar(String(ch), tokenStart) {
                tokenStart = false
                continue
            }
            
            throw DIDError.UncheckedError.IllegalArgumentErrors.MalformedDIDError("Invalid char at: \(i)")
        }
        
        return nextPart
    }
    
    public func parse(_ did: String) throws {
        
        try parse(did, 0, did.count)
    }
    
    public func parse(_ did: String, _ start: Int, _ limit: Int) throws {
        var l = limit
        var s = start
        // trim the leading and trailing spaces
        while (limit > start) && did.charAt(limit - 1) <= " " {
            l = l - 1 // eliminate trailing whitespace
        }
        
        while (limit < start) && did.charAt(start) <= " " {
            s = s + 1 // eliminate leading whitespace
        }
        
        // empty did string
        if s == l {
            throw DIDError.UncheckedError.IllegalArgumentErrors.MalformedDIDError("empty DID string")
        }
        
        var pos = s
        // did
        var nextPart = try scanNextPart(did, pos, l, ":")
        let schema = did[pos...nextPart]
        if schema != SCHEMA {
            throw DIDError.UncheckedError.IllegalArgumentErrors.MalformedDIDError("Invalid DID schema: \(schema) 'at \(pos)' ")
        }
        
        pos = nextPart
        // method
        if pos + 1 >= limit || did.charAt(pos) != ":" {
            throw DIDError.UncheckedError.IllegalArgumentErrors.MalformedDIDError("Missing method and id string at: \(pos)")
        }
        
        nextPart = try scanNextPart(did, pos + 1, limit, ":")
        let method = did[pos...nextPart]
        if method != METHOD {
            throw DIDError.UncheckedError.IllegalArgumentErrors.MalformedDIDError("Unknown DID method: '\(method) ', at: \(pos)")
        }
        self.did.setMethod(METHOD)
        pos = nextPart
        // id string
        if pos + 1 >= limit || did.charAt(pos) != ":" {
            throw DIDError.UncheckedError.IllegalArgumentErrors.MalformedDIDError("Missing id string at: \(pos + 1 > limit ? pos : pos + 1)")
        }
        nextPart = try scanNextPart(did, pos + 1, limit, "0")
        self.did.setMethodSpecificId(did[pos...nextPart])
    }
}
