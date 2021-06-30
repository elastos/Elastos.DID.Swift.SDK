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

/// The proof object of ID chain transaction request.
public class IDChainProof: NSObject {
    var _type: String
    var _verificationMethod: DIDURL
    var _signature: String
    
    init(_ type: String, _ verificationMethod: DIDURL, _ signature: String) {
        self._type = type
        self._verificationMethod = verificationMethod
        self._signature = signature
    }
    
    init(_ verificationMethod: DIDURL, _ signature: String) {
        self._type = Constants.DEFAULT_PUBLICKEY_TYPE
        self._verificationMethod = verificationMethod
        self._signature = signature
    }
    
    /// Get the proof type string. the type is derived from the type of the
    /// public key that signed this proof.
    public var type: String {
        return _type
    }
    
    /// Get the public key id that signed this proof.
    public var verificationMethod: DIDURL {
        return _verificationMethod
    }
    
    /// Get the signature string of this proof.
    public var signature: String {
        return _signature
    }
    
    func qualifyVerificationMethod(_ ref: DID) {
        //TODO:
    }
    
    func serialize(_ generator: JsonGenerator) {
        generator.writeStartObject()
        generator.writeStringField("type", type)
        generator.writeStringField("verificationMethod", verificationMethod.toString())
        generator.writeStringField("signature", signature)
        
        generator.writeEndObject()
    }
    
    class func parse(_ content: JsonNode) throws -> IDChainProof {
        let type = content.get(forKey: "type")?.asString()
        let signature = content.get(forKey: "signature")!.asString()
        let verificationMethod = content.get(forKey: "verificationMethod")!.asString()
        if let _ = type {
            return try IDChainProof(type!,DIDURL(verificationMethod!), signature!)
        }
        return try IDChainProof(DIDURL(verificationMethod!), signature!)
    }
}

