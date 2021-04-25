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

/// The proof information for DID transfer ticket.
/// The default proof type is ECDSAsecp256r1.
public class TransferTicketProof: NSObject {
    private static let TYPE = "type"
    private static let CREATED = "created"
    private static let VERIFICATION_METHOD = "verificationMethod"
    private static let SIGNATURE = "signature"

    var _type: String
    var _created: Date
    var _verificationMethod: DIDURL
    var _signature: String
    
    /// Constructs the Proof object with the given values.
    /// - Parameters:
    ///   - type: the verification method type
    ///   - method: the verification method, normally it's a public key
    ///   - signature: the signature encoded in base64 URL safe format
    init(_ type: String, _ method: DIDURL, _ created: Date, _ signature: String) {
        self._type = type
        self._created = created
        self._verificationMethod = method
        self._signature = signature
        super.init()
    }
    
    init(_ method: DIDURL, _ signature: String) {
        self._type = Constants.DEFAULT_PUBLICKEY_TYPE
        self._verificationMethod = method
        self._created = DateFormatter.currentDate()
        self._signature = signature
        super.init()
    }
    
    ///  Get the verification method type.
    var type: String {
        return _type
    }
    
    /// Get the verification method, normally it's a public key id.
    var verificationMethod: DIDURL {
        return _verificationMethod
    }
    
    /// Get the created timestamp.
    var created: Date {
        return _created
    }
    
    /// Get the signature encoded in URL safe base64 string
    var signature: String {
        return _signature
    }

    public func serialize(_ generator: JsonGenerator) {
        generator.writeStartObject()
        generator.writeStringField(TransferTicketProof.TYPE, type)
        generator.writeStringField(TransferTicketProof.CREATED, DateFormatter.convertToUTCStringFromDate(created))
        generator.writeStringField(TransferTicketProof.VERIFICATION_METHOD, verificationMethod.toString())
        generator.writeStringField(TransferTicketProof.SIGNATURE, signature)
        generator.writeEndObject()
    }
    
    public func serialize() -> String {
        let generator = JsonGenerator()
        serialize(generator)
        
        return generator.toString()
    }
    
    /// Parse a TransferTicket object from from a string JSON representation.
    /// - Parameter content: the string JSON content for building the object
    /// - Returns: the TransferTicket object
    public class func deserialize(_ content: [String: Any]) throws -> TransferTicketProof {
        let type = content[TYPE] as! String
        let created = DateFormatter.convertToUTCDateFromString(content[CREATED] as! String)
        let signature = content[SIGNATURE] as! String
        let verificationMethod = try DIDURL(content[VERIFICATION_METHOD] as! String)
        let tf = TransferTicketProof(type, verificationMethod, created!, signature)
        
       return tf
    }

    public func compareTo(_ proof: TransferTicketProof) -> Int {
        var rc = DateFormatter.getTimeStamp(self.created) - DateFormatter.getTimeStamp(proof.created)
        
        if rc == 0 {
            rc = (self.verificationMethod == proof.verificationMethod) ? 1 : 0
        }
        
        return rc
    }
}
