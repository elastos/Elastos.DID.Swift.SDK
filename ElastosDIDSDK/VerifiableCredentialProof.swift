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

@objc(VerifiableCredentialProof)
/// The proof information for verifiable credential.
/// The default proof type is ECDSAsecp256r1.
public class VerifiableCredentialProof: NSObject {
    private var _type: String
    private var _verificationMethod: DIDURL
    private var _signature: String
    private var _created: Date?
    
    /// Constructs the Proof object with the given values.
    /// - Parameters:
    ///   - type: the verification method type
    ///   - method: the verification method, normally it's a public key
    ///   - signature: the signature encoded in base64 URL safe format
    init(_ type: String, _ method: DIDURL, _ created: Date?, _ signature: String) {
        self._type = type
        self._verificationMethod = method
        self._created = created
        self._signature = signature
    }
    
    /// Constructs the Proof object with the given values.
    /// - Parameters:
    ///   - method: the verification method, normally it's a public key
    ///   - signature: the signature encoded in base64 URL safe format
    init(_ method: DIDURL, _ signature: String) {
        self._type = Constants.DEFAULT_PUBLICKEY_TYPE
        self._verificationMethod = method
        self._signature = signature
    }

    /// Get the verification method type.
    @objc
    public var type: String {
        return _type
    }
    
    /// Get the created time stamp.
    public var created: Date? {
        return _created
    }
    
    /// Get the verification method, normally it's a public key id.
    @objc
    public var verificationMethod: DIDURL {
        return _verificationMethod
    }

    /// Get the signature.
    /// the signature encoded in URL safe base64 string
    @objc
    public var signature: String {
        return _signature
    }

    class func fromJson(_ node: JsonNode, _ ref: DID?) throws -> VerifiableCredentialProof {
        let serializer = JsonSerializer(node)
        var options: JsonSerializer.Options

        options = JsonSerializer.Options()
                                .withOptional()
                                .withRef(Constants.DEFAULT_PUBLICKEY_TYPE)
        guard let type = try serializer.getString(Constants.TYPE, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedCredentialError("Mssing credential proof type")
        }

        options = JsonSerializer.Options()
                                .withOptional()
                                .withRef(Constants.CREATED)
        let create = try serializer.getDate(Constants.CREATED, options)
        
        options = JsonSerializer.Options()
                                .withRef(ref)
        guard let method = try serializer.getDIDURL(Constants.VERIFICATION_METHOD, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedCredentialError("Mssing credential proof verificationMethod")
        }

        options = JsonSerializer.Options()
        guard let signature = try serializer.getString(Constants.SIGNATURE, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedCredentialError("Mssing credential proof signature")
        }
        
        return VerifiableCredentialProof(type, method, create, signature)
    }

    func toJson(_ generator: JsonGenerator, _ ref: DID?, _ normalized: Bool) {
        generator.writeStartObject()
        if normalized || type != Constants.DEFAULT_PUBLICKEY_TYPE {
            generator.writeStringField(Constants.TYPE, type)
        }
        if let _ = created {
            generator.writeFieldName(Constants.CREATED)
            generator.writeString(DateFormatter.convertToUTCStringFromDate(self.created!))
        }

        generator.writeFieldName(Constants.VERIFICATION_METHOD)
        generator.writeString(IDGetter(verificationMethod, ref).value(normalized))

        generator.writeStringField(Constants.SIGNATURE, signature)
        generator.writeEndObject()
    }
}
