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

/// The proof information for verifiable presentation.
/// The default proof type is ECDSAsecp256r1.
@objc(VerifiablePresentationProof)
public class VerifiablePresentationProof: NSObject {
    private let _type: String
    private let _verificationMethod: DIDURL
    private let _realm: String
    private let _nonce: String
    private let _signature: String
    
    /// Create the proof object with the given values.
    /// - Parameters:
    ///   - type: the type string
    ///   - method: the sign key
    ///   - realm: where is presentation use
    ///   - nonce: the nonce string
    ///   - signature: the signature string
    init(_ type: String,  _ method: DIDURL, _ realm: String,  _ nonce: String, _ signature: String) {
        self._type = type
        self._verificationMethod = method
        self._realm = realm
        self._nonce = nonce
        self._signature = signature
    }
    
    /// Create the proof object with the given values.
    /// - Parameters:
    ///   - method: the sign key
    ///   - realm: where is presentation use
    ///   - nonce: the nonce string
    ///   - signature: the signature string
    convenience init(_ method: DIDURL, _ realm: String, _ nonce: String, _ signature: String) {
        self.init(Constants.DEFAULT_PUBLICKEY_TYPE, method, realm, nonce, signature)
    }

    /// Get the proof type.
    @objc
    public var type: String {
        return _type
    }

    /// Get the verification method.
    @objc
    public var verificationMethod: DIDURL {
        return _verificationMethod
    }

    /// Get the realm string of this presentation object.
    @objc
    public var realm: String {
        return _realm
    }

    /// Get the nonce string of this presentation object.
    @objc
    public var nonce: String {
        return _nonce
    }

    /// Get signature value of this presentation object.
    @objc
    public var signature: String {
        return _signature
    }

    class func fromJson(_ node: JsonNode, _ ref: DID?) throws -> VerifiablePresentationProof {
        let serializer = JsonSerializer(node)
        var options: JsonSerializer.Options

        options = JsonSerializer.Options()
                                .withOptional()
                                .withRef(Constants.DEFAULT_PUBLICKEY_TYPE)
        guard let type = try serializer.getString(Constants.TYPE, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedPresentationError("Mssing presentation proof type")
        }

        options = JsonSerializer.Options()
                                .withRef(ref)
        guard let method = try serializer.getDIDURL(Constants.VERIFICATION_METHOD, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedPresentationError("Mssing presentation proof verificationMethod")
        }

        options = JsonSerializer.Options()
        guard let realm = try serializer.getString(Constants.REALM, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedPresentationError("Mssing presentation proof realm")
        }

        options = JsonSerializer.Options()
        guard let nonce = try serializer.getString(Constants.NONCE, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedPresentationError("Mssing presentation proof nonce")
        }

        options = JsonSerializer.Options()
        guard let signature = try serializer.getString(Constants.SIGNATURE, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedPresentationError("Mssing presentation proof signature")
        }

        return VerifiablePresentationProof(type, method, realm, nonce, signature)
    }

    func toJson(_ generator: JsonGenerator) {
        generator.writeStartObject()
        generator.writeStringField(Constants.TYPE, type)
        generator.writeStringField(Constants.VERIFICATION_METHOD, verificationMethod.toString())
        generator.writeStringField(Constants.REALM, realm)
        generator.writeStringField(Constants.NONCE, nonce)
        generator.writeStringField(Constants.SIGNATURE, signature)
        generator.writeEndObject()
    }
}
