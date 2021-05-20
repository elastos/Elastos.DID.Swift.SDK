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
import ObjectMapper

/// The Proof class represents the proof content of DID Document.
@objc(DIDDocumentProof)
public class DIDDocumentProof: NSObject {
    private var _type: String
    private var _createdDate: Date
    private var _creator: DIDURL?
    private var _signature: String
    
    /// Constructs a Proof object with the given values.
    /// - Parameters:
    ///   - type: the type of Proof
    ///   - createdDate: the create time stamp
    ///   - creator: the key that sign this proof
    ///   - signature: the signature string
    init(_ type: String, _ createdDate: Date, _ creator: DIDURL, _ signature: String) {
        self._type = type
        self._createdDate = createdDate
        self._creator = creator
        self._signature = signature
    }
    
    /// Constructs a Proof object with the given values.
    /// - Parameters:
    ///   - type: the type of Proof
    ///   - createdDate: the create time stamp
    ///   - signature: the signature string
    init(_ type: String, _ createdDate: Date, _ signature: String) {
        self._type = type
        self._createdDate = createdDate
        self._signature = signature
    }
    
    /// Constructs a Proof object with the given values.
    /// - Parameters:
    ///   - creator: the key that sign this proof
    ///   - signature: the signature string
    convenience init(_ creator: DIDURL, _ signature: String) {
        self.init(Constants.DEFAULT_PUBLICKEY_TYPE, DateFormatter.currentDate(), creator, signature)
    }
    
    /// Constructs a Proof object with the given values.
    /// - Parameter signature: the signature string
    convenience init(_ signature: String) {
        self.init(Constants.DEFAULT_PUBLICKEY_TYPE, DateFormatter.currentDate(), signature)
    }

    /// Get the proof type.
    @objc
    public var type: String {
        return self._type
    }

    /// Get the create time of this proof object.
    @objc
    public var createdDate: Date {
        return self._createdDate
    }

    /// Get the key id that sign this proof object
    @objc
    public var creator: DIDURL? {
        return self._creator
    }

    func setCreator(_ newValue: DIDURL) {
        self._creator = newValue
    }
    
    /// Get signature string.
    @objc
    public var signature: String {
        return self._signature
    }

    class func fromJson(_ node: JsonNode, _ refSginKey: DIDURL?) throws -> DIDDocumentProof {
        let serializer = JsonSerializer(node)
        var options: JsonSerializer.Options

        options = JsonSerializer.Options()
                                .withOptional()
                                .withRef(Constants.DEFAULT_PUBLICKEY_TYPE)
        guard let type = try serializer.getString(Constants.TYPE, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Mssing document proof type")
        }

        options = JsonSerializer.Options()
                                .withOptional()
        guard let created = try serializer.getDate(Constants.CREATED, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Mssing document proof created date")
        }

        options = JsonSerializer.Options()
                                .withOptional()
                                .withRef(refSginKey?.did)
        var creator = try serializer.getDIDURL(Constants.CREATOR, options)
        if  creator == nil {
            creator = refSginKey
        }

        options = JsonSerializer.Options()
        guard let signature = try serializer.getString(Constants.SIGNATURE_VALUE, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Mssing document proof signature")
        }

        if let _ = creator {
            return DIDDocumentProof(type, created, creator!, signature)
        }
        return DIDDocumentProof(type, created, signature)
    }

    func toJson(_ generator: JsonGenerator, _ normalized: Bool) {
        generator.writeStartObject()

        // type
        if normalized || self.type != Constants.DEFAULT_PUBLICKEY_TYPE {
            generator.writeFieldName(Constants.TYPE)
            generator.writeString(self._type)
        }

        // createdDate
        generator.writeFieldName(Constants.CREATED)
        generator.writeString(DateFormatter.convertToUTCStringFromDate(self.createdDate))

        // creator
        if let _ = creator {
            generator.writeFieldName(Constants.CREATOR)
            generator.writeString(self.creator!.toString())
        }

        // signature
        generator.writeFieldName(Constants.SIGNATURE_VALUE)
        generator.writeString(self.signature)

        generator.writeEndObject()
    }
}
