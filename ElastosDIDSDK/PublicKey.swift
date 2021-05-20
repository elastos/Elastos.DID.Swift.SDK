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

/// Public keys are used for digital signatures, encryption and other cryptographic operations,
/// which are the basis for purposes such as authentication or establishing secure communication with service endpoints.
@objc(PublicKey)
public class PublicKey: DIDObject {
    
    private var _controller: DID
    private var _keyBase58: String
    private var _id: DIDURL
    private var _type: String
    
    private var authenticationKey: Bool?
    private var authorizationKey: Bool?
    
    /// Constructs a PublicKey instance with the given values.
    /// - Parameters:
    ///   - id: the id of the PublicKey
    ///   - type: the key type, default type is "ECDSAsecp256r1"
    ///   - controller: the DID who holds the private key
    ///   - keyBase58: the base58 encoded public key
    init(_ id: DIDURL, _ type: String, _ controller: DID, _ keyBase58: String) {
        self._controller = controller
        self._keyBase58 = keyBase58
        self._id = id
        self._type = type
        self.authenticationKey = false
        self.authorizationKey = false

        super.init(id, type)
    }

    convenience init(_ id: DIDURL, _ controller: DID, _ keyBase58: String) {
        self.init(id, Constants.DEFAULT_PUBLICKEY_TYPE, controller, keyBase58)
    }
    
    /// Get the PublicKey id.
    @objc public var id: DIDURL {
        return _id
    }
    
    /// Get the PublicKey type.
    @objc public var type: String {
        return _type
    }

    /// Get the controller of this PublicKey.
    @objc public var controller: DID {
        return _controller
    }
    
    func setController(_ newVaule: DID) {
        self._controller = newVaule
    }

    /// Get the base58 encoded public key string.
    @objc public var publicKeyBase58: String {
        return _keyBase58
    }

    /// Get the raw binary public key [UInt8].
    @objc public var publicKeyBytes: [UInt8] {
        return Base58.bytesFromBase58(_keyBase58)
    }
    
    /// Get the raw binary public key Data.
    public var publicKeyData: Data {
        return Data(publicKeyBytes)
    }

    /// Check if the key is an authentication key.
    @objc public var isAuthenticationKey: Bool {
        return authenticationKey!
    }
    
    /// Set this PublicKey as an authentication key or not.
    /// - Parameter newValue: true set this key as an authentication key;
    ///           false remove this key from authentication keys
    func setAuthenticationKey(_ newValue: Bool) {
        self.authenticationKey = newValue
    }

    /// Check if the key is an authorization key.
    @objc public var isAuthorizationKey: Bool {
        return authorizationKey!
    }
    
    /// Set this PublicKey as an authorization key or not.
    /// - Parameter newValue: true set this key as an authorization key;
    ///           false remove this key from authorization keys
    func setAuthorizationKey(_ newValue: Bool) {
        self.authorizationKey = newValue
    }

    class func fromJson(_ node: JsonNode, _ ref: DID?) throws -> PublicKey {
        let serializer = JsonSerializer(node)
        var options: JsonSerializer.Options

        options = JsonSerializer.Options()
                                .withRef(ref)
        guard let id = try serializer.getDIDURL(Constants.ID, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Mssing publicKey id")
        }

        options = JsonSerializer.Options()
                                .withOptional()
                                .withRef(Constants.DEFAULT_PUBLICKEY_TYPE)
        guard let type = try serializer.getString(Constants.TYPE, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Mssing publicKey type")
        }

        options = JsonSerializer.Options()
                                .withOptional()
                                .withRef(ref)
        guard let controller = try serializer.getDID(Constants.CONTROLLER, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Mssing publicKey controller")
        }

        options = JsonSerializer.Options()
        guard let keybase58 = try serializer.getString(Constants.PUBLICKEY_BASE58, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Mssing publicKeyBase58")
        }

        return PublicKey(id, type, controller, keybase58)
    }

    func toJson(_ generator: JsonGenerator, _ ref: DID?, _ normalized: Bool) {
        generator.writeStartObject()
        generator.writeFieldName(Constants.ID)
        generator.writeString(IDGetter(getId()!, ref).value(normalized))

        // type
        if normalized || !isDefType() {
            generator.writeStringField(Constants.TYPE, getType()!)
        }

        // controller
        if normalized || ref == nil || ref != controller {
            generator.writeFieldName(Constants.CONTROLLER);
            generator.writeString(controller.toString())
        }

        // publicKeyBase58
        generator.writeFieldName(Constants.PUBLICKEY_BASE58)
        generator.writeString(publicKeyBase58)
        generator.writeEndObject()
    }

    override func equalsTo(_ other: DIDObject) -> Bool {
        guard other is PublicKey else {
            return false
        }

        let publicKey = other as! PublicKey
        return super.equalsTo(other) &&
               controller == publicKey.controller &&
               publicKeyBase58 == publicKey.publicKeyBase58
    }
}

extension PublicKey {
    public static func == (lhs: PublicKey, rhs: PublicKey) -> Bool {
        return lhs.equalsTo(rhs)
    }

    public static func != (lhs: PublicKey, rhs: PublicKey) -> Bool {
        return !lhs.equalsTo(rhs)
    }

    @objc
    public override func isEqual(_ object: Any?) -> Bool {
        return equalsTo(object as! DIDObject)
    }
    
    public func compareTo(_ key: PublicKey) throws -> ComparisonResult {
        
        try checkArgument(self.getId() != nil || key.getId() != nil, "id is nil")
        var result = self.getId()!.compareTo(key.getId()!)
        
        if result == ComparisonResult.orderedSame {
            result = self.publicKeyBase58.compare(key.publicKeyBase58)
        } else {
            return result
        }
        
        try checkArgument(self.getType() != nil || key.getType() != nil, "type is nil")
        if result == ComparisonResult.orderedSame {
            result = self.getType()!.compare(key.getType()!)
        } else {
            return result
        }
        
        if result == ComparisonResult.orderedSame {
            
            return try self.controller.compareTo(self.controller)
        } else {
            return result
        }
    }
}
