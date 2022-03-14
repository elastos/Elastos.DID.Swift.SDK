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

/// Create a credential builder.
@objc(VerifiableCredentialBuilder)
public class VerifiableCredentialBuilder: NSObject {
    private var _issuer: VerifiableCredentialIssuer
    private var _target: DID
    private var _credential: VerifiableCredential?
    private var _signKey: DIDURL
    private var _forDoc: DIDDocument
    static let CONTEXT = "@context"
    public static let DEFAULT_CREDENTIAL_TYPE = "VerifiableCredential"// The default verifiable credential type.

    init(_ issuer: VerifiableCredentialIssuer, _ target: DID, _ doc: DIDDocument, _ signKey: DIDURL) throws {
        _issuer = issuer
        _target  = target
        _forDoc  = doc
        _signKey = signKey
        
        _credential = VerifiableCredential()
        _credential?.setIssuer(issuer.did)
        _credential?.setSubject(VerifiableCredentialSubject(target))
        super.init()
        try setDefaultType()
    }
    
    private func checkNotSealed() throws {
        guard let _ = _credential else {
            throw DIDError.UncheckedError.IllegalStateError.AlreadySealedError()
        }
    }

    /// Set the credential id.
    /// - Parameter id: the credential id
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiableCredentialBuilder object.
    @objc
    public func withId(_ id: DIDURL) throws -> VerifiableCredentialBuilder {
        try checkNotSealed()
        try checkArgument(id.did != nil || id.did != _target, "Invalid id")
        var _id = id
        if id.did == nil {
            _id = DIDURL(_target, id)
        }
        
        _credential!.setId(_id)
        return self
    }
    
    /// Set the credential id.
    /// - Parameter id: the credential id
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiableCredentialBuilder object.
    @objc(withIdString:error:)
    public func withId(_ id: String) throws -> VerifiableCredentialBuilder {
        try checkArgument(!id.isEmpty , "id is nil")

        return try withId(DIDURL(_target, id))
    }
    
    /// Add a new credential type.
    /// - Parameters:
    ///   - type: the type name
    ///   - context: the JSON-LD context for type, or null if not enabled the JSON-LD feature
    /// - Returns: the VerifiableCredentialBuilder instance for method chaining
    @objc(withType:context:error:)
    public func withType(_ type: String, _ context: String) throws -> VerifiableCredentialBuilder{
        try checkNotSealed()
        try checkArgument(!type.isEmpty, "Invalid type: \(type)")
        if (Features.isEnabledJsonLdContext()) {
            try checkArgument(!context.isEmpty, "Invalid context: \(context)")
            if !_credential!._context.contains(context) {
                _credential!._context.append(context)
            }
        }
        
        if (!_credential!.getTypes().contains(type)) {
            _credential?.appendType(type)
        }
        
        return self
    }
    
    /// Add a new credential type.
    /// If enabled the JSON-LD feature, the type should be a full type URI:
    /// [scheme:]scheme-specific-part#fragment,
    /// [scheme:]scheme-specific-part should be the context URL,
    /// the fragment should be the type name.
    ///
    /// Otherwise, the context URL part and # symbol could be omitted or
    /// ignored.
    /// - Parameter type: the type name
    /// - Returns: the VerifiableCredentialBuilder instance for method chaining
    public func withType(_ type: String) throws -> VerifiableCredentialBuilder {
        try checkNotSealed()
        try checkArgument(!type.isEmpty, "Invalid type: \(type)")
        if type.index(of: "#") == nil {
            return try withType(type, "")
        }
        else {
            let content_type = type.split(separator: "#")
            return try withType(String(content_type[1]), String(content_type[0]))
        }
    }

    /// Add a new credential type.
    /// If enabled the JSON-LD feature, the type should be a full type URI:
    /// [scheme:]scheme-specific-part#fragment,
    /// [scheme:]scheme-specific-part should be the context URL,
    /// the fragment should be the type name.
    ///
    /// Otherwise, the context URL part and # symbol could be omitted or
    /// ignored.
    /// - Parameter type: the type names
    /// - Returns: the VerifiableCredentialBuilder instance for method chaining
    public func withTypes(_ types: String...) throws -> VerifiableCredentialBuilder {

        return try withTypes(types)
    }
    
    /// Add a new credential type.
    /// If enabled the JSON-LD feature, the type should be a full type URI:
    /// [scheme:]scheme-specific-part#fragment,
    /// [scheme:]scheme-specific-part should be the context URL,
    /// the fragment should be the type name.
    ///
    /// Otherwise, the context URL part and # symbol could be omitted or
    /// ignored.
    /// - Parameter type: the type names
    /// - Returns: the VerifiableCredentialBuilder instance for method chaining
    @objc
    public func withTypes(_ types: Array<String>) throws -> VerifiableCredentialBuilder {
        if types.count == 0 {
            return self
        }
        try checkNotSealed()
        try types.forEach { item in
            try _ = withType(item)
        }
        
        return self
     }

    /// Set credential default expiration date
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiableCredentialBuilder object.
    @objc
    public func withDefaultExpirationDate() throws -> VerifiableCredentialBuilder {
        try checkNotSealed()
        _credential!.setExpirationDate(maxExpirationDate())
        
        return self
    }
    
    /// Set expire time for the credential.
    /// - Parameter expirationDate: the expires time
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiableCredentialBuilder object.
    @objc
    public func withExpirationDate(_ expirationDate: Date) throws -> VerifiableCredentialBuilder {
        try checkNotSealed()
        var _expirationDate = expirationDate

        if _expirationDate > maxExpirationDate() {
            _expirationDate = maxExpirationDate()
        }

        _credential!.setExpirationDate(expirationDate)
        return self
    }
    
    /// Set the claim properties to the credential subject from a dictionary object.
    /// - Parameter properites: a dictionary include the claims
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiableCredentialBuilder object.
    @objc
    public func withProperties(_ properites: Dictionary<String, String>) throws -> VerifiableCredentialBuilder {
        try checkNotSealed()
        guard !properites.isEmpty else {
            return self
        }
        // TODO: CHECK
        let jsonNode = JsonNode(properites)
        let subject = VerifiableCredentialSubject(_target)
        subject.setProperties(jsonNode)
        _credential!.setSubject(subject)
        
        return self
    }
    
    /// Set the claim properties to the credential subject from JSON string.
    /// - Parameter json: Credential dictionary string
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiableCredentialBuilder object.
    @objc(withPropertiesWithJson:error:)
    public func withProperties(_ json: String) throws -> VerifiableCredentialBuilder {
        try checkNotSealed()
        try checkArgument(!json.isEmpty, "properties is nil")

        // TODO: CHECK
        let dic = try (JSONSerialization.jsonObject(with: json.data(using: .utf8)!, options: [JSONSerialization.ReadingOptions.init(rawValue: 0)]) as? [String: Any])
        guard let _ = dic else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedCredentialError("properties data formed error.")
        }
        let jsonNode = JsonNode(dic!)
        let subject = VerifiableCredentialSubject(_target)
        subject.setProperties(jsonNode)
        _credential!.setSubject(subject)
        
        return self
    }
    
    /// Add new claim property to the credential subject.
    /// - Parameters:
    ///   - key: the property name
    ///   - value: the property value
    /// - Returns: VerifiableCredentialBuilder object.
    @objc(withPropertiesWith::error:)
    public func withProperties(_ key: String, _ value: String) throws -> VerifiableCredentialBuilder {
        try checkNotSealed()
        try checkArgument(!key.isEmpty && key != "id", "Invalid name")
        _credential?.subject?.setProperties(key, value)
        
        return self
    }
    
    /// Set claims about the subject of the credential.
    /// - Parameter properties: Credential dictionary JsonNode
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiableCredentialBuilder object.
    @objc(withPropertiesWithJsonNode:errro:)
    public func withProperties(_ properties: JsonNode) throws -> VerifiableCredentialBuilder {
        try checkNotSealed()
        try checkArgument(properties.count > 0, "properties is nil ")

        let subject = VerifiableCredentialSubject(_target)
        subject.setProperties(properties)

        _credential!.setSubject(subject)
        return self
    }
    
    private func sanitize() throws {
        guard _credential?.id != nil else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedCredentialError("Missing credential id")
        }
        guard _credential?.getTypes() != nil, _credential!.getTypes().count != 0 else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedCredentialError("Missing credential type")
        }
        _credential?.setIssuanceDate(DateFormatter.currentDate())
        if _credential!.hasExpirationDate() {
            _ = try withDefaultExpirationDate()
        }
        // TODO: CHECK
        _credential!._types = _credential!._types.sorted()

        _credential?.setProof(nil)
    }

    /// Seal the credential object, attach the generated proof to the
    /// credential.
    /// - Parameter storePassword: the password for DIDStore
    /// - Throws: if an error occurred, throw error.
    /// - Returns: the sealed credential object
    @objc
    public func seal(using storePassword: String) throws -> VerifiableCredential {
        try checkNotSealed()
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        guard _credential!.checkIntegrity() else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedCredentialError("imcomplete credential")
        }
        try sanitize()
        
        _credential!.setIssuanceDate(DateFormatter.currentDate())
        if try _credential!.getExpirationDate() == nil {
            _ = try withDefaultExpirationDate()
        }

        guard let data = _credential!.toJson(true, true).data(using: .utf8) else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalArgumentError("credential is nil")
        }
        let signature = try _forDoc.sign(_signKey, storePassword, [data])
        let proof = VerifiableCredentialProof(_signKey, signature)

        _credential!.setProof(proof)

        // invalidate builder
        let sealed = self._credential!
        self._credential = nil

        return sealed
    }
    
    func setDefaultType() throws {
        try checkNotSealed()
        if (Features.isEnabledJsonLdContext()) {
            if !_credential!._context.contains(VerifiableCredential.W3C_CREDENTIAL_CONTEXT) {
                _credential!._context.append(VerifiableCredential.W3C_CREDENTIAL_CONTEXT)
            }
            if !_credential!._context.contains(VerifiableCredential.ELASTOS_CREDENTIAL_CONTEXT) {
                _credential!._context.append(VerifiableCredential.ELASTOS_CREDENTIAL_CONTEXT)
            }
        }
        
        if !_credential!.getTypes().contains(VerifiableCredentialBuilder.DEFAULT_CREDENTIAL_TYPE) {
            _credential!.appendType(VerifiableCredentialBuilder.DEFAULT_CREDENTIAL_TYPE)
        }
    }

    private func maxExpirationDate() -> Date {
        
        guard _credential?.issuanceDate == nil else {
            return DateFormatter.convertToWantDate(_credential!.issuanceDate!, Constants.MAX_VALID_YEARS)
        }
        return DateFormatter.convertToWantDate(Date(), Constants.MAX_VALID_YEARS)
    }
}
