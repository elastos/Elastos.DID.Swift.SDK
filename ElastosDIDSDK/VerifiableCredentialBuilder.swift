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

@objc(VerifiableCredentialBuilder)
public class VerifiableCredentialBuilder: NSObject {
    private var _issuer: VerifiableCredentialIssuer
    private var _target: DID
    private var _credential: VerifiableCredential?
    private var _signKey: DIDURL
    private var _forDoc: DIDDocument

    init(_ issuer: VerifiableCredentialIssuer, _ target: DID, _ doc: DIDDocument, _ signKey: DIDURL) {
        _issuer = issuer
        _target  = target
        _forDoc  = doc
        _signKey = signKey
        
        _credential = VerifiableCredential()
        _credential?.setIssuer(issuer.did)
        _credential?.setSubject(VerifiableCredentialSubject(target))
    }
    
    private func checkNotSealed() throws {
        guard let _ = _credential else {
            throw DIDError.UncheckedError.IllegalStateError.AlreadySealedError()
        }
    }

    /// Set  an identifier for credential
    /// - Parameter id: An identifier of credential.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiableCredentialBuilder instance.
    @objc
    public func withId(_ id: DIDURL) throws -> VerifiableCredentialBuilder {
        try checkNotSealed()
        try checkArgument(id.did != nil || id.did != _target, "Invalid id")
        var _id = id
        if id.did == nil {
            _id = try DIDURL(_target, id)
        }
        
        _credential!.setId(_id)
        return self
    }
    
    /// Set  an identifier for credential
    /// - Parameter id: An identifier of credential.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiableCredentialBuilder instance.
    @objc(withIdString:error:)
    public func withId(_ id: String) throws -> VerifiableCredentialBuilder {
        guard !id.isEmpty else {
            throw DIDError.illegalArgument()
        }

        return try withId(DIDURL(_target, id))
    }

    /// Set  type for credential
    /// - Parameter types: the credential types, which declare what data to expect in the credential
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiableCredentialBuilder instance.
    public func withTypes(_ types: String...) throws -> VerifiableCredentialBuilder {
        try checkNotSealed()
        try checkArgument(types.count > 0, "Invalid types")
        _credential!.setType(types)
        
        return self
    }
   
    /// Set  type for credential
    /// - Parameter types: the credential types, which declare what data to expect in the credential
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiableCredentialBuilder instance.
    @objc
    public func withTypes(_ types: Array<String>) throws -> VerifiableCredentialBuilder {

        try checkNotSealed()
        try checkArgument(types.count > 0, "Invalid types")
        _credential!.setType(types)
        
        return self
     }

    /// Set credential default expiration date
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiableCredentialBuilder instance.
    @objc
    public func withDefaultExpirationDate() throws -> VerifiableCredentialBuilder {
        try checkNotSealed()
        _credential!.setExpirationDate(maxExpirationDate())
        
        return self
    }
    
    /// Set credential expiration date
    /// - Parameter expirationDate: when the credential will expire
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiableCredentialBuilder instance.
    @objc
    public func withExpirationDate(_ expirationDate: Date) throws -> VerifiableCredentialBuilder {
        try checkNotSealed()
        guard !DateFormatter.isExpired(expirationDate, maxExpirationDate()) else {
            throw DIDError.illegalArgument()
        }

        // TODO: check
        _credential!.setExpirationDate(expirationDate)
        return self
    }
    
    /// Set claims about the subject of the credential.
    /// - Parameter properites: Credential dictionary data.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiableCredentialBuilder instance.
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
    
    /// Set claims about the subject of the credential.
    /// - Parameter json: Credential dictionary string
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiableCredentialBuilder instance.
    @objc(withPropertiesWithJson:error:)
    public func withProperties(_ json: String) throws -> VerifiableCredentialBuilder {
        try checkNotSealed()
        guard !json.isEmpty else {
            throw DIDError.illegalArgument()
        }
        // TODO: CHECK
        let dic = try (JSONSerialization.jsonObject(with: json.data(using: .utf8)!, options: [JSONSerialization.ReadingOptions.init(rawValue: 0)]) as? [String: Any])
        guard let _ = dic else {
            throw DIDError.malformedCredential("properties data formed error.")
        }
        let jsonNode = JsonNode(dic!)
        let subject = VerifiableCredentialSubject(_target)
        subject.setProperties(jsonNode)
        _credential!.setSubject(subject)
        
        return self
    }
    
    /// Set claims about the subject of the credential.
    /// - Parameter properties: Credential dictionary JsonNode
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiableCredentialBuilder instance.
    @objc(withPropertiesWithJsonNode:errro:)
    public func withProperties(_ properties: JsonNode) throws -> VerifiableCredentialBuilder {
        try checkNotSealed()
        guard properties.count > 0 else {
            throw DIDError.illegalArgument()
        }

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
        
        _credential?.setProof(nil)
    }

    /// Finish modiy VerifiableCredential.
    /// - Parameter storePassword: Pass word to sign.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: A handle to VerifiableCredential.
    @objc
    public func sealed(using storePassword: String) throws -> VerifiableCredential {
        try checkNotSealed()
        try checkArgument(!storePassword.isEmpty, "Invalid storepass")
        guard _credential!.checkIntegrity() else {
            throw DIDError.malformedCredential("imcomplete credential")
        }
        try sanitize()
        
        _credential!.setIssuanceDate(DateFormatter.currentDate())
        if try _credential!.expirationDate() == nil {
            _ = try withDefaultExpirationDate()
        }

        guard let data = _credential!.toJson(true, true).data(using: .utf8) else {
            throw DIDError.illegalArgument("credential is nil")
        }
        let signature = try _forDoc.sign(_signKey, storePassword, [data])
        let proof = VerifiableCredentialProof(Constants.DEFAULT_PUBLICKEY_TYPE, _signKey, signature)

        _credential!.setProof(proof)

        // invalidate builder
        let sealed = self._credential!
        self._credential = nil

        return sealed
    }

    private func maxExpirationDate() -> Date {
        guard _credential?.issuanceDate != nil else {
            return DateFormatter.convertToWantDate(_credential!.issuanceDate!, Constants.MAX_VALID_YEARS)
        }
        return DateFormatter.convertToWantDate(Date(), Constants.MAX_VALID_YEARS)
    }
}
