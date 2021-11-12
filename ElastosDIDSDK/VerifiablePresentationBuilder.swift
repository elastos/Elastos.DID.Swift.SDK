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

/// Presentation Builder object to create presentation.
@objc(VerifiablePresentationBuilder)
public class VerifiablePresentationBuilder: NSObject {
    private let DEFAULT_PRESENTATION_TYPE = "VerifiablePresentation"
    private let _holder: DIDDocument
    private let _signKey: DIDURL
    private var _realm: String?
    private var _nonce: String?
    static let CONTEXT = "@context"

    private var presentation: VerifiablePresentation?
    
    /// Create a Builder object with given holder and sign key.
    /// - Parameters:
    ///   - holder: the holder's DID document
    ///   - signKey: the key to sign the presentation
    init(_ holder: DIDDocument, _ signKey: DIDURL) {
        self._holder = holder
        self._signKey = signKey

        self.presentation = VerifiablePresentation(_holder.subject)
    }
    
    /// Set the id for the presentation.
    /// - Parameter id: the presentation id
    /// - Returns: the Builder instance for method chaining
    public func withId(_ id: DIDURL) throws -> VerifiablePresentationBuilder {
        try checkNotSealed()
        try checkArgument((id.did == nil || id.did == _holder.subject),
                "Invalid id")
        presentation?.setId(try DIDURL(_holder.subject, id))
        
       return self
    }
    
    /// Set the id for the presentation.
    /// - Parameter id: the presentation id
    /// - Returns: the Builder instance for method chaining
    public func withId(_ id: String) throws -> VerifiablePresentationBuilder {
        
        return try withId(DIDURL.valueOf(_holder.subject, id)!)
    }
    
    func setDefaultType() throws {
        try checkNotSealed()
        
        if (Features.isEnabledJsonLdContext()) {
            if !presentation!._context.contains(VerifiableCredential.W3C_CREDENTIAL_CONTEXT) {
                presentation!._context.append(VerifiableCredential.W3C_CREDENTIAL_CONTEXT)
            }

            if !presentation!._context.contains(VerifiableCredential.ELASTOS_CREDENTIAL_CONTEXT) {
                presentation!._context.append(VerifiableCredential.ELASTOS_CREDENTIAL_CONTEXT)
            }
        }
        
        if !presentation!.types.contains(DEFAULT_PRESENTATION_TYPE) {
            presentation!._types.append(DEFAULT_PRESENTATION_TYPE)
        }
    }
    
    /// Add a new presentation type.
    /// - Parameters:
    ///   - type: the type name
    ///   - context: the JSON-LD context for type, or null if not enabled the JSON-LD feature
    /// - Returns: the DIDDocumentBuilder instance for method chaining
    public func withType(_ type: String, _ context: String) throws -> VerifiablePresentationBuilder {
        try checkNotSealed()
        try checkArgument(!type.isEmpty, "Invalid type: \(type)")
        
        if (Features.isEnabledJsonLdContext()) {
            try checkArgument(!context.isEmpty, "Invalid context: \(context)")
            
            if !presentation!._context.contains(context) {
                presentation!._context.append(context)
            }
        }
        
        if !presentation!.types.contains(type) {
            presentation!._types.append(type)
        }
        
        return self
    }
    
    /// Add a new presentation type.
    ///
    /// If enabled the JSON-LD feature, the type should be a full type URI:
    ///   [scheme:]scheme-specific-part#fragment,
    /// [scheme:]scheme-specific-part should be the context URL,
    /// the fragment should be the type name.
    ///
    /// Otherwise, the context URL part and # symbol could be omitted or
    /// ignored.
    /// - type: the type name
    /// - Returns: the VerifiablePresentationBuilder instance for method chaining
    public func withType(_ type: String) throws -> VerifiablePresentationBuilder {
        try checkNotSealed()
        try checkArgument(!type.isEmpty, "Invalid type: \(type)")

        if (type.index(of: "#") == nil) {
            return try withType(type, "")
        }
        else {
            let context_type = type.split(separator: "#")
            return try withType(String(context_type[1]), String(context_type[0]))
        }
    }
    
    /// Add a new presentation type.
    ///
    /// If enabled the JSON-LD feature, the type should be a full type URI:
    ///   [scheme:]scheme-specific-part#fragment,
    /// [scheme:]scheme-specific-part should be the context URL,
    /// the fragment should be the type name.
    ///
    /// Otherwise, the context URL part and # symbol could be omitted or
    /// ignored.
    /// - type: the type names
    /// - Returns: the VerifiablePresentationBuilder instance for method chaining
    public func withTypes(_ types: Array<String>) throws -> VerifiablePresentationBuilder {

        return try withTypes(types)
     }
    
    /// Add a new presentation type.
    ///
    /// If enabled the JSON-LD feature, the type should be a full type URI:
    ///   [scheme:]scheme-specific-part#fragment,
    /// [scheme:]scheme-specific-part should be the context URL,
    /// the fragment should be the type name.
    ///
    /// Otherwise, the context URL part and # symbol could be omitted or
    /// ignored.
    /// - type: the type names
    /// - Returns: the VerifiablePresentationBuilder instance for method chaining
    public func withTypes(_ types: String...) throws -> VerifiablePresentationBuilder {
        
        if types.count == 0 {
            return self
        }
        try checkNotSealed()
        
        try types.forEach{ item in
            try _ = withType(item)
        }
        
        return self
    }

    /// Set verifiable credentials for presentation.
    /// - Parameter credentials: Verifiable credentials
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiablePresentationBuilder instance.
    public func withCredentials(_ credentials: VerifiableCredential...) throws
        -> VerifiablePresentationBuilder {

        return try withCredentials(credentials)
    }

    /// Set verifiable credentials for presentation.
    /// - Parameter credentials: Verifiable credentials
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiablePresentationBuilder instance.
    @objc
    public func withCredentials(_ credentials: Array<VerifiableCredential>) throws
        -> VerifiablePresentationBuilder {
        try checkNotSealed()
        
        for credential in credentials {
            // Presentation should be signed by the subject of Credentials
            guard credential.subject!.did == self._holder.subject else {
                throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalUsageError(
                    "Credential \(String(describing: credential.getId())) not match with requested id")
            }
            guard credential.checkIntegrity() else {
                throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectAlreadyExistError("incomplete credential \(credential.toString())")
            }
            presentation!._credentialsArray.append(credential)
            presentation!.appendCredential(credential)
        }
        return self
    }

    private func checkNotSealed() throws {
        guard let _ = presentation else {
            throw DIDError.UncheckedError.IllegalStateError.AlreadySealedError()
        }
    }
    
    /// Set realm for the new presentation.
    /// - Parameter realm: the realm string
    /// - Throws: if an error occurred, throw error.
    /// - Returns: the Builder instance for method chaining
    @objc
    public func withRealm(_ realm: String) throws -> VerifiablePresentationBuilder {
        try checkNotSealed()
        try checkArgument(!realm.isEmpty, "Invalid realm")

        self._realm = realm
        return self
    }

    /// Set nonce for the new presentation.
    /// - Parameter nonce:  the nonce string
    /// - Throws: if an error occurred, throw error.
    /// - Returns: the Builder instance for method chaining
    @objc
    public func withNonce(_ nonce: String) throws -> VerifiablePresentationBuilder {
        try checkNotSealed()
        try checkArgument(!nonce.isEmpty, "Invalid nonce")

        self._nonce = nonce
        return self
    }

    /// Seal the presentation object, attach the generated proof to the
    /// presentation.
    /// - Parameter storePassword: the password for DIDStore
    /// - Throws: if an error occurred, throw error.
    /// - Returns: the new presentation object
    @objc
    public func seal(using storePassword: String) throws -> VerifiablePresentation {
        try checkNotSealed()
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        try checkArgument(_realm != nil && _nonce != nil, "Missing realm and nonce")

        if presentation!.types.count == 0 {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedPresentationError("Missing presentation type")
        }
        _ = presentation!._types.sorted()

        presentation!.setCreatedDate(DateFormatter.currentDate())
        var data: [Data] = []
        data.append(presentation!.toJson(true))
        if let realm = _realm {
            data.append(realm.data(using: .utf8)!)
        }
        if let nonce = _nonce {
            data.append(nonce.data(using: .utf8)!)
        }
        let signature = try _holder.sign(_signKey, storePassword, data)

        let proof = VerifiablePresentationProof(_signKey, _realm!, _nonce!, signature)
        presentation!.setProof(proof)

        // invalidate builder.
        let sealed = self.presentation!
        self.presentation = nil

        return sealed
    }
}
