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

@objc(VerifiablePresentationBuilder)
public class VerifiablePresentationBuilder: NSObject {
    private let _holder: DIDDocument
    private let _signKey: DIDURL
    private var _realm: String?
    private var _nonce: String?

    private var presentation: VerifiablePresentation?

    init(_ holder: DIDDocument, _ signKey: DIDURL) {
        self._holder = holder
        self._signKey = signKey

        self.presentation = VerifiablePresentation(_holder.subject)
    }

    public func withId(_ id: DIDURL) throws -> VerifiablePresentationBuilder {
        try checkNotSealed()
        try checkArgument((id.did == nil || id.did == _holder.subject),
                "Invalid id")
        presentation?.setId(try DIDURL(_holder.subject, id))
        
       return self
    }
    
    public func withId(_ id: String) throws -> VerifiablePresentationBuilder {
        
        return try withId(DIDURL.valueOf(_holder.subject, id)!)
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
                throw DIDError.illegalArgument(
                    "Credential \(credential.getId()) not match with requested id")
            }
            guard credential.checkIntegrity() else {
                throw DIDError.illegalArgument("incomplete credential \(credential.toString())")
            }

            presentation!.appendCredential(credential)
        }
        return self
    }

    private func checkNotSealed() throws {
        guard let _ = presentation else {
            throw DIDError.UncheckedError.IllegalStateError.AlreadySealedError()
        }
    }
    
    /// Set realm for presentation.
    /// - Parameter realm: Target areas to which the expression applies, such as website domain names, application names, etc.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiablePresentationBuilder instance.
    @objc
    public func withRealm(_ realm: String) throws -> VerifiablePresentationBuilder {
        guard let _ = presentation else {
            throw DIDError.invalidState(Errors.PRESENTATION_ALREADY_SEALED)
        }
        guard !realm.isEmpty else {
            throw DIDError.illegalArgument()
        }

        self._realm = realm
        return self
    }

    /// Set nonce for presentation.
    /// - Parameter nonce: Random value used for signature operation
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiablePresentationBuilder instance.
    @objc
    public func withNonce(_ nonce: String) throws -> VerifiablePresentationBuilder {
        guard let _ = presentation else {
            throw DIDError.invalidState(Errors.PRESENTATION_ALREADY_SEALED)
        }
        guard !nonce.isEmpty else {
            throw DIDError.illegalArgument()
        }

        self._nonce = nonce
        return self
    }

    /// Finish modiy VerifiablePresentation.
    /// - Parameter storePasswordword: Pass word to sign.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: A handle to VerifiablePresentation.
    @objc
    public func sealed(using storePasswordword: String) throws -> VerifiablePresentation {
        guard let _ = presentation else {
            throw DIDError.invalidState(Errors.PRESENTATION_ALREADY_SEALED)
        }
        guard !storePasswordword.isEmpty else {
            throw DIDError.illegalArgument()
        }
        guard _realm != nil && _nonce != nil else {
            throw DIDError.invalidState("Missing realm and nonce")
        }

        var data: [Data] = []
        data.append(presentation!.toJson(true))
        if let realm = _realm {
            data.append(realm.data(using: .utf8)!)
        }
        if let nonce = _nonce {
            data.append(nonce.data(using: .utf8)!)
        }
        let signature = try _holder.sign(_signKey, storePasswordword, data)

        let proof = VerifiablePresentationProof(_signKey, _realm!, _nonce!, signature)
        presentation!.setProof(proof)

        // invalidate builder.
        let sealed = self.presentation!
        self.presentation = nil

        return sealed
    }
}
