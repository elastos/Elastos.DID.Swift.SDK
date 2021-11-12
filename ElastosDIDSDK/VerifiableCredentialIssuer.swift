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

@objc(VerifiableCredentialIssuer)
public class VerifiableCredentialIssuer: NSObject {
    private var _issuerDoc: DIDDocument
    private var _signKey: DIDURL

    private init(doc: DIDDocument, signKey: DIDURL?) throws {
        // use the default public key if no signKey provided.
        var key = signKey
        if  key == nil {
            key = doc.defaultPublicKeyId()
        }

        // The key would be used to sign verifiable crendetial when using
        // builder to create a new verifiable credential. So,
        // should make sure the key would be authenticationKey and
        // has corresponding private key to make sign.
        guard try doc.containsAuthenticationKey(forId: key!) else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError()
        }
        guard try doc.containsPrivateKey(forId: key!) else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError(Errors.NO_PRIVATE_KEY_EXIST)
        }

        self._issuerDoc = doc
        self._signKey = key!
    }
/*
     private void init(DIDDocument doc, DIDURL signKey) throws DIDStoreException {
         this.self = doc;

         if (signKey == null) {
             signKey = self.getDefaultPublicKeyId();
             if (signKey == null)
                 throw new InvalidKeyException("Need explict sign key or effective controller");
         } else {
             if (!self.isAuthenticationKey(signKey))
                 throw new InvalidKeyException(signKey.toString());
         }

         if (!doc.hasPrivateKey(signKey))
             throw new InvalidKeyException("No private key: " + signKey);

         this.signKey = signKey;
     }
     */
    private convenience init(_ did: DID, signKey: DIDURL? , _ store: DIDStore) throws {
        let doc: DIDDocument?
        do {
            doc = try store.loadDid(did)
            if doc == nil {
                throw DIDError.CheckedError.DIDStoreError.DIDStorageError("Can not load DID.")
            }
        } catch {
            throw DIDError.CheckedError.DIDBackendError.DIDResolveError("Can not resolve did")
        }
        try self.init(doc: doc!, signKey: signKey)
    }

    /// Create a issuer to issue Credential.
    /// - Parameters:
    ///   - doc: Specified DID document
    ///   - signKey:  Issuer’s key to sign credential.
    /// - Throws: if an error occurred, throw error.
    @objc
    public convenience init(_ doc: DIDDocument, _ signKey: DIDURL) throws {
        try self.init(doc: doc, signKey: signKey)
    }

    /// Create a issuer to issue Credential.
    /// - Parameter doc: Specified DID document
    /// - Throws: if an error occurred, throw error.
    @objc
    public convenience init(_ doc: DIDDocument) throws {
        try self.init(doc: doc, signKey: nil)
    }

    /// Create a issuer to issue Credential.
    /// - Parameters:
    ///   - did: Issuer’s did.
    ///   - signKey: Issuer’s key to sign credential.
    ///   - store: The handle to DIDStore.
    /// - Throws: if an error occurred, throw error.
    @objc
    public convenience init(_ did: DID, _ signKey: DIDURL, _ store: DIDStore) throws {
        try self.init(did, signKey: signKey, store)
    }

    /// Create a issuer to issue Credential.
    /// - Parameters:
    ///   - did: Issuer’s did.
    ///   - store: Issuer’s key to sign credential.
    /// - Throws: if an error occurred, throw error.
    @objc(init:store:error:)
    public convenience init(_ did: DID, _ store: DIDStore) throws {
        try self.init(did, signKey: nil, store)
    }

    /// Issuer’s did.
    @objc
    public var did: DID {
        return _issuerDoc.subject
    }

    /// Get the DID of this issuer.
    @objc
    public var signKey: DIDURL {
        return _signKey
    }

    /// Get VerifiableCredential Builder to modify VerifiableCredential.
    /// - Parameter did: Issuer’s did.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiableCredentialBuilder instance.
    @objc
    public func editingVerifiableCredentialFor(did: String) throws -> VerifiableCredentialBuilder {
        return try VerifiableCredentialBuilder(self, try DID(did), _issuerDoc, signKey)
    }

    /// Get VerifiableCredential Builder to modify VerifiableCredential.
    /// - Parameter did: Issuer’s did.
    /// - Returns: VerifiableCredentialBuilder instance.
    @objc(editingVerifiableCredentialForDidWith:error:)
    public func editingVerifiableCredentialFor(did: DID) throws -> VerifiableCredentialBuilder {
        return try VerifiableCredentialBuilder(self, did, _issuerDoc, signKey)
    }
}
