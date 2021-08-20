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

/// A DIDDocument Builder to modify DIDDocument elems.
@objc(DIDDocumentBuilder)
public class DIDDocumentBuilder: NSObject {
    private var document: DIDDocument?
    private var controllerDoc: DIDDocument?
    
    /// Constructs DID Document Builder with given DID and DIDStore.
    /// - Parameters:
    ///   - did: the specified DID
    ///   - store: the DIDStore object
    init(_ did: DID, _ store: DIDStore) {
        self.document = DIDDocument(did)
        let metadata = DIDMetadata(did, store)
        self.document!.setMetadata(metadata)
    }
    
    /// Constructs DID Document Builder with given customizedDid and DIDStore.
    /// - Parameters:
    ///   - did: the specified DID
    ///   - store: the DIDStore object
    init(_ did: DID, _ controller: DIDDocument, _ store: DIDStore) {
        self.document = DIDDocument(did)
        self.document!._controllers = []
        self.document!._controllerDocs = [: ]
        self.document!._controllers.append(controller.subject)
        self.document!._controllerDocs[controller.subject] = controller
        self.document!._effectiveController = controller.subject
        self.document!.setMetadata(DIDMetadata(did, store))
        
        self.controllerDoc = controller
    }
    
    init(_ doc: DIDDocument) throws { // Make a copy
        self.document = try doc.copy()
    }

    init(_ doc: DIDDocument, _ controller: DIDDocument) throws { // Make a copy
        self.document = try doc.copy()
        self.document?._effectiveController = controller.subject
        self.controllerDoc = controller
    }
    
    private func canonicalId(_ id: String) throws -> DIDURL? {
        return try DIDURL.valueOf(getSubject(), id)
    }
    
    private func canonicalId(_ id: DIDURL) throws -> DIDURL? {
        if id.did != nil {
            return id
        }
        return try DIDURL(getSubject(), id)
    }

    public func getSubject() throws -> DID {
        try checkNotSealed()
        return document!.subject
    }

    private func appendPublicKey(_ key: PublicKey) throws {
        try document?._publicKeyDic.values.forEach{ pk in
            if pk.getId() == key.getId() {
                throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectAlreadyExistError("PublicKey id '\(String(describing: key.getId()?.toString()))' already exist.")
            }
            if pk.publicKeyBase58 == key.publicKeyBase58 {
                throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectAlreadyExistError("PublicKey '\(key.publicKeyBase58)' already exist.")
            }
        }
        document?._publicKeyDic[key.getId()!] = key
        
        if document?.defaultPublicKey() == nil {
            let address = DIDHDKey.toAddress(key.publicKeyBytes)
            if try (address == getSubject().methodSpecificId) {
                document?._defaultPublicKey = key
                document?._authenticationKeys[key.getId()!] = key
            }
        }
        invalidateProof()
    }
    
    /// Add PublicKey to did document builder.
    /// - Parameters:
    ///   - id: the key id
    ///   - type: the key type
    ///   - controller: the owner of public key
    ///   - pk: the base58 encoded public key
    /// - Returns: the Builder instance for method chaining
    private func appendPublicKey(id: DIDURL, type: String?, controller: DID?, pk: String) throws -> DIDDocumentBuilder {
        try checkNotSealed()
        try checkArgument(id.did == nil || id.did == getSubject(), "Invalid publicKey id")
        try checkArgument(!pk.isEmpty, "Invalid publicKey")
        let ctr = try controller != nil ? controller : getSubject()

        if type == nil {
            try appendPublicKey(PublicKey(canonicalId(id)!, ctr!, pk))
            
            return self
        }
        try appendPublicKey(PublicKey(canonicalId(id)!, type!, ctr!, pk))
        
        return self
    }
    
    /// Add PublicKey to did document builder.
    /// - Parameters:
    ///   - id: the key id
    ///   - type: the key type
    ///   - controller: the owner of public key
    ///   - keyBase58: the base58 encoded public key
    /// - Returns: the Builder instance for method chaining
    public func appendPublicKey(with id: DIDURL,
                             type: String,
                             controller: DID,
                             keyBase58: String) throws -> DIDDocumentBuilder {
        return try appendPublicKey(id: id, type: type, controller: controller, pk: keyBase58)
    }
    
    /// Add PublicKey to did document builder.
    /// - Parameters:
    ///   - id: the key id
    ///   - type: the key type
    ///   - controller: the owner of public key
    ///   - keyBase58: the base58 encoded public key
    /// - Returns: the Builder instance for method chaining
    public func appendPublicKey(with id: String,
                             type: String,
                             controller: String,
                             keyBase58: String) throws -> DIDDocumentBuilder {
        return try appendPublicKey(id: canonicalId(id)!, type: type, controller: DID.valueOf(controller), pk: keyBase58)
    }
    
    /// Add PublicKey to did document builder.
    /// - Parameters:
    ///   - id: the key id
    ///   - controller: the owner of public key
    ///   - keyBase58: the base58 encoded public key
    /// - Returns: the Builder instance for method chaining
    public func appendPublicKey(_ id: DIDURL,
                                _ controller: DID,
                                _ keyBase58: String) throws -> DIDDocumentBuilder {
        return try appendPublicKey(id: id, type: nil, controller: controller, pk: keyBase58)
    }
    
    /// Add PublicKey to did document builder.
    /// - Parameters:
    ///   - id: the key id
    ///   - controller: the owner of public key
    ///   - keyBase58: the base58 encoded public key
    /// - Returns: the Builder instance for method chaining
    public func appendPublicKey(with id: DIDURL,
                                controller: String,
                                keyBase58: String) throws -> DIDDocumentBuilder {
        return try appendPublicKey(id: id, type: nil, controller: DID.valueOf(controller), pk: keyBase58)
    }
    
    /// Add PublicKey to did document builder.
    /// - Parameters:
    ///   - id: the key id
    ///   - controller: the owner of public key
    ///   - keyBase58: the base58 encoded public key
    /// - Returns: the Builder instance for method chaining
    public func appendPublicKey(with id: String,
                                controller: String,
                                keyBase58: String) throws -> DIDDocumentBuilder {
        return try appendPublicKey(id: canonicalId(id)!, type: nil, controller: DID.valueOf(controller), pk: keyBase58)
    }
    
    /// Add PublicKey to did document builder.
    /// - Parameters:
    ///   - id: the key id
    ///   - type: the key type
    ///   - keyBase58: the base58 encoded public key
    /// - Returns: the Builder instance for method chaining
    public func appendPublicKey(with id: DIDURL,
                                type: String,
                                keyBase58: String) throws -> DIDDocumentBuilder {
        return try appendPublicKey(id: id, type: type, controller: nil, pk: keyBase58)
    }
    
    /// Add PublicKey to did document builder.
    /// - Parameters:
    ///   - id: the key id
    ///   - type: the key type
    ///   - keyBase58: the base58 encoded public key
    /// - Returns: the Builder instance for method chaining
    public func appendPublicKey(with id: DIDURL,
                                keyBase58: String) throws -> DIDDocumentBuilder {
        return try appendPublicKey(id: id, type: nil, controller: nil, pk: keyBase58)
    }
    
    /// Add PublicKey to did document builder.
    /// - Parameters:
    ///   - id: the key id
    ///   - type: the key type
    ///   - keyBase58: the base58 encoded public key
    /// - Returns: the Builder instance for method chaining
    public func appendPublicKey(with id: String,
                                 keyBase58: String) throws -> DIDDocumentBuilder {
        return try appendPublicKey(id: canonicalId(id)!, type: nil, controller: nil, pk: keyBase58)
    }
    
    private func removePublicKey(_ id: DIDURL,
                                 _ force: Bool) throws -> DIDDocumentBuilder {
        try checkNotSealed()
        let key = document!._publicKeyDic[id]

        guard let _ = key else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError(id.toString())
        }
        guard document!.publicKeyCount != 0 else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError(id.toString())
        }
        
        if document!.defaultPublicKey() != nil && document!.defaultPublicKey()?.getId() == id {
            throw DIDError.UncheckedError.UnsupportedOperationError.DIDObjectHasReferenceError(id.toString() + "is default key")
        }
        if !force {
            let keyValue1 = document?._authenticationKeys[key!.getId()!]
            let keyValue2 = document?._authorizationKeys[key!.getId()!]

            if keyValue1 != nil || keyValue2 != nil {
                throw DIDError.UncheckedError.UnsupportedOperationError.DIDObjectHasReferenceError(id.toString())
            }
        }
        
        if (document!._publicKeyDic.removeValue(forKey: id) != nil) {
            document!._authenticationKeys.removeValue(forKey: id)
            document!._authorizationKeys.removeValue(forKey: id)
            // TODO: should delete the loosed private key when store the document
            if (document!.getMetadata().attachedStore) {
                _ = document!.getMetadata().store?.deletePrivateKey(for: id)
            }
            invalidateProof()
        }

        return self
    }

    /// Remove specified public key from DID Document.
    /// - Parameters:
    ///   - id: An identifier of public key.
    ///   - force: True, must to remove key; false,
    ///    if key is authentication or authorization key, not to remove.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func removePublicKey(with id: DIDURL,
                               _ force: Bool) throws -> DIDDocumentBuilder {
        return try removePublicKey(id, force)
    }

    /// Remove specified public key from DID Document.
    /// - Parameters:
    ///   - id: An identifier of public key.
    ///   - force: True, must to remove key; false,
    ///    if key is authentication or authorization key, not to remove.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(removePublicKey:force:error:)
    public func removePublicKey(with id: String,
                               _ force: Bool) throws -> DIDDocumentBuilder {
        return try removePublicKey(DIDURL(getSubject(), id), force)
    }

    /// Remove specified public key from DID Document.
    /// - Parameter id: An identifier of public key.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func removePublicKey(with id: DIDURL) throws -> DIDDocumentBuilder {
        return try removePublicKey(id, false)
    }

    /// Remove specified public key from DID Document.
    /// - Parameter id: An identifier of public key.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(removePublicKey:error:)
    public func removePublicKey(with id: String) throws -> DIDDocumentBuilder {
        return try removePublicKey(DIDURL(getSubject(), id), false)
    }

    // authenticationKey scope
    private func appendAuthenticationKey(_ id: DIDURL) throws -> DIDDocumentBuilder {
        try checkNotSealed()

        let key = try document!.publicKey(ofId: id)
        guard let _ = key else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError(id.toString())
        }
        // Check the controller is current DID subject
        guard try key!.controller == getSubject() else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalUsageError(id.toString())
        }
        let keyVaule = document!._authenticationKeys[id]
        if keyVaule == nil {
            document!._authenticationKeys[key!.getId()!] = key
            invalidateProof()
        }
        
        return self
    }

    /// Add public key to Authenticate.
    /// Authentication is the mechanism by which the controller(s) of a DID can
    /// cryptographically prove that they are associated with that DID.
    /// A DID Document must include an authentication property.
    /// - Parameter id: An identifier of public key.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func appendAuthenticationKey(with id: DIDURL) throws -> DIDDocumentBuilder {
        return try appendAuthenticationKey(id)
    }

    /// Add public key to Authenticate.
    /// Authentication is the mechanism by which the controller(s) of a DID can
    /// cryptographically prove that they are associated with that DID.
    /// A DID Document must include an authentication property.
    /// - Parameter id: An identifier of public key.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(appendAuthenticationKey:error:)
    public func appendAuthenticationKey(with id: String) throws -> DIDDocumentBuilder {
        return try appendAuthenticationKey(DIDURL(getSubject(), id))
    }

    private func appendAuthenticationKey(_ id: DIDURL,
                                         _ keyBase58: String) throws -> DIDDocumentBuilder {
        try checkNotSealed()
        try checkArgument(id.did == nil || id.did == getSubject(), "Invalid publicKey id")
        try checkArgument(!keyBase58.isEmpty, "Invalid publicKey")

        let key = try PublicKey(canonicalId(id)!, getSubject(), keyBase58)
        try appendPublicKey(key)
        document!._authenticationKeys[key.getId()!] = key

        return self
    }

    /// Add public key to Authenticate.
    /// Authentication is the mechanism by which the controller(s) of a DID can
    /// cryptographically prove that they are associated with that DID.
    /// A DID Document must include an authentication property.
    /// - Parameters:
    ///   - id: An identifier of public key.
    ///   - keyBase58: Key propertie depend on key type.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func appendAuthenticationKey(with id: DIDURL,
                                      keyBase58: String) throws -> DIDDocumentBuilder {
        return try appendAuthenticationKey(id, keyBase58)
    }

    /// Add public key to Authenticate.
    /// Authentication is the mechanism by which the controller(s) of a DID can
    /// cryptographically prove that they are associated with that DID.
    /// A DID Document must include an authentication property.
    /// - Parameters:
    ///   - id: An identifier of public key.
    ///   - keyBase58: Key propertie depend on key type.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(appendAuthenticationKey:keyBase58:error:)
    public func appendAuthenticationKey(with id: String,
                                      keyBase58: String) throws -> DIDDocumentBuilder {
        return try appendAuthenticationKey(canonicalId(id)!, keyBase58)
    }

    private func removeAuthenticationKey(_ id: DIDURL) throws -> DIDDocumentBuilder {
        try checkNotSealed()
        if document!._publicKeyDic.isEmpty {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError(id.toString())
        }

        let key = document!._publicKeyDic[try canonicalId(id)!]
        let value = try document!._authenticationKeys[canonicalId(id)!]
        guard let _ = key, let _ = value else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError(id.toString())
        }
        
        // Can not remove default public key
        if (document!._defaultPublicKey != nil && document!._defaultPublicKey!.getId() == id ) {
            throw DIDError.UncheckedError.UnsupportedOperationError.DIDObjectHasReferenceError(
                "Cannot remove the default PublicKey from authentication.")
        }

        if (document!._authenticationKeys.removeValue(forKey: id) != nil) {
            invalidateProof()
        }
        else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError(id.toString())
        }

        return self
    }

    /// Remove authentication key from Authenticate.
    /// - Parameter id: An identifier of public key.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func removeAuthenticationKey(with id: DIDURL) throws -> DIDDocumentBuilder {
        return try removeAuthenticationKey(id)
    }

    /// Remove authentication key from Authenticate.
    /// - Parameter id: An identifier of public key.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(removeAuthenticationKeyWithId:error:)
    public func removeAuthenticationKey(with id: String) throws -> DIDDocumentBuilder {
        return try removeAuthenticationKey(DIDURL(getSubject(), id))
    }

    private func appendAuthorizationKey(_ id: DIDURL) throws -> DIDDocumentBuilder {
        try checkNotSealed()
        guard !document!.isCustomizedDid() else {
            throw DIDError.UncheckedError.IllegalStateError.NotPrimitiveDIDError(id.toString())
        }
        
        guard !document!._publicKeyDic.isEmpty else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError(id.toString())
        }
        
        let key = document!._publicKeyDic[id]
        guard let _ = key else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError(id.toString())
        }
        // Can not authorize to self
        guard try key!.controller != getSubject() else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalUsageError(id.toString())
        }

        let value = try document!._authorizationKeys[canonicalId(id)!]
        if value == nil {
            document!._authorizationKeys[key!.getId()!] = key
            invalidateProof()
        }

        return self
    }

    /// Add public key to authorizate.
    /// Authorization is the mechanism used to state how operations may be performed on behalf of the DID subject.
    /// - Parameter id: An identifier of authorization key.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func appendAuthorizationKey(with id: DIDURL) throws -> DIDDocumentBuilder {
        return try appendAuthorizationKey(id)
    }

    /// Add public key to authorizate.
    /// Authorization is the mechanism used to state how operations may be performed on behalf of the DID subject.
    /// - Parameter id: An identifier of authorization key.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(appendAuthorizationKeyWithId:error:)
    public func appendAuthorizationKey(with id: String) throws -> DIDDocumentBuilder  {
        return try appendAuthorizationKey(DIDURL(getSubject(), id))
    }

    /// Add public key to authorizate.
    /// Authorization is the mechanism used to state how operations may be performed on behalf of the DID subject.
    /// - Parameters:
    ///   - id: An identifier of authorization key.
    ///   - controller: A controller property, identifies the controller of the corresponding private key.
    ///   - keyBase58: Key property depend on key type.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func appendAuthorizationKey(_ id: DIDURL,
                                       _ controller: DID,
                                       _ keyBase58: String) throws -> DIDDocumentBuilder {
        try checkNotSealed()
        try checkArgument(id.did == nil || id.did == getSubject(), "Invalid publicKey id")
        try checkArgument(!keyBase58.isEmpty, "Invalid publicKey")
        try checkArgument(Base58.bytesFromBase58(keyBase58).count == DIDHDKey.DID_PUBLICKEY_BYTES, "Invalied keyBase58")

        if document!.isCustomizedDid() {
            throw DIDError.UncheckedError.IllegalStateError.NotPrimitiveDIDError(try getSubject().toString())
        }
        // Can not authorize to self
        if try controller == getSubject() {
            throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalUsageError("Key's controller is self.")
        }
        let key = try PublicKey(canonicalId(id)!, controller, keyBase58)
        try appendPublicKey(key)
        document!._authorizationKeys[key.getId()!] = key
        
        return self
    }

    /// Add public key to authorizate.
    /// Authorization is the mechanism used to state how operations may be performed on behalf of the DID subject.
    /// - Parameters:
    ///   - id: An identifier of authorization key.
    ///   - controller: A controller property, identifies the controller of the corresponding private key.
    ///   - keyBase58: Key property depend on key type.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func appendAuthorizationKey(with id: DIDURL,
                                    controller: DID,
                                     keyBase58: String) throws -> DIDDocumentBuilder {

        return try appendAuthorizationKey(id, controller, keyBase58)
    }

    /// Add public key to authorizate.
    /// Authorization is the mechanism used to state how operations may be performed on behalf of the DID subject.
    /// - Parameters:
    ///   - id: An identifier of authorization key.
    ///   - controller: A controller property, identifies the controller of the corresponding private key.
    ///   - keyBase58: Key property depend on key type.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(appendAuthorizationKey:controller:keyBase58:error:)
    public func appendAuthorizationKey(with id: String,
                                    controller: String,
                                     keyBase58: String) throws -> DIDDocumentBuilder {

        return try appendAuthorizationKey(DIDURL(getSubject(), id), DID(controller), keyBase58)
    }

    /// Add public key to authorizate.
    /// Authorization is the mechanism used to state how operations may be performed on behalf of the DID subject.
    /// - Parameters:
    ///   - id: An identifier of authorization key.
    ///   - controller: A controller property, identifies the controller of the corresponding private key.
    ///   - keyBase58: Key property depend on key type.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(appendAuthorizationKeyWithId:controller:keyBase58:error:)
    public func appendAuthorizationKey(with id: String,
                                    controller: DID,
                                     keyBase58: String) throws -> DIDDocumentBuilder {

        return try appendAuthorizationKey(DIDURL(getSubject(), id), controller, keyBase58)
    }
                 
    private func authorizeDID(_ id: DIDURL,
                                  _ controller: DID,
                                  _ key: DIDURL?) throws -> DIDDocumentBuilder {
        try checkNotSealed()
        try checkArgument(controller != getSubject(), "Invalid controller")
        try checkArgument(id.did == getSubject(), "Invalid publicKey id")
        
        if document!.isCustomizedDid() {
            throw DIDError.UncheckedError.IllegalStateError.NotPrimitiveDIDError(try getSubject().toString())
        }
        let controllerDoc: DIDDocument? = try controller.resolve()
        if (controllerDoc == nil) {
            throw DIDError.UncheckedError.IllegalStateError.DIDNotFoundError(id.toString())
        }
        guard !controllerDoc!.isDeactivated else {
            throw DIDError.UncheckedError.IllegalStateError.DIDDeactivatedError(controller.toString())
        }
        guard !controllerDoc!.isExpired else {
            throw DIDError.UncheckedError.IllegalStateError.DIDExpiredError(controller.toString())
        }
        
        guard try controllerDoc!.isGenuine() else {
            throw DIDError.UncheckedError.IllegalStateError.DIDNotGenuineError(controller.toString())
        }
        guard !controllerDoc!.isCustomizedDid() else {
            throw DIDError.UncheckedError.IllegalStateError.NotPrimitiveDIDError(controller.toString())
        }
        
        let _key = key != nil ? key : controllerDoc!.defaultPublicKeyId()
        
        // Check the key should be a authentication key.
        let targetPk = try controllerDoc!.authenticationKey(ofId: _key!)
        if (targetPk == nil) {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError(_key!.toString())
        }
        
        let pk = PublicKey(try canonicalId(id)!, targetPk!.getType()!, controller, targetPk!.publicKeyBase58)
        try appendPublicKey(pk)
        document!._authorizationKeys[pk.getId()!] = pk

        return self
    }

    /// Add Authorization key to Authentication array according to DID.
    /// Authentication is the mechanism by which the controller(s) of a DID can cryptographically prove that they are associated with that DID.
    /// A DID Document must include an authentication property.
    /// - Parameters:
    ///   - id: An identifier of public key.
    ///   - controller: A controller property, identifies the controller of the corresponding private key.
    ///   - key: An identifier of authorization key.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func authorizeDID(with id: DIDURL,
                              controller: DID,
                                     key: DIDURL) throws -> DIDDocumentBuilder {

        return try authorizeDID(id, controller, key)
    }

    /// Add Authorization key to Authentication array according to DID.
    /// Authentication is the mechanism by which the controller(s) of a DID can cryptographically prove that they are associated with that DID.
    /// A DID Document must include an authentication property.
    /// - Parameters:
    ///   - id: An identifier of public key.
    ///   - controller: A controller property, identifies the controller of the corresponding private key.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func authorizeDID(with id: DIDURL,
                              controller: DID) throws -> DIDDocumentBuilder {

        return try authorizeDID(id, controller, nil)
    }

    /// Add Authorization key to Authentication array according to DID.
    /// Authentication is the mechanism by which the controller(s) of a DID can cryptographically prove that they are associated with that DID.
    /// A DID Document must include an authentication property.
    /// - Parameters:
    ///   - id: An identifier of public key.
    ///   - controller: A controller property, identifies the controller of the corresponding private key.
    ///   - key: An identifier of authorization key.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(authorizeDID:controller:key:error:)
    public func authorizeDID(with id: String,
                              controller: String,
                                     key: String) throws -> DIDDocumentBuilder {
        let controllerId = try DID(controller)
        let usedKey:DIDURL = try DIDURL(controllerId, key)

        return try authorizeDID(DIDURL(getSubject(), id), controllerId, usedKey)
    }

    /// Add Authorization key to Authentication array according to DID.
    /// Authentication is the mechanism by which the controller(s) of a DID can cryptographically prove that they are associated with that DID.
    /// A DID Document must include an authentication property.
    /// - Parameters:
    ///   - id: An identifier of public key.
    ///   - controller: A controller property, identifies the controller of the corresponding private key.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(authorizeDID:controller:error:)
    public func authorizeDID(with id: String,
                              controller: String) throws -> DIDDocumentBuilder {

        return try authorizeDID(DIDURL(getSubject(), id), DID(controller), nil)
    }

    private func removeAuthorizationKey(_ id: DIDURL) throws -> DIDDocumentBuilder {
        try checkNotSealed()
        
        if document?._publicKeyDic == nil || document!._publicKeyDic.isEmpty {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError(id.toString())
        }
        
        let _id = try canonicalId(id)!
        let key = document?._publicKeyDic[_id]
        if key == nil {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError(_id.toString())
        }
        
        if document!._authorizationKeys.removeValue(forKey: _id) != nil {
            invalidateProof()
        }
        else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError(_id.toString())
        }
        
        return self
    }

    /// Remove authorization key from Authenticate.
    /// - Parameter id: An identifier of public key.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func removeAuthorizationKey(with id: DIDURL) throws -> DIDDocumentBuilder {
        return try removeAuthorizationKey(id)
    }

    /// Remove authorization key from Authenticate.
    /// - Parameter id: An identifier of public key.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(removeAuthorizationKey:error:)
    public func removeAuthorizationKey(with id: String) throws -> DIDDocumentBuilder {
        return try removeAuthorizationKey(DIDURL(getSubject(), id))
    }

    /// Add one credential to credential array.
    /// - Parameter credential: The handle to Credential.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func appendCredential(with credential: VerifiableCredential) throws -> DIDDocumentBuilder {
        try checkNotSealed()
        
        //         Check the credential belongs to current DID.
        // Check the credential belongs to current DID.
        guard try credential.subject?.did == getSubject() else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalUsageError(credential.subject?.did.toString())
        }
        guard document!._credentialDic[credential.getId()!] == nil else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectAlreadyExistError(credential.subject?.did.toString())
        }
        document!._credentialDic[credential.getId()!] = credential
        document!._credentials.append(credential)
        invalidateProof()

        return self
    }

    private func appendCredential(_ id: DIDURL,
                                  _ types: Array<String>?,
                                  _ subject: Dictionary<String, String>,
                                  _ expirationDate: Date?,
                                  _ storePassword: String) throws -> DIDDocumentBuilder  {
        try checkNotSealed()
        try checkArgument(!subject.isEmpty, "Invalid subject")
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")

        let realTypes: Array<String>
        if let _ = types {
            realTypes = types!
        } else {
            realTypes = Array<String>(["SelfProclaimedCredential"])
        }

        let realExpires: Date
        if let _ = expirationDate {
            realExpires = expirationDate!
        } else {
            realExpires = document!.expirationDate!
        }

        let issuer  = try VerifiableCredentialIssuer(document!)
        let builder = issuer.editingVerifiableCredentialFor(did: document!.subject)
        
        let credential = try builder.withId(id)
            .withTypes(realTypes)
            .withProperties(subject)
            .withExpirationDate(realExpires)
            .seal(using: storePassword)
        _ = try appendCredential(with: credential)
        
        return self
    }

    /// Add one credential to credential array.
    /// - Parameters:
    ///   - id: The handle to DIDURL.
    ///   - types: The array of credential types.
    ///   - subject: The array of credential subject property.
    ///   - expirationDate: The time to credential be expired.
    ///   - storePassword: Password for DIDStores.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func appendCredential(with id: DIDURL,
                                   types: Array<String>,
                                 subject: Dictionary<String, String>,
                          expirationDate: Date,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(id, types, subject, expirationDate, storePassword)
    }

    /// Add one credential to credential array.
    /// - Parameters:
    ///   - id: The handle to DIDURL.
    ///   - types: The array of credential types.
    ///   - subject: The array of credential subject property.
    ///   - expirationDate: The time to credential be expired.
    ///   - storePassword: Password for DIDStores.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(appendCredential:types:subject:expirationDate:storePassword:error:)
    public func appendCredential(with id: String,
                                   types: Array<String>,
                                 subject: Dictionary<String, String>,
                          expirationDate: Date,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(DIDURL(getSubject(), id), types, subject, expirationDate, storePassword)
    }

    /// Add one credential to credential array.
    /// - Parameters:
    ///   - id: The handle to DIDURL.
    ///   - subject: The array of credential subject property.
    ///   - expirationDate: The time to credential be expired.
    ///   - storePassword: Password for DIDStores.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func appendCredential(with id: DIDURL,
                                 subject: Dictionary<String, String>,
                          expirationDate: Date,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(id, nil, subject, expirationDate, storePassword)
    }

    /// Add one credential to credential array.
    /// - Parameters:
    ///   - id: The handle to DIDURL.
    ///   - subject: The array of credential subject property.
    ///   - expirationDate: The time to credential be expired.
    ///   - storePassword: Password for DIDStores.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(appendCredential:subject:expirationDate:storePassword:error:)
    public func appendCredential(with id: String,
                                 subject: Dictionary<String, String>,
                          expirationDate: Date,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(DIDURL(getSubject(), id), nil, subject, expirationDate, storePassword)
    }

    /// Add one credential to credential array.
    /// - Parameters:
    ///   - id: The handle to DIDURL.
    ///   - types: The array of credential types.
    ///   - subject: The array of credential subject property.
    ///   - storePassword: Password for DIDStores.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func appendCredential(with id: DIDURL,
                                   types: Array<String>,
                                 subject: Dictionary<String, String>,
                     using storePassword: String) throws -> DIDDocumentBuilder {
        return try appendCredential(id, types, subject, nil, storePassword)
    }

    /// Add one credential to credential array.
    /// - Parameters:
    ///   - id: The handle to DIDURL.
    ///   - types: The array of credential types.
    ///   - subject: The array of credential subject property.
    ///   - storePassword: Password for DIDStores.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(appendCredential:types:subject:storePassword:error:)
    public func appendCredential(with id: String,
                                   types: Array<String>,
                                 subject: Dictionary<String, String>,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(DIDURL(getSubject(), id), types, subject, nil, storePassword)
    }

    /// Add one credential to credential array.
    /// - Parameters:
    ///   - id: The handle to DIDURL.
    ///   - subject: The array of credential subject property.
    ///   - storePassword: Password for DIDStores.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func appendCredential(with id: DIDURL,
                                 subject: Dictionary<String, String>,
                     using storePassword: String) throws -> DIDDocumentBuilder {
        return try appendCredential(id, nil, subject, nil, storePassword)
    }

    /// Add one credential to credential array.
    /// - Parameters:
    ///   - id: The handle to DIDURL.
    ///   - subject: The array of credential subject property.
    ///   - storePassword: Password for DIDStores.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(appendCredential:subject:storePassword:error:)
    public func appendCredential(with id: String,
                                 subject: Dictionary<String, String>,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(DIDURL(getSubject(), id), nil, subject, nil, storePassword)
    }

    private func appendCredential(_ id: DIDURL,
                                  _ types: Array<String>?,
                                  _ json: String,
                                  _ expirationDate: Date?,
                                  _ storePassword: String) throws -> DIDDocumentBuilder {
        try checkNotSealed()

        try checkArgument(!json.isEmpty, "Invalid json")
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")

        let realTypes: Array<String>
        if let _ = types {
            realTypes = types!
        } else {
            realTypes = Array<String>(["SelfProclaimedCredential"])
        }

        let realExpires: Date
        if let _ = expirationDate {
            realExpires = expirationDate!
        } else {
            realExpires = document!.expirationDate!
        }

        let issuer  = try VerifiableCredentialIssuer(document!)
        let builder = issuer.editingVerifiableCredentialFor(did: document!.subject)
        
        let credential = try builder.withId(id)
            .withTypes(realTypes)
            .withProperties(json)
            .withExpirationDate(realExpires)
            .seal(using: storePassword)
        _ = try appendCredential(with: credential)
        
        return self
    }

    /// Add one credential to credential array.
    /// - Parameters:
    ///   - id: The handle to DIDURL.
    ///   - types: The array of credential types.
    ///   - json: The json string of credential subject property.
    ///   - expirationDate: The time to credential be expired.
    ///   - storePassword: Password for DIDStores.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func appendCredential(with id: DIDURL,
                                   types: Array<String>,
                                    json: String,
                          expirationDate: Date,
                     using storePassword: String) throws -> DIDDocumentBuilder {
        return try appendCredential(id, types, json, expirationDate, storePassword)
    }

    /// Add one credential to credential array.
    /// - Parameters:
    ///   - id: The handle to DIDURL.
    ///   - types: The array of credential types.
    ///   - json: The json string of credential subject property.
    ///   - expirationDate: The time to credential be expired.
    ///   - storePassword: Password for DIDStores.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(appendCredential:types:json:expirationDate:storePassword:error:)
    public func appendCredential(with id: String,
                                   types: Array<String>,
                                    json: String,
                          expirationDate: Date,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(DIDURL(getSubject(), id), types, json, expirationDate, storePassword)
    }

    /// Add one credential to credential array.
    /// - Parameters:
    ///   - id: The handle to DIDURL.
    ///   - json: The json string of credential subject property.
    ///   - expirationDate: The time to credential be expired.
    ///   - storePassword: Password for DIDStores.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func appendCredential(with id: DIDURL,
                                    json: String,
                          expirationDate: Date,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(id, nil, json, expirationDate, storePassword)
    }

    /// Add one credential to credential array.
    /// - Parameters:
    ///   - id: The handle to DIDURL.
    ///   - json: The json string of credential subject property.
    ///   - expirationDate: The time to credential be expired.
    ///   - storePassword: Password for DIDStores.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(appendCredentialWithId:json:expirationDate:storePassword:error:)
    public func appendCredential(with id: String,
                                    json: String,
                          expirationDate: Date,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(DIDURL(getSubject(), id), nil, json, expirationDate, storePassword)
    }

    /// Add one credential to credential array.
    /// - Parameters:
    ///   - id: The handle to DIDURL.
    ///   - types: The array of credential types.
    ///   - json: The json string of credential subject property.
    ///   - storePassword: Password for DIDStores.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func appendCredential(with id: DIDURL,
                                   types: Array<String>,
                                    json: String,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(id, types, json, nil, storePassword)
    }

    /// Add one credential to credential array.
    /// - Parameters:
    ///   - id: The handle to DIDURL.
    ///   - types: The array of credential types.
    ///   - json: The json string of credential subject property.
    ///   - storePassword: Password for DIDStores.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(appendCredential:types:json:storePassword:error:)
    public func appendCredential(with id: String,
                                   types: Array<String>,
                                    json: String,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(DIDURL(getSubject(), id), types, json, nil, storePassword)
    }

    /// Add one credential to credential array.
    /// - Parameters:
    ///   - id: The handle to DIDURL.
    ///   - json: The json string of credential subject property.
    ///   - storePassword: Password for DIDStores.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func appendCredential(with id: DIDURL,
                                    json: String,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(id, nil, json, nil, storePassword)
    }

    /// Add one credential to credential array.
    /// - Parameters:
    ///   - id: The handle to DIDURL.
    ///   - json: The json string of credential subject property.
    ///   - storePassword: Password for DIDStores.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(appendCredential:jsonString:storePassword:error:)
    public func appendCredential(with id: String,
                                    json: String,
                     using storePassword: String) throws -> DIDDocumentBuilder {

        return try appendCredential(DIDURL(getSubject(), id), nil, json, nil, storePassword)
    }

    private func removeCredential(_ id: DIDURL) throws -> DIDDocumentBuilder {
        try checkNotSealed()
    
        guard document!._credentialDic.count > 0 else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError(id.toString())
        }

        guard (document!._credentialDic.removeValue(forKey: try canonicalId(id)!) != nil) else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError(id.toString())
        }
        
        invalidateProof()
        
        return self
    }

    /// Remove specified credential from credential array.
    /// - Parameter id: An identifier of Credential.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func removeCredential(with id: DIDURL) throws -> DIDDocumentBuilder {
        return try removeCredential(id)
    }

    /// Remove specified credential from credential array.
    /// - Parameter id: An identifier of Credential.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(removeCredential:error:)
    public func removeCredential(with id: String) throws -> DIDDocumentBuilder {
        return try removeCredential(DIDURL(getSubject(), id))
    }

    private func appendService(_ id: DIDURL,
                               _ type: String,
                               _ endpoint: String, _ properties: [String: Any]?) throws -> DIDDocumentBuilder {
        try checkNotSealed()
        try checkArgument(id.did == nil || id.did == getSubject(), "Invalid publicKey id")
        try checkArgument(!type.isEmpty, "Invalid type")
        try checkArgument(!endpoint.isEmpty, "Invalid endpoint")

        var svc: Service
        if let _ = properties {
            let node = JsonNode(properties as Any)
            svc = try Service(canonicalId(id)!, type, endpoint, node)
        }
        else {
            svc = try Service(canonicalId(id)!, type, endpoint)
        }
            
        if document!._serviceDic[svc.id] != nil {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectAlreadyExistError("Service '\(svc.id)' already exist.")
        }
        document!._serviceDic[svc.getId()!] = svc
        document!._services.append(svc)
        invalidateProof()

        return self
    }

    /// Add one Service to services array.
    /// - Parameters:
    ///   - id: The identifier of Service.
    ///   - type: The type of Service.
    ///   - endpoint: ServiceEndpoint property is a valid URI.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func appendService(with id: DIDURL,
                                 type: String,
                                 endpoint: String, properties: [String: Any]) throws -> DIDDocumentBuilder {
        return try appendService(id, type, endpoint, properties)
    }
    
    /// Add one Service to services array.
    /// - Parameters:
    ///   - id: The identifier of Service.
    ///   - type: The type of Service.
    ///   - endpoint: ServiceEndpoint property is a valid URI.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func appendService(with id: DIDURL,
                                 type: String,
                             endpoint: String) throws -> DIDDocumentBuilder {
        return try appendService(id, type, endpoint, nil)
    }

    /// Add one Service to services array.
    /// - Parameters:
    ///   - id: The identifier of Service.
    ///   - type: The type of Service.
    ///   - endpoint: ServiceEndpoint property is a valid URI.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(appendService:type:endpoint:error:)
    public func appendService(with id: String,
                                 type: String,
                             endpoint: String) throws -> DIDDocumentBuilder {
        return try appendService(DIDURL(getSubject(), id), type, endpoint, nil)
    }
    
    /// Add one Service to services array.
    /// - Parameters:
    ///   - id: The identifier of Service.
    ///   - type: The type of Service.
    ///   - endpoint: ServiceEndpoint property is a valid URI.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(appendService:type:endpoint:properties:error:)
    public func appendService(with id: String,
                                 type: String,
                             endpoint: String, properties: [String: Any]) throws -> DIDDocumentBuilder {
        return try appendService(DIDURL(getSubject(), id), type, endpoint, properties)
    }

    private func removeService(_ id: DIDURL) throws -> DIDDocumentBuilder {
        try checkNotSealed()
        if document!._serviceDic.isEmpty {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError(id.toString())
        }
        
        if (document!._serviceDic.removeValue(forKey: try canonicalId(id)!) != nil) {
            invalidateProof()
        }
        else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError(id.toString())
        }
        
        return self
    }

    /// Remove specified Service to services array.
    /// - Parameter id: The identifier of Service.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func removeService(with id: DIDURL) throws -> DIDDocumentBuilder {
        return try removeService(id)
    }

    /// Remove specified Service to services array.
    /// - Parameter id: The identifier of Service.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc(removeService:error:)
    public func removeService(with id: String) throws -> DIDDocumentBuilder {
        return try removeService(DIDURL(getSubject(), id))
    }

    /// Set default expire time about DID Document.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func withDefaultExpiresDate() throws -> DIDDocumentBuilder {
        try checkNotSealed()
        
        document!.setExpirationDate(DateFormatter.maxExpirationDate())
        invalidateProof()
        
        return self
    }

    /// Set expire time about DID Document.
    /// - Parameter expiresDate: ime to expire.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: DIDDocumentBuilder instance.
    @objc
    public func withExpiresDate(_ expiresDate: Date) throws -> DIDDocumentBuilder {
        try checkNotSealed()

        let maxExpirationDate = DateFormatter.maxExpirationDate()
        guard !DateFormatter.isExpired(expiresDate, maxExpirationDate) else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalArgumentError("Invalid expires, out of range.")
        }

        document!.setExpirationDate(expiresDate)
        invalidateProof()
        
        return self
    }

    /// Seal the document object, attach the generated proof to the document.
    /// - Parameter storePassword: the password for DIDStore
    /// - Throws: if an error occurred, throw error.
    /// - Returns: A handle to DIDDocument
    @objc
    public func seal(using storePassword: String) throws -> DIDDocument {
        try checkNotSealed()
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        
        try sanitize()
        let signerDoc = document!.isCustomizedDid() ? controllerDoc : document
        let signKey = signerDoc?.defaultPublicKeyId()
        
        if (document!._proofsDic.contains(where: { (k, v) -> Bool in
            k == signerDoc?.subject
        })) {
            throw DIDError.UncheckedError.IllegalStateError.AlreadySignedError(signerDoc?.subject.toString())
        }
        let json = document?.toString(true)
        let sig = try document?.sign(withId: signKey!, using: storePassword, for: [json!.data(using: .utf8)!])
        let proof = DIDDocumentProof(signKey!, sig!)
        document!._proofsDic[proof.creator!.did!] = proof
        let values = document!._proofsDic.values
        values.forEach { df in
            document!._proofs.append(df)
        }
        
        document?._proofs.sort(by: { (proofA, proofB) -> Bool in
            let compareResult = DateFormatter.convertToUTCStringFromDate(proofA.createdDate)
                .compare(DateFormatter.convertToUTCStringFromDate(proofB.createdDate))
            if compareResult == ComparisonResult.orderedSame {
                
                return proofA.creator!.compareTo(proofB.creator!) == ComparisonResult.orderedAscending
            } else {
                return compareResult == ComparisonResult.orderedAscending
            }
        })
        
        // Invalidate builder
        let doc = document
        self.document = nil

        return doc!
    }
    
    /// Add a new controller to the customized DID document.
    /// - Parameter controller: the new controller's DID
    /// - Throws: DIDResolveError if failed resolve the new controller's DID
    /// - Returns: the Builder object
    @objc(addController:error:)
    public func appendController(with controller: DID) throws -> DIDDocumentBuilder {
        try checkNotSealed()
        try checkIsCustomized()
        try checkArgument(!document!._controllers.contains(controller), "Controller already exists.")
        let controllerDoc = try controller.resolve(true)
        guard (controllerDoc != nil) else {
            throw DIDError.UncheckedError.IllegalStateError.DIDNotFoundError(controller.toString())
        }
        
        guard !controllerDoc!.isDeactivated else {
            throw DIDError.UncheckedError.IllegalStateError.DIDDeactivatedError(controller.toString())
        }
        guard !controllerDoc!.isExpired else {
            throw DIDError.UncheckedError.IllegalStateError.DIDExpiredError(controller.toString())
        }
        
        guard try controllerDoc!.isGenuine() else {
            throw DIDError.UncheckedError.IllegalStateError.DIDNotGenuineError(controller.toString())
        }
        guard !controllerDoc!.isCustomizedDid() else {
            throw DIDError.UncheckedError.IllegalStateError.NotPrimitiveDIDError(controller.toString())
        }
        document?._controllers.append(controller)
        document?._controllerDocs[controller] = controllerDoc
        document?._multisig = nil // invalidate multisig
        
        invalidateProof()
        return self
    }
    
    /// Add a new controller to the customized DID document.
    /// - Parameter controller: the new controller's DID
    /// - Throws: DIDResolveError if failed resolve the new controller's DID
    /// - Returns: the Builder object
    public func appendController(_ controller: String) throws -> DIDDocumentBuilder {
        return try appendController(with: DID.valueOf(controller)!)
    }
    
    /// Remove controller from the customized DID document.
    /// - Parameter controller: the controller's DID to be remove
    public func removeController(_ controller: DID) throws -> DIDDocumentBuilder {
        try checkNotSealed()
        try checkIsCustomized()
        guard controller != controllerDoc?.subject else {
            throw DIDError.UncheckedError.UnsupportedOperationError.CanNotRemoveEffectiveControllerError(controller.toString())
        }
        
        if document != nil && document!._controllers.contains(controller) {
            invalidateProof()
        }
        document?._controllers = document!._controllers.filter { $0 != controller}
        
        document?._controllerDocs.removeValue(forKey: controller)
        
        return self
    }
    
    /// Remove controller from the customized DID document.
    /// - Parameter controller: the controller's DID to be remove
    /// - Returns: the Builder object
    public func removeController(_ controller: String) throws -> DIDDocumentBuilder {

        return try removeController(DID.valueOf(controller)!)
    }

    /// Set multiple signature for multi-controllers DID document.
    /// - Parameter m: the required signature count
    /// - Returns: the Builder object
    public func setMultiSignature(_ m: Int) throws -> DIDDocumentBuilder {
        try checkNotSealed()
        try checkIsCustomized()
        try checkArgument(m >= 1, "Invalid signature count")
        let n = document!.controllers().count
        try checkArgument(m <= n, "Signature count exceeds the upper limit")

        var multisig: MultiSignature?
        if n > 1 {
            multisig = try MultiSignature(m, n)
        }
        
        if document?._multisig == nil && multisig == nil {
            return self
        }
        
        if document?._multisig != nil && multisig != nil && document!._multisig == multisig {
            return self
        }
        
        document?._multisig = try MultiSignature(m, n)
        invalidateProof()
        
        return self
    }

    private func invalidateProof() {
        if !document!._proofsDic.isEmpty{
            document!._proofsDic.removeAll()
        }
    }
    
    private func checkNotSealed() throws {
        guard document != nil else {
            throw DIDError.UncheckedError.IllegalStateError.AlreadySealedError()
        }
    }
    
    private func checkIsCustomized() throws {
        guard document!.isCustomizedDid() else {
            throw DIDError.UncheckedError.IllegalStateError.NotCustomizedDIDError(document!.subject.toString())
        }
    }
    
    private func getMaxExpires() -> Date {
       
        return  DateFormatter.convertToWantDate(DateFormatter.currentDate(), Constants.MAX_VALID_YEARS)
    }
    
    /// Set the current time to be expires time for DID Document Builder.
    /// - Returns: the DID Document Builder
    public func setDefaultExpires() throws -> DIDDocumentBuilder {
        try checkNotSealed()
        document?._expires = getMaxExpires()
        invalidateProof()
        
        return self
    }
    
    /// Set the specified time to be expires time for DID Document Builder.
    /// - Parameter expires: the specified time
    /// - Returns: the DID Document Builder
    public func setExpires(_ expires: Date) throws -> DIDDocumentBuilder {
        try checkNotSealed()

        if expires > getMaxExpires() {
            // Error
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidExpires("Invalid expires, out of range.")
        }
        document?._expires = expires
        invalidateProof()
        return self
    }
    
    /// Remove the proof that created by the specific controller.
    /// - Parameter controller: the controller's DID
    /// - Returns: the DID Document Builder
    public func removeProof(_ controller: DID) throws -> DIDDocumentBuilder {
        try checkNotSealed()
        if document!._proofsDic.count == 0  {
            return self
        }
        
        if document!._proofsDic.removeValue(forKey: controller) == nil {
            throw DIDError.UncheckedError.IllegalArgumentErrors.DIDObjectNotExistError("No proof signed by: \(controller)")
        }
        return self
    }
    
    func sanitize() throws {
        if (document!.isCustomizedDid()) {
            if (document!.controllers().isEmpty){
                throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Missing controllers")
            }
            
            if (document!.controllers().count > 1) {
                if (document!._multisig == nil) {
                    throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Missing multisig")
                }
                
                if (document!._multisig!.n != document!.controllers().count) {
                    throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Invalid multisig, not matched with controllers")
                }
            } else {
                if (document!._multisig != nil) {
                    throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Invalid multisig")
                }
            }
        }
        
        let sigs = document!._multisig == nil ? 1 : document!._multisig!.m
        if (document!._proofsDic.count > 0 && document!._proofsDic.count == sigs) {
            throw DIDError.UncheckedError.IllegalStateError.AlreadySealedError(try getSubject().toString())
        }
        try document?._controllers.sort { (didA, didB) -> Bool in
            return try didA.compareTo(didB) == ComparisonResult.orderedAscending
        }
        document!._publickeys.removeAll()
        document!._publicKeyDic.values.forEach { pk in
            document!._publickeys.append(pk)
        }
        
        for pk in document!._authenticationKeys.values {
                document!._authentications.append(PublicKeyReference(pk))
        }
        
        for pk in document!._authorizationKeys.values {
            document!._authorizations.append(PublicKeyReference(pk))
        }
        try document!._authentications.sort { (publicKeyReferenceA, publicKeyReferenceB) -> Bool in
            return try publicKeyReferenceA.compareTo(publicKeyReferenceB) == ComparisonResult.orderedAscending
        }
        try document!._authorizations.sort { (publicKeyReferenceA, publicKeyReferenceB) -> Bool in
            return try publicKeyReferenceA.compareTo(publicKeyReferenceB) == ComparisonResult.orderedAscending
        }
        
        document!._credentials.removeAll()
        document!._credentialDic.values.forEach { vc in
            document!._credentials.append(vc)
        }
        
        document!._services.removeAll()
        document!._serviceDic.values.forEach { service in
            document!._services.append(service)
        }
        
        if (document!._proofsDic.isEmpty) {
            if (document?._expires == nil) {
               _ = try setDefaultExpires()
            }
        }
        
        document!._proofs.removeAll()
    }
}
