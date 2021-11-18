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
import PromiseKit

/// DID documents contain information associated with a DID.
/// They typically express verification methods, such as cryptographic
/// public keys, and services relevant to interactions with the DID subject.
///
/// <p>
/// The generic properties supported in a DID document are specified by the
/// <a href="https://github.com/elastos/Elastos.DID.Method">Elastos DID Method Specification</a>.
/// </p>
@objc(DIDDocument)
public class DIDDocument: NSObject {
    private static let TAG = NSStringFromClass(DIDDocument.self)
    let CONTEXT = "@context"
    let ID = "id"
    let PUBLICKEY = "publicKey"
    let TYPE = "type"
    let CONTROLLER = "controller"
    let MULTI_SIGNATURE = "multisig"
    let PUBLICKEY_BASE58 = "publicKeyBase58"
    let AUTHENTICATION = "authentication"
    let AUTHORIZATION = "authorization"
    let SERVICE = "service"
    let VERIFIABLE_CREDENTIAL = "verifiableCredential"
    let SERVICE_ENDPOINT = "serviceEndpoint"
    let EXPIRES = "expires"
    let PROOF = "proof"
    let CREATOR = "creator"
    let CREATED = "created"
    let SIGNATURE_VALUE = "signatureValue"

    var _subject: DID?
    var _controllers: [DID] = [ ]
    var _controllerDocs: [DID: DIDDocument] = [: ]
    var _effectiveController: DID?
    var _multisig: MultiSignature?
    var _defaultPublicKey: PublicKey?
    var _publickeys: [PublicKey] = []
    var _authentications: [PublicKeyReference] = []
    var _authorizations: [PublicKeyReference] = []
    var _credentials: [VerifiableCredential] = []
    var _services: [Service] = []
    var _expires: Date?
    var _proofs: [DIDDocumentProof] = [ ]
    var _metadata: DIDMetadata?
    
    //    var publicKeyMap: EntryMap<PublicKey> = EntryMap()
    var _publicKeyDict: [DIDURL: PublicKey] = [: ]
    var _credentialDict: [DIDURL: VerifiableCredential] = [: ]
    var _serviceDict: [DIDURL: Service] = [: ]
    var _proofsDict: [DID: DIDDocumentProof] = [: ]
    var _authenticationKeys: [DIDURL: PublicKey] = [: ]
    var _authorizationKeys: [DIDURL: PublicKey] = [: ]
    private var _capacity: Int = 0
    var _context: [String] = [ ]

    override init() { }

    init(_ subject: DID) {
        self._subject = subject
    }

    /// Copy constructor.
    /// - Parameters:
    ///   - doc: the document be copied
    ///   - withProof: copy with the proof or not
    init(_ doc: DIDDocument, _ withProof: Bool) {
        _context = doc._context
        _subject = doc.subject
        _controllers = doc._controllers
        _controllerDocs = doc._controllerDocs
        _effectiveController = doc.effectiveController
        _multisig = doc._multisig
        _publicKeyDict = doc._publicKeyDict
        _authenticationKeys = doc._authenticationKeys
        _authorizationKeys = doc._authorizationKeys
        _publickeys = doc._publickeys
        _authentications = doc._authentications
        _authorizations = doc._authorizations
        _defaultPublicKey = doc._defaultPublicKey
        _credentialDict = doc._credentialDict
        _credentials = doc._credentials
        _serviceDict = doc._serviceDict
        _services = doc._services
        _expires = doc._expires
        if withProof {
            self._proofsDict = doc._proofsDict
            self._proofs = doc._proofs
        }
        _metadata = doc._metadata
    }

    /// Get subject of this DIDDocument.
    /// - return: the DID object
    @objc
    public var subject: DID {
        return self._subject!
    }

    private func setSubject(_ subject: DID) {
        self._subject = subject
    }
    
    private func canonicalId(_ id: String) throws -> DIDURL? {
        return try DIDURL.valueOf(subject, id)
    }
    
    private func canonicalId(_ id: DIDURL) throws -> DIDURL {
        if id.did != nil {
            return id
        }
        return DIDURL(subject, id)
    }
    
    public func isCustomizedDid() -> Bool {
        return _defaultPublicKey == nil
    }
    
    /// Get contoller's DID.
    /// - Returns: the Controllers DID list or empty list if no controller
    public func controllers() -> [DID] {
        return _controllers
    }
    
    /// Get controller count.
    /// - Returns: the controller count
    public func controllerCount() -> Int {
        return _controllers.count
    }
    
    /// Get contoller's DID.
    /// - Returns: the Controller's DID if only has one controller, other wise nil
    var controller: DID? {
        return _controllers.count == 1 ? _controllers[0] : nil
    }
    
    /// Check if current DID has controller.
    /// - Returns: true if has, otherwise false
    public func hasController() -> Bool {
        return !(_controllers.isEmpty)
    }
    
    /// Check if current DID has specific controller.
    /// - Returns: true if has, otherwise false
    public func hasController(_ did: DID) -> Bool {
        return _controllers.contains(did)
    }
    
    /// Get controller's DID document.
    /// - Returns: the DIDDocument object or null if no controller
    public func controllerDocument(_ did: DID) -> DIDDocument? {
        return _controllerDocs[did]
    }
    
    /// Get the current effective controller for the customized DIDDocument.
    public var effectiveController: DID? {
        return _effectiveController
    }
    
    /// Get the current effective controller's document for the
    /// customized DIDDocument.
    /// - Returns: the effective controller's document or null if not set
    func effectiveControllerDocument() -> DIDDocument? {
        return _effectiveController == nil ? nil : controllerDocument(_effectiveController!)
    }
    
    /// Set the current effective controller for the customized DIDDocument.
    /// - Parameter controller: the new effective controller
    public func setEffectiveController(_ controller: DID?) throws {
        try checkIsCustomized()
        guard controller != nil else {
            _effectiveController = controller
            return
        }
        
        guard hasController(controller!) else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.NotControllerError("Not contoller for target DID")
        }
        _effectiveController = controller
        
        // attach to the store if necessary
        let doc = controllerDocument(_effectiveController!)
        if !((doc?.getMetadata().attachedStore)!) {
            doc?.getMetadata().attachStore(getMetadata().store!)
        }
    }
    
    /// Check if this document is a multisig document.
    public var isMultiSignature: Bool {
        return _multisig != nil
    }
    
    /// Get the multisig specification of this document.
    public var multiSignature: MultiSignature? {
        get {
            return _multisig
        }
    }

    /// Get the number of the public keys.
    /// A DID Document must include a publicKey property.
    @objc
    public var publicKeyCount: Int {
        
        var count = self._publicKeyDict.count
        if hasController() {
            _controllerDocs.values.forEach({ document in
                count += document.authenticationKeyCount
            })
        }
        return count
    }

    /// Get all the public keys.
    /// - Returns: a array of PublicKey object
    @objc
    public func publicKeys() -> [PublicKey] {
        var pks: [PublicKey] = []
        self._publicKeyDict.values.forEach { pk in
            pks.append(pk)
        }
        if hasController() {
            _controllerDocs.values.forEach({ doc in
                pks.append(contentsOf: doc.authenticationKeys())
            })
        }
        return pks
    }

    private func selectPublicKeys(_ byId: DIDURL?, _ andType: String?) throws -> [PublicKey] {
        try checkArgument(byId != nil || andType != nil, "Invalid select args")
        let id: DIDURL? = byId != nil ? try canonicalId(byId!) : nil
        var pks: [PublicKey] = []
        
        for pk in _publicKeyDict.values {
            if (id != nil && pk.id != id) {
                continue
            }
            if (andType != nil && pk.type != andType) {
                continue
            }
            
            pks.append(pk)
        }
        
        if (hasController()) {
            try _controllerDocs.values.forEach{ doc in
                try pks.append(contentsOf: doc.selectAuthenticationKeys(id, andType))
            }
        }
        
        return pks
    }
    
    /// Select the public keys by the specified key id or key type.
    /// - Parameters:
    ///   - byId: the key id
    ///   - andType: the type string
    /// - Returns: an array of the matched public keys
    @objc
    public func selectPublicKeys(byId: DIDURL, andType: String) throws -> [PublicKey] {
        return try selectPublicKeys(byId, andType)
    }

    /// Select public keys with the specified key id or key type.
    /// - Parameters:
    ///   - byId: the key id
    ///   - andType: the type string
    /// - Throws: If an error occurred, throw error
    /// - Returns: an array of the matched public keys
    @objc (selectPublicKeysbyIdString:andType:error:)
    public func selectPublicKeys(byId: String, andType: String) throws -> [PublicKey] {
        return try selectPublicKeys(byId: try DIDURL(subject, byId), andType: andType)
    }
    
    /// Select the public keys by the specified key id or key type.
    /// - Parameter byId: the key id
    /// - Throws: If an error occurred, throw error
    /// - Returns: an array of the matched public keys
    public func selectPublicKeys(byId: DIDURL) throws -> [PublicKey] {
        return try selectPublicKeys(byId, nil)
    }
    
    /// Select the public keys by the specified key id or key type.
    /// - Parameter byId: the key id
    /// - Throws: If an error occurred, throw error
    /// - Returns: an array of the matched public keys
    public func selectPublicKeys(byId: String) throws -> [PublicKey] {
        return try selectPublicKeys(byId: try DIDURL(subject, byId))
    }

    /// Get public key conforming to type or identifier.
    /// - Parameter byType: The type of public key to be selected.
    /// - Returns: an array of the matched public keys
    @objc
    public func selectPublicKeys(byType: String) throws -> [PublicKey] {
        return try selectPublicKeys(nil, byType)
    }

    /// Get the specific public key.
    /// - Parameter ofId: the key id string
    /// - Returns: the PublicKey object
    //    @objc
    public func publicKey(ofId: DIDURL) throws -> PublicKey? {
        let id = try canonicalId(ofId)
        var pk = self._publicKeyDict[id]
        if pk == nil && hasController() {
            let doc = controllerDocument(id.did!)
            if doc != nil {
                pk = try doc?.authenticationKey(ofId: id)
            }
        }
        
        return pk
    }

    /// Get the specific public key.
    /// - Parameter ofId: the key id
    /// - Throws: If an error occurred, throw error
    /// - Returns: the PublicKey object
    public func publicKey(ofId: String) throws -> PublicKey? {
        return try publicKey(ofId: canonicalId(ofId)!)
    }

    /// Get the specific public key with Object-C
    /// - Parameter ofId: the key id
    /// - Throws: If an error occurred, throw error
    /// - Returns: the PublicKey object
    @objc
    public func publicKey(ofId: String, error: NSErrorPointer) -> PublicKey? {
        do {
            return try publicKey(ofId: canonicalId(ofId)!)
        } catch let aError as NSError {
            error?.pointee = aError
            return nil
        }
    }

    /// Check if the specified public key exists.
    /// - Parameter forId: the key id
    /// - Returns: the key exists or not
//    @objc
    public func containsPublicKey(forId: DIDURL) throws -> Bool {
        return try publicKey(ofId: forId) != nil
    }

    /// Check if the specified public key exists.
    /// - Parameter forId: the key id string
    /// - Throws: If an error occurred, throw error
    /// - Returns: the key exists or not
    public func containsPublicKey(forId: String) throws -> Bool {
        return try publicKey(ofId: forId) != nil
    }

    /// Check if the specified public key exists with Object-C
    /// - Parameter forId: An identifier of public key.
    /// - Throws: If an error occurred, throw error
    /// - Returns: True if has public key, or false.
    @objc
    public func containsPublicKey(forId: String, error: NSErrorPointer) -> Bool {
        do {
            return try publicKey(ofId: forId) != nil
        } catch let aError as NSError {
            error?.pointee = aError
            return false
        }
    }

    /// Check if the specified private key exists.
    /// - Parameter forId: the key id
    /// - Returns: the key exists or not
    public func containsPrivateKey(forId: DIDURL) throws -> Bool {
        guard try containsPublicKey(forId: forId) else {
            return false
        }
        guard let store = getMetadata().store else {
            return false
        }

        return try store.containsPrivateKey(for: forId)
    }
    
    /// Check if the specified private key exists.
    /// - Parameter forId: the key id string
    /// - Returns: the key exists or not
    //    @objc(containsPrivateKey:)
    public func containsPrivateKey(forId: String) throws -> Bool {
        return try containsPrivateKey(forId: canonicalId(forId)!)
    }

    private func getDefaultPublicKey() -> DIDURL? {
        for key in publicKeys() {
            if subject != key.controller {
                continue
            }

            let address = DIDHDKey.toAddress(key.publicKeyBytes)
            if  address == subject.methodSpecificId {
                return key.getId()
            }
        }
        return nil
    }
    
    /// Get default public key id
    /// - Returns: the default public key id
    public func defaultPublicKeyId() -> DIDURL? {
        let pk = defaultPublicKey()

        return pk != nil ? pk?.getId() : nil
    }
    
    /// Get default public key.
    /// - Returns: the default public key
    public func defaultPublicKey() -> PublicKey? {
        if _defaultPublicKey != nil {
            return _defaultPublicKey!
        }
        
        if effectiveController != nil {
            return controllerDocument(effectiveController!)?.defaultPublicKey()
        }
        
        return nil
    }
    
    ///  Get the keyPair_PublicKey data for the given public key.
    /// - Parameter ofId: the public key id
    /// - Returns: the publicKey data
    public func keyPair_PublicKey(ofId: DIDURL) throws -> Data {
        try checkAttachedStore()
        guard try containsPublicKey(forId: ofId) else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("No publicKey key: \(ofId)")
        }
        guard try getMetadata().store!.containsPrivateKey(for: ofId) else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("No private key: \(ofId)")

        }
        let pubKey = try publicKey(ofId: ofId)
        let pubs = pubKey!.publicKeyBytes
        let pubData = Data(bytes: pubs, count: pubs.count)
        let publicKeyData = try DIDHDKey.PEM_ReadPublicKey(pubData)

        return publicKeyData.data(using: .utf8)!
    }

    /// Get the keyPair_PrivateKey data for the given public key.
    /// - Parameters:
    ///   - ofId: the public key id
    ///   - storePassword: the password for DIDStore
    /// - Returns: the privateKey data
    public func keyPair_PrivateKey(ofId: DIDURL, using storePassword: String) throws -> Data {
        try checkAttachedStore()
        guard try containsPublicKey(forId: ofId) else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("No publicKey key: \(ofId)")
        }
        guard try getMetadata().store!.containsPrivateKey(for: ofId) else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("No private key: \(ofId)")
        }

        let pubKey = try publicKey(ofId: ofId)
        let pubs = pubKey!.publicKeyBytes
        let pubData = Data(bytes: pubs, count: pubs.count)
        // 46 - 78
        let privKey = try getMetadata().store!.loadPrivateKey(ofId, storePassword)
        let pkey = privKey![46..<78]
        let privateKeyData = try DIDHDKey.PEM_ReadPrivateKey(pubData, pkey)

        return privateKeyData.data(using: .utf8)!
    }

    /// Derive a private key from this DID. The new private key will derive from
    /// the default private key of the this DIDDocument.
    /// - Parameters:
    ///   - index: the derive index
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the extended private key format. (the real private key is
    ///         32 bytes long start from position 46)
    public func derive(index: Int, storePassword: String) throws -> String {

        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        try checkAttachedStore()
        try checkIsPrimitive()
        let key = DIDHDKey.deserialize((try getMetadata().store?.loadPrivateKey(defaultPublicKeyId()!, storePassword))!)

        return key.derive(index).serializeBase58()
    }
    
        private func mapToDerivePath(_ identifier: String, _ securityCode: Int) -> String {
            let sha256 = SHA256Helper()
            var bytes = [UInt8](identifier.data(using: .utf8)!)
            sha256.update(&bytes)
            let result = sha256.finalize()

            var path: String = ""
            let resultArr = stride(from: 0, to: 32, by: 4).map {
                Array(result[$0...$0+3])
            }

            resultArr.forEach { buf in
                let data = Data(buf)
                let idx = data.buffer().getInt()

                if idx >= 0 {
                    path.append("\(idx)")
                }
                else {
                    path.append("\(idx & 0x7FFFFFFF)")
                    path.append("H")
                }
                path.append("/")
            }
            if securityCode >= 0 {
                path.append("\(securityCode)")
            }
            else {
                path.append("\(securityCode & 0x7FFFFFFF)")
                path.append("H")
            }

            return path
        }

    /// Derive a private key from this DID. The new private key will derive from
    /// the default private key of the this DIDDocument.
    /// - Parameters:
    ///   - identifier: the identifier string
    ///   - securityCode: the security code
    ///   - storePassword: the password for DID store
    /// - Throws: DIDStoreError there is no DID store to get root private key
    /// - Returns: the extended private key format. (the real private key is
    ///         32 bytes long start from position 46)
    public func derive(_ identifier: String, _ securityCode: Int, _ storePassword: String) throws -> String {
        try checkArgument(!identifier.isEmpty, "Invalid identifier")
        try checkAttachedStore()
        try checkIsPrimitive()
        let key = DIDHDKey.deserialize(try getMetadata().store!.loadPrivateKey(defaultPublicKeyId()!, storePassword)!)
        let path = mapToDerivePath(identifier, securityCode)
        
        return try key.derive(path).serializeBase58()
    }

    private func checkAttachedStore() throws {
        guard getMetadata().attachedStore else {
            throw DIDError.UncheckedError.IllegalStateError.NotAttachedWithStoreError()
        }
    }
    
    private func checkIsPrimitive() throws {
        guard !isCustomizedDid() else {
            throw DIDError.UncheckedError.IllegalStateError.NotPrimitiveDIDError(subject.toString())
        }
    }

    private func checkIsCustomized() throws {
        guard isCustomizedDid() else {
            throw DIDError.UncheckedError.IllegalStateError.NotCustomizedDIDError(subject.toString())
        }
    }
    
    private func checkHasEffectiveController() throws {
        guard effectiveController != nil else {
            throw DIDError.UncheckedError.IllegalStateError.NoEffectiveControllerError(subject.toString())
        }
    }
  
    /// Create a JwtBuilder instance.
    /// - Throws: If error occurs, throw error.
    /// - Returns: JwtBuilder instance.
    @objc
    public func jwtBuilder() throws -> JwtBuilder {

        let build = JwtBuilder(issuer: subject.toString(), publicKey: { (id) -> Data in

            var _id: DIDURL
            if id == nil {
                _id = self.getDefaultPublicKey()!
            } else {
                _id = try DIDURL(self.subject, id!)
            }
            return try self.keyPair_PublicKey(ofId: _id)

        }) { (id, storePassword) -> Data in
            var _id: DIDURL

            if id == nil {
                _id = self.getDefaultPublicKey()!
            } else {
                _id = try DIDURL(self.subject, id!)
            }
            return try self.keyPair_PrivateKey(ofId: _id, using: storePassword)
        }
        return build.setIssuer(iss: subject.description)
    }

    /// Create a JwtParserBuilder instance.
    /// - Returns: JwtParserBuilder instance.
    @objc
    public func jwtParserBuilder() -> JwtParserBuilder {

        let builder: JwtParserBuilder = JwtParserBuilder()
        builder.getPublicKey = { (id) in

            var _id: DIDURL
            if id == nil {
                _id = self.getDefaultPublicKey()!
            } else {
                _id = try DIDURL(self.subject, id!)
            }
            return try self.keyPair_PublicKey(ofId: _id)
        }
        builder.getPrivateKey = {(id, storePassword) in

            var _id: DIDURL
            if id == nil {
                _id = self.getDefaultPublicKey()!
            } else {
                _id = try DIDURL(self.subject, id!)
            }
            return try self.keyPair_PrivateKey(ofId: _id, using: storePassword)
        }
        return builder
    }

    /// Create a JwtParser instance.
    /// - Throws: If error occurs, throw error.
    /// - Returns: JwtParser instance.
    @objc
    public func build() throws -> JwtParser {
        return try JwtParserBuilder().build()
    }

    /// Get the numbers of the authentication keys.
    @objc
    public var authenticationKeyCount: Int {
        
        var count = _authenticationKeys.count
        if hasController() {
            _controllerDocs.values.forEach({ doc in
                count += doc.authenticationKeyCount
            })
        }
        
        return count
    }

    /// Get all the authentication keys.
    /// - Returns: an array of the authentication keys
    @objc
    public func authenticationKeys() -> [PublicKey] {
        var pks: [PublicKey] = []
        pks.append(contentsOf: _authenticationKeys.values)
        if hasController() {
            _controllerDocs.values.forEach{ doc in
                pks.append(contentsOf: doc.authenticationKeys())
            }
        }
        
        return pks
    }
    
    private func selectAuthenticationKeys(_ byId: DIDURL?, _ andType: String?) throws -> Array<PublicKey> {
        try checkArgument(byId != nil || andType != nil, "Invalid select args")
        var id: DIDURL? = nil
        if let _ = byId {
            id = try canonicalId(byId!)
        }
        
        var pks: [PublicKey] = []
        for pk in _authenticationKeys.values {
            if id != nil && pk.id != id {
                continue
            }
            
            if andType != nil && pk.type != andType {
                continue
            }
            
            pks.append(pk)
        }
        
        if hasController() {
            try _controllerDocs.values.forEach{ doc in
                pks.append(contentsOf: try doc.selectAuthenticationKeys(id, andType))
            }
        }
        
        return pks
    }
    
    /// Select the authentication keys by the specified key id or key type.
    /// - Parameters:
    ///   - byId: the key id
    ///   - andType: the key type
    /// - Returns: an array of the matched authentication keys
    public func selectAuthenticationKeys(byId: DIDURL, andType: String) throws -> Array<PublicKey> {
        return try selectAuthenticationKeys(byId, andType)
    }

    /// Select the authentication keys by the specified key id or key type.
    /// - Parameters:
    ///   - byId: the key id
    ///   - andType: the key type
    /// - Throws: if an error occurred, throw error.
    /// - Returns: an array of the matched authentication keys
    @objc
    public func selectAuthenticationKeys(byId: String, andType: String) throws -> Array<PublicKey> {
        return try selectAuthenticationKeys(byId: try canonicalId(byId)!, andType: andType)
    }

    /// Select the authentication keys by the specified key id or key type.
    /// - Parameter byType: The type of authentication key to be selected.
    /// - Returns: an array of the matched authentication keys
    @objc
    public func selectAuthenticationKeys(byType: String) throws -> Array<PublicKey> {
        return try selectAuthenticationKeys(nil, byType)
    }
    
    /// Select the authentication keys by the specified key id or key type.
    /// - Parameters:
    ///   - byId: the key id
    /// - Throws: if an error occurred, throw error.
    /// - Returns: an array of the matched authentication keys
    public func selectAuthenticationKeys(byId: DIDURL) throws -> Array<PublicKey> {
        return try selectAuthenticationKeys(byId, nil)
    }
    
    /// Select the authentication keys by the specified key id or key type.
    /// - Parameters:
    ///   - byId: the key id
    /// - Throws: if an error occurred, throw error.
    /// - Returns: an array of the matched authentication keys
    public func selectAuthenticationKeys(byId: String) throws -> Array<PublicKey> {
        return try selectAuthenticationKeys(try canonicalId(byId)!, nil)
    }

    /// Get authentication key with specified key id.
    /// A DID Document must include a authentication property.
    /// - Parameter ofId: the key id
    /// - Returns: the matched authentication key object
    public func authenticationKey(ofId: DIDURL) throws -> PublicKey? {
        let id = try canonicalId(ofId)
        let pk = _authenticationKeys[id]
        if let _ = pk {
            return pk
        }
        if hasController() {
            let doc = _controllerDocs[id.did!]
            if let _ = doc {
                return try doc?.authenticationKey(ofId: id)
            }
        }

        return nil
    }

    /// Get authentication key with specified key id.
    /// A DID Document must include a authentication property.
    /// - Parameter ofId: the key id string
    /// - Throws: if an error occurred, throw error.
    /// - Returns: the matched authentication key object
    public func authenticationKey(ofId: String) throws -> PublicKey?  {
        return try authenticationKey(ofId: try canonicalId(ofId)!)
    }
    
    /// Get authentication key according to identifier of authentication key with Object-C
    /// A DID Document must include a authentication property.
    /// - Parameter ofId: the key id string
    /// - Throws: if an error occurred, throw error.
    /// - Returns: the matched authentication key object
    @objc
    public func authenticationKey(ofId: String, error: NSErrorPointer) -> PublicKey?  {
        do {
            return try authenticationKey(ofId: try DIDURL(subject, ofId))
        } catch let aError as NSError {
            error?.pointee = aError
            return nil
        }
    }

    /// Check whether the given key is authentication key.
    /// - Parameter forId: the key id string
    /// - Throws: if an error occurred, throw error.
    /// - Returns: true if the key is an authentication key, false otherwise
    public func containsAuthenticationKey(forId: String) throws -> Bool {
        return try containsAuthenticationKey(forId: canonicalId(forId)!)
    }

    /// Check whether the given key is authentication key with Object-C
    /// - Parameter forId: An identifier of authentication key.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: true if the key is an authentication key, false otherwise
    @objc
    public func containsAuthenticationKey(forId: String, error: NSErrorPointer) -> Bool {
        do {
            return try authenticationKey(ofId: forId) != nil
        } catch let aError as NSError {
            error?.pointee = aError
            return false
        }
    }

    /// Check key if authentiacation key or not.
    /// - Parameter forId: An identifier of authentication key.
    /// - Returns: true if has authentication key, or false.
    public func containsAuthenticationKey(forId: DIDURL) throws -> Bool {
        return try authenticationKey(ofId: forId) != nil
    }

    /// Add public key to Authenticate.
    ///  Authentication is the mechanism by which the controller(s) of a DID can cryptographically prove that they are associated with that DID.
    ///  A DID Document must include an authentication property.
    /// - Parameter id: An identifier of public key.
    /// - Returns: true if append authentication key success, or false.
    func appendAuthenticationKey(_ id: DIDURL) throws -> Bool {
        let key = try publicKey(ofId: id)
        guard let _ = key else {
            return false
        }

        // Make sure that controller should be current DID subject.
        guard key!.controller == self.subject else {
            return false
        }

        _authenticationKeys[key!.getId()!] = key
        return true
    }

    /// Get the numbers of the authorization keys.
    @objc
    public var authorizationKeyCount: Int {
        return _authorizationKeys.count
    }

    /// Get all the authorization keys.
    /// - Returns: an array of authorization keys
    @objc
    public func authorizationKeys() -> Array<PublicKey> {
        var keys: [PublicKey] = []
            _authorizationKeys.values.forEach { pk in
            keys.append(pk)
        }
        try? keys.sort { (publicKeyA, publicKeyB) -> Bool in
            return try publicKeyA.compareTo(publicKeyB) == ComparisonResult.orderedAscending
        }
        return keys
    }

    private func selectAuthorizationKeys(_ byId: DIDURL?, _ andType: String?) throws -> Array<PublicKey> {
        try checkArgument(byId != nil || andType != nil, "Invalid select args")

        let id = byId != nil ? try canonicalId(byId!) : nil
        var pks: [PublicKey] = []
        for pk in authorizationKeys() {
            if (id != nil && pk.getId() != id) {
                continue
            }

            if (andType != nil && pk.getType() != andType) {
                continue
            }
            pks.append(pk)
        }

        return pks
    }
    
    /// Select the authorization keys by the specified key id or key type.
    /// - Parameters:
    ///   - byId: the key id
    ///   - andType: the key type
    /// - Returns: an array of the matched authorization keys
//    @objc
    public func selectAuthorizationKeys(byId: DIDURL, andType: String) throws -> Array<PublicKey> {
        return try selectAuthorizationKeys(byId, andType)
    }

    /// Select the authorization keys by the specified key id or key type.
    /// - Parameters:
    ///   - byId: the key id
    ///   - andType: the key type
    /// - Throws: if an error occurred, throw error.
    /// - Returns: an array of the matched authorization keys
    @objc
    public func selectAuthorizationKeys(byId: String, andType: String) throws -> Array<PublicKey> {
        let id = try DIDURL(subject, byId)
        return try selectAuthorizationKeys(byId: id, andType: andType)
    }
    
    /// Select the authorization keys by the specified key id or key type.
    /// - Parameters:
    ///   - byId: the key id
    /// - Throws: if an error occurred, throw error.
    /// - Returns: an array of the matched authorization keys
    public func selectAuthorizationKeys(byId: DIDURL) throws -> Array<PublicKey> {
        return try selectAuthorizationKeys(byId, nil)
    }
    
    /// Select the authorization keys by the specified key id or key type.
    /// - Parameters:
    ///   - byId: the key id
    /// - Throws: if an error occurred, throw error.
    /// - Returns: an array of the matched authorization keys
    public func selectAuthorizationKeys(byId: String) throws -> Array<PublicKey> {
        return try selectAuthorizationKeys(byId: try DIDURL(subject, byId))
    }
    
    /// Select the authorization keys by the specified key id or key type.
    /// - Parameter byType: the key type
    /// - Returns: an array of the matched authorization keys
    @objc
    public func selectAuthorizationKeys(byType: String) throws -> Array<PublicKey> {
        return try selectAuthorizationKeys(nil, byType)
    }

    /// Get the specific authorization key.
    /// - Parameter ofId: the key id
    /// - Returns: the PublicKey object
    public func authorizationKey(ofId: DIDURL) throws -> PublicKey? {
        return _authorizationKeys[ofId]
    }

    /// Get the specific authorization key.
    /// - Parameter ofId: the key id
    /// - Throws: if an error occurred, throw error.
    /// - Returns: the PublicKey object
    public func authorizationKey(ofId: String) throws -> PublicKey?  {
        return try authorizationKey(ofId: canonicalId(ofId)!)
    }

    /// Get the specific authorization key with Object-C.
    /// - Parameter ofId: the key id
    /// - Throws: if an error occurred, throw error.
    /// - Returns: the PublicKey object
    @objc
    public func authorizationKey(ofId: String, error: NSErrorPointer) -> PublicKey?  {
        do {
            return try authorizationKey(ofId: try canonicalId(ofId)!)
        } catch let aError as NSError {
            error?.pointee = aError
            return nil
        }
    }

    /// Check whether the given key is authorization key.
    /// - Parameter forId: the key id string
    /// - Throws: if an error occurred, throw error.
    /// - Returns: true if the key is an authorization key, false otherwise
    public func containsAuthorizationKey(forId: String) throws -> Bool {
        return try containsAuthorizationKey(forId: canonicalId(forId)!)
    }

    /// Check whether the given key is authorization key with Object-C.
    /// - Parameter forId: the key id string
    /// - Throws: if an error occurred, throw error.
    /// - Returns: true if the key is an authorization key, false otherwise
    @objc
    public func containsAuthorizationKey(forId: String, error: NSErrorPointer) -> Bool {
        do {
            return try containsAuthorizationKey(forId: canonicalId(forId)!)
        } catch let aError as NSError {
            error?.pointee = aError
            return false
        }
    }

    /// Check whether the given key is authorization key.
    /// - Parameter forId: the key id string
    /// - Returns: true if the key is an authorization key, false otherwise
    public func containsAuthorizationKey(forId: DIDURL) throws -> Bool {
        return try authorizationKey(ofId: forId) != nil
    }

    /// Get the numbers of the credentials.
    @objc
    public var credentialCount: Int {
        return _credentials.count
    }

    /// Get all the credential.
    /// - Returns: an array of the credential objects
    @objc
    public func credentials() -> Array<VerifiableCredential> {
        return _credentials
    }

    private func selectCredentials(_ byId: DIDURL?, _ andType: String?) throws -> Array<VerifiableCredential>  {
        try checkArgument((byId != nil || andType != nil), "Invalid select args")
        let id: DIDURL? = byId != nil ? try canonicalId(byId!) : nil
        
        var vcs: [VerifiableCredential] = []
        for vc in _credentialDict.values {
            if (id != nil && vc.getId() != id) {
                continue
            }
            if andType != nil && !vc.getTypes().contains(andType!) {
                continue
            }
            
            vcs.append(vc)
        }
        
        return vcs
    }
    
    /// Select the credentials by the specified id or type.
    /// - Parameters:
    ///   - byId: the credential id
    ///   - andType: the credential type
    /// - Returns: an array of the matched credentials
    @objc
    public func selectCredentials(byId: DIDURL, andType: String) throws -> Array<VerifiableCredential>  {
        return try selectCredentials(byId, andType)
    }

    /// Select the credentials by the specified id or type.
    /// - Parameters:
    ///   - byId: the credential id
    /// - Throws: if an error occurred, throw error.
    /// - Returns: an array of the matched credentials
//    @objc
    public func selectCredentials(byId: String) throws -> Array<VerifiableCredential>  {
        return try selectCredentials(byId: try canonicalId(byId)!)
    }

    /// Select the credentials by the specified id or type.
    /// - Parameters:
    ///   - byId: the credential id
    /// - Returns: an array of the matched credentials
    @objc
    public func selectCredentials(byId: DIDURL) throws -> Array<VerifiableCredential>  {
        return try selectCredentials(byId, nil)
    }

    /// Select the credentials by the specified id or type.
    /// - Parameters:
    ///   - byId: the credential id
    ///   - andType: the credential type
    /// - Throws: if an error occurred, throw error.
    /// - Returns: an array of the matched credentials
//    @objc
    public func selectCredentials(byId: String, andType: String) throws -> Array<VerifiableCredential>  {
        return try selectCredentials(byId: try canonicalId(byId)!, andType: andType)
    }
    
    /// Select the credentials by the specified id or type.
    /// - Parameter byType: the credential type
    /// - Returns: an array of the matched credentials
    @objc
    public func selectCredentials(byType: String) throws -> Array<VerifiableCredential>  {
        return try selectCredentials(nil, byType)
    }

    /// Get the specific credential.
    /// - Parameter ofId: the credential id
    /// - Returns: the credential object
    @objc
    public func credential(ofId: DIDURL) -> VerifiableCredential? {
        return _credentialDict[ofId]
    }

    /// Get the specific credential.
    /// - Parameter ofId: the credential id
    /// - Throws: if an error occurred, throw error.
    /// - Returns: the credential object. Otherwise, return nil
    public func credential(ofId: String) throws -> VerifiableCredential? {
        return credential(ofId: try DIDURL(subject, ofId))
    }

    /// Get the specific credential with Object-C
    /// - Parameter ofId: the credential id
    /// - Throws: if an error occurred, throw error.
    /// - Returns: the credential object. Otherwise, return nil
    @objc
    public func credential(ofId: String, error: NSErrorPointer) -> VerifiableCredential? {
        do {
            return credential(ofId: try DIDURL(subject, ofId))
        } catch let aError as NSError {
            error?.pointee = aError
            return nil
        }
    }

    /// Get the numbers of the services.
    @objc
    public var serviceCount: Int {
        return _services.count
    }

    /// Get all the services.
    /// - Returns: an array of the services
    @objc
    public func services() -> Array<Service> {
        return _services
    }

    private func selectServices(_ byId: DIDURL?, _ andType: String?) throws -> Array<Service>  {
        try checkArgument(byId != nil || andType != nil, "Invalid select args")
        
        let id: DIDURL? = byId != nil ? try canonicalId(byId!) : nil
        
        var svcs: [Service] = [ ]
        for svc in _serviceDict.values {
            if (id != nil && svc.getId() != id) {
                continue
            }
            
            if andType != nil && svc.getType() != andType {
                continue
            }
            svcs.append(svc)
        }
        try svcs.sort { (serviceA, serviceB) -> Bool in
            return try serviceA.compareTo(serviceB) == ComparisonResult.orderedAscending
        }
        return svcs
    }
    
    /// Select the services by the specified id or type.
    /// - Parameters:
    ///   - byId: the service id
    ///   - andType: the service type
    /// - Returns: an array of the matched services
    @objc
    public func selectServices(byId: DIDURL, andType: String) throws -> Array<Service>  {
        return try selectServices(byId, andType)
    }

    /// Select the services by the specified id or type.
    /// - Parameters:
    ///   - byId: the service id
    ///   - andType: the service type
    /// - Returns: an array of the matched services
    @objc (selectServicesbyIdString:andType:error:)
    public func selectServices(byId: String, andType: String) throws -> Array<Service>  {
        let id = try DIDURL(subject, byId)
        return try selectServices(byId: id, andType: andType)
    }

    /// Select the services by the specified id or type.
    /// - Parameters:
    ///   - byId: the service id
    /// - Returns: an array of the matched services
    @objc
    public func selectServices(byId: DIDURL) throws -> Array<Service>  {
        return try selectServices(byId, nil)
    }
    
    /// Select the services by the specified id or type.
    /// - Parameters:
    ///   - byId: the service id
    /// - Returns: an array of the matched services
    @objc (selectServicesbyIdString:error:)
    public func selectServices(byId: String) throws -> Array<Service>  {
        let id = try DIDURL(subject, byId)
        return try selectServices(id, nil)
    }

    /// Select the services by the specified id or type.
    /// - Parameters:
    ///   - andType: the service type
    /// - Returns: an array of the matched services
    @objc
    public func selectServices(byType: String) throws -> Array<Service>  {
        return try selectServices(nil, byType)
    }

    /// Get the specific service.
    /// - Parameter ofId: the service id
    /// - Returns: the service object
    @objc
    public func service(ofId: DIDURL) -> Service? {
        return _serviceDict[ofId]
    }

    /// Get the specific service.
    /// - Parameter ofId: the service id
    /// - Returns: the service object
    public func service(ofId: String) throws -> Service? {
        return service(ofId: try DIDURL(subject, ofId))
    }

    /// Get the specific service with Object-C
    /// - Parameter ofId: the service id
    /// - Returns: the service object
    @objc
    public func service(ofId: String, error: NSErrorPointer) -> Service? {
        do {
            return service(ofId: try DIDURL(subject, ofId))
        } catch let aError as NSError {
            error?.pointee = aError
            return nil
        }
    }
    
    /// Get expire time of this DIDDocument.
    @objc
    public var expirationDate: Date? {
        return self._expires
    }

    func setExpirationDate(_ expirationDate: Date) {
        self._expires = expirationDate
    }
    
    /// Get last modified time of this DIDDocument.
    public var lastModified: Date? {
        return proof.createdDate
    }
    
    /// Get signature of this DIDDocumet.
    ///
    /// For single-signed DIDDocument object, the document signature is the
    /// proof's signature. For multi-signed DIDDocument object, the document
    /// signature is the first proof's signature.
    public var signature: String? {
        return proof.signature
    }

    /// Get the proof object of this DIDDocument. if this document is a
    /// multi-signed document, this method returns the first proof object.
    var proof: DIDDocumentProof {
        // Guaranteed that this field would not be nil because the object
        // was generated by "builder".
        return _proofs[0]
    }

    // Get all Proof objects.
    public func proofs() -> [DIDDocumentProof] {
        return _proofs
    }
    
    /// Return the subject DID.
    var serializeContextDid: DID {
        return subject
    }
    
    /// Sanitize routine before sealing or after deserialization.
    /// - Throws: MalformedDocumentError if the document object is invalid
    func sanitize() throws {
        try sanitizeControllers()
        try sanitizePublickKey()
        try sanitizeCredential()
        try sanitizeService()
        guard _expires != nil else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError()
        }
        try sanitizeProof()
    }
    
    private func sanitizeControllers() throws {
        if _controllers.isEmpty {
            _controllers = []
            _controllerDocs = [: ]
            
            guard _multisig == nil else {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Invalid multisig property")
            }
            
            return
        }
        _controllerDocs = [: ]
        do {
            try _controllers.forEach{ did in
                let doc = try did.resolve()
                guard doc != nil else {
                    throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Can not resolve controller: \(did)")
                }
                _controllerDocs[did] = doc
            }
        } catch {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Can not resolve the controller's DID")
        }
        
        if _controllers.count == 1 {
            guard _multisig == nil else {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Invalid multisig property")
            }
        }
        else {
            guard _multisig != nil else {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Missing multisig property")
            }
            
            guard _multisig!.n == _controllers.count else {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Invalid multisig property")
            }
        }

        try _controllers.sort { (didA, didB) -> Bool in
            return try didA.compareTo(didB) == ComparisonResult.orderedAscending
        }

        if _controllers.count == 1 {
            _effectiveController = _controllers[0]
        }
    }
    
    func sanitizePublickKey() throws {
        var pks: [DIDURL: PublicKey] = [: ]
        if  _publickeys.count > 0 {
            try _publickeys.forEach { pk in
                if pk.getId()?.did == nil {
                    pk.getId()!.setDid(subject)
                }
                else {
                    guard pk.getId()?.did == subject else {
                        throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Invalid public key id: \(String(describing: pk.getId()))")
                    }
                }
                guard pks[pk.getId()!] == nil else {
                    throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Public key already exists: \(String(describing: pk.getId()))")
                }
                guard !pk.publicKeyBase58.isEmpty else {
                    throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Invalid public key base58 value.")
                }
                if pk.getType() == nil {
                    pk.setType(Constants.DEFAULT_PUBLICKEY_TYPE)
                }
                if pk.controller == nil {
                    pk.setController(subject)
                }
                pks[pk.getId()!] = pk
            }
        }
        
        if _authentications.count > 0 {
            var pk: PublicKey?
            try _authentications.forEach{ keyRef in
                if keyRef.isVirtual {
                    if keyRef.id?.did == nil {
                        keyRef.id?.setDid(subject)
                    }
                    else {
                        guard keyRef.id?.did == subject else {
                            throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Invalid publicKey id: \(String(describing: keyRef.id))")
                        }
                    }
                    pk = pks[keyRef.id!]
                    guard pk != nil else {
                        throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Not exists publicKey reference: \(String(describing: keyRef.id))")
                    }
                    try keyRef.update(pk!)
                }
                else {
                    pk = keyRef.publicKey
                    if keyRef.id?.did == nil {
                        keyRef.id?.setDid(subject)
                    }
                    else {
                        guard keyRef.id?.did != nil else {
                            throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Invalid publicKey id: \(String(describing: keyRef.id))")
                        }
                    }
                    guard pks[pk!.getId()!] == nil else {
                        throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Public key already exists: \(String(describing: pk?.getId()))")
                    }
                    guard pk?.publicKeyBase58 != nil || !pk!.publicKeyBase58.isEmpty else {
                        throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Invalid public key base58 value.")
                    }
                    if pk?.getType() == nil {
                        pk?.setType(Constants.DEFAULT_PUBLICKEY_TYPE)
                    }
                    if pk?.controller == nil {
                        pk?.setController(subject)
                    }
                    pks[pk!.getId()!] = pk!
                }
                _authenticationKeys[pk!.getId()!] = pk
            }
        }
        else {
            _authentications = [ ]
            _authenticationKeys = [: ]
        }
        if _authorizations.count > 0 {
            var pk: PublicKey?
            
            try _authorizations.forEach { keyRef in
                if keyRef.isVirtual {
                    if keyRef.id?.did == nil {
                        keyRef.id?.setDid(subject)
                    }
                    else {
                        guard keyRef.id?.did == subject else {
                            throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Invalid publicKey id: \(String(describing: keyRef.id))")
                        }
                    }
                    pk = pks[keyRef.id!]
                    guard pk != nil else {
                        throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Not exists publicKey reference: \(String(describing: keyRef.id))")
                    }
                    try keyRef.update(pk!)
                }
                else {
                    pk = keyRef.publicKey
                    if keyRef.id?.did == nil {
                        keyRef.id?.setDid(subject)
                    }
                    else {
                        guard keyRef.id?.did == subject else {
                            throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Invalid publicKey id: \(String(describing: keyRef.id))")
                        }
                    }
                    guard (pks[pk!.getId()!] == nil) else {
                        throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Public key already exists: \(String(describing: pk?.getId()))")
                    }
                    if pk?.publicKeyBase58 == nil || pk!.publicKeyBase58.isEmpty {
                        throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Invalid public key base58 value.")
                    }
                    if pk?.getType() == nil {
                        pk?.setType(Constants.DEFAULT_PUBLICKEY_TYPE)
                    }
                    guard pk?.controller != nil else {
                        throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Public key missing controller: \(String(describing: pk?.getId()))")
                    }
                    if pk!.controller == subject {
                        throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Authorization key with wrong controller: \(String(describing: pk?.getId()))")
                    }
                    pks[pk!.getId()!] = pk!
                }
                _authorizationKeys[pk!.getId()!] = pk
            }
        }
        else {
            _authorizations = [ ]
            _authorizationKeys = [: ]
        }
        // for customized DID with controller, could be no public keys
        if pks.count > 0 {
            self._publicKeyDict = pks
            self._publickeys.removeAll()
            pks.values.forEach { pk in
                self._publickeys.append(pk)
            }
        }
        else {
            self._publicKeyDict = [: ]
            self._publickeys = [ ]
        }
        try _publickeys.sort { (publicKeyA, publicKeyB) -> Bool in
            return try publicKeyA.compareTo(publicKeyB) == ComparisonResult.orderedAscending
        }
        
        // Find default key
        for pk in _publicKeyDict.values {
            if pk.controller == subject {
                let address = DIDHDKey.toAddress(pk.publicKeyBytes)
                if address == subject.methodSpecificId {
                    _defaultPublicKey = pk
                    let value = _authenticationKeys[pk.getId()!]
                    if value == nil {
                        if _authentications.isEmpty {
                            _authenticationKeys = [: ]
                        }

                        _authentications.append(PublicKeyReference(pk))
                        _authenticationKeys[pk.getId()!] = pk
                        try _authentications.sort { (publicKeyReferenceA, publicKeyReferenceB) -> Bool in
                            return try publicKeyReferenceA.compareTo(publicKeyReferenceB) == ComparisonResult.orderedAscending
                        }
                    }
                }
            }
        }
        if _controllers.isEmpty && _defaultPublicKey == nil {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Missing default public key.")
        }
    }
    
    private func sanitizeCredential() throws {
        if _credentials.isEmpty {
            _credentials = [ ]
            _credentialDict = [: ]
            return
        }
        
        var vcs: [DIDURL: VerifiableCredential] = [: ]
         try _credentials.forEach { vc in
            guard let _ = vc.getId() else {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Missing credential id.")
            }
            if vc.getId()!.did == nil {
                vc.getId()!.setDid(subject)
            }
            else {
                guard vc.getId()!.did == subject else {
                    throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Invalid crdential id: \(String(describing: vc.getId()))")
                }
            }
            
            guard vcs[vc.getId()!] == nil else {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Credential already exists: \(String(describing: vc.getId()))")
            }
            if vc.subject?.did == nil {
                vc.subject!.setId(subject)
            }
            
            do {
               try vc.sanitize()
            }
            catch {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Invalid credential: \(String(describing: vc.getId()))")
            }
            vcs[vc.getId()!] = vc
        }
                
        self._credentialDict = vcs
        _credentials.removeAll()
        _credentialDict.values.forEach { vc in
            _credentials.append(vc)
        }
        
        try _credentials.sort { (vcA, vcB) -> Bool in
            return try vcA.compareTo(vcB) == ComparisonResult.orderedAscending
        }
        
        try _authorizations.sort { (publicKeyReferenceA, publicKeyReferenceB) -> Bool in
            return try publicKeyReferenceA.compareTo(publicKeyReferenceB) == ComparisonResult.orderedAscending
        }
    }
    
    private func sanitizeService() throws {
        if _services.isEmpty {
            return
        }
        var svcs: [DIDURL: Service] = [: ]
        try _services.forEach { svc in
            if svc.getId()?.did == nil {
                svc.getId()!.setDid(subject)
            }
            else {
                guard svc.getId()!.did == subject else {
                    throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Invalid crdential id: \(String(describing: svc.getId()))")
                }
            }
            guard !svc.getType()!.isEmpty else {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Invalid service type.")
            }
            guard !svc.endpoint.isEmpty else {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Missing service endpoint.")
            }
            guard svcs[svc.getId()!] == nil else {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Service already exists: \(String(describing: svc.getId()))")
            }
            svcs[svc.getId()!] = svc
        }
        self._serviceDict = svcs
        _services.removeAll()
        svcs.values.forEach { service in
            _services.append(service)
        }
        try _services.sort { (serviceA, serviceB) -> Bool in
            return try serviceA.compareTo(serviceB) == ComparisonResult.orderedAscending
        }
    }
    
    private func sanitizeProof() throws {
        guard _proofs.isEmpty == false else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Missing document proof")
        }
        
        try _proofs.forEach { proof in
            if proof.creator == nil {
                if defaultPublicKey() != nil {
                    proof.setCreator(_defaultPublicKey!.getId()!)
                }
                else if _controllers.count == 1 {
                    proof.setCreator(_controllerDocs[_controllers[0]]!.defaultPublicKeyId()!)
                }
                else {
                    throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Missing creator key.")
                }
            }
            else {
                if proof.creator?.did == nil {
                    if _defaultPublicKey != nil {
                        proof.creator!.setDid(subject)
                    }
                    else if _controllers.count == 1 {
                        proof.creator!.setDid(_controllers[0])
                    }
                    else {
                        throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Invalid creator key.")
                    }
                }
            }

            if _proofsDict[proof.creator!.did!] != nil {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedDocumentError("Aleady exist proof from \(String(describing: proof.creator?.did))")
            }
            
            _proofsDict[proof.creator!.did!] = proof
        }
        self._proofs.removeAll()
        _proofsDict.values.forEach { proof in
            _proofs.append(proof)
        }
        
        // sort
        _proofs.sort { (proofA, proofB) -> Bool in

            let compareResult = DateFormatter.convertToUTCStringFromDate(proofA.createdDate)
                .compare(DateFormatter.convertToUTCStringFromDate(proofB.createdDate))
            if compareResult == ComparisonResult.orderedSame {

                return proofA.creator!.compareTo(proofB.creator!) == ComparisonResult.orderedAscending
            } else {
                return compareResult == ComparisonResult.orderedDescending
            }
        }
    }
    
    /// Set the metadata object for this DIDDocument.
    /// - Parameter metadata: a DIDMetadata object
    func setMetadata(_ metadata: DIDMetadata) {
        self._metadata = metadata
        subject.setMetadata(metadata)
    }

    /// Get the metadata object of this DIDDocument.
    /// - Returns: the DIDMetadata object
    @objc
    public func getMetadata() -> DIDMetadata {
        if _metadata == nil {

            _metadata = DIDMetadata(subject)
        }

        return _metadata!
    }

    var store: DIDStore? {
        return getMetadata().store
    }

    ///
    /// Check if this DIDDocument is deactivated.
    /// true if deactivated, false otherwise
    @objc
    public var isDeactivated: Bool {
        return getMetadata().isDeactivated
    }

    /// Check if this DIDDocument is expired.
    /// true if expired, false otherwise
    @objc
    public var isExpired: Bool {
        return DateFormatter.isExipired(self.expirationDate!)
    }

    /// Check is this DIDDocument is genuine.
    /// true if genuine, false otherwise
    public func isGenuine() throws -> Bool {
        return try isGenuine(nil)
    }
    
    /// Check is this DIDDocument is genuine.
    /// - Parameter listener: the listener for the verification events and messages
    /// true if genuine, false otherwise
    public func isGenuine(listener: VerificationEventListener) throws -> Bool {
        return try isGenuine(listener)
    }
    
    /// Check is this DIDDocument is genuine.
    /// - Parameter listener: the listener for the verification events and messages
    /// true if genuine, false otherwise
    func isGenuine(_ listener: VerificationEventListener?) throws -> Bool {
        // Proofs count should match with multisig
        let expectedProofs = _multisig == nil ? 1 : _multisig!.m
        if _proofsDict.count != expectedProofs {
            listener?.failed(context: self, args: "\(subject): proof size not matched with multisig, \(String(describing: multiSignature?.m)) expected, actual is \(_proofsDict.count)")
            listener?.failed(context: self, args: "\(subject): is not genuine")
            return false
        }
        let doc = DIDDocument(self, false)
        let json = doc.toString(true)
        let jsonData = json.data(using: .utf8)
        let digest = sha256Digest([jsonData!])
        
        // Document should signed(only) by default public key.
        if !isCustomizedDid() {
            let proof = self.proof
            // Unsupported public key type;
            guard proof.type == Constants.DEFAULT_PUBLICKEY_TYPE else {
                listener?.failed(context: self, args: "\(subject): key type '\(proof.type)' for proof is not supported")
                listener?.failed(context: self, args: "\(subject): is not genuine")
                return false
            }
            
            guard proof.creator == defaultPublicKeyId() else {
                listener?.failed(context: self, args: "\(subject): key '\(String(describing: proof.creator))' for proof is not default key")
                listener?.failed(context: self, args: "\(subject): is not genuine")
                return false
            }
            let result = try verifyDigest(withId: proof.creator!, using: proof.signature, for: digest)
            if (result) {
                listener?.succeeded(context: self, args: "\(subject): is genuine")
            } else {
                listener?.failed(context: self, args: "\(subject): can not verify the signature")
                listener?.failed(context: self, args: "\(subject): is not genuine")
            }
            
            return result
        }
        else {
            for proof in _proofs {
                // Unsupported public key type;
                guard proof.type == Constants.DEFAULT_PUBLICKEY_TYPE else {
                    listener?.failed(context: self, args: "\(subject): key type '\(proof.type)' for proof is not supported")
                    listener?.failed(context: self, args: "\(subject): is not genuine")
                    
                    return false
                }
                let controllerDoc = controllerDocument(proof.creator!.did!)
                guard controllerDoc != nil else {
                    listener?.failed(context: self, args: "\(subject): can not resolve the document for controller '\(String(describing: proof.creator?.did))' to verify the proof")
                    listener?.failed(context: self, args: "\(subject): is not genuine")
                    
                    return false
                }
                guard try controllerDoc!.isGenuine() else {
                    listener?.failed(context: self, args: "\(subject): controller '\(String(describing: proof.creator?.did))' is not genuine, failed to verify the proof")
                    listener?.failed(context: self, args: "\(subject): is not genuine")
                    
                    return false
                }
                guard proof.creator == controllerDoc!.defaultPublicKeyId() else {
                    listener?.failed(context: self, args: "\(subject): key '\(String(describing: proof.creator))' for proof is not default key of '\(String(describing: proof.creator?.did))'")
                    listener?.failed(context: self, args: "\(subject): is not genuine")
                    
                    return false
                }
                guard try controllerDoc!.verifyDigest(withId: proof.creator!, using: proof.signature, for: digest) else {
                    listener?.failed(context: self, args: "\(subject): proof '\(String(describing: proof.creator))' is invalid, signature mismatch")
                    listener?.failed(context: self, args: "\(subject): is not genuine")
                    
                    return false
                }
            }
            
            listener?.succeeded(context: self, args: "\(subject): is genuine")
            
            return true
        }
    }
    
    /// Check if this DIDDocument is qualified. It means the proof matched
    /// With the multisig specification.
    /// - Returns: true if qualified, false otherwise
    public func isQualified() -> Bool {
        guard _proofs.count != 0 else {
            return false
        }
        
        return _proofs.count == (_multisig == nil ? 1 : _multisig!.m)
    }

    /// Check if this DIDDocument is valid.
    /// true if valid, false otherwise
    public func isValid() throws -> Bool {
        return try isValid(nil)
    }
    
    /// Check if this DIDDocument is valid.
    /// - Parameter listener: the listener for the verification events and messages
    /// true if valid, false otherwise
    public func isValid(listener: VerificationEventListener) throws -> Bool {
        return try isValid(listener)
    }
    
    /// Check if this DIDDocument is valid.
    /// true if valid, false otherwise
    func isValid(_ listener: VerificationEventListener?) throws -> Bool {
        if (isDeactivated) {
            listener?.failed(context: self, args: "\(subject): is deactivated")
            listener?.failed(context: self, args: "\(subject): is invalid")
            return false
        }
        
        if (isExpired) {
            listener?.failed(context: self, args: "\(subject): is expired")
            listener?.failed(context: self, args: "\(subject): is invalid")
            
            return false
        }
        
        if (try !isGenuine(listener)) {
            listener?.failed(context: self, args: "\(subject): is invalid")
            return false
        }
        
        if hasController() {
            for doc in _controllerDocs.values {
                if (doc.isDeactivated) {
                    listener?.failed(context: self, args: "\(subject): controller \(doc.subject)' is deactivated")
                    listener?.failed(context: self, args: "\(subject): is invalid")
                    
                    return false
                }
                
                if try !doc.isGenuine(listener) {
                    listener?.failed(context: self, args: "\(subject): controller '\(doc.subject)' is not genuine")
                    listener?.failed(context: self, args: "\(subject): is invalid")
                    
                    return false
                }
            }
        }
        listener?.succeeded(context: self, args: "\(subject): is valid")
        
        return true
    }
    
    func copy() throws -> DIDDocument {
        let doc = DIDDocument(subject)
        doc._context = _context
        doc._controllers = _controllers.copy()
        doc._controllerDocs = _controllerDocs.copy()
        if self._multisig != nil {
            doc._multisig = try MultiSignature(_multisig!)
        }
        doc._publicKeyDict = _publicKeyDict.copy()
        
        doc._defaultPublicKey = _defaultPublicKey
        doc._credentialDict = _credentialDict.copy()
        doc._authenticationKeys = _authenticationKeys.copy()
        doc._authorizationKeys = _authorizationKeys.copy()
        doc._serviceDict = _serviceDict.copy()
        doc._expires = _expires
        doc._proofsDict = _proofsDict.copy()
        let metadata = try getMetadata().clone()
        doc.setMetadata(metadata)
        
        return doc
    }

    /// Get DIDDocument Builder object to editing this DIDDocument.
    /// - Returns: the DIDDocumentBuilder object
    @objc
    public func editing() throws -> DIDDocumentBuilder {
        if !isCustomizedDid() {
            try checkAttachedStore()
            return try DIDDocumentBuilder(self)
        }
        guard effectiveController != nil else {
            throw DIDError.UncheckedError.IllegalStateError.NoEffectiveControllerError()
        }
        return try editing(effectiveControllerDocument()!)
    }

    /// Get DIDDocument Builder object to editing this DIDDocument.
    /// - Parameter controller: the effective controller to editing a customized DIDDocument
    /// - Returns: the DIDDocumentBuilder object
    @objc
    public func editing(_ controller: DIDDocument) throws -> DIDDocumentBuilder {
        try checkIsCustomized()
        if !getMetadata().attachedStore && !controller.getMetadata().attachedStore {
            throw DIDError.UncheckedError.IllegalStateError.NotAttachedWithStoreError()
        }
        if controller.getMetadata().attachedStore {
            controller.getMetadata().attachStore(getMetadata().store!)
        }
        
        guard hasController(controller.subject) else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.NotControllerError(controller.subject.toString())
        }
        
        return try DIDDocumentBuilder(self, controller)
    }
    
    /// Sign the data by the specified key.
    /// SDK will get default key from DID
    /// - Parameters:
    ///   - storePassword: the password for the DIDStore
    ///   - data: the data be signed
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the signature string
    public func sign(using storePassword: String, for data: Data...) throws -> String {
        return try sign(self.defaultPublicKeyId()!, storePassword, data)
    }

    /// Sign the data by the specified key.
    /// SDK will get default key from DID
    /// - Parameters:
    ///   - storePassword: the password for the DIDStore
    ///   - data: the data be signed
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the signature string
    @objc
    public func sign(using storePassword: String, for data: [Data]) throws -> String {
        return try sign(self.defaultPublicKeyId()!, storePassword, data)
    }

    /// Sign the data by the specified key.
    /// - Parameters:
    ///   - withId: the key id to sign the data
    ///   - storePassword: the password for the DIDStore
    ///   - data: the data be signed
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the signature string
    public func sign(withId: DIDURL, using storePassword: String, for data: Data...) throws -> String {
        return try sign(withId, storePassword, data)
    }

    /// Sign the data by the specified key.
    /// - Parameters:
    ///   - withId: the key id to sign the data
    ///   - storePassword: the password for the DIDStore
    ///   - data: the data be signed
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the signature string
    @objc
    public func sign(withId: DIDURL, using storePassword: String, for data: [Data]) throws -> String {
        return try sign(withId, storePassword, data)
    }

    /// Sign the data by the specified key.
    /// - Parameters:
    ///   - withId: the key id to sign the data
    ///   - storePassword: the password for the DIDStore
    ///   - data: the data be signed
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the signature string
    public func sign(withId: String, using storePassword: String, for data: Data...) throws -> String {
        return try sign(try DIDURL(self.subject, withId), storePassword, data)
    }

    /// Sign the data by the specified key.
    /// - Parameters:
    ///   - withId: the key id to sign the data
    ///   - storePassword: the password for the DIDStore
    ///   - data: the data be signed
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the signature string
    @objc(sign:storePassword:data:error:)
    public func sign(withId: String, using storePassword: String, for data: [Data]) throws -> String {
        return try sign(try DIDURL(self.subject, withId), storePassword, data)
    }

    func sign(_ id: DIDURL, _ storePassword: String, _ data: [Data]) throws -> String {
        try checkArgument(!data.isEmpty, "Invalid data.")
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        let digest = sha256Digest(data)
        return try signDigest(withId: id, using: storePassword, for: digest)
    }

    /// Sign the digest by the specified key.
    /// SDK will get default key from DID
    /// - Parameters:
    ///   - storePassword: the password for the DIDStore
    ///   - digest: the data digest to be signed
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the signature string
    @objc
    public func signDigest(using storePassword: String, for digest: Data) throws -> String {
        return try signDigest(withId: self.defaultPublicKeyId()!, using: storePassword, for: digest)
    }

    /// Sign the digest by the specified key.
    /// - Parameters:
    ///   - withId: the key id to sign the data
    ///   - storePassword: the password for the DIDStore
    ///   - digest: the data digest to be signed
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the signature string
    @objc
    public func signDigest(withId: DIDURL, using storePassword: String, for digest: Data) throws -> String {
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        try checkAttachedStore()
        
        return try getMetadata().store!.sign(WithId: withId, using: storePassword, for: digest, digest.count * 3)
    }
    
    func sha256Digest(_ data: [Data]) -> Data {
        var cinputs: [CVarArg] = []
        var capacity: Int = 0
        data.forEach { data in
            let json = String(data: data, encoding: .utf8)
            if json != "" {
                let cjson = json!.toUnsafePointerInt8()!
                cinputs.append(cjson)
                cinputs.append(json!.lengthOfBytes(using: .utf8))
                capacity += json!.count * 3
            }
        }

        let c_inputs = getVaList(cinputs)
        let count = cinputs.count / 2
        _capacity = capacity
        
        // digest
        let cdigest = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
        let size = sha256v_digest(cdigest, Int32(count), c_inputs)
        let cdigestPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: cdigest, count: size)

        return Data(buffer: cdigestPointerToArry)
    }

    /// Sign the digest by the specified key.
    /// - Parameters:
    ///   - withId: the key id to sign the data
    ///   - storePassword: the password for the DIDStore
    ///   - digest: the data digest to be signed
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the signature string
    @objc(signDigest:storePassword:digest:error:)
    public func signDigest(withId: String, using storePassword: String, for digest: Data) throws -> String {
        let _id = try DIDURL(subject, withId)

        return try signDigest(withId: _id, using: storePassword, for: digest)
    }

    /// verify data.
    /// SDK will get default key from DID
    /// - Parameters:
    ///   - signature: Signature data.
    ///   - data: To verify of data list
    /// - Throws: If no error occurs, throw error.
    /// - Returns: True on success, or false.
    public func verify(signature: String, onto data: Data...) throws -> Bool {
        return try verify(self.defaultPublicKeyId()!, signature, data)
    }

    /// Verify the signature by the specific key and the data.
    /// SDK will get default key from DID
    /// - Parameters:
    ///   - signature: the signature string
    ///   - data: the data to be checked
    /// - Returns: true if the signature was verified, false otherwise
    @objc
    public func verify(signature: String, onto data: [Data], error: NSErrorPointer) -> Bool {
        do {
            return try verify(self.defaultPublicKeyId()!, signature, data)
        } catch let aError as NSError {
            error?.pointee = aError
            return false
        }
    }

    /// Verify the signature by the specific key and the data.
    /// - Parameters:
    ///   - withId: the key id
    ///   - signature: the signature string
    ///   - data: the data to be checked
    /// - Throws: if no error occurs, throw error.
    /// - Returns: true if the signature was verified, false otherwise
    public func verify(withId: DIDURL, using signature: String, onto data: Data...) throws -> Bool {
        return try verify(withId, signature, data)
    }

    /// Verify the signature by the specific key and the data with Object-C
    /// - Parameters:
    ///   - withId: the key id
    ///   - signature: the signature string
    ///   - data: the data to be checked
    /// - Throws: if no error occurs, throw error.
    /// - Returns: true if the signature was verified, false otherwise
    @objc
    public func verifyUsingObjectC(withId: DIDURL, using signature: String, onto data: [Data], error: NSErrorPointer) -> Bool {
        do {
            return try verify(withId, signature, data)
        } catch let aError as NSError {
            error?.pointee = aError
            return false
        }
    }

    /// Verify the signature by the specific key and the data.
    /// - Parameters:
    ///   - withId: the key id
    ///   - signature: the signature string
    ///   - data: the data to be checked
    /// - Throws: if no error occurs, throw error.
    /// - Returns: true if the signature was verified, false otherwise
    public func verify(withId: String, using signature: String, onto data: Data...) throws -> Bool {
        return try verify(DIDURL(self.subject, withId), signature, data)
    }

    /// Verify the signature by the specific key and the data.
    /// - Parameters:
    ///   - withId: the key id
    ///   - signature: the signature string
    ///   - data: the data to be checked
    /// - Throws: if no error occurs, throw error.
    /// - Returns: true if the signature was verified, false otherwise
    @objc
    public func verify(withId: String, using signature: String, onto data: [Data], error: NSErrorPointer) -> Bool {
        do {
            return try verify(DIDURL(self.subject, withId), signature, data)
        } catch let aError as NSError {
            error?.pointee = aError
            return false
        }
    }

    func verify(_ id: DIDURL, _ sigature: String, _ data: [Data]) throws -> Bool {
        try checkArgument(!data.isEmpty, "Invalid data.")
        try checkArgument(!sigature.isEmpty, "Invalid sigature.")

        let digest = sha256Digest(data)

        return try verifyDigest(withId: id, using: sigature, for: digest)
    }

    /// Verify the signature by the specific key and the data digest.
    /// SDK will get default key from DID
    /// - Parameters:
    ///   - signature: the signature string
    ///   - digest: the data to be checked
    /// - Throws: if no error occurs, throw error.
    /// - Returns: true if the signature was verified, false otherwise
    public func verifyDigest(signature: String, for digest: Data) throws -> Bool {

        return try verifyDigest(withId: self.defaultPublicKeyId()!, using: signature, for: digest)
    }

    /// Verify the signature by the specific key and the data digest with Object-C
    /// SDK will get default key from DID
    /// - Parameters:
    ///   - signature: the signature string
    ///   - digest: the data to be checked
    /// - Throws: if no error occurs, throw error.
    /// - Returns: true if the signature was verified, false otherwise
    @objc
    public func verifyDigest(signature: String, for digest: Data, error: NSErrorPointer) -> Bool {
        do {
            return try verifyDigest(withId: self.defaultPublicKeyId()!, using: signature, for: digest)
        } catch let aError as NSError {
            error?.pointee = aError
            return false
        }
    }

    /// Verify the signature by the specific key and the data digest.
    /// - Parameters:
    ///   - withId: the key id
    ///   - signature: the signature string
    ///   - digest: the data digest to be checked
    /// - Throws: if no error occurs, throw error.
    /// - Returns: true if the signature was verified, false otherwise
    public func verifyDigest(withId: DIDURL, using signature: String, for digest: Data) throws -> Bool {
        try checkArgument(!signature.isEmpty, "Invalid sigature.")
        try checkArgument(!digest.isEmpty, "Invalid digest.")

        let pk = try publicKey(ofId: withId)
        guard let _ = pk else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError(withId.toString())
        }

        let pks = pk!.publicKeyBytes
        let pkData = Data(bytes: pks, count: pks.count)
        let cpk = pkData.withUnsafeBytes { (pk: UnsafePointer<UInt8>) -> UnsafePointer<UInt8> in
            return pk
        }
        let cdigest = digest.toPointer()
        let size: Int = digest.count
        let csignature = signature.toUnsafeMutablePointerInt8()
        let re = ecdsa_verify_base64(csignature, cpk, UnsafeMutablePointer(mutating: cdigest), size)

        return re == 0 ? true : false
    }

    /// Verify the signature by the specific key and the data digest.
    /// - Parameters:
    ///   - withId: the key id
    ///   - signature: the signature string
    ///   - digest: the data digest to be checked
    /// - Throws: if no error occurs, throw error.
    /// - Returns: true if the signature was verified, false otherwise
    @objc
    public func verifyDigest(withId: DIDURL, using signature: String, for digest: Data, error: NSErrorPointer) -> Bool {
        do {
            return try verifyDigest(withId: withId, using: signature, for: digest)
        } catch let aError as NSError {
            error?.pointee = aError
            return false
        }
    }

    /// Verify the signature by the specific key and the data digest.
    /// - Parameters:
    ///   - id: the key id
    ///   - signature: the signature string
    ///   - digest: the data digest to be checked
    /// - Throws: if no error occurs, throw error.
    /// - Returns: true if the signature was verified, false otherwise
    public func verifyDigest(withId id: String, using signature: String, for digest: Data) throws -> Bool {
        let _id = try DIDURL(subject, id)

        return try verifyDigest(withId: _id, using: signature, for: digest)
    }

    /// Verify the signature by the specific key and the data digest.
    /// - Parameters:
    ///   - id: the key id
    ///   - signature: the signature string
    ///   - digest: the data digest to be checked
    /// - Throws: if no error occurs, throw error.
    /// - Returns: true if the signature was verified, false otherwise
    @objc(verifyDigest:signature:digest:error:)
    public func verifyDigest(withId id: String, using signature: String, for digest: Data, error: NSErrorPointer) -> Bool {
        do {
            return try verifyDigest(withId: id, using: signature, for: digest)
        } catch let aError as NSError {
            error?.pointee = aError
            return false
        }
    }
    
    /// Create a new customized DID using current DID as the controller.
    /// - Parameters:
    ///   - did: the new customized identifier
    ///   - force: do not try to resolving the DID, create the document directly
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDResolveError if an error occurred when resolving the DIDs
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the new created DIDDocument
    public func newCustomizedDid(withId did: DID, _ force: Bool, _ storePassword: String) throws -> DIDDocument {
        return try newCustomizedDid(did, nil, 1, force, storePassword)
    }
    
    /// Create a new customized DID using current DID as the controller.
    /// - Parameters:
    ///   - did: the new customized identifier
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDResolveError if an error occurred when resolving the DIDs
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the new created DIDDocument
    public func newCustomizedDid(withId did: DID, _ storePassword: String) throws -> DIDDocument {
        return try newCustomizedDid(withId: did, false, storePassword)
    }
    
    /// Create a new customized DID using current DID as the controller.
    /// - Parameters:
    ///   - did: the new customized identifier
    ///   - force: do not try to resolving the DID, create the document directly
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDResolveError if an error occurred when resolving the DIDs
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the new created DIDDocument
    public func newCustomizedDid(withId did: String, _ force: Bool, _ storePassword: String) throws -> DIDDocument {
        return try newCustomizedDid(DID.valueOf(did)!, nil, 1, force, storePassword)
    }
    
    /// Create a new customized DID using current DID as the controller.
    /// - Parameters:
    ///   - did: the new customized identifier
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDResolveError if an error occurred when resolving the DIDs
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the new created DIDDocument
    public func newCustomizedDid(withId did: String, _ storePassword: String) throws -> DIDDocument {
        return try newCustomizedDid(withId: did, false, storePassword)
    }
    
    private func newCustomizedDid(_ did: DID, _ controllers: [DID]?, _ multisig: Int, _ force: Bool, _ storePassword: String) throws -> DIDDocument {
        
        try checkAttachedStore()
        var ctrls: [DID] = []
        if controllers != nil && controllers!.count > 0 {
            controllers?.forEach{ ctrl in
                if ctrl != subject && !ctrls.contains(ctrl) {
                    ctrls.append(ctrl)
                }
            }
        }
        
       try checkArgument(multisig >= 0 && multisig <= ctrls.count + 1, "Invalid multisig")
        // TODO: LOG
        var doc: DIDDocument?
        if !force {
            doc = try did.resolve()
            guard doc == nil else {
                throw DIDError.UncheckedError.IllegalStateError.DIDAlreadyExistError(did.toString())
            }
        }
        // TODO: LOG
        let db = try DIDDocumentBuilder(did, self, store!)
        try ctrls.forEach { ctrl in
            _ = try db.appendController(with: ctrl)
        }
        _ = try db.setMultiSignature(multisig)
        do {
            doc = try db.seal(using: storePassword)
            try store!.storeDid(using: doc!)
            return doc!
        } catch {
            throw DIDError.UncheckedError.IllegalStateError.UnknownInternalError(error.localizedDescription)
        }
    }
    
    /// Create a new customized DID using current DID as the controller.
    /// - Parameters:
    ///   - did: the new customized identifier
    ///   - controllers: the other controllers for the new customized DID
    ///   - multisig: how many signatures are required
    ///   - force: do not try to resolving the DID, create the document directly
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDResolveException if an error occurred when resolving the DIDs
    /// - Throws DIDStoreException if an error occurred when accessing the store
    /// - Returns: the new created DIDDocument
    public func newCustomizedDid(withId did: DID, _ controllers: [DID], _ multisig: Int, _ force: Bool, _ storePassword: String) throws -> DIDDocument {
        return try newCustomizedDid(did, controllers, multisig, force, storePassword)
    }
    
    /// Create a new customized DID using current DID as the controller.
    /// - Parameters:
    ///   - did: the new customized identifier
    ///   - controllers: the other controllers for the new customized DID
    ///   - multisig: how many signatures are required
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDResolveException if an error occurred when resolving the DIDs
    /// - Throws DIDStoreException if an error occurred when accessing the store
    /// - Returns: the new created DIDDocument
    public func newCustomizedDid(withId did: DID, _ controllers: [DID], _ multisig: Int, _ storePassword: String) throws -> DIDDocument {
        
        return try newCustomizedDid(did, controllers, multisig, false, storePassword)
    }
    
    /// Create a new customized DID using current DID as the controller.
    /// - Parameters:
    ///   - did: the new customized identifier
    ///   - controllers: the other controllers for the new customized DID
    ///   - multisig: how many signatures are required
    ///   - force: do not try to resolving the DID, create the document directly
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDResolveException if an error occurred when resolving the DIDs
    /// - Throws DIDStoreException if an error occurred when accessing the store
    /// - Returns: the new created DIDDocument
    public func newCustomizedDid(withId did: String, _ controllers: [String], _ multisig: Int, _ force: Bool, _ storePassword: String) throws -> DIDDocument {
        var _controllers: [DID] = []
        try controllers.forEach { ctrl in
           try _controllers.append(DID(ctrl))
        }
        
        return try newCustomizedDid(DID.valueOf(did)!, _controllers, multisig, force, storePassword)
    }
    
    /// Create a new customized DID using current DID as the controller.
    /// - Parameters:
    ///   - did: the new customized identifier
    ///   - controllers: the other controllers for the new customized DID
    ///   - multisig: how many signatures are required
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDResolveException if an error occurred when resolving the DIDs
    /// - Throws DIDStoreException if an error occurred when accessing the store
    /// - Returns: the new created DIDDocument
    public func newCustomizedDid(withId did: String, _ controllers: [String], _ multisig: Int, _ storePassword: String) throws -> DIDDocument {
        
        return try newCustomizedDid(withId: did, controllers, multisig, false, storePassword)
    }
    
    /// Create a TransferTicket object for the this (customized) DIDDocument.
    /// The document should have an effective controller, otherwise this method
    /// will fail.
    /// - Parameters:
    ///   - did: who the did will transfer to
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDResolveError if an error occurred when resolving the DIDs
    /// - Throws DIDStoreError if an error occurred when accessing the store
    /// - Returns: the TransferTicket object
    public func createTransferTicket(to did: DID, using storePassword: String) throws -> TransferTicket {
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        try checkIsCustomized()
        try checkAttachedStore()
        try checkHasEffectiveController()
        let ticket = try TransferTicket(self, did)
        try ticket.seal(effectiveControllerDocument()!, storePassword)
        
        return ticket
    }
    
    /// Create a TransferTicket object for the this (customized) DIDDocument.
    /// The document should have an effective controller, otherwise this method
    /// will fail.
    /// - Parameters:
    ///   - did: the target customized DID to be transfer
    ///   - to: who the did will transfer to
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDResolveError if an error occurred when resolving the DIDs
    /// - Throws DIDStoreError if an error occurred when accessing the store
    /// - Returns: the TransferTicket object
    public func createTransferTicket(withId did: DID, to: DID, using storePassword: String) throws -> TransferTicket {
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        try checkIsPrimitive()
        try checkAttachedStore()
        
        let target = try did.resolve()
        guard target != nil else {
            throw DIDError.UncheckedError.IllegalStateError.DIDNotFoundError(did.toString())
        }
        guard !target!.isDeactivated else {
            throw DIDError.UncheckedError.IllegalStateError.DIDDeactivatedError(did.toString())
        }
        guard target!.isCustomizedDid() else {
            throw DIDError.UncheckedError.IllegalStateError.NotCustomizedDIDError(did.toString())
        }
        guard target!.hasController(subject) else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.NotControllerError(did.toString())
        }
        let ticket = try TransferTicket(target!, to)
        try ticket.seal(self, storePassword)
        return ticket
    }
    
    /// Sign and seal the TransferTicket object. The current DID should be
    /// the controller of the DID that the TransferTicket to be transfer.
    /// - Parameters:
    ///   - ticket: the TransferTicket object to be sign
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the signed TransferTicket object
    public func sign(with ticket: TransferTicket, using storePassword: String) throws -> TransferTicket {
        
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        try checkAttachedStore()
        try ticket.seal(self, storePassword)
        
        return ticket
    }
    
    /// Sign and seal the customized DIDDocument object. The current DID should
    /// be the controller of the target DIDDocument.
    /// - Parameters:
    ///   - doc: the customized DIDDocument object to be sign
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Returns: the signed DIDDocument object
    public func sign(with doc: DIDDocument, using storePassword: String) throws -> DIDDocument {
        
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        try checkAttachedStore()
        guard doc.isCustomizedDid() else {
            throw DIDError.UncheckedError.IllegalStateError.NotCustomizedDIDError(doc.subject.toString())
        }
        guard doc.isCustomizedDid() else {
            throw DIDError.UncheckedError.IllegalStateError.NotCustomizedDIDError(doc.subject.toString())
        }
        
        guard doc.hasController(subject) else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.NotControllerError(subject.toString())
        }
        guard doc._proofsDict[subject] == nil else {
            throw DIDError.UncheckedError.IllegalStateError.AlreadySignedError(subject.toString())
        }
        let builder = try doc.editing(self)
        do {
            return try builder.seal(using: storePassword)
        } catch {
            throw DIDError.UncheckedError.IllegalStateError.AlreadySignedError(subject.toString())
        }
    }
    
    private func publish(_ ticket: TransferTicket, _ signKey: DIDURL?, _ storePassword: String, _ adapter: DIDTransactionAdapter?) throws {
        var sigK = signKey
        try checkArgument(ticket.isValid(), "Invalid ticket")
        try checkArgument(ticket.subject == subject, "Ticket mismatch with current DID")
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        try checkIsCustomized()
        try checkArgument(_proofsDict[ticket.to] != nil, "Document not signed by: \(ticket.to)")
        try checkAttachedStore()
        guard defaultPublicKeyId() != nil else {
            throw DIDError.UncheckedError.IllegalStateError.NoEffectiveControllerError(subject.toString())
        }
        
        let did = subject
        let targetDoc = try did.resolve(true)
        guard targetDoc != nil else {
            throw DIDError.UncheckedError.IllegalStateError.DIDNotFoundError(did.toString())
        }
        guard !targetDoc!.isDeactivated else {
            throw DIDError.UncheckedError.IllegalStateError.DIDDeactivatedError(did.toString())
        }
        if sigK == nil {
            sigK = defaultPublicKeyId()
        }
        else {
            guard try authenticationKey(ofId: sigK!) != nil else {
                throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError(sigK!.toString())
            }
        }
        
        try DIDBackend.sharedInstance().transferDid(self, ticket, sigK!, storePassword, adapter as? DIDAdapter)
    }     
    
    /// Publish a DID transfer transaction for current (customized) DIDDocument.
    /// - Parameters:
    ///   - ticket: the TransferTicket for current DID
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Throws DIDBackendError if an error occurred when publishing the transaction
    public func publish(with ticket: TransferTicket, of signKey: DIDURL, using storePassword: String, adapter: DIDTransactionAdapter) throws {
        return try publish(ticket, signKey, storePassword, adapter)
    }
    
    /// Publish a DID transfer transaction for current (customized) DIDDocument.
    /// - Parameters:
    ///   - ticket: the TransferTicket for current DID
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Throws DIDBackendError if an error occurred when publishing the transaction
    public func publish(with ticket: TransferTicket, of signKey: DIDURL, using storePassword: String) throws {
        try publish(ticket, signKey, storePassword, nil)
    }
    
    /// Publish a DID transfer transaction for current (customized) DIDDocument.
    /// - Parameters:
    ///   - ticket: the TransferTicket for current DID
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Throws DIDBackendError if an error occurred when publishing the transaction
    public func publish(with ticket: TransferTicket, of signKey: String, using storePassword: String, adapter: DIDTransactionAdapter?) throws {
        try publish(ticket, canonicalId(signKey), storePassword, adapter)
    }
    
    /// Publish a DID transfer transaction for current (customized) DIDDocument.
    /// - Parameters:
    ///   - ticket: the TransferTicket for current DID
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Throws DIDBackendError if an error occurred when publishing the transaction
    public func publish(with ticket: TransferTicket, of signKey: String, using storePassword: String) throws {
        try publish(ticket, canonicalId(signKey), storePassword, nil)
    }
    
    /// Publish a DID transfer transaction for current (customized) DIDDocument.
    /// - Parameters:
    ///   - ticket: the TransferTicket for current DID
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Throws DIDBackendError if an error occurred when publishing the transaction
    public func publish(with ticket: TransferTicket, using storePassword: String, adapter: DIDTransactionAdapter) throws {
        try publish(ticket, nil, storePassword, adapter)
    }
    
    /// Publish a DID transfer transaction for current (customized) DIDDocument.
    /// - Parameters:
    ///   - ticket: the TransferTicket for current DID
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Throws DIDBackendError if an error occurred when publishing the transaction
    public func publish(with ticket: TransferTicket, using storePassword: String) throws {
        try publish(ticket, nil, storePassword, nil)
    }
    
    /// Publish a DID transfer transaction for current (customized) DIDDocument
    /// in asynchronous mode.
    /// - Parameters:
    ///   - ticket: the TransferTicket for current DID
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// - Returns: a new CompletableStage
    private func publishAsync(_ ticket: TransferTicket, _ signKey: DIDURL?, _ storePassword: String, _ adapter: DIDTransactionAdapter?) throws -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try publish(ticket, signKey, storePassword, adapter) }
    }
    
    /// Publish a DID transfer transaction for current (customized) DIDDocument
    /// in asynchronous mode.
    /// - Parameters:
    ///   - ticket: the TransferTicket for current DID
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// - Returns: a new CompletableStage
    public func publishAsync(with ticket: TransferTicket, of signKey: DIDURL, using storePassword: String, adapter: DIDTransactionAdapter) throws -> Promise<Void> {
        return try publishAsync(ticket, signKey, storePassword, adapter)
    }
    
    /// Publish a DID transfer transaction for current (customized) DIDDocument
    /// in asynchronous mode.
    /// - Parameters:
    ///   - ticket: the TransferTicket for current DID
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    /// - Returns: a new CompletableStage
    public func publishAsync(with ticket: TransferTicket, of signKey: DIDURL, using storePassword: String) throws -> Promise<Void> {
        return try publishAsync(ticket, signKey, storePassword, nil)
    }
    
    /// Publish a DID transfer transaction for current (customized) DIDDocument
    /// in asynchronous mode.
    /// - Parameters:
    ///   - ticket: the TransferTicket for current DID
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// - Returns: a new CompletableStage
    public func publishAsync(with ticket: TransferTicket, of signKey: String, using storePassword: String, adapter: DIDTransactionAdapter) throws -> Promise<Void> {
        return try publishAsync(ticket, canonicalId(signKey), storePassword, adapter)
    }
    
    /// Publish a DID transfer transaction for current (customized) DIDDocument
    /// in asynchronous mode.
    /// - Parameters:
    ///   - ticket: the TransferTicket for current DID
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    /// - Returns: a new CompletableStage
    public func publishAsync(with ticket: TransferTicket, of signKey: String, using storePassword: String) throws -> Promise<Void> {
        return try publishAsync(ticket, canonicalId(signKey), storePassword, nil)
    }
    
    /// Publish a DID transfer transaction for current (customized) DIDDocument
    /// in asynchronous mode.
    /// - Parameters:
    ///   - ticket: the TransferTicket for current DID
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if nil the method will
    ///           use the default adapter from the DIDBackend
    /// - Returns: a new CompletableStage
    public func publishAsync(with ticket: TransferTicket, using storePassword: String, adapter: DIDTransactionAdapter) throws -> Promise<Void> {
        return try publishAsync(ticket, nil, storePassword, adapter)
    }
    
    /// Publish a DID transfer transaction for current (customized) DIDDocument
    /// in asynchronous mode.
    /// - Parameters:
    ///   - ticket: the TransferTicket for current DID
    ///   - storePassword: the password for the DIDStore
    /// - Returns: a new CompletableStage
    public func publishAsync(with ticket: TransferTicket, using storePassword: String) throws -> Promise<Void> {
        return try publishAsync(ticket, nil, storePassword, nil)
    }
    
    // TODO: to be remove in the future
    public func publishUntrusted(_ signKey: DIDURL?, _ storepass: String, _ adapter: DIDTransactionAdapter?) throws {
        try checkArgument(!storepass.isEmpty, "Invalid storepass")
        try checkIsPrimitive()
        try checkAttachedStore()
        
        if (signKey == nil && defaultPublicKeyId() == nil) {
            throw DIDError.UncheckedError.IllegalStateError.NoEffectiveControllerError(subject.toString())
        }
        
        Log.i(DIDDocument.TAG, "Publishing untrusted DID ", subject, "...")
        
        if (try !isGenuine()) {
            try isGenuine()
            Log.e(DIDDocument.TAG, "Publish failed because document is not genuine.")
            throw DIDError.UncheckedError.IllegalStateError.DIDNotGenuineError(subject.toString())
        }
        
        if (isDeactivated) {
            Log.e(DIDDocument.TAG, "Publish failed because DID is deactivated.")
            throw DIDError.UncheckedError.IllegalStateError.DIDDeactivatedError(subject.toString())
        }
        
        if (isExpired) {
            Log.e(DIDDocument.TAG, "Publish failed because document is expired.")
            throw DIDError.UncheckedError.IllegalStateError.DIDExpiredError(subject.toString())
        }
        
        var lastTxid: String? = nil
        var resolvedSignature: String? = nil
        let _signKey = signKey != nil ? signKey : defaultPublicKeyId()
        let resolvedDoc = try DIDBackend.sharedInstance().resolveUntrustedDid(subject, true)
        if (resolvedDoc != nil) {
            if (resolvedDoc!.isDeactivated) {
                getMetadata().setDeactivated(true)
                
                Log.e(DIDDocument.TAG, "Publish failed because DID is deactivated.")
                throw DIDError.UncheckedError.IllegalStateError.DIDDeactivatedError(subject.toString())
            }
            
            resolvedSignature = resolvedDoc?.proof.signature
            lastTxid = resolvedDoc?.getMetadata().transactionId
        }
        
        guard try authenticationKey(ofId: _signKey!) != nil else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError(_signKey?.toString())
        }
        
        if (lastTxid == nil || lastTxid!.isEmpty) {
            Log.i(DIDDocument.TAG, "Try to publish[create] ", subject, "...")
            try DIDBackend.sharedInstance().createDid(self, _signKey!, storepass, adapter)
        } else {
            Log.i(DIDDocument.TAG, "Try to publish[update] ", subject, "...")
            try DIDBackend.sharedInstance().updateDid(self, lastTxid!, _signKey!, storepass, adapter)
        }
        
        if (resolvedSignature != nil ) {
            getMetadata().setPreviousSignature(resolvedSignature!)
        }
        getMetadata().setSignature(proof.signature)
    }
    
    /// Publish DID Document to the ID chain.
    /// - Parameters:
    ///   - signKey: the key to sign
    ///   - force: force = true, must be publish whether the local document is lastest one or not;
    ///            force = false, must not be publish if the local document is not the lastest one,
    ///   - storePassword: the password for DIDStore
    private func publish(_ signKey: DIDURL?, _ force: Bool, _ storePassword: String, _ adapter: DIDAdapter?) throws {
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        try checkAttachedStore()
        if signKey == nil && defaultPublicKeyId() == nil {
            throw DIDError.UncheckedError.IllegalStateError.NoEffectiveControllerError(subject.toString())
        }
        Log.i(DIDDocument.TAG, "Publishing DID ", subject, "force " , force , "...")
        guard try isGenuine() else {
           _ =  try isGenuine()
            Log.e(DIDDocument.TAG, "Publish failed because document is not genuine.")
            throw DIDError.UncheckedError.IllegalStateError.DIDNotGenuineError(subject.toString())
        }
        guard !isDeactivated else {
            Log.e(DIDDocument.TAG, "Publish failed because DID is deactivated.")
            throw DIDError.UncheckedError.IllegalStateError.DIDDeactivatedError(subject.toString())
        }
        
        if isExpired && !force {
            Log.e(DIDDocument.TAG, "Publish failed because document is expired.")
            Log.e(DIDDocument.TAG, "You can publish the expired document using force mode.")
            throw DIDError.UncheckedError.IllegalStateError.DIDExpiredError(subject.toString())
        }
        
        var signK: DIDURL? = signKey
        var lastTxid: String?
        var resolvedSignature: String = ""
        let resolvedDoc = try subject.resolve(true)
        if resolvedDoc != nil {
            guard !resolvedDoc!.isDeactivated else {
                getMetadata().setDeactivated(true)
                Log.e(DIDDocument.TAG, "Publish failed because DID is deactivated.")
                throw DIDError.UncheckedError.IllegalStateError.DIDDeactivatedError(subject.toString())
            }
            if (isCustomizedDid()) {
                let orgControllers = resolvedDoc?.controllers()
                let curControllers = controllers()

                if curControllers != orgControllers {
                    throw DIDError.UncheckedError.IllegalStateError.DIDControllersChangedError()
                }
                
                let curMultisig = multiSignature == nil ? MultiSignature.ONE_OF_ONE : multiSignature
                let orgMultisig = resolvedDoc?.multiSignature == nil ? MultiSignature.ONE_OF_ONE : resolvedDoc?.multiSignature

                if curMultisig != orgMultisig {
                    throw DIDError.UncheckedError.IllegalStateError.DIDControllersChangedError()
                }
            }
            resolvedSignature = resolvedDoc!.proof.signature
            if !force {
                let localPrevSignature = getMetadata().previousSignature
                let localSignature = getMetadata().signature
                if localPrevSignature == nil && localSignature == nil {
                    Log.e(DIDDocument.TAG, "Missing signatures information, ", "DID SDK dosen't know how to handle it, ", "use force mode to ignore checks.")
                    throw DIDError.UncheckedError.IllegalStateError.DIDNotUpToDateError(subject.toString())
                }
                else if (localPrevSignature == nil || localSignature == nil) {
                    let ls = localPrevSignature != nil ? localPrevSignature : localSignature
                    guard ls == resolvedSignature else {
                        Log.e(DIDDocument.TAG, "Current copy not based on the lastest on-chain copy, signature mismatch.")
                        throw DIDError.UncheckedError.IllegalStateError.DIDNotUpToDateError(subject.toString())
                    }
                }
                else {
                    if localSignature != resolvedSignature && localPrevSignature != resolvedSignature {
                        Log.e(DIDDocument.TAG, "Current copy not based on the lastest on-chain copy, signature mismatch.")
                        throw DIDError.UncheckedError.IllegalStateError.DIDNotUpToDateError(subject.toString())
                    }
                }
            }
            lastTxid = resolvedDoc!.getMetadata().transactionId
        }
        
        if signK == nil {
            signK = defaultPublicKeyId()
        }
        else {
            guard try authenticationKey(ofId: signK!) != nil else {
                throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError(signK?.toString())
            }
        }
        
        if lastTxid == nil || lastTxid!.isEmpty {
            Log.i(DIDDocument.TAG, "Try to publish[create] ", subject, " ...")
            try DIDBackend.sharedInstance().createDid(self, signK!, storePassword, adapter)
        }
        else {
            Log.i(DIDDocument.TAG, "Try to publish[update] ", subject, " ...")
            try DIDBackend.sharedInstance().updateDid(self, lastTxid!, signK!, storePassword, adapter)
        }
        

        if resolvedSignature != "" {
            getMetadata().setPreviousSignature(resolvedSignature)
        }
        getMetadata().setSignature(proof.signature)
    }
    
    /// Publish DID Document to the ID chain.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - force: if true will ignore the conflict between local copy and
    ///                 the chain copy; otherwise will check the conflict
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Throws DIDBackendError if an error occurred when publishing the transaction
    public func publish(with signKey: DIDURL, force: Bool, using storePassword: String, adapter: DIDAdapter) throws {
        return try publish(signKey, force, storePassword, adapter)
    }
    
    /// Publish DID Document to the ID chain.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - force: if true will ignore the conflict between local copy and
    ///                 the chain copy; otherwise will check the conflict
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Throws DIDBackendError if an error occurred when publishing the transaction
    public func publish(with signKey: DIDURL, force: Bool, using storePassword: String) throws {
        try publish(signKey, force, storePassword, nil)
    }
    
    /// Publish DID Document to the ID chain.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Throws DIDBackendError if an error occurred when publishing the transaction
    public func publish(with signKey: DIDURL, using storePassword: String, adapter: DIDAdapter) throws {
        try publish(signKey, false, storePassword, adapter)
    }
    
    /// Publish DID Document to the ID chain.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Throws DIDBackendError if an error occurred when publishing the transaction
    public func publish(with signKey: DIDURL, using storePassword: String) throws {
        try publish(signKey, false, storePassword, nil)
    }
    
    /// Publish DID Document to the ID chain.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - force: if true will ignore the conflict between local copy and
    ///                 the chain copy; otherwise will check the conflict
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Throws DIDBackendError if an error occurred when publishing the transaction
    public func publish(with signKey: String, force: Bool, using storePassword: String, adapter: DIDAdapter) throws {
        try publish(canonicalId(signKey), force, storePassword, adapter)
    }
    
    /// Publish DID Document to the ID chain.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - force: if true will ignore the conflict between local copy and
    ///                 the chain copy; otherwise will check the conflict
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Throws DIDBackendError if an error occurred when publishing the transaction
    public func publish(with signKey: String, force: Bool, using storePassword: String) throws {
        try publish(canonicalId(signKey), force, storePassword, nil)
    }
    
    /// Publish DID Document to the ID chain.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Throws DIDBackendError if an error occurred when publishing the transaction
    public func publish(with signKey: String, using storePassword: String, adapter: DIDAdapter) throws {
        try publish(canonicalId(signKey), false, storePassword, adapter)
    }
    
    /// Publish DID Document to the ID chain.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Throws DIDBackendError if an error occurred when publishing the transaction
    public func publish(with signKey: String, using storePassword: String) throws {
        try publish(canonicalId(signKey), false, storePassword, nil)
    }
    
    /// Publish DID Document to the ID chain.
    /// - Parameters:
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Throws DIDBackendError if an error occurred when publishing the transaction
    public func publish(using storePassword: String, adapter: DIDAdapter) throws {
        try publish(nil, false, storePassword, adapter)
    }
    
    /// Publish DID Document to the ID chain.
    /// - Parameters:
    ///   - storePassword: the password for the DIDStore
    /// - Throws: DIDStoreError if an error occurred when accessing the store
    /// - Throws DIDBackendError if an error occurred when publishing the transaction
    public func publish(using storePassword: String) throws {
        try publish(nil, false, storePassword, nil)
    }
    
    /// Publish DID Document to the ID chain in asynchronous mode.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - force: if true will ignore the conflict between local copy and
    ///                 the chain copy; otherwise will check the conflict
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// - Returns: the new Promise
    private func publishAsync(_ signKey: DIDURL?, _ force: Bool, _ storePassword: String, _ adapter: DIDAdapter?) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try publish(signKey, force, storePassword, adapter) }
    }
    
    /// Publish DID Document to the ID chain in asynchronous mode.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - force: if true will ignore the conflict between local copy and
    ///                 the chain copy; otherwise will check the conflict
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// - Returns: the new Promise
    public func publishAsync(with signKey: DIDURL, force: Bool, using storePassword: String, adapter: DIDAdapter) -> Promise<Void> {
        return publishAsync(signKey, force, storePassword, adapter)
    }
    
    /// Publish DID Document to the ID chain in asynchronous mode.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - force: if true will ignore the conflict between local copy and
    ///                 the chain copy; otherwise will check the conflict
    ///   - storePassword: the password for the DIDStore
    /// - Returns: the new Promise
    public func publishAsync(with signKey: DIDURL, force: Bool, using storePassword: String) -> Promise<Void> {
        return publishAsync(signKey, force, storePassword, nil)
    }
    
    /// Publish DID Document to the ID chain in asynchronous mode.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - force: if true will ignore the conflict between local copy and
    ///                 the chain copy; otherwise will check the conflict
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// - Returns: the new Promise
    public func publishAsync(with signKey: String, force: Bool, using storePassword: String, _ adapter: DIDAdapter) throws -> Promise<Void> {
        return try publishAsync(DIDURL.valueOf(signKey), force, storePassword, adapter)
    }
    
    /// Publish DID Document to the ID chain in asynchronous mode.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - force: if true will ignore the conflict between local copy and
    ///                 the chain copy; otherwise will check the conflict
    ///   - storePassword: the password for the DIDStore
    /// - Returns: the new Promise
    public func publishAsync(with signKey: String, force: Bool, using storePassword: String) throws -> Promise<Void> {
        return try publishAsync(DIDURL.valueOf(signKey), force, storePassword, nil)
    }
    
    /// Publish DID Document to the ID chain in asynchronous mode.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - force: if true will ignore the conflict between local copy and
    ///                 the chain copy; otherwise will check the conflict
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// - Returns: the new Promise
    public func publishAsync(with signKey: DIDURL, using storePassword: String, adapter: DIDAdapter) -> Promise<Void> {
        return publishAsync(signKey, false, storePassword, adapter)
    }
    
    /// Publish DID Document to the ID chain in asynchronous mode.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - force: if true will ignore the conflict between local copy and
    ///                 the chain copy; otherwise will check the conflict
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// - Returns: the new Promise
    public func publishAsync(with signKey: DIDURL, using storePassword: String) -> Promise<Void> {
        return publishAsync(signKey, false, storePassword, nil)
    }
    
    /// Publish DID Document to the ID chain in asynchronous mode.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// - Returns: the new Promise
    public func publishAsync(with signKey: String, using storePassword: String, adapter: DIDAdapter) throws -> Promise<Void> {
        return try publishAsync(DIDURL.valueOf(signKey), false, storePassword, adapter)
    }
    
    /// Publish DID Document to the ID chain in asynchronous mode.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    /// - Returns: the new Promise
    public func publishAsync(with signKey: String, using storePassword: String) throws -> Promise<Void> {
        return try publishAsync(DIDURL.valueOf(signKey), false, storePassword, nil)
    }
    
    /// Publish DID Document to the ID chain in asynchronous mode.
    /// - Parameters:
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// - Returns: the new Promise
    public func publishAsync(using storePassword: String, adapter: DIDAdapter) -> Promise<Void> {
        return publishAsync(nil, false, storePassword, adapter)
    }
    
    /// Publish DID Document to the ID chain in asynchronous mode.
    /// - Parameters:
    ///   - storePassword: the password for the DIDStore
    /// - Returns: the new Promise
    public func publishAsync(using storePassword: String) -> Promise<Void> {
        return publishAsync(nil, false, storePassword, nil)
    }
    
    /// Deactivate this DID using the authentication key.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    private func deactivate(_ signKey: DIDURL?, _ storePassword: String, _ adapter: DIDAdapter?) throws {
        try checkAttachedStore()
        if signKey == nil && defaultPublicKeyId() == nil {
            throw DIDError.UncheckedError.IllegalStateError.NoEffectiveControllerError(subject.toString())
        }
        var sigK = signKey
        // Document should use the IDChain's copy
        let doc = try subject.resolve(true)
        if doc == nil {
            throw DIDError.UncheckedError.IllegalStateError.DIDNotFoundError(subject.toString())
        }
        else if doc!.isDeactivated {
            throw DIDError.UncheckedError.IllegalStateError.DIDDeactivatedError(subject.toString())
        }
        else {
            doc!.getMetadata().attachStore(store!)
        }
        doc!._effectiveController = _effectiveController
        if sigK == nil {
            sigK = doc!.defaultPublicKeyId()
        }
        else {
            if !doc!.isCustomizedDid() {
                // the signKey should be default key or authorization key
                if try doc?.defaultPublicKeyId() != sigK && doc?.authorizationKey(ofId: sigK!) == nil {
                    throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError(subject.toString())
                }
            }
            else {
                // the signKey should be controller's default key
                let controller = doc?.controllerDocument(sigK!.did!)
                if controller == nil || controller!.defaultPublicKeyId() != sigK {
                    throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError(subject.toString())
                }
            }
        }
        
        try DIDBackend.sharedInstance().deactivateDid(doc!, sigK!, storePassword, adapter)
        if signature != doc!.signature {
            try store?.storeDid(using: doc!)
        }
    }
    
    /// Deactivate this DID using the authentication key.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    public func deactivate(with signKey: DIDURL, using storePassword: String, adapter: DIDAdapter) throws {
        return try deactivate(signKey, storePassword, adapter)
    }
    
    /// Deactivate this DID using the authentication key.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    public func deactivate(with signKey: DIDURL, using storePassword: String) throws {
        try deactivate(signKey, storePassword, nil)
    }
    
    /// Deactivate this DID using the authentication key.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    public func deactivate(with signKey: String, using storePassword: String, adapter: DIDAdapter) throws {
        try deactivate(canonicalId(signKey), storePassword, adapter)
    }
    
    /// Deactivate this DID using the authentication key.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    public func deactivate(with signKey: String, using storePassword: String) throws {
        try deactivate(canonicalId(signKey), storePassword, nil)
    }
    
    /// Deactivate this DID using the authentication key.
    /// - Parameters:
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    public func deactivate(using storePassword: String, adapter: DIDAdapter) throws {
        try deactivate(nil, storePassword, adapter)
    }
    
    /// Deactivate this DID using the authentication key.
    /// - Parameters:
    ///   - storePassword: the password for the DIDStore
    public func deactivate(using storePassword: String) throws {
        try deactivate(nil, storePassword, nil)
    }
    
    /// Deactivate this DID using the authentication key in asynchronous mode.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// - Returns: the new Promise
    private func deactivateAsync(_ signKey: DIDURL?, _ storePassword: String, _ adapter: DIDAdapter?) throws -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try deactivate(signKey, storePassword, adapter) }
    }
    
    /// Deactivate this DID using the authentication key in asynchronous mode.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    /// - Returns: the new Promise
    public func deactivateAsync(with signKey: DIDURL, using storePassword: String) throws -> Promise<Void> {
        return try deactivateAsync(signKey, storePassword, nil)
    }
    
    /// Deactivate this DID using the authentication key in asynchronous mode.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// - Returns: the new Promise
    public func deactivateAsync(with signKey: String, using storePassword: String, adapter: DIDAdapter) throws -> Promise<Void> {
        return try deactivateAsync(canonicalId(signKey), storePassword, adapter)
    }
    
    /// Deactivate this DID using the authentication key in asynchronous mode.
    /// - Parameters:
    ///   - signKey: the key to sign the transaction
    ///   - storePassword: the password for the DIDStore
    /// - Returns: the new Promise
    public func deactivateAsync(with signKey: String, using storePassword: String) throws -> Promise<Void> {
        return try deactivateAsync(canonicalId(signKey), storePassword, nil)
    }
    
    /// Deactivate this DID using the authentication key in asynchronous mode.
    /// - Parameters:
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// - Returns: the new Promise
    public func deactivateAsync(using storePassword: String, adapter: DIDAdapter) throws -> Promise<Void> {
        return try deactivateAsync(nil, storePassword, adapter)
    }
    
    /// Deactivate this DID using the authentication key in asynchronous mode.
    /// - Parameters:
    ///   - storePassword: the password for the DIDStore
    /// - Returns: the new Promise
    public func deactivateAsync(using storePassword: String) throws -> Promise<Void> {
        return try deactivateAsync(nil, storePassword, nil)
    }
    
    /// Deactivate the target DID with the authorization.
    /// - Parameters:
    ///   - target: the DID to be deactivated
    ///   - signKey: the key to sign the transaction, should be
    ///           authorized by the target DID
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    private func deactivate(_ target: DID, _ signKey: DIDURL?, _ storePassword: String, _ adapter: DIDAdapter?) throws {
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        try checkAttachedStore()
        if signKey == nil && defaultPublicKeyId() == nil {
            throw DIDError.UncheckedError.IllegalStateError.NoEffectiveControllerError(subject.toString())
        }
        let targetDoc = try target.resolve(true)
        guard let _ = targetDoc else {
            throw DIDError.UncheckedError.IllegalStateError.DIDNotFoundError(target.toString())
        }
        guard !targetDoc!.isDeactivated else {
            throw DIDError.UncheckedError.IllegalStateError.DIDDeactivatedError(target.toString())
        }
        
        var _signKey = signKey
        
        targetDoc!.getMetadata().attachStore(store!)
        if !targetDoc!.isCustomizedDid() {
            if targetDoc!.authorizationKeyCount == 0 {
                throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("No authorization key from: \(target)")
            }
            var candidatePks: [PublicKey] = []
            if signKey == nil {
                candidatePks = self.authenticationKeys()
            }
            else {
                let pk = try authenticationKey(ofId: signKey!)
                guard let _ = pk else {
                    throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError(signKey!.toString())
                }
                candidatePks.append(pk!)
            }
            // Lookup the authorization key id in the target doc
            var realSignKey: DIDURL?
            var targetSignKey: DIDURL?
            for candidatePk in candidatePks {
                for pk in targetDoc!.authorizationKeys() {
                    if pk.controller != subject {
                        continue
                    }
                    
                    if pk.publicKeyBase58 == candidatePk.publicKeyBase58 {
                        realSignKey = candidatePk.getId()
                        targetSignKey = pk.getId()
                    }
                }
            }
            guard realSignKey != nil , targetSignKey != nil else {
                throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("No matched authorization key.")
            }
            try DIDBackend.sharedInstance().deactivateDid(targetDoc!, targetSignKey!, self, realSignKey!, storePassword, adapter)
        }
        else {
            guard targetDoc!.hasController(subject) else {
                throw DIDError.UncheckedError.IllegalArgumentErrors.NotControllerError(subject.toString())
            }
            if _signKey == nil {
                _signKey = defaultPublicKeyId()
            }
            else {
                guard _signKey == defaultPublicKeyId() else {
                    throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError(_signKey!.toString())
                }
            }
            
            try DIDBackend.sharedInstance().deactivateDid(targetDoc!, _signKey!, storePassword, adapter)
            
            if try store!.containsDid(target) {
                try store?.storeDid(using: targetDoc!)
            }
        }
    }
    
    /// Deactivate the target DID with the authorization.
    /// - Parameters:
    ///   - target: the DID to be deactivated
    ///   - signKey: the key to sign the transaction, should be
    ///           authorized by the target DID
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    public func deactivate(with target: DID, of signKey: DIDURL, using storePassword: String, adapter: DIDAdapter) throws {
        try deactivate(target, signKey, storePassword, adapter)
    }
    
    /// Deactivate target DID by authorizor's DID.
    /// - Parameters:
    ///   - target: target the target DID
    ///   - signKey: the authorizor's key to sign
    ///   - storePassword: the password for DIDStore
    public func deactivate(with target: DID, of signKey: DIDURL, using storePassword: String) throws {
        try deactivate(target, signKey, storePassword, nil)
    }
    
    /// Deactivate the target DID with the authorization.
    /// - Parameters:
    ///   - target: the DID to be deactivated
    ///   - signKey: the key to sign the transaction, should be
    ///           authorized by the target DID
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    public func deactivate(with target: String, of signKey: String, using storePassword: String, adapter: DIDAdapter) throws {
        try deactivate(DID.valueOf(target)!, canonicalId(signKey), storePassword, adapter)
    }
    
    /// Deactivate the target DID with the authorization.
    /// - Parameters:
    ///   - target: the DID to be deactivated
    ///   - signKey: the key to sign the transaction, should be
    ///           authorized by the target DID
    ///   - storePassword: the password for the DIDStore
    public func deactivate(with target: String, of signKey: String, using storePassword: String) throws {
        try deactivate(DID.valueOf(target)!, canonicalId(signKey), storePassword, nil)
    }
    
    /// Deactivate the target DID with the authorization.
    /// - Parameters:
    ///   - target: the DID to be deactivated
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    public func deactivate(with target: DID, using storePassword: String, adapter: DIDAdapter) throws {
        try deactivate(target, nil , storePassword, adapter)
    }
    
    /// Deactivate the target DID with the authorization.
    /// - Parameters:
    ///   - target: the DID to be deactivated
    ///   - storePassword: the password for the DIDStore
    public func deactivate(with target: DID, using storePassword: String) throws {
        try deactivate(target, nil, storePassword, nil)
    }
    
    /// Deactivate the target DID with the authorization in asynchronous mode.
    /// - Parameters:
    ///   - target: the DID to be deactivated
    ///   - signKey: the key to sign the transaction, should be
    ///              authorized by the target DID
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// -Returns: the new promise
    private func deactivateAsync(_ target: DID, _ signKey: DIDURL?, _ storePassword: String, _ adapter: DIDAdapter?) throws -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try deactivate(target, signKey, storePassword, adapter) }
    }
    
    /// Deactivate the target DID with the authorization in asynchronous mode.
    /// - Parameters:
    ///   - target: the DID to be deactivated
    ///   - signKey: the key to sign the transaction, should be
    ///              authorized by the target DID
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// -Returns: the new promise
    public func deactivateAsync(with target: DID, of signKey: DIDURL, using storePassword: String, adapter: DIDAdapter) throws -> Promise<Void> {
        return try deactivateAsync(target, signKey, storePassword, adapter)
    }
    
    /// Deactivate the target DID with the authorization in asynchronous mode.
    /// - Parameters:
    ///   - target: the DID to be deactivated
    ///   - signKey: the key to sign the transaction, should be
    ///              authorized by the target DID
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// -Returns: the new promise
    public func deactivateAsync(with target: String, of signKey: DIDURL, using storePassword: String, adapter: DIDAdapter) throws -> Promise<Void> {
        return try deactivateAsync(DID.valueOf(target)!, signKey, storePassword, nil)
    }
    
    /// Deactivate the target DID with the authorization in asynchronous mode.
    /// - Parameters:
    ///   - target: the DID to be deactivated
    ///   - signKey: the key to sign the transaction, should be
    ///              authorized by the target DID
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// -Returns: the new promise
    public func deactivateAsync(with target: String, of signKey: String, using storePassword: String, adapter: DIDAdapter) throws -> Promise<Void> {
        return try deactivateAsync(DID.valueOf(target)!, DIDURL.valueOf(signKey), storePassword, nil)
    }
    
    /// Deactivate the target DID with the authorization in asynchronous mode.
    /// - Parameters:
    ///   - target: the DID to be deactivated
    ///   - signKey: the key to sign the transaction, should be
    ///              authorized by the target DID
    ///   - storePassword: the password for the DIDStore
    /// -Returns: the new promise
    public func deactivateAsync(with target: String, of signKey: String, using storePassword: String) throws -> Promise<Void> {
        return try deactivateAsync(DID.valueOf(target)!, DIDURL.valueOf(signKey), storePassword, nil)
    }
    
    /// Deactivate the target DID with the authorization in asynchronous mode.
    /// - Parameters:
    ///   - target: the DID to be deactivated
    ///   - storePassword: the password for the DIDStore
    ///   - adapter: an optional DIDTransactionAdapter, if null the method will
    ///           use the default adapter from the DIDBackend
    /// -Returns: the new promise
    public func deactivateAsync(with target: DID, using storePassword: String, adapter: DIDAdapter) throws -> Promise<Void> {
        return try deactivateAsync(target, nil, storePassword, adapter)
    }
    
    /// Deactivate the target DID with the authorization in asynchronous mode.
    /// - Parameters:
    ///   - target: the DID to be deactivated
    ///   - storePassword: the password for the DIDStore
    /// -Returns: the new promise
    public func deactivateAsync(with target: DID, using storePassword: String) throws -> Promise<Void> {
        return try deactivateAsync(target, nil, storePassword, nil)
    }

    func parse(_ path: String) throws {
        let content = try path.readTextFromPath()
        let contentDic = content.toDictionary()
        try parse(JsonNode(contentDic))
    }
    
    private func parse(_ doc: JsonNode) throws {
        try parse(withoutSanitize: doc)
        try sanitize()
    }
    
    func parse(withoutSanitize doc: JsonNode) throws {
        let serializer = JsonSerializer(doc)
        var options: JsonSerializer.Options
        // content
        let content = doc.get(forKey: CONTEXT)
        if content != nil {
            try parseContent(content!)
        }
        // subject
        options = JsonSerializer.Options()
        guard let did = try serializer.getDID(Constants.ID, options) else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.MalformedDIDError("Mssing subject")
        }
        setSubject(did)

        // controller
        var node: JsonNode?

        node = doc.get(forKey: Constants.CONTROLLER)
        if let _ = node {
            try parseController(node!)
        }
        
        // multisig
        let multisig = doc.get(forKey: MULTI_SIGNATURE)
        if let _ = multisig {
            _multisig = try MultiSignature(multisig!.asString()!)
        }
        
        //publicKey
        node = doc.get(forKey: Constants.PUBLICKEY)
        if let _ = node {
            try parsePublicKeys(node!)
        }

        node = doc.get(forKey: Constants.AUTHENTICATION)
        if let _ = node {
            try parseAuthenticationKeys(node!)
        }

        //authorization
        node = doc.get(forKey: Constants.AUTHORIZATION)
        if let _ = node {
            try parseAuthorizationKeys(node!)
        }

        //verifiableCredential
        node = doc.get(forKey: Constants.VERIFIABLE_CREDENTIAL)
        if let _ = node {
            try parseCredential(node!)
        }
        // service
        node = doc.get(forKey: Constants.SERVICE)
        if let _ = node {
            try parseService(node!)
        }

        //expires
        options = JsonSerializer.Options()
                                .withOptional()
        guard let expirationDate = try serializer.getDate(Constants.EXPIRES, options) else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidExpires("Mssing document expires")
        }
        self.setExpirationDate(expirationDate)

        //proof
        node = doc.get(forKey: Constants.PROOF)
        try checkArgument(node != nil, "missing document proof")
        try parseProof(node!)
    }
    
    private func parseContent(_ arrayNode: JsonNode) throws {
        let array = arrayNode.asArray()
        var contexts: [String] = []
        array?.forEach{ item in
            contexts.append(item.asString()!)
        }
        print(contexts)
        _context = contexts
    }
    
    private func parseProof(_ arrayNode: JsonNode) throws {
        
        let array = arrayNode.asArray()
        
        if array == nil {
            var refSginKey: DIDURL? = nil
            if let creator = arrayNode.get(forKey: "creator") {
                if creator.asString()!.hasPrefix("#") {
                    refSginKey = try DIDURL(subject.toString() + creator.asString()!)
                }
                else {
                    refSginKey = try DIDURL(creator.asString()!)
                }
            }
            
            let p = try DIDDocumentProof.fromJson(arrayNode, refSginKey)
            _proofs = [p]
            return
        }
        
        try array?.forEach{ node in
            let value = arrayNode.get(forKey: "creator") != nil ? try DIDURL(arrayNode.get(forKey: "creator")!.asString()!) : nil
            let p = try DIDDocumentProof.fromJson(node, value)
            _proofs.append(p)
            
        }
    }
    
    private func parseController(_ arrayNode: JsonNode) throws {
        let array = arrayNode.asArray()
        
        if array == nil {
            let ct = arrayNode.asString()
            if ct != nil && ct!.count > 0 {
                _controllers = [try DID(ct!)]
            }
            return
        }

        try array?.forEach{ node in
            let n = node.asString()
            _controllers.append(try DID(n!))
        }
    }

    private func parsePublicKeys(_ arrayNode: JsonNode) throws {
        let array = arrayNode.asArray()

        try checkArgument(array != nil || !array!.isEmpty, "invalid publicKeys, should not be empty.")
        for node in array! {
            let pk = try PublicKey.fromJson(node, self.subject)
            _publickeys.append(pk)
        }
    }

    private func parseAuthenticationKeys(_ arrayNode: JsonNode) throws {
        let array = arrayNode.asArray()
        guard array?.count ?? 0 > 0 else {
            return
        }
        
        for node in array! {
            var pk: PublicKey
            if let _ = node.asDictionary() {
                pk =  try PublicKey.fromJson(node, self.subject)
                let rf = PublicKeyReference(pk.id, pk)
                self._authentications.append(rf)
            }
            else {
                let serializer = JsonSerializer(node)
                var options: JsonSerializer.Options
                options = JsonSerializer.Options()
                    .withRef(subject)
                let didUrl = try serializer.getDIDURL(options)
                let rf = PublicKeyReference(didUrl!)
                self._authentications.append(rf)
            }
        }
    }

    private func parseAuthorizationKeys(_ arrayNode: JsonNode) throws {
        let array = arrayNode.asArray()
        guard array?.count ?? 0 > 0 else {
            return
        }

        for node in array! {
            var pk: PublicKey
            if let _ = node.asDictionary() {
                pk =  try PublicKey.fromJson(node, self.subject)
                let rf = PublicKeyReference(pk.id, pk)
                self._authorizations.append(rf)
            } else {
                var key = node.toString()
                if key.hasPrefix("#") {
                    key = subject.toString() + key
                }
                let didURL = try DIDURL(key)
                let rf = PublicKeyReference(didURL)
                self._authorizations.append(rf)
            }
        }
    }

    private func parseCredential(_ arrayNode: JsonNode) throws {
        let array = arrayNode.asArray()
        guard array?.count ?? 0 > 0 else {
            return
        }

        for node in array! {
            _credentials.append(try VerifiableCredential.fromJson(node, self.subject))
        }
    }

    private func parseService(_ arrayNode: JsonNode) throws {
        let array = arrayNode.asArray()
        guard array?.count ?? 0 > 0 else {
            return
        }
        
        for node in array! {
            _services.append(try Service.fromJson(node, self.subject))
        }
    }

    class func convertToDIDDocument(fromJson: JsonNode) throws -> DIDDocument {
        let doc = DIDDocument()
        try doc.parse(fromJson)

        return doc
    }

    /// Get DID Document from Data context.
    /// - Parameter data: Context of did conforming to Data informat.
    /// - Throws: If no error occurs, throw error.
    /// - Returns: DIDDocument instance.
    @objc
    public class func convertToDIDDocument(fromData data: Data) throws -> DIDDocument {
        try checkArgument(!data.isEmpty, "invalid data.")
        
        let node = try JSONSerialization.jsonObject(with: data, options: []) as? Dictionary<String, Any>
        let doc = DIDDocument()
        try doc.parse(JsonNode(node!))
        
        return doc
    }
    
    /// Get DID Document from Data context.
    /// - Parameter dictionary: Context of did conforming to dictionary informat.
    /// - Throws: If no error occurs, throw error.
    /// - Returns: DIDDocument instance.
    @objc
    public class func convertToDIDDocument(fromDictionary: [String: Any]) throws -> DIDDocument {
        try checkArgument(!fromDictionary.isEmpty, "invalid fromDictionary.")

        let doc = DIDDocument()
        try doc.parse(JsonNode(fromDictionary))

        return doc
    }

    /// Get DID Document from json string context.
    /// - Parameter fromJson: Context of did conforming to string informat.
    /// - Throws: If no error occurs, throw error.
    /// - Returns: DIDDocument instance.
    @objc
    public class func convertToDIDDocument(fromJson: String) throws -> DIDDocument {
        return try  convertToDIDDocument(fromData: fromJson.data(using: .utf8)!)
    }

    /// Get DID Document from data path.
    /// - Parameter fromFileAtPath: The data path with string.
    /// - Throws: If no error occurs, throw error.
    /// - Returns: DIDDocument instance.
    @objc
    public class func convertToDIDDocument(fromFileAtPath : String) throws -> DIDDocument {
        return try convertToDIDDocument(fromJson: String(contentsOfFile: fromFileAtPath, encoding: .utf8))
    }

    /// Get DID Document from data path.
    /// - Parameter url: The data path with URL.
    /// - Throws: If no error occurs, throw error.
    /// - Returns: DIDDocument instance.
    @objc
    public class func convertToDIDDocument(fromUrl url: URL) throws -> DIDDocument {
        return try convertToDIDDocument(fromJson: String(contentsOf: url, encoding: .utf8))
    }

    /*
     * Normalized serialization order:
     *
     * - id
     * + publickey
     *   + public keys array ordered by id(case insensitive/ascending)
     *     - id
     *     - type
     *     - controller
     *     - publicKeyBase58
     * + authentication
     *   - ordered by public key' ids(case insensitive/ascending)
     * + authorization
     *   - ordered by public key' ids(case insensitive/ascending)
     * + verifiableCredential
     *   - credentials array ordered by id(case insensitive/ascending)
     * + service
     *   + services array ordered by id(case insensitive/ascending)
     *     - id
     *     - type
     *     - endpoint
     * - expires
     * + proof
     *   - type
     *   - created
     *   - creator
     *   - signatureValue
     */
    private func toJson(_ generator: JsonGenerator, _ normalized: Bool, _ forSign: Bool) throws {
        try sort()
        generator.writeStartObject()
        if _context.count > 0 {
            generator.writeFieldName("@context")
            generator.writeStartArray()
            _context.forEach { item in
                generator.writeString(item)
            }
            generator.writeEndArray()
        }
        // subject
        generator.writeFieldName(Constants.ID)
        generator.writeString(self.subject.toString())

        // controller
        if _controllers.count > 0 {
            if _controllers.count == 1 {
                generator.writeFieldName(Constants.CONTROLLER)
                generator.writeString(_controllers[0].toString())
            }
            else {
                generator.writeFieldName(Constants.CONTROLLER)
                generator.writeStartArray()
                for c in _controllers {
                    generator.writeString(c.toString())
                }
                generator.writeEndArray()
            }
        }
        //multisig
        if let _ = multiSignature {
            generator.writeFieldName(MULTI_SIGNATURE)
            generator.writeString(multiSignature!.description)
        }
        // publicKey
        if _publickeys.count > 0 {
            generator.writeFieldName(Constants.PUBLICKEY)
            generator.writeStartArray()
            for pubKey in _publickeys {
                pubKey.toJson(generator, self.subject, normalized)
            }
            generator.writeEndArray()
        }

        // authentication
        if _authentications.count > 0 {
            generator.writeFieldName(Constants.AUTHENTICATION)
            generator.writeStartArray()
            for pubKey in _authentications {
                var value: String
                let pubkeyId = pubKey.id?.did != nil ? pubKey.id!.did! : pubKey.publicKey?.getId()?.did
                if normalized || pubkeyId != self.subject {
                    if let _ = pubKey.id {
                        value = pubKey.id!.toString()
                    }
                    else {
                        value = pubKey.publicKey!.getId()!.toString()
                    }
                } else {
                    if let _ = pubKey.id {
                        value = "#" + pubKey.id!.fragment!
                    }
                    else {
                        value = "#" + pubKey.publicKey!.getId()!.fragment!
                    }
                }
                generator.writeString(value)
            }
            generator.writeEndArray()
        }

        if self._authorizations.count > 0 {
            generator.writeFieldName(Constants.AUTHORIZATION)
            generator.writeStartArray()

            for pubKey in _authorizations {
                var value: String = ""
                if normalized || (pubKey.id?.did != subject || pubKey.publicKey?.id.did != subject) {
                    value = pubKey.id?.toString() != nil ? pubKey.id!.toString() : pubKey.publicKey!.id.toString()
                }
                else {
                    value = "#" + ((pubKey.id != nil ? pubKey.id!.fragment! : pubKey.publicKey!.id.fragment)!)
                }
                generator.writeString(value)
            }
            generator.writeEndArray()
        }

        // verifiableCredential
        if self.credentialCount > 0 {
            generator.writeFieldName(Constants.VERIFIABLE_CREDENTIAL)
            generator.writeStartArray()
            for credential in credentials() {
                credential.toJson(generator, self.subject, normalized)
            }
            generator.writeEndArray()
        }

        if self.serviceCount > 0 {
            generator.writeFieldName(Constants.SERVICE)
            generator.writeStartArray()
            for service in services() {
                service.toJson(generator, self.subject, normalized)
            }
            generator.writeEndArray()
        }

        if let _ = self.expirationDate {
            generator.writeFieldName(Constants.EXPIRES)
            generator.writeString(DateFormatter.convertToUTCStringFromDate(self.expirationDate!))
        }
        
        if _proofs.count != 0 {
            generator.writeFieldName(Constants.PROOF)
            if _proofs.count > 1 {
                generator.writeStartArray()
                _proofs.forEach { proof in
                    proof.toJson(generator, subject, normalized)
                }
                generator.writeEndArray()
            }
            else {
                self.proof.toJson(generator, subject, normalized)
            }
        }

        generator.writeEndObject()
    }
    
    private func sort() throws {
        try _controllers.sort { (didA, didB) -> Bool in
            return try didA.compareTo(didB) == ComparisonResult.orderedAscending
        }
        try _publickeys.sort { (publicKeyA, publicKeyB) -> Bool in
            return try publicKeyA.compareTo(publicKeyB) == ComparisonResult.orderedAscending
        }
        try _authentications.sort { (publicKeyReferenceA, publicKeyReferenceB) -> Bool in
            return try publicKeyReferenceA.compareTo(publicKeyReferenceB) == ComparisonResult.orderedAscending
        }
        try _authorizations.sort { (publicKeyReferenceA, publicKeyReferenceB) -> Bool in
            return try publicKeyReferenceA.compareTo(publicKeyReferenceB) == ComparisonResult.orderedAscending
        }
        try _credentials.sort { (vcA, vcB) -> Bool in
            return try vcA.compareTo(vcB) == ComparisonResult.orderedAscending
        }
        try _services.sort { (serviceA, serviceB) -> Bool in
            return try serviceA.compareTo(serviceB) == ComparisonResult.orderedAscending
        }
        _proofs.sort { (proofA, proofB) -> Bool in

            let compareResult = DateFormatter.convertToUTCStringFromDate(proofA.createdDate)
                .compare(DateFormatter.convertToUTCStringFromDate(proofB.createdDate))
            if compareResult == ComparisonResult.orderedSame {

                return proofA.creator!.compareTo(proofB.creator!) == ComparisonResult.orderedAscending
            } else {
                return compareResult == ComparisonResult.orderedDescending
            }
        }
    }

    func toJson(_ generator: JsonGenerator, _ normalized: Bool) throws {
        return try toJson(generator, normalized, false)
    }

    func toJson(_ normalized: Bool, _ forSign: Bool) throws -> String {
        let generator = JsonGenerator()
        try toJson(generator, normalized, forSign)
        return generator.toString()
    }

    func toJson(_ normalized: Bool, _ forSign: Bool) throws -> Data {
        return try toJson(normalized, forSign).data(using: .utf8)!
    }
    
    func serialize(_ generator: JsonGenerator, _ normalized: Bool) throws {
        try toJson(generator, normalized, false)
    }
    
    func serialize(_ generator: JsonGenerator) throws {
        try toJson(generator, false, false)
    }

    /// Get json context from DID Document.
    /// - Parameter normalized: Json context is normalized or not.
    /// true represents normalized, false represents not compact.
    /// - Throws: If no error occurs, throw error.
    /// - Returns: json context.
    @objc
    public func convertFromDIDDocument(_ normalized: Bool) throws -> String {
        return try toJson(normalized, false)
    }

    /// Get json context from DID Document.
    /// - Throws: If no error occurs, throw error.
    /// - Returns: json context.
    @objc
    public func convertFromDIDDocument() throws -> String {
        return try toJson(false, false)
    }

    /// Get json context from DID Document.
    /// - Parameter normalized: Json context is normalized or not.
    /// true represents normalized, false represents not compact.
    /// - Throws: If no error occurs, throw error.
    /// - Returns: json context.
    @objc(convertFromDIDDocumentWithNormalized:error:)
    public func convertFromDIDDocument(_ normalized: Bool) throws -> Data {
        return try toJson(normalized, false)
    }

    /// Get data context from DID Document.
    /// - Throws: If no error occurs, throw error.
    /// - Returns: data context.
    @objc(convertFromDIDDocument:)
    public func convertFromDIDDocument() throws -> Data {
        return try toJson(false, false)
    }

    /// Write DIDDocument in path
    /// - Parameters:
    ///   - normalized: Json context is normalized or not.
    /// true represents normalized, false represents not compact.
    ///   - asFileAtPath: the path to write of string format.
    /// - Throws: If no error occurs, throw error.
    @objc
    public func convertFromDIDDocument(_ normalized: Bool, asFileAtPath: String) throws {
        return try convertFromDIDDocument(normalized, asURL: URL.init(fileURLWithPath: asFileAtPath))
    }

    ///  Write DIDDocument in path.
    ///  Default  represents not compact.
    /// - Parameter asFileAtPath: the path to write of string format.
    /// - Throws: If no error occurs, throw error.
    @objc
    public func convertFromDIDDocument(asFileAtPath: String) throws {
        return try convertFromDIDDocument(false, asFileAtPath: asFileAtPath)
    }

    /// Write DIDDocument in path.
    /// - Parameters:
    ///   - normalized: Json context is normalized or not.
    /// true represents normalized, false represents not compact.
    ///   - asURL: the path to write of URL format.
    /// - Throws: If no error occurs, throw error.
    @objc
    public func convertFromDIDDocument(_ normalized: Bool, asURL: URL) throws {
        let data: Data = try convertFromDIDDocument(normalized)
        let fileManager = FileManager.default
        if !fileManager.fileExists(atPath: asURL.path) {
            let dirPath = asURL.path.dirname()
            if !FileManager.default.fileExists(atPath: dirPath) {
                try fileManager.createDirectory(atPath: dirPath, withIntermediateDirectories: true, attributes: nil)
            }
            fileManager.createFile(atPath: asURL.path, contents: nil, attributes: nil)
        }
        let handle = try FileHandle(forWritingTo: asURL)
        handle.write(data)
    }

    /// Write DIDDocument in path.
    /// - Parameter asURL:  the path to write of URL format.
    /// - Throws: If no error occurs, throw error.
    @objc
    public func convertFromDIDDocument(asURL: URL) throws {
        return try convertFromDIDDocument(false, asURL: asURL)
    }
}

extension DIDDocument {

    /// Get DID Document string from DIDDocument.
    /// Default  represents not compact.
    /// - Returns: DIDDocument string
    @objc
    public func toString() -> String {
        return (try? toJson(true, false)) ?? ""
    }

    /// Get DID Document string from DIDDocument.
    /// Default  represents not compact.
    /// - Parameter force: Json context is normalized or not.
    /// true represents normalized, false represents not compact.
    /// - Returns: DIDDocument string
    @objc
    public func toString(_ force: Bool) -> String {
        return (try? toJson(force, false)) ?? ""
    }

    /// Get DID Document string from DIDDocument.
    /// - Parameters:
    ///   - force: Json context is normalized or not.
    /// true represents normalized, false represents not compact.
    ///   - forSign: is sign or not
    /// - Returns: DIDDocument string
    @objc
    public func toString(_ force: Bool, forSign: Bool) -> String {
        return (try? toJson(force, forSign)) ?? ""
    }

    /// DIDDocument string.
    /// Default  represents not compact.
    @objc
    public override var description: String {
        return toString()
    }

    public func clone() throws -> DIDDocument {
        let doc = DIDDocument(subject)
        doc._context = _context
        doc._controllers = _controllers
        doc._controllerDocs = _controllerDocs
        doc._effectiveController = _effectiveController
        doc._multisig = _multisig
        doc._publicKeyDict = _publicKeyDict
        doc._publickeys = _publickeys
        doc._authenticationKeys = _authenticationKeys
        doc._authentications = _authentications
        doc._authorizationKeys = _authorizationKeys
        doc._authorizations = _authorizations
        doc._defaultPublicKey = _defaultPublicKey
        doc._credentials = _credentials
        doc._credentialDict = _credentialDict
        doc._services = _services
        doc._serviceDict = _serviceDict
        doc._expires = _expires
        doc._proofsDict = _proofsDict
        doc._proofs = _proofs
        doc._metadata = try getMetadata().clone()

        return doc
    }
}
