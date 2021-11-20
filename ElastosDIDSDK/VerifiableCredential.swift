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

/// A verifiable credential can represent the information that a physical
/// credential represents. The addition of technologies, such as digital
/// signatures, makes verifiable credentials more tamper-evident and more
/// trustworthy than their physical counterparts.
///
/// <p>
/// This class following W3C's
/// <a href="https://www.w3.org/TR/vc-data-model/">Verifiable Credentials Data Model 1.0</a>
/// specification.
/// </p>
@objc(VerifiableCredential)
public class VerifiableCredential: DIDObject {
    private let TAG = NSStringFromClass(VerifiableCredential.self)
    let CONTEXT = "@context"
    private let ID = "id"
    private let TYPE = "type"
    private let ISSUER = "issuer"
    private let ISSUANCE_DATE = "issuanceDate"
    private let EXPIRATION_DATE = "expirationDate"
    private let CREDENTIAL_SUBJECT = "credentialSubject"
    private let PROOF = "proof"
    private let VERIFICATION_METHOD = "verificationMethod"
    private let CREATED = "created";
    private let SIGNATURE = "signature"

    public static let W3C_CREDENTIAL_CONTEXT = "https://www.w3.org/2018/credentials/v1"
    public static let ELASTOS_CREDENTIAL_CONTEXT = "https://elastos.org/credentials/v1"
    
    var _types: Array<String> = []
    private var _id: DIDURL?
    private var _issuer: DID?
    private var _issuanceDateString: String?
    private var _expirationDateString: String?
    private var _issuanceDate: Date?
    private var _expirationDate: Date?
    private var _subject: VerifiableCredentialSubject?
    private var _proof: VerifiableCredentialProof?
    private var _metadata: CredentialMetadata?

    private let RULE_EXPIRE : Int = 1
    private let RULE_GENUINE: Int = 2
    private let RULE_VALID  : Int = 3
    var _context: [String] = [ ]

    override init() {
        super.init()
    }
    
    /// Constructs a credential object, copy the contents from the given object.
    /// - Parameter credential: the source credential object
    init(_ credential: VerifiableCredential, _ withProof: Bool) throws {
        super.init(credential.getId()!, credential.getType())
        self._context = credential._context
        self._id = credential._id
        self._types = credential.getTypes()
        self._issuer = credential.issuer
        self._issuanceDate = credential.issuanceDate
        self._expirationDate = try credential.getExpirationDate()
        self._subject = credential.subject
        if withProof {
            self._proof = credential.proof
        }
    }
    
    func checkAttachedStore() throws {
        guard getMetadata().attachedStore else {
            throw DIDError.UncheckedError.IllegalStateError.NotAttachedWithStoreError()
        }
    }

    /// Get the id of this credential object
    /// the id of this credential
    public var id: DIDURL? {
        return _id
    }
    
    override func setId(_ id: DIDURL) {
        super.setId(id)
        self._id = id
    }

    /// Get the credential type.
    /// - Returns: the type string
    @objc
    public override func getType() -> String {
        var builder = ""
        var first = true

        builder.append("[")
        for type in _types {
            builder.append(!first ? ", ": "")
            builder.append(type)

            if  first {
                first = true
            }
        }
        builder.append("]")

        return builder
    }

    /// Get the credential type.
    /// - Returns: the type array
    @objc
    public func getTypes() -> [String] {
        return self._types
    }

    func appendType(_ type: String) {
        self._types.append(type)
        _types = _types.sorted()
    }

    func setType(_ newTypes: [String]) {
        for type in newTypes {
            self._types.append(type)
        }
        _types = _types.sorted()
    }

    /// Get the issuer of this credential.
    @objc
    public var issuer: DID? {
        // Guaranteed that this field would not be nil because the object
        // was generated by "builder".
        return self._issuer
    }

    func setIssuer(_ newIssuer: DID) {
        self._issuer = newIssuer
    }

    /// Get the issuance time.
    @objc
    public var issuanceDate: Date? {
        // Guaranteed that this field would not be nil because the object
        // was generated by "builder".
        return _issuanceDate
    }

    func setIssuanceDate(_ issuanceDate: Date) {
        self._issuanceDate = issuanceDate
    }

    /// Get the date of credential expired.
    public func getExpirationDate() throws -> Date? {
        guard let _ = _expirationDate else {
            let controllerDoc = try _subject?.did.resolve()
            guard let _ = controllerDoc else {
                return nil
            }
            return controllerDoc!.expirationDate
        }
        
        return _expirationDate
    }

    func setExpirationDate(_ expirationDate: Date) {
        self._expirationDate = expirationDate
    }

    func getMetadata() -> CredentialMetadata {
        if  self._metadata == nil {
            self._metadata = CredentialMetadata(id!)
        }
        return self._metadata!
    }

    /// Set meta data for this credential object.
    /// - Parameter newValue: the metadata object
    func setMetadata(_ newValue: CredentialMetadata) {
        self._metadata = newValue
        getId()!.setMetadata(newValue)
    }

    /// Get credential alias.
    /// - Returns: CredentialMeta instance.
    @objc
    public var metadata: CredentialMetadata {
        return getMetadata()
    }
    
    /// Checks if there is an expiration time specified.
    /// - Returns: whether the credential has expiration time
    public func hasExpirationDate() -> Bool {
        return _expirationDate != nil
    }
    
    /// Get last modified time.
    /// the last modified time, maybe null for old version credential object
    public var lastModified: Date? {
        return proof!.created
    }
    
    /// Get Credential subject object.
    @objc
    public var subject: VerifiableCredentialSubject? {
        return _subject
    }

    func setSubject(_ newSubject: VerifiableCredentialSubject) {
        self._subject = newSubject
    }

    /// Get Credential proof object.
    @objc
    public var proof: VerifiableCredentialProof? {
        return _proof
    }

    func setProof(_ newProof: VerifiableCredentialProof?) {
        self._proof = newProof
    }
    
    /// Sanitize routine before sealing or after deserialization.
    func sanitize() throws {
        guard let _ = id else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedCredentialError("Missing credential id")
        }
        guard _types.count != 0 else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedCredentialError("Missing credential type")
        }
        guard let _ = issuanceDate else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedCredentialError("Missing credential issuance date")
        }
        guard let _ = subject else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedCredentialError("Missing credential subject")
        }
//        guard let _ = subject!.did else {
//            throw DIDError.CheckedError.DIDSyntaxError.MalformedCredentialError("Missing credential subject id")
//        }
        guard let _ = proof else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedCredentialError("Missing credential proof")
        }
        _types = _types.sorted()
        if issuer == nil {
            _issuer = subject!.did
        }
        if id?.did == nil {
            id?.setDid(subject!.did)
        }
        if proof?.verificationMethod.did == nil {
            proof?.verificationMethod.setDid(issuer!)
        }
    }
    
    var serializeContextDid: DID? {
        return subject?.did
    }
    
    public var store: DIDStore? {
        return metadata.store
    }
    
    /// Check if this credential is a self proclaimed or not.
    public var isSelfProclaimed: Bool {
        return issuer == subject?.did
    }
    
    private func checkExpired() -> Bool {
        return _expirationDate != nil ? DateFormatter.isExipired(_expirationDate!) : false
    }

    /// Check if this credential object is expired or not.
    /// whether the credential object is expired
    public func isExpired() throws -> Bool {
        if (_expirationDate != nil) {
            if checkExpired() {
                return true
            }
        }
        
        let controllerDoc = try subject?.did.resolve()
        if (controllerDoc != nil && controllerDoc!.isExpired) {
            return true
        }
        
        if (!isSelfProclaimed) {
            let issuerDoc = try issuer?.resolve()
            if (issuerDoc != nil && issuerDoc!.isExpired) {
                return true
            }
        }
        
        return false
    }

    /// Check if this credential object is expired or not in asynchronous mode.
    /// - Returns: Issuance always occurs before any other actions involving a credential.
    public func isExpiredAsync() -> Promise<Bool> {
        return DispatchQueue.global().async(.promise){ [self] in try isExpired() }
    }

    /// Credential is expired or not asynchronous.
    /// - Returns: Issuance always occurs before any other actions involving a credential.
    @objc
    public func isExpiredAsyncUsingObjectC() -> AnyPromise {
        return AnyPromise(__resolverBlock: { [self] resolver in
            DispatchQueue.global().async{
                do {
                    resolver(try isExpired())
                }
                catch {
                    resolver(error)
                }
            }
        })
    }

    /// Check whether this credential object is genuine or not.
    /// Issuance always occurs before any other actions involving a credential.
    /// return: whether the credential object is genuine
    public func isGenuine() throws -> Bool {
        return try isGenuine(nil)
    }
    
    /// Check whether this credential object is genuine or not.
    /// Issuance always occurs before any other actions involving a credential.
    /// - Parameter listener: the listener for the verification events and messages
    /// return: whether the credential object is genuine
    public func isGenuine(listener: VerificationEventListener) throws -> Bool {
        return try isGenuine(listener)
    }
    
    /// Check whether this credential object is genuine or not.
    /// - Parameter listener: the listener for the verification events and messages
    /// Issuance always occurs before any other actions involving a credential.
    /// return: whether the credential object is genuine
    func isGenuine(_ listener: VerificationEventListener?) throws -> Bool {
    
        guard id?.did == subject?.did else {
            listener?.failed(context: self, args: "VC \(String(describing: id)): invalid id '\(String(describing: id))', should under the scope of '\(String(describing: subject?.did))'")
            listener?.failed(context: self, args: "VC \(String(describing: id)): is not genuine")

            return false
        }
        let issuerDoc = try issuer?.resolve()
        guard let _ = issuerDoc else {
            //throw new DIDNotFoundException(issuer.toString());
            listener?.failed(context: self, args: "VC \(String(describing: id)): Can not resolve the document for issuer '\(String(describing: issuer))'")
            listener?.failed(context: self, args: "VC \(String(describing: id)): is not genuine")
            
            throw DIDError.UncheckedError.IllegalStateError.DIDNotFoundError(issuer?.toString())
        }
        guard try issuerDoc!.isGenuine(listener) else {
            listener?.failed(context: self, args: "VC \(String(describing: id)): issuer '\(String(describing: issuer))' is not genuine")
            listener?.failed(context: self, args: "VC \(String(describing: id)): is not genuine")

            return false
        }
        // Credential should signed by any authentication key.
        guard try issuerDoc!.containsAuthenticationKey(forId: proof!.verificationMethod) else {
            listener?.failed(context: self, args: "VC \(String(describing: id)): key '\(String(describing: proof?.verificationMethod))' for proof is not an authencation key of '\(String(describing: proof?.verificationMethod.did))'")
            listener?.failed(context: self, args: "VC \(String(describing: id)): is not genuine")

            return false
        }
        // Unsupported public key type
        guard proof?.type == Constants.DEFAULT_PUBLICKEY_TYPE else {
            listener?.failed(context: self, args: "VC \(String(describing: id)): key type '\(String(describing: proof?.type))' for proof is not supported")
            listener?.failed(context: self, args: "VC \(String(describing: id)): is not genuine")

            return false
        }
        let vc = try VerifiableCredential(self, false)
        let json = vc.toString(true)
        guard let data = json.data(using: .utf8) else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalArgumentError("credential is nil")
        }
        guard try issuerDoc!.verify(withId: proof!.verificationMethod, using: proof!.signature, onto: data) else {
            listener?.failed(context: self, args: "VC \(String(describing: id)): proof is invalid, signature mismatch")
            listener?.failed(context: self, args: "VC \(String(describing: id)): is not genuine")

            return false
        }
        if !isSelfProclaimed {
            let controllerDoc = try subject?.did.resolve()
            if (try controllerDoc != nil && !controllerDoc!.isGenuine(listener)) {
                listener?.failed(context: self, args: "VC \(String(describing: id)): holder's document is not genuine")
                listener?.failed(context: self, args: "VC \(String(describing: id)): is not genuine")
                
                return false
            }
        }
        listener?.succeeded(context: self, args: "VC \(String(describing: id)): is genuine")
        
        return true
    }

    /// Credential is genuine or not asynchronous.
    /// Issuance always occurs before any other actions involving a credential.
    /// flase if not genuine, true if genuine.
    public func isGenuineAsync() -> Promise<Bool> {
        return DispatchQueue.global().async(.promise){ [self] in try isGenuine() }
    }
    
    /// Credential is genuine or not asynchronous.
    /// - Parameter listener: the listener for the verification events and messages
    /// - Returns: flase if not genuine, true if genuine.
    public func isGenuineAsync(listener: VerificationEventListener) -> Promise<Bool> {
        return DispatchQueue.global().async(.promise){ [self] in try isGenuine(listener) }
    }

    /// Credential is genuine or not asynchronous.
    /// Issuance always occurs before any other actions involving a credential.
    /// flase if not genuine, true if genuine.
    @objc
    public func isGenuineAsyncUsingObjectC() -> AnyPromise {
        return AnyPromise(__resolverBlock: { [self] resolver in
            DispatchQueue.global().async{
                do {
                    resolver(try isGenuine())
                }
                catch {
                    resolver(error)
                }
            }
        })
    }

    /// Credential is genuine or not asynchronous.
    /// Issuance always occurs before any other actions involving a credential.
    /// - Parameter listener: the listener for the verification events and messages
    /// flase if not genuine, true if genuine.
    @objc (isGenuineWithListenerAsyncUsingObjectC:)
    public func isGenuineAsyncUsingObjectC(listener: VerificationEventListener) -> AnyPromise {
        return AnyPromise(__resolverBlock: { [self] resolver in
            DispatchQueue.global().async{
                do {
                    resolver(try isGenuine(listener))
                }
                catch {
                    resolver(error)
                }
            }
        })
    }
    
    /// Credential is expired or not.
    /// Issuance always occurs before any other actions involving a credential.
    public func isValid() throws -> Bool {
        return try isValid(nil)
    }
    
    /// Credential is expired or not.
    /// Issuance always occurs before any other actions involving a credential.
    /// - Parameter listener: the listener for the verification events and messages
    /// - Returns: whether the credential object is valid
    public func isValid(listener: VerificationEventListener) throws -> Bool {
        return try isValid(listener)
    }
    
    /// Credential is expired or not.
    /// Issuance always occurs before any other actions involving a credential.
    func isValid(_ listener: VerificationEventListener?) throws -> Bool {
        if (_expirationDate != nil) {
            if checkExpired() == true {
                listener?.failed(context: self, args: "VC \(String(describing: id)): is expired")
                listener?.failed(context: self, args: "VC \(String(describing: id)): is invalid")
                
                return false
            }
        }
        
        let issuerDoc = try issuer?.resolve()
        if (issuerDoc == nil) {
            //throw new DIDNotFoundException(issuer.toString());
            listener?.failed(context: self, args: "VC \(String(describing: id)): can not resolve the document for issuer '\(String(describing: issuer))'")
            listener?.failed(context: self, args: "VC \(String(describing: id)): is invalid")

            return false
        }
        
        if (try !issuerDoc!.isValid(listener)) {
            listener?.failed(context: self, args: "VC \(String(describing: id)): issuer '\(String(describing: issuer))' is invalid")
            listener?.failed(context: self, args: "VC \(String(describing: id)): is invalid")

            return false
        }
        
        // Credential should signed by any authentication key.
        if (try !issuerDoc!.containsAuthenticationKey(forId: proof!.verificationMethod)) {
            listener?.failed(context: self, args: "VC \(String(describing: id)): key '\(String(describing: proof?.verificationMethod))' for proof is not an authencation key of '\(String(describing: proof?.verificationMethod.did))'")
            listener?.failed(context: self, args: "VC \(String(describing: subject)): is invalid")

            return false
        }
        
        // Unsupported public key type;
        if proof?.type != Constants.DEFAULT_PUBLICKEY_TYPE {
            listener?.failed(context: self, args: "VC \(String(describing: id)): key type '\(String(describing: proof?.type))' for proof is not supported")
            listener?.failed(context: self, args: "VC \(String(describing: id)): is invalid")

            return false
        }
        
        let vc = try VerifiableCredential(self, false)
        let json = vc.toString(true)
        if try !issuerDoc!.verify(withId: proof!.verificationMethod, using: proof!.signature, onto: json.data(using: .utf8)!) {
            listener?.failed(context: self, args: "VC \(String(describing: id)): proof is invalid, signature mismatch")
            listener?.failed(context: self, args: "VC \(String(describing: id)): is invalid")
            
            return false
        }

        if !isSelfProclaimed {
            let controllerDoc = try subject?.did.resolve()
            if (try controllerDoc == nil && !controllerDoc!.isValid(listener)) {
                listener?.failed(context: self, args: "VC \(String(describing: id)): holder's document is invalid")
                listener?.failed(context: self, args: "VC \(String(describing: id)): is invalid")

                return false
            }
        }
        listener?.succeeded(context: self, args: "VC \(String(describing: id)): is valid")

        return true
    }
    
    /// Credential is expired or not asynchronous.
    /// - Returns: flase if not genuine, true if genuine.
    public func isValidAsync() -> Promise<Bool> {
       return DispatchQueue.global().async(.promise){ [self] in try isValid() }
    }
    
    /// Credential is expired or not asynchronous.
    /// - Parameter listener: the listener for the verification events and messages
    /// - Returns: flase if not genuine, true if genuine.
    public func isValidAsync(listener: VerificationEventListener) -> Promise<Bool> {
       return DispatchQueue.global().async(.promise){ [self] in try isValid(listener) }
    }

    /// Credential is expired or not asynchronous.
    /// - Returns: flase if not genuine, true if genuine.
    @objc
    public func isValidAsyncUsingObjectC() -> AnyPromise {
        return AnyPromise(__resolverBlock: { [self] resolver in
            DispatchQueue.global().async{
                do {
                    resolver(try isValid())
                }
                catch {
                    resolver(error)
                }
            }
        })
    }
    
    /// Credential is expired or not asynchronous.
    /// - Parameter listener: the listener for the verification events and messages
    /// - Returns: flase if not genuine, true if genuine.
    @objc (isValidWithListenerAsyncUsingObjectC:)
    public func isValidAsyncUsingObjectC(listener: VerificationEventListener) -> AnyPromise {
        return AnyPromise(__resolverBlock: { [self] resolver in
            DispatchQueue.global().async{
                do {
                    resolver(try isValid(listener))
                }
                catch {
                    resolver(error)
                }
            }
        })
    }
    
    /// Credential is expired or not.
    /// Issuance always occurs before any other actions involving a credential.
    public func isRevoked() throws -> Bool {
        guard !getMetadata().isRevoked() else {
            return true
        }
        let bio = try DIDBackend.sharedInstance().resolveCredentialBiography(id!, issuer!)
        let revoked = bio!.status == CredentialBiographyStatus.STATUS_REVOKED
        if revoked {
            metadata.setRevoked(revoked)
        }
        
        return revoked
    }
    
    /// Credential is expired or not asynchronous.
    /// - Returns: flase if not genuine, true if genuine.
    public func isRevokedAsync() -> Promise<Bool> {
       return DispatchQueue.global().async(.promise){ [self] in try isRevoked() }
    }
    
    /// Check whether this credential object was declared or not.
    /// - Throws: whether the credential object was declared
    /// - Returns: DIDResolveError if error occurs when resolve the DIDs
    public func wasDeclared() throws -> Bool {
        let bio = try DIDBackend.sharedInstance().resolveCredentialBiography(id!, issuer!)
        guard bio!.status != CredentialBiographyStatus.STATUS_NOT_FOUND else {
            return false
        }
        for tx in bio!.getAllTransactions() {
            if tx.request.operation == IDChainRequestOperation.DECLARE {
                return true
            }
        }
        
        return false
    }
    
    /// Check whether this credential object was declared or not.
    /// - Throws: whether the credential object was declared
    /// - Returns: the new Promise if success; false otherwise.
    ///            The boolean result was declared or not
    public func wasDeclaredAsync() -> Promise<Bool> {
       return DispatchQueue.global().async(.promise){ [self] in try wasDeclared() }
    }
    
    private func declare(signKey: DIDURL?, storePassword: String, adapter: DIDTransactionAdapter?) throws {
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        try checkAttachedStore()
        guard try isGenuine() else {
            Log.e(TAG, "Publish failed because the credential is not genuine.")
            throw DIDError.UncheckedError.IllegalStateError.CredentialNotGenuineError(id?.toString())
        }
        guard try !isExpired() else {
            Log.e(TAG, "Publish failed because the credential is expired.")
            throw DIDError.UncheckedError.IllegalStateError.CredentialRevokedError(id?.toString())
        }
        guard try !isRevoked() else {
            Log.e(TAG, "Publish failed because the credential is revoked.")
            throw DIDError.UncheckedError.IllegalStateError.CredentialRevokedError(id?.toString())
        }
        guard try !wasDeclared() else {
            Log.e(TAG, "Publish failed because the credential already declared.")
            throw DIDError.UncheckedError.IllegalStateError.CredentialAlreadyExistError(id?.toString())
        }
        var owner = try store!.loadDid(subject!.did)
        if owner == nil {
            // Fail-back: resolve the owner's document
            owner = try subject?.did.resolve()
            guard let _ = owner else {
                throw DIDError.UncheckedError.IllegalStateError.DIDNotFoundError(subject!.did.toString())
            }
            owner?.getMetadata().attachStore(store!)
        }
        
        if signKey == nil && owner?.defaultPublicKeyId() == nil {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("Unknown sign key.")
        }
        var sk = signKey
        if (sk != nil) {
            if (try !owner!.containsAuthenticationKey(forId: signKey!)) {
                throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError(signKey!.toString())
            }
        } else {
            sk = owner!.defaultPublicKeyId()
        }
        try DIDBackend.sharedInstance().declareCredential(self, owner!, sk!, storePassword, adapter as? DIDAdapter)
    }
    
    /// Publish this credential object to the ID chain, declare it to the public.
    /// - Parameters:
    ///   - signKey: the contoller's key id to sign the declare transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an DIDTransactionAdapter object
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public func declare(_ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try declare(signKey: signKey, storePassword: storePassword, adapter: adapter)
    }
    
    /// Publish this credential object to the ID chain, declare it to the public.
    /// - Parameters:
    ///   - signKey: the contoller's key id to sign the declare transaction
    ///   - storePassword: the password of the DID store
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public func declare(_ signKey: DIDURL, _ storePassword: String) throws {
        try declare(signKey: signKey, storePassword: storePassword, adapter: nil)
    }
    
    /// Publish this credential object to the ID chain, declare it to the public.
    /// - Parameters:
    ///   - signKey: the contoller's key id to sign the declare transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an DIDTransactionAdapter object
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public func declare(_ signKey: String, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try declare(signKey: DIDURL.valueOf(subject!.did, signKey), storePassword: storePassword, adapter: adapter)
    }
    
    /// Publish this credential object to the ID chain, declare it to the public.
    /// - Parameters:
    ///   - signKey: the contoller's key id to sign the declare transaction
    ///   - storePassword: the password of the DID store
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public func declare(_ signKey: String, _ storePassword: String) throws {
        try declare(signKey: DIDURL.valueOf(subject!.did, signKey), storePassword: storePassword, adapter: nil)
    }
    
    /// Publish this credential object to the ID chain, declare it to the public.
    /// - Parameters:
    ///   - storePassword: the password of the DID store
    ///   - adapter: an DIDTransactionAdapter object
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public func declare(_ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try declare(signKey: nil, storePassword: storePassword, adapter: adapter)
    }
    
    /// Publish this credential object to the ID chain, declare it to the public.
    /// - Parameters:
    ///   - storePassword: the password of the DID store
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public func declare(_ storePassword: String) throws {
        try declare(signKey: nil, storePassword: storePassword, adapter: nil)
    }
    
    /// Publish this credential object to the ID chain, declare it to the public
    /// in asynchronous mode.
    ///
    /// Only the owner of the credential object who can declare credential to
    /// public.
    ///
    /// - Parameters:
    ///   - signKey: the contoller's key id to sign the declare transaction
    ///   - the contoller's key id to sign the declare transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object, use the
    ///                   DIDBackend's default implementation if nil
    /// - Returns: a new Promise
    private func declareAsync(signKey: DIDURL?, storePassword: String, adapter: DIDTransactionAdapter?) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try declare(signKey: signKey, storePassword: storePassword, adapter: adapter) }
    }
    
    /// Publish this credential object to the ID chain, declare it to the public
    /// in asynchronous mode.
    ///
    /// Only the owner of the credential object who can declare credential to
    /// public.
    ///
    /// - Parameters:
    ///   - signKey: the contoller's key id to sign the declare transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object, use the
    ///                   DIDBackend's default implementation if nil
    /// - Returns: a new Promise
    public func declareAsync(_ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return declareAsync(signKey: signKey, storePassword: storePassword, adapter: adapter)
    }
    
    /// Publish this credential object to the ID chain, declare it to the public
    /// in asynchronous mode.
    ///
    /// Only the owner of the credential object who can declare credential to
    /// public.
    ///
    /// - Parameters:
    ///   - signKey: the contoller's key id to sign the declare transaction
    ///   - storePassword: the password of the DID store
    /// - Returns: a new Promise
    public func declareAsync(_ signKey: DIDURL, _ storePassword: String) -> Promise<Void> {
        return declareAsync(signKey: signKey, storePassword: storePassword, adapter: nil)
    }
    
    /// Publish this credential object to the ID chain, declare it to the public
    /// in asynchronous mode.
    ///
    /// Only the owner of the credential object who can declare credential to
    /// public.
    ///
    /// - Parameters:
    ///   - signKey: the contoller's key id to sign the declare transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object
    /// - Returns: a new Promise
    public func declareAsync(_ signKey: String, _ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try declare(signKey, storePassword, adapter) }
    }
    
    /// Publish this credential object to the ID chain, declare it to the public
    /// in asynchronous mode.
    ///
    /// Only the owner of the credential object who can declare credential to
    /// public.
    ///
    /// - Parameters:
    ///   - signKey: the contoller's key id to sign the declare transaction
    ///   - storePassword: the password of the DID store
    /// - Returns: a new Promise
    public func declareAsync(_ signKey: String, _ storePassword: String) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try declare(signKey, storePassword) }
    }
    
    /// Publish this credential object to the ID chain, declare it to the public
    /// in asynchronous mode.
    ///
    /// Only the owner of the credential object who can declare credential to
    /// public.
    ///
    /// - Parameters:
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object, use the
    ///                   DIDBackend's default implementation if nil
    /// - Returns: a new Promise
    public func declareAsync(_ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try declare(storePassword, adapter) }
    }
    
    /// Publish this credential object to the ID chain, declare it to the public
    /// in asynchronous mode.
    ///
    /// Only the owner of the credential object who can declare credential to
    /// public.
    ///
    /// - Parameters:
    ///   - storePassword: the password of the DID store
    /// - Returns: a new Promise
    public func declareAsync(_ storePassword: String) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try declare(storePassword) }
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object, use the
    ///                   DIDBackend's default implementation if nil
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    private func revoke(signer: DIDDocument?, signKey: DIDURL?, storePassword: String, adapter: DIDTransactionAdapter?) throws {
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        try checkAttachedStore()
        let owner = try subject?.did.resolve()
        guard let _ = owner else {
            throw DIDError.UncheckedError.IllegalStateError.DIDNotFoundError(subject?.did.toString())
        }
        owner?.getMetadata().attachStore(store!)
        let issuerDoc = try issuer!.resolve()
        guard let _ = issuerDoc else {
            Log.e(TAG, "Publish failed because the credential issuer is not published.")
            throw DIDError.UncheckedError.IllegalStateError.DIDNotFoundError(issuer?.toString())
        }
        issuerDoc?.getMetadata().attachStore(store!)
        guard try !isRevoked() else {
            Log.e(TAG, "Publish failed because the credential is revoked.")
            throw DIDError.UncheckedError.IllegalStateError.CredentialRevokedError(id?.toString())
        }
        var sg = signer
        if signer == nil {
            let signerDid = (signKey != nil && signKey!.did != nil) ?
                    signKey!.did : subject!.did
            sg = try store!.loadDid(signerDid!)
            if sg == nil {
                // Fail-back: resolve the owner's document
                sg = try subject!.did.resolve()
                guard let _ = sg else {
                    throw DIDError.UncheckedError.IllegalStateError.DIDNotFoundError(subject?.did.toString())
                }
                sg?.getMetadata().attachStore(store!)
            }
        }
        if sg!.subject != subject?.did && sg!.subject != issuer && !owner!.hasController(sg!.subject) && !issuerDoc!.hasController(sg!.subject) {
            Log.e(TAG, "Publish failed because the invalid signer or signkey.")
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("Not owner or issuer: \(sg!.subject)")
        }
        
        if signKey == nil && sg!.defaultPublicKeyId() == nil {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("Unknown sign key")
        }
        var sk = signKey
        if signKey != nil{
            guard try sg!.containsAuthenticationKey(forId: signKey!) else {
                throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError(signKey!.toString())
            }
        }
        else {
            sk = sg!.defaultPublicKeyId()
        }
        try DIDBackend.sharedInstance().revokeCredential(self, sg!, sk!, storePassword, adapter as? DIDAdapter)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object, use the
    ///                   DIDBackend's default implementation if nil
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public func revoke(_ signer: DIDDocument, _ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try revoke(signer: signer, signKey: signKey, storePassword: storePassword, adapter: adapter)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public func revoke(_ signer: DIDDocument, _ signKey: DIDURL, _ storePassword: String) throws {
        try revoke(signer: signer, signKey: signKey, storePassword: storePassword, adapter: nil)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signer: the DID document of credential owner or issuer
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object, use the
    ///                   DIDBackend's default implementation if nil
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public func revoke(_ signer: DIDDocument, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try revoke(signer: signer, signKey: nil, storePassword: storePassword, adapter: adapter)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signer: the DID document of credential owner or issuer
    ///   - storePassword: the password of the DID store
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public func revoke(_ signer: DIDDocument, _ storePassword: String) throws {
        try revoke(signer: signer, signKey: nil, storePassword: storePassword, adapter: nil)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object, use the
    ///                   DIDBackend's default implementation if nil
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public func revoke(_ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try revoke(signer: nil, signKey: signKey, storePassword: storePassword, adapter: adapter)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public func revoke(_ signKey: DIDURL, _ storePassword: String) throws {
        try revoke(signer: nil, signKey: signKey, storePassword: storePassword, adapter: nil)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object, use the
    ///                   DIDBackend's default implementation if nil
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    private func revoke(signer: DIDDocument? = nil, signKey: String, storePassword: String, adapter: DIDTransactionAdapter? = nil) throws {
        try revoke(signer: signer, signKey: DIDURL.valueOf(subject!.did, signKey), storePassword: storePassword, adapter: adapter)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public func revoke(_ signer: DIDDocument, _ signKey: String, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try revoke(signer: signer, signKey: signKey, storePassword: storePassword, adapter: adapter)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public func revoke(_ signer: DIDDocument, _ signKey: String, _ storePassword: String) throws {
        try revoke(signer: signer, signKey: signKey, storePassword: storePassword)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signer: the DID document of credential owner or issuer
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public func revoke(_ signKey: String, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try revoke(signKey: signKey, storePassword: storePassword, adapter: adapter)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public func revoke(_ signKey: String, _ storePassword: String) throws {
        try revoke(signKey: signKey, storePassword: storePassword)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public func revoke(_ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try revoke(signer: nil, signKey: nil, storePassword: storePassword, adapter: adapter)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - storePassword: the password of the DID store
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public func revoke(_ storePassword: String) throws {
        try revoke(signer: nil, signKey: nil, storePassword: storePassword, adapter: nil)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// chain in asynchronous mode.
    ///
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object, use the
    ///                   DIDBackend's default implementation if nil
    /// - Returns: a new Promise
    private func revokeAsync(signer: DIDDocument? = nil, signKey: DIDURL? = nil, storePassword: String, adapter: DIDTransactionAdapter? = nil) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try revoke(signer: signer, signKey: signKey, storePassword: storePassword, adapter: adapter) }
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// chain in asynchronous mode.
    ///
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object
    /// - Returns: a new Promise
    public func revokeAsync(_ signer: DIDDocument, _ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return revokeAsync(signer: signer, signKey: signKey, storePassword: storePassword, adapter: adapter)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// chain in asynchronous mode.
    ///
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    /// - Returns: a new Promise
    public func revokeAsync(_ signer: DIDDocument, _ signKey: DIDURL, _ storePassword: String) -> Promise<Void> {
        return revokeAsync(signer: signer, signKey: signKey, storePassword: storePassword)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// chain in asynchronous mode.
    ///
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signer: the DID document of credential owner or issuer
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object
    /// - Returns: a new Promise
    public func revokeAsync(_ signer: DIDDocument, _ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return revokeAsync(signer: signer, storePassword: storePassword, adapter: adapter)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// chain in asynchronous mode.
    ///
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signer: the DID document of credential owner or issuer
    ///   - storePassword: the password of the DID store
    /// - Returns: a new Promise
    public func revokeAsync(_ signer: DIDDocument, _ storePassword: String) -> Promise<Void> {
        return revokeAsync(signer: signer, storePassword: storePassword, adapter: nil)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// chain in asynchronous mode.
    ///
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object
    /// - Returns: a new Promise
    public func revokeAsync(_ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return revokeAsync(signKey: signKey, storePassword: storePassword, adapter: adapter)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// chain in asynchronous mode.
    ///
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    /// - Returns: a new Promise
    public func revokeAsync(_ signKey: DIDURL, _ storePassword: String) -> Promise<Void> {
        return revokeAsync(signKey: signKey, storePassword: storePassword)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// chain in asynchronous mode.
    ///
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object, use the
    ///                   DIDBackend's default implementation if nil
    /// - Returns: a new Promise
    private func revokeAsync(signer: DIDDocument? = nil, signKey: String, storePassword: String, adapter: DIDTransactionAdapter? = nil) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try revoke(signer: signer, signKey: DIDURL.valueOf(subject!.did, signKey), storePassword: storePassword, adapter: adapter) }
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// chain in asynchronous mode.
    ///
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object
    /// - Returns: a new Promise
    public func revokeAsync(_ signer: DIDDocument, _ signKey: String, _ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return revokeAsync(signer: signer, signKey: signKey, storePassword: storePassword, adapter: adapter)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// chain in asynchronous mode.
    ///
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    /// - Returns: a new Promise
    public func revokeAsync(_ signer: DIDDocument, _ signKey: String, _ storePassword: String) -> Promise<Void> {
        return revokeAsync(signer: signer, signKey: signKey, storePassword: storePassword)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// chain in asynchronous mode.
    ///
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object
    /// - Returns: a new Promise
    public func revokeAsync(_ signKey: String, _ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return revokeAsync(signKey: signKey, storePassword: storePassword, adapter: adapter)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// chain in asynchronous mode.
    ///
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    /// - Returns: a new Promise
    public func revokeAsync(_ signKey: String, _ storePassword: String) -> Promise<Void> {
        return revokeAsync(signKey: signKey, storePassword: storePassword)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// chain in asynchronous mode.
    ///
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object
    /// - Returns: a new Promise
    public func revokeAsync(_ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return revokeAsync(storePassword: storePassword, adapter: adapter)
    }
    
    /// Revoke this credential object and announce the revocation to the ID
    /// chain in asynchronous mode.
    ///
    /// The credential owner and issuer both can revoke the credential.
    /// - Parameters:
    ///   - storePassword: the password of the DID store
    /// - Returns: a new Promise
    public func revokeAsync(_ storePassword: String) -> Promise<Void> {
        return revokeAsync(storePassword: storePassword)
    }
    
    /// Revoke a credential by id and announce the revocation to the ID chain.
    /// - Parameters:
    ///   - id: the id of the credential to be revoke
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object, use the
    ///                   DIDBackend's default implementation if nil
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    private class func revoke(id: DIDURL, signer: DIDDocument, signKey: DIDURL? = nil, storePassword: String, adapter: DIDTransactionAdapter? = nil) throws {
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        guard signer.getMetadata().attachedStore else {
            throw DIDError.UncheckedError.IllegalStateError.NotAttachedWithStoreError(signer.subject.toString())
        }
        let bio = try DIDBackend.sharedInstance().resolveCredentialBiography(id, signer.subject)
        guard bio!.status != CredentialBiographyStatus.STATUS_REVOKED else {
            throw DIDError.UncheckedError.IllegalStateError.CredentialRevokedError(id.toString())
        }
        if bio!.status == CredentialBiographyStatus.STATUS_VALID {
            let vc = bio!.getTransaction(0).request.credential
            guard signer == vc!.subject!.did else {
                Log.e(NSStringFromClass(VerifiableCredential.self), "Publish failed because the invalid signer or signkey.")
                throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("Not owner or issuer: \(signer.subject)")
            }
        }
        
        if signKey == nil && signer.defaultPublicKeyId() == nil {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("Unknown sign key")
        }
        var sk = signKey
        if signKey != nil {
            guard try signer.containsAuthenticationKey(forId: signKey!) else {
                throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError(signKey!.toString())
            }
        }
        else {
            sk = signer.defaultPublicKeyId()
        }
        try DIDBackend.sharedInstance().revokeCredential(id, signer, sk!, storePassword, adapter as? DIDAdapter)
    }
    
    /// Revoke a credential by id and announce the revocation to the ID chain.
    /// - Parameters:
    ///   - id: the id of the credential to be revoke
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public class func revoke(_ id: DIDURL, _ signer: DIDDocument, _ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try revoke(id, signer, signKey, storePassword, adapter)
    }
    
    /// Revoke a credential by id and announce the revocation to the ID chain.
    /// - Parameters:
    ///   - id: the id of the credential to be revoke
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public class func revoke(_ id: DIDURL, _ signer: DIDDocument, _ signKey: DIDURL, _ storePassword: String) throws {
        try revoke(id: id, signer: signer, signKey: signKey, storePassword: storePassword)
    }
    
    /// Revoke a credential by id and announce the revocation to the ID chain.
    /// - Parameters:
    ///   - id: the id of the credential to be revoke
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public class func revoke(_ id: String, _ signer: DIDDocument, _ signKey: String, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try revoke(id: DIDURL.valueOf(id), signer: signer, signKey: DIDURL.valueOf(signer.subject, signKey), storePassword: storePassword, adapter: adapter)
    }
   
    /// Revoke a credential by id and announce the revocation to the ID chain.
    /// - Parameters:
    ///   - id: the id of the credential to be revoke
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public class func revoke(_ id: String, _ signer: DIDDocument, _ signKey: String, _ storePassword: String) throws {
        try revoke(id: DIDURL.valueOf(id), signer: signer, signKey: DIDURL.valueOf(signer.subject, signKey), storePassword: storePassword)
    }
    
    /// Revoke a credential by id and announce the revocation to the ID chain.
    /// - Parameters:
    ///   - id: the id of the credential to be revoke
    ///   - signer: the DID document of credential owner or issuer
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public class func revoke(_ id: DIDURL, _ signer: DIDDocument, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try revoke(id: id, signer: signer, storePassword: storePassword, adapter: adapter)
    }
    
    /// Revoke a credential by id and announce the revocation to the ID chain.
    /// - Parameters:
    ///   - id: the id of the credential to be revoke
    ///   - signer: the DID document of credential owner or issuer
    ///   - storePassword: the password of the DID store
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public class func revoke(_ id: DIDURL, _ signer: DIDDocument, _ storePassword: String) throws {
        try revoke(id: id, signer: signer, storePassword: storePassword)
    }
    
    /// Revoke a credential by id and announce the revocation to the ID chain.
    /// - Parameters:
    ///   - id: the id of the credential to be revoke
    ///   - signer: the DID document of credential owner or issuer
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public class func revoke(_ id: String, _ signer: DIDDocument, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try revoke(id: DIDURL.valueOf(id), signer: signer, storePassword: storePassword, adapter: adapter)
    }
   
    /// Revoke a credential by id and announce the revocation to the ID chain.
    /// - Parameters:
    ///   - id: the id of the credential to be revoke
    ///   - signer: the DID document of credential owner or issuer
    ///   - storePassword: the password of the DID store
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public class func revoke(_ id: String, _ signer: DIDDocument, _ storePassword: String) throws {
        try revoke(id: DIDURL.valueOf(id), signer: signer, storePassword: storePassword)
    }
    
    /// Revoke a credential by id and announce the revocation to the ID chain
    /// in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the credential to be revoke
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object, use the
    ///                   DIDBackend's default implementation if nil
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    private class func revokeAsync(id: DIDURL, signer: DIDDocument, signKey: DIDURL? = nil, storePassword: String, adapter: DIDTransactionAdapter? = nil) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try revoke(id: id, signer: signer, signKey: signKey, storePassword: storePassword, adapter: adapter) }
    }
    
    /// Revoke a credential by id and announce the revocation to the ID chain
    /// in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the credential to be revoke
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public class func revokeAsync(_ id: DIDURL, _ signer: DIDDocument, _ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return revokeAsync(id: id, signer: signer, signKey: signKey, storePassword: storePassword, adapter: adapter)
    }
    
    /// Revoke a credential by id and announce the revocation to the ID chain
    /// in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the credential to be revoke
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public class func revokeAsync(_ id: DIDURL, _ signer: DIDDocument, _ signKey: DIDURL, _ storePassword: String) -> Promise<Void> {
        return revokeAsync(id: id, signer: signer, signKey: signKey, storePassword: storePassword)
    }
    
    /// Revoke a credential by id and announce the revocation to the ID chain
    /// in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the credential to be revoke
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public class func revokeAsync(_ id: String, _ signer: DIDDocument, _ signKey: String, _ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try revoke(id, signer, signKey, storePassword, adapter) }
    }
    
    /// Revoke a credential by id and announce the revocation to the ID chain
    /// in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the credential to be revoke
    ///   - signer: the DID document of credential owner or issuer
    ///   - signKey: the key id to sign the revoke transaction
    ///   - storePassword: the password of the DID store
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public class func revokeAsync(_ id: String, _ signer: DIDDocument, _ signKey: String, _ storePassword: String) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try revoke(id, signer, signKey, storePassword) }
    }

    /// Revoke a credential by id and announce the revocation to the ID chain
    /// in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the credential to be revoke
    ///   - signer: the DID document of credential owner or issuer
    ///   - storePassword: the password of the DID store
    ///   - adapter: an optional DIDTransactionAdapter object
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public class func revokeAsync(_ id: String, _ signer: DIDDocument, _ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try revoke(id, signer, storePassword, adapter) }
    }
    
    /// Revoke a credential by id and announce the revocation to the ID chain
    /// in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the credential to be revoke
    ///   - signer: the DID document of credential owner or issuer
    ///   - storePassword: the password of the DID store
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public class func revokeAsync(_ id: DIDURL, _ signer: DIDDocument, _ storePassword: String) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try revoke(id, signer, storePassword) }
    }
    
    /// Revoke a credential by id and announce the revocation to the ID chain
    /// in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the credential to be revoke
    ///   - signer: the DID document of credential owner or issuer
    ///   - storePassword: the password of the DID store
    /// - Throws: DIDStoreError if an error occurred when accessing the DID store
    /// - Throws DIDBackendError if an error occurred when publish the transaction
    public class func revokeAsync(_ id: String, _ signer: DIDDocument, _ storePassword: String) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try revoke(id, signer, storePassword) }
    }
    
    /// Resolve the specific VerifiableCredential object.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - signer: optional, the issuer's did
    ///   - force: if true then ignore the local cache and resolve the
    ///            credential from the ID chain directly; otherwise will try
    ///            to load the credential from the local cache, if the local
    ///            cache not contains this credential, then resolve it from
    ///            the ID chain
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Returns: the resolved VerifiableCredential object
    private class func resolve(id: DIDURL, _ signer: DID?, _ force: Bool) throws -> VerifiableCredential? {
        var vc: VerifiableCredential? = nil
        if let _ = signer {
            vc = try DIDBackend.sharedInstance().resolveCredential(id, signer!, force)
        }
        else {
            vc = try DIDBackend.sharedInstance().resolveCredential(id, force)
        }

        if vc != nil {
            id.setMetadata(vc!.getMetadata())
        }
        
        return vc
    }
    
    /// Resolve the specific VerifiableCredential object.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - issuer: the issuer's did
    ///   - force: if true then ignore the local cache and resolve the
    ///            credential from the ID chain directly; otherwise will try
    ///            to load the credential from the local cache, if the local
    ///            cache not contains this credential, then resolve it from
    ///            the ID chain
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Returns: the resolved VerifiableCredential object
    public class func resolve(_ id: DIDURL, _ issuer: DID, _ force: Bool) throws -> VerifiableCredential? {
        return try resolve(id: id, issuer, force)
    }
    
    /// Resolve the specific VerifiableCredential object.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - issuer: the issuer's did
    ///   - force: if true then ignore the local cache and resolve the
    ///            credential from the ID chain directly; otherwise will try
    ///            to load the credential from the local cache, if the local
    ///            cache not contains this credential, then resolve it from
    ///            the ID chain
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Returns: the resolved VerifiableCredential object
    private class func resolve(_ id: String, _ issuer: String?, _ force: Bool) throws -> VerifiableCredential? {
        return try resolve(id: DIDURL.valueOf(id), issuer != nil ? DID.valueOf(issuer!) : nil, force)
    }
    
    /// Resolve the specific VerifiableCredential object.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - issuer: the issuer's did
    ///   - force: if true then ignore the local cache and resolve the
    ///            credential from the ID chain directly; otherwise will try
    ///            to load the credential from the local cache, if the local
    ///            cache not contains this credential, then resolve it from
    ///            the ID chain
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Returns: the resolved VerifiableCredential object
    public class func resolve(_ id: String, _ issuer: String, _ force: Bool) throws -> VerifiableCredential? {
        return try resolve(DIDURL.valueOf(id), DID.valueOf(issuer)!, force)
    }
    
    /// Resolve the specific VerifiableCredential object.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - issuer: the issuer's did
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Returns: the resolved VerifiableCredential object
    public class func resolve(_ id: DIDURL, _ issuer: DID)throws -> VerifiableCredential? {
        return try resolve(id, issuer, false)
    }
    
    /// Resolve the specific VerifiableCredential object.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - issuer: the issuer's did
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Returns: the resolved VerifiableCredential object
    public class func resolve(_ id: String, _ issuer: String) throws -> VerifiableCredential? {
        return try resolve(DIDURL.valueOf(id), DID.valueOf(issuer)!, false)
    }
    
    /// Resolve the specific VerifiableCredential object.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - force: if true then ignore the local cache and resolve the
    ///            credential from the ID chain directly; otherwise will try
    ///            to load the credential from the local cache, if the local
    ///            cache not contains this credential, then resolve it from
    ///            the ID chain
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Returns: the resolved VerifiableCredential object
    public class func resolve(_ id: DIDURL, _ force: Bool) throws -> VerifiableCredential? {
        return try resolve(id: id, nil, force)
    }
    
    /// Resolve the specific VerifiableCredential object.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - force: if true then ignore the local cache and resolve the
    ///            credential from the ID chain directly; otherwise will try
    ///            to load the credential from the local cache, if the local
    ///            cache not contains this credential, then resolve it from
    ///            the ID chain
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Returns: the resolved VerifiableCredential object
    public class func resolve(_ id: String, _ force: Bool) throws -> VerifiableCredential? {
        return try resolve(id: DIDURL.valueOf(id), nil, force)
    }
    
    /// Resolve the specific VerifiableCredential object.
    /// - Parameters:
    ///   - id: the id of the target credential
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Returns: the resolved VerifiableCredential object
    public class func resolve(_ id: DIDURL) throws -> VerifiableCredential? {
        return try resolve(id: id, nil, false)
    }
    
    /// Resolve the specific VerifiableCredential object.
    /// - Parameters:
    ///   - id: the id of the target credential
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Returns: the resolved VerifiableCredential object
    public class func resolve(_ id: String) throws -> VerifiableCredential? {
        return try resolve(id: DIDURL.valueOf(id), nil, false)
    }
    
    /// Resolve the specific VerifiableCredential object in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - issuer: the issuer's did
    ///   - force: if true then ignore the local cache and resolve the
    ///            credential from the ID chain directly; otherwise will try
    ///            to load the credential from the local cache, if the local
    ///            cache not contains this credential, then resolve it from
    ///            the ID chain
    /// - Returns: a new Promise, the result is the resolved
    ///             VerifiableCredential object if success; nil otherwise
    private class func resolveAsync(_ id: DIDURL, _ issuer: DID?, _ force: Bool) -> Promise<VerifiableCredential?> {
        return DispatchQueue.global().async(.promise){ [self] in try resolve(id: id, issuer, force) }
    }
    
    /// Resolve the specific VerifiableCredential object in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - issuer: the issuer's did
    ///   - force: if true then ignore the local cache and resolve the
    ///            credential from the ID chain directly; otherwise will try
    ///            to load the credential from the local cache, if the local
    ///            cache not contains this credential, then resolve it from
    ///            the ID chain
    /// - Returns: a new Promise, the result is the resolved
    ///             VerifiableCredential object if success; nil otherwise
    public class func resolveAsync(_ id: DIDURL, _ issuer: DID, _ force: Bool) -> Promise<VerifiableCredential?> {
        return resolveAsync(id, issuer, force)
    }
    
    /// Resolve the specific VerifiableCredential object in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - issuer: the issuer's did
    ///   - force: if true then ignore the local cache and resolve the
    ///            credential from the ID chain directly; otherwise will try
    ///            to load the credential from the local cache, if the local
    ///            cache not contains this credential, then resolve it from
    ///            the ID chain
    /// - Returns: a new Promise, the result is the resolved
    ///             VerifiableCredential object if success; nil otherwise
    private class func resolveAsync(_ id: String, _ issuer: String?, _ force: Bool) -> Promise<VerifiableCredential?> {
        return DispatchQueue.global().async(.promise){ [self] in try resolve(id, issuer, force) }
    }
    
    /// Resolve the specific VerifiableCredential object in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - issuer: the issuer's did
    ///   - force: if true then ignore the local cache and resolve the
    ///            credential from the ID chain directly; otherwise will try
    ///            to load the credential from the local cache, if the local
    ///            cache not contains this credential, then resolve it from
    ///            the ID chain
    /// - Returns: a new Promise, the result is the resolved
    ///             VerifiableCredential object if success; nil otherwise
    public class func resolveAsync(_ id: String, _ issuer: String, _ force: Bool) -> Promise<VerifiableCredential?> {
        return resolveAsync(id, issuer, force)
    }
    
    /// Resolve the specific VerifiableCredential object in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - issuer: the issuer's did
    /// - Returns: a new Promise, the result is the resolved
    ///             VerifiableCredential object if success; nil otherwise
    public class func resolveAsync(_ id: DIDURL, _ issuer: DID) -> Promise<VerifiableCredential?> {
        return resolveAsync(id, issuer, false)
    }
    
    /// Resolve the specific VerifiableCredential object in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - issuer: the issuer's did
    /// - Returns: a new Promise, the result is the resolved
    ///             VerifiableCredential object if success; nil otherwise
    public class func resolveAsync(_ id: String, _ issuer: String) -> Promise<VerifiableCredential?> {
        return resolveAsync(id, issuer, false)
    }
    
    /// Resolve the specific VerifiableCredential object in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - force: if true then ignore the local cache and resolve the
    ///            credential from the ID chain directly; otherwise will try
    ///            to load the credential from the local cache, if the local
    ///            cache not contains this credential, then resolve it from
    ///            the ID chain
    /// - Returns: a new Promise, the result is the resolved
    ///             VerifiableCredential object if success; nil otherwise
    public class func resolveAsync(_ id: DIDURL, _ force: Bool) -> Promise<VerifiableCredential?> {
        return resolveAsync(id, force)
    }
    
    /// Resolve the specific VerifiableCredential object in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - force: if true then ignore the local cache and resolve the
    ///            credential from the ID chain directly; otherwise will try
    ///            to load the credential from the local cache, if the local
    ///            cache not contains this credential, then resolve it from
    ///            the ID chain
    /// - Returns: a new Promise, the result is the resolved
    ///             VerifiableCredential object if success; nil otherwise
    public class func resolveAsync(_ id: String, _ force: Bool) -> Promise<VerifiableCredential?> {
        return resolveAsync(id, nil, force)
    }
    
    /// Resolve the specific VerifiableCredential object in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the target credential
    /// - Returns: a new Promise, the result is the resolved
    ///             VerifiableCredential object if success; nil otherwise
    public class func resolveAsync(_ id: DIDURL) -> Promise<VerifiableCredential?> {
        return resolveAsync(id, nil, false)
    }
    
    /// Resolve the specific VerifiableCredential object in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the target credential
    /// - Returns: a new Promise, the result is the resolved
    ///             VerifiableCredential object if success; nil otherwise
    public class func resolveAsync(_ id: String) -> Promise<VerifiableCredential?> {
        return resolveAsync(id, nil, false)
    }
    
    /// Resolve all transaction of the specific credential.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - issuer: the issuer's did
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Returns: the resolved VerifiableCredential object
    public class func resolveBiography(_ id: DIDURL, _ issuer: DID) throws -> CredentialBiography? {
        return try DIDBackend.sharedInstance().resolveCredentialBiography(id, issuer)
    }
    
    /// Resolve all transaction of the specific credential.
    /// - Parameters:
    ///   - id: the id of the target credential
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Returns: the resolved VerifiableCredential object
    public class func resolveBiography(_ id: DIDURL) throws -> CredentialBiography {
        return try DIDBackend.sharedInstance().resolveCredentialBiography(id)!
    }
    
    /// Resolve all transaction of the specific credential.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - issuer: the issuer's did
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Returns: the resolved VerifiableCredential object
    public class func resolveBiography(_ id: String, _ issuer: String) throws -> CredentialBiography? {
        return try DIDBackend.sharedInstance().resolveCredentialBiography(DIDURL.valueOf(id), DID.valueOf(issuer)!)
    }
    
    /// Resolve all transaction of the specific credential.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - issuer: the issuer's did
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Returns: the resolved VerifiableCredential object
    public class func resolveBiography(_ id: DIDURL, _ issuer: String) throws -> CredentialBiography? {
        return try DIDBackend.sharedInstance().resolveCredentialBiography(id, DID.valueOf(issuer)!)
    }
    
    /// Resolve all transaction of the specific credential.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - issuer: the issuer's did
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Returns: the resolved VerifiableCredential object
    public class func resolveBiography(_ id: String, _ issuer: DID) throws -> CredentialBiography? {
        return try DIDBackend.sharedInstance().resolveCredentialBiography(DIDURL.valueOf(id), issuer)
    }
    
    /// Resolve all transaction of the specific credential.
    /// - Parameters:
    ///   - id: the id of the target credential
    /// - Throws: DIDResolveError if an error occurred when resolving DID
    /// - Returns: the resolved VerifiableCredential object
    public class func resolveBiography(_ id: String) throws -> CredentialBiography? {
        return try DIDBackend.sharedInstance().resolveCredentialBiography(DIDURL.valueOf(id))
    }
    
    /// Resolve all transaction of the specific credential in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - issuer: the issuer's did
    /// - Returns: a new Promise, the result is the resolved
    ///             CredentialBiography object if success; nil otherwise
    public class func resolveBiographyAsync(_ id: DIDURL, _ issuer: DID) -> Promise<CredentialBiography?> {
        return DispatchQueue.global().async(.promise){ [self] in try resolveBiography(id, issuer) }
    }
    
    /// Resolve all transaction of the specific credential in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the target credential
    /// - Returns: a new Promise, the result is the resolved
    ///             CredentialBiography object if success; nil otherwise
    public class func resolveBiographyAsync(_ id: DIDURL) -> Promise<CredentialBiography> {
        return DispatchQueue.global().async(.promise){ [self] in try resolveBiography(id) }
    }
    
    /// Resolve all transaction of the specific credential in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - issuer: the issuer's did
    /// - Returns: a new Promise, the result is the resolved
    ///             CredentialBiography object if success; nil otherwise
    public class func resolveBiographyAsync(_ id: String, _ issuer: String) -> Promise<CredentialBiography?> {
        return DispatchQueue.global().async(.promise){ [self] in try resolveBiography(id, issuer) }
    }
    
    /// Resolve all transaction of the specific credential in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - issuer: the issuer's did
    /// - Returns: a new Promise, the result is the resolved
    ///             CredentialBiography object if success; nil otherwise
    public class func resolveBiographyAsync(_ id: DIDURL, _ issuer: String) -> Promise<CredentialBiography?> {
        return DispatchQueue.global().async(.promise){ [self] in try resolveBiography(id, issuer) }
    }
    
    /// Resolve all transaction of the specific credential in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the target credential
    ///   - issuer: the issuer's did
    /// - Returns: a new Promise, the result is the resolved
    ///             CredentialBiography object if success; nil otherwise
    public class func resolveBiographyAsync(_ id: String, _ issuer: DID) -> Promise<CredentialBiography?> {
        return DispatchQueue.global().async(.promise){ [self] in try resolveBiography(id, issuer) }
    }
    
    /// Resolve all transaction of the specific credential in asynchronous mode.
    /// - Parameters:
    ///   - id: the id of the target credential
    /// - Returns: a new Promise, the result is the resolved
    ///             CredentialBiography object if success; nil otherwise
    public class func resolveBiographyAsync(_ id: String) -> Promise<CredentialBiography?> {
        return DispatchQueue.global().async(.promise){ [self] in try resolveBiography(id) }
    }
    
    /// List the published credentials that owned by the specific DID.
    /// - Parameters:
    ///   - did: the did to be list
    ///   - skip: set to skip N credentials ahead in this request
    ///           (useful for pagination).
    ///   - limit: set the limit of credentials returned in the request
    ///           (useful for pagination).
    /// - Throws: DIDResolveError if an error occurred when resolving the list
    /// - Returns: an array of DIDURL denoting the credentials
    public class func list(_ did: DID, _ skip: Int, _ limit: Int) throws -> [DIDURL] {
        return try DIDBackend.sharedInstance().listCredentials(did, skip, limit)
    }
    
    /// List the published credentials that owned by the specific DID.
    /// - Parameters:
    ///   - did: the did to be list
    ///   - limit: set the limit of credentials returned in the request
    ///           (useful for pagination).
    /// - Throws: DIDResolveError if an error occurred when resolving the list
    /// - Returns: an array of DIDURL denoting the credentials
    public class func list(_ did: DID, _ limit: Int) throws -> [DIDURL] {
        return try list(did, 0, limit)
    }
    
    /// List the published credentials that owned by the specific DID.
    /// - Parameters:
    ///   - did: the did to be list
    /// - Throws: DIDResolveError if an error occurred when resolving the list
    /// - Returns: an array of DIDURL denoting the credentials
    public class func list(_ did: DID) throws -> [DIDURL] {
        return try list(did, 0, 0)
    }
    
    /// List the published credentials that owned by the specific DID in
    /// asynchronous mode.
    /// - Parameters:
    ///   - did: the did to be list
    ///   - skip: set to skip N credentials ahead in this request
    ///           (useful for pagination).
    ///   - limit: set the limit of credentials returned in the request
    ///           (useful for pagination).
    /// - Returns: a new Promise, the result is an array of DIDURL
    ///           denoting the credentials
    public class func listAsync(_ did: DID, _ skip: Int, _ limit: Int) -> Promise<[DIDURL]> {
        return DispatchQueue.global().async(.promise){ [self] in try list(did, skip, limit) }
    }
    
    /// List the published credentials that owned by the specific DID in
    /// asynchronous mode.
    /// - Parameters:
    ///   - did: the did to be list
    ///   - limit: set the limit of credentials returned in the request
    ///           (useful for pagination).
    /// - Returns: a new Promise, the result is an array of DIDURL
    ///           denoting the credentials
    public class func listAsync(_ did: DID, _ limit: Int) -> Promise<[DIDURL]> {
        return listAsync(did, 0, limit)
    }
    
    /// List the published credentials that owned by the specific DID in
    /// asynchronous mode.
    /// - Parameters:
    ///   - did: the did to be list
    /// - Returns: a new Promise, the result is an array of DIDURL
    ///           denoting the credentials
    public class func listAsync(_ did: DID) -> Promise<[DIDURL]> {
        return listAsync(did, 0, 0)
    }

    func checkIntegrity() -> Bool {
        return (!getTypes().isEmpty && _subject != nil)
    }

    func parse(_ node: JsonNode, _ ref: DID?) throws  {
        let serializer = JsonSerializer(node)
        var options: JsonSerializer.Options
        // content
        let content = node.get(forKey: CONTEXT)
        if content != nil {
            try parseContext(content!)
        }
        let arrayNode = node.get(forKey: Constants.TYPE)?.asArray()
        guard let _ = arrayNode else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedCredentialError("missing credential type")
        }
        for item in arrayNode! {
            appendType(item.toString())
        }

        options = JsonSerializer.Options()
        guard let expirationDate = try serializer.getDate(Constants.EXPIRATION_DATE, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedCredentialError("Mssing credential expirationDate")
        }

        var subNode = node.get(forKey: Constants.CREDENTIAL_SUBJECT)
        guard let _ = subNode else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedCredentialError("missing credential subject.")
        }
        let subject = try VerifiableCredentialSubject.fromJson(subNode!, ref)
        var _ref: DID? = ref
        if _ref == nil {
            _ref = subject.did
        }
        options = JsonSerializer.Options()
            .withRef(_ref)
        guard let id = try serializer.getDIDURL(Constants.ID, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedCredentialError("missing credential id.")
        }

        subNode = node.get(forKey: Constants.PROOF)
        guard let _ = subNode else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedCredentialError("missing credential proof")
        }

        options = JsonSerializer.Options()
            .withOptional()
        if _ref != nil {
            _ = options.withRef(_ref)
        }
        var issuer = try serializer.getDID(Constants.ISSUER, options)
        options = JsonSerializer.Options()
        guard let issuanceDate = try serializer.getDate(Constants.ISSUANCE_DATE, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedCredentialError("Mssing credential issuanceDate")
        }

        if issuer == nil {
            issuer = subject.did
        }
        let proof = try VerifiableCredentialProof.fromJson(subNode!, issuer)

        setIssuer(issuer!)
        setIssuanceDate(issuanceDate)
        setExpirationDate(expirationDate)
        setSubject(subject)
        setId(id)
        setProof(proof)

        guard let _ = self.issuer else {
            setIssuer(self.subject!.did)
            return
        }
    }
    
    private func parseContext(_ arrayNode: JsonNode) throws {
        let array = arrayNode.asArray()
        var contexts: [String] = []
        array?.forEach{ item in
            contexts.append(item.asString()!)
        }
        print(contexts)
        _context = contexts
    }

    class func fromJson(_ node: JsonNode, _ ref: DID?) throws -> VerifiableCredential {
        let credential = VerifiableCredential()
        try credential.parse(node, ref)
        return credential
    }

    /// Get one DID’s Credential from json context.
    /// - Parameter json: Json context about credential.
    /// - Throws: If error occurs, throw error.
    /// - Returns: VerifiableCredential instance.
    @objc
    public class func fromJson(_ json: Data) throws -> VerifiableCredential {
        try checkArgument(!json.isEmpty, "Invalid json")

        let data: [String: Any]?
        do {
            data = try JSONSerialization.jsonObject(with: json, options: []) as? [String: Any]
        } catch {
            throw DIDError.CheckedError.DIDBackendError.DIDResolveError("Parse resolve result error")
        }
        guard let _  = data else {
            throw DIDError.CheckedError.DIDBackendError.DIDResolveError("Parse resolve result error")
        }
        return try fromJson(JsonNode(data!), nil)
    }

    /// Parse the VerifiableCredential object from a string JSON
    /// representation.
    /// - Parameter json: Json context to deserialize the VerifiableCredential object
    /// - Throws: If error occurs, throw error.
    /// - Returns: the VerifiableCredential object
    @objc(fromJsonWithJson:error:)
    public class func fromJson(_ json: String) throws -> VerifiableCredential {
        return try fromJson(json.data(using: .utf8)!)
    }
    
    @objc(fromJsonWithJsonfor:error:)
    public class func fromJson(for path: String) throws -> VerifiableCredential {
        return try fromJson(path.readTextFromPath())
    }

    /// Parse the VerifiableCredential object from a string JSON
    /// representation.
    /// - Parameter json: Json context about credential.
    /// - Throws: If error occurs, throw error.
    /// - Returns: VerifiableCredential instance.
    @objc(fromJsonWithDict:error:)
    public class func fromJson(for json: [String: Any]) throws -> VerifiableCredential {
        return try fromJson(JsonNode(json), nil)
    }

    func toJson(_ generator: JsonGenerator, _ ref: DID?, _ normalized: Bool) {
        toJson(generator, ref, normalized, false)
    }

    func toJson(_ generator: JsonGenerator, _ normalized: Bool) {
        toJson(generator, nil, normalized)
    }

    /*
    * Normalized serialization order:
    *
    * - id
    * - type ordered names array(case insensitive/ascending)
    * - issuer
    * - issuanceDate
    * - expirationDate
    * + credentialSubject
    *   - id
    *   - properties ordered by name(case insensitive/ascending)
    * + proof
    *   - type
    *   - method
    *   - signature
    */
    func toJson(_ generator: JsonGenerator, _ ref: DID?, _ normalized: Bool, _ forSign: Bool) {
        generator.writeStartObject()
        if _context.count > 0 {
            generator.writeFieldName(CONTEXT)
            generator.writeStartArray()
            _context.forEach { item in
                generator.writeString(item)
            }
            generator.writeEndArray()
        }
        // id
        generator.writeFieldName(Constants.ID)
        generator.writeString(IDGetter(getId()!, subject?.did).value(normalized))

        // type
        generator.writeFieldName(Constants.TYPE)
        _types.sort { (a, b) -> Bool in
            let compareResult = a.compare(b)
            return compareResult == ComparisonResult.orderedAscending
        }
        generator.writeStartArray()
        for type in getTypes() {
            generator.writeString(type)
        }
        generator.writeEndArray()

        // issuer
        if normalized || issuer != subject?.did {
            generator.writeStringField(Constants.ISSUER, issuer!.toString())
        }

        // issuanceDate
        generator.writeFieldName(Constants.ISSUANCE_DATE)
        generator.writeString(DateFormatter.convertToUTCStringFromDate(issuanceDate!))

        // expirationDate // TODO:
        if let e = try! getExpirationDate() {
            generator.writeFieldName(Constants.EXPIRATION_DATE)
            generator.writeString(DateFormatter.convertToUTCStringFromDate(e))
        }

        // credenitalSubject
        generator.writeFieldName(Constants.CREDENTIAL_SUBJECT)
        subject!.toJson(generator, ref, normalized)

        // proof
        if let _ = proof {
            generator.writeFieldName(Constants.PROOF)
            proof!.toJson(generator, subject?.did, normalized)
        }

        generator.writeEndObject()
    }

    func toJson(_ normalized: Bool, _ forSign: Bool) -> String {
        let generator = JsonGenerator()
        toJson(generator, nil, normalized, forSign)
        return generator.toString()
    }
    
    public func serialize(_ generator: JsonGenerator, _ normalized: Bool) {
        toJson(generator, nil, normalized)
    }
    
    public func serialize(_ generator: JsonGenerator) {
        serialize(generator, false)
    }
}

extension VerifiableCredential {
    @objc
    public func toString(_ normalized: Bool) -> String {
        return toJson(normalized, false)
    }

    func toString() -> String {
        return toString(false)
    }

    @objc
    public override var description: String {
        return toString()
    }
    
    public func compareTo(_ key: VerifiableCredential) throws -> ComparisonResult {
        try checkArgument(self.getId() != nil || key.getId() != nil, "id is nil")
        let result = self.getId()!.compareTo(key.getId()!)
        
        return result
    }
}
