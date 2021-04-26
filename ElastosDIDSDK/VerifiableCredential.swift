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
import ObjectMapper

//@objc(VerifiableCredentialA)
public class VerifiableCredentialA: Mappable {

    public required init?(map: Map) {
//        super.init()
    }
    
    public func mapping(map: Map) {
        issuanceDate <- (map["issuanceDate"], ISO8601DateTransform())
        string <- map["string"]
    }
    
    public var issuanceDate: Date?
    public var string: String?


}
/// Credential is a set of one or more claims made by the same entity.
/// Credentials might also include an identifier and metadata to describe properties of the credential.
@objc(VerifiableCredential)
public class VerifiableCredential: DIDObject, Mappable {

    public required init?(map: Map) {
        super.init()
    }
    
    public func mapping(map: Map) {
        _id = try! DIDURL(map.value("id") as String)
        _types <- map["type"]
        _subject <- map["credentialSubject"]
        _issuanceDate <- (map["issuanceDate"], ISO8601DateTransform())
        _expirationDateString <- map["expirationDate"]
    }
    
    private let TAG = NSStringFromClass(VerifiableCredential.self)
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

    private var _id: DIDURL?
    private var _types: Array<String> = []
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

    override init() {
        super.init()
    }
    
    /// Constructs a credential object, copy the contents from the given object.
    /// - Parameter credential: the source credential object
    init(_ credential: VerifiableCredential, _ withProof: Bool) throws {
        super.init(credential.getId()!, credential.getType())
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

    public var id: DIDURL? {
        return _id
    }
    
    override func setId(_ id: DIDURL) {
        super.setId(id)
        self._id = id
    }

    /// Get string of Credential types.
    /// - Returns: String of Credential type.
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

    /// Get array of Credential types.
    /// - Returns: Array of Credential types.
    @objc
    public func getTypes() -> [String] {
        return self._types
    }

    func appendType(_ type: String) {
        self._types.append(type)
    }

    func setType(_ newTypes: [String]) {
        for type in newTypes {
            self._types.append(type)
        }
    }

    /// Get DID issuer of Credential.
    @objc
    public var issuer: DID? {
        // Guaranteed that this field would not be nil because the object
        // was generated by "builder".
        return self._issuer
    }

    // This type of getXXXX function would specifically be provided for
    // sdk internal when we can't be sure about it's validity/integrity.
    func getIssuer() -> DID? {
        return self._issuer
    }

    func setIssuer(_ newIssuer: DID) {
        self._issuer = newIssuer
    }

    /// Get date of issuing credential.
    @objc
    public var issuanceDate: Date? {
        // Guaranteed that this field would not be nil because the object
        // was generated by "builder".
        return _issuanceDate
    }

    func getIssuanceDate() -> Date? {
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
    
    public func hasExpirationDate() -> Bool {
        return _expirationDate != nil
    }
    
    public var lastModified: Date? {
        return proof!.created
    }
    
    /// claims about the subject of the credential
    @objc
    public var subject: VerifiableCredentialSubject? {
        return _subject
    }

    func getSubject() -> VerifiableCredentialSubject? {
        return _subject
    }

    func setSubject(_ newSubject: VerifiableCredentialSubject) {
        self._subject = newSubject
    }

    /// digital proof that makes the credential tamper-evident
    @objc
    public var proof: VerifiableCredentialProof? {
        return _proof
    }

    func getProof() -> VerifiableCredentialProof? {
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
    
    public var isSelfProclaimed: Bool {
        return issuer == subject?.did
    }

    private func traceCheck(_ rule: Int) throws -> Bool {
        var controllerDoc: DIDDocument?
        do {
            controllerDoc = try issuer!.resolve()
        } catch {
            controllerDoc = nil
        }

        guard let _ = controllerDoc else {
            return false
        }

        switch rule {
        case RULE_EXPIRE:
            if controllerDoc!.isExpired {
                return true
            }
        case RULE_GENUINE:
            if try !controllerDoc!.isGenuine() {
                return false
            }
        case RULE_VALID:
            if try !controllerDoc!.isValid() {
                return false
            }
        default:
            break
        }

        if !isSelfProclaimed {
            let issuerDoc: DIDDocument?
            do {
                issuerDoc = try issuer!.resolve()
            } catch {
                issuerDoc = nil
            }
            guard let _ = issuerDoc else {
                return false
            }

            switch rule {
            case RULE_EXPIRE:
                if issuerDoc!.isExpired {
                    return true
                }
            case RULE_GENUINE:
                if try !issuerDoc!.isGenuine() {
                    return false
                }
            case RULE_VALID:
                if try !issuerDoc!.isValid() {
                    return false
                }
            default:
                break
            }
        }

        return rule != RULE_EXPIRE
    }
    
    private func checkExpired() throws -> Bool {
        return _expirationDate != nil ? DateFormatter.isExipired(_expirationDate!) : false
    }

    /// Check if the Credential is expired or not.
    /// Issuance always occurs before any other actions involving a credential.
    @objc
    public var isExpired: Bool {
        do {
            return try traceCheck(RULE_EXPIRE) ? true : checkExpired()
        } catch {
            return false
        }
    }

    /// Credential is expired or not asynchronous.
    /// - Returns: Issuance always occurs before any other actions involving a credential.
    public func isExpiredAsync() -> Promise<Bool> {
        return DispatchQueue.global().async(.promise){ [self] in isExpired }
    }

    /// Credential is expired or not asynchronous.
    /// - Returns: Issuance always occurs before any other actions involving a credential.
    @objc
    public func isExpiredAsyncUsingObjectC() -> AnyPromise {
        return AnyPromise(__resolverBlock: { [self] resolver in
            DispatchQueue.global().async{ resolver(isExpired) }
        })
    }

    /// Check whether the Credential is genuine or not.
    /// Issuance always occurs before any other actions involving a credential.
    /// return: flase if not genuine, true if genuine.
    public func isGenuine() throws -> Bool {
        guard id?.did == subject?.did else {
            return false
        }
        let issuerDoc = try issuer?.resolve()
        guard let _ = issuerDoc else {
            throw DIDError.UncheckedError.IllegalStateError.DIDNotFoundError(issuer?.toString())
        }
        guard try issuerDoc!.isGenuine() else {
            return false
        }
        // Credential should signed by any authentication key.
        guard try issuerDoc!.containsAuthenticationKey(forId: proof!.verificationMethod) else {
            return false
        }
        // Unsupported public key type
        guard proof?.type == Constants.DEFAULT_PUBLICKEY_TYPE else {
            return false
        }
        let vc = try VerifiableCredential(self, false)
        let json = vc.toString(true)
        guard let data = json.data(using: .utf8) else {
            throw DIDError.illegalArgument("credential is nil")
        }
        guard try issuerDoc!.verify(withId: proof!.verificationMethod, using: proof!.signature, onto: data) else {
            return false
        }
        if !isSelfProclaimed {
            let controllerDoc = try subject?.did.resolve()
            if try controllerDoc != nil && !controllerDoc!.isGenuine() {
                return false
            }
        }
        
        return true
    }

    /// Credential is genuine or not asynchronous.
    /// Issuance always occurs before any other actions involving a credential.
    /// flase if not genuine, true if genuine.
    public func isGenuineAsync() -> Promise<Bool> {
        return DispatchQueue.global().async(.promise){ [self] in try isGenuine() }
    }

    /// Credential is genuine or not asynchronous.
    /// Issuance always occurs before any other actions involving a credential.
    /// flase if not genuine, true if genuine.
    @objc
    public func isGenuineAsyncUsingObjectC() -> AnyPromise {
        return AnyPromise(__resolverBlock: { [self] resolver in
            DispatchQueue.global().async{ resolver(isGenuine) }
        })
    }

    /// Credential is expired or not.
    /// Issuance always occurs before any other actions involving a credential.
    @objc
    public var isValid: Bool {
        do {
            if try !traceCheck(RULE_VALID) {
                return false
            }
            return try !checkExpired() && isGenuine()
        } catch {
            return false
        }
    }

    /// Credential is expired or not asynchronous.
    /// - Returns: flase if not genuine, true if genuine.
    public func isValidAsync() -> Promise<Bool> {
       return DispatchQueue.global().async(.promise){ [self] in isValid }
    }

    /// Credential is expired or not asynchronous.
    /// - Returns: flase if not genuine, true if genuine.
    @objc
    public func isValidAsyncUsingObjectC() -> AnyPromise {
        return AnyPromise(__resolverBlock: { [self] resolver in
            DispatchQueue.global().async{ resolver(isValid) }
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
    
    private func declare(signKey: DIDURL?, storePassword: String, adapter: DIDTransactionAdapter?) throws {
        try checkArgument(!storePassword.isEmpty, "Invalid storePassword")
        try checkAttachedStore()
        guard try isGenuine() else {
            Log.e(TAG, "Publish failed because the credential is not genuine.")
            throw DIDError.UncheckedError.IllegalStateError.CredentialNotGenuineError(id?.toString())
        }
        guard !isExpired else {
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
            throw DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError("Unknown sign key.")
        }
        var sk = signKey
        if (sk != nil) {
            if (try !owner!.containsAuthenticationKey(forId: signKey!)) {
                throw DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError(signKey!.toString())
            }
        } else {
            sk = owner!.defaultPublicKeyId()
        }
        try DIDBackend.sharedInstance().declareCredential(self, owner!, sk!, storePassword, adapter as? DIDAdapter)
    }
    
    public func declare(_ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try declare(signKey: signKey, storePassword: storePassword, adapter: adapter)
    }
    
    public func declare(_ signKey: DIDURL, _ storePassword: String) throws {
        try declare(signKey: signKey, storePassword: storePassword, adapter: nil)
    }
    
    public func declare(_ signKey: String, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try declare(signKey: DIDURL.valueOf(subject!.did, signKey), storePassword: storePassword, adapter: adapter)
    }
    
    public func declare(_ signKey: String, _ storePassword: String) throws {
        try declare(signKey: DIDURL.valueOf(subject!.did, signKey), storePassword: storePassword, adapter: nil)
    }
    
    public func declare(_ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try declare(signKey: nil, storePassword: storePassword, adapter: adapter)
    }
    
    public func declare(_ storePassword: String) throws {
        try declare(signKey: nil, storePassword: storePassword, adapter: nil)
    }
    
    public func declareAsync(_ signKey: DIDURL?, _ storePassword: String, _ adapter: DIDTransactionAdapter?) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try declare(signKey: signKey, storePassword: storePassword, adapter: adapter) }
    }
    
    public func declareAsync(_ signKey: DIDURL?, _ storePassword: String) -> Promise<Void> {
        return declareAsync(signKey, storePassword, nil)
    }
    
    public func declareAsync(_ signKey: String, _ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try declare(signKey, storePassword, adapter) }
    }
    
    public func declareAsync(_ signKey: String, _ storePassword: String) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try declare(signKey, storePassword) }
    }
    
    public func declareAsync(_ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try declare(storePassword, adapter) }
    }
    
    public func declareAsync(_ storePassword: String) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try declare(storePassword) }
    }
    
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
            throw DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError("Not owner or issuer: \(sg!.subject)")
        }
        
        if signKey == nil && sg!.defaultPublicKeyId() == nil {
            throw DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError("Unknown sign key")
        }
        var sk = signKey
        if signKey != nil{
            guard try sg!.containsAuthenticationKey(forId: signKey!) else {
                throw DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError(signKey!.toString())
            }
        }
        else {
            sk = sg!.defaultPublicKeyId()
        }
        try DIDBackend.sharedInstance().revokeCredential(self, sg!, sk!, storePassword, adapter as? DIDAdapter)
    }
    
    public func revoke(_ signer: DIDDocument, _ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try revoke(signer: signer, signKey: signKey, storePassword: storePassword, adapter: adapter)
    }
    
    public func revoke(_ signer: DIDDocument, _ signKey: DIDURL, _ storePassword: String) throws {
        try revoke(signer: signer, signKey: signKey, storePassword: storePassword, adapter: nil)
    }
    
    public func revoke(_ signer: DIDDocument, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try revoke(signer: signer, signKey: nil, storePassword: storePassword, adapter: adapter)
    }
    
    public func revoke(_ signer: DIDDocument, _ storePassword: String) throws {
        try revoke(signer: signer, signKey: nil, storePassword: storePassword, adapter: nil)
    }
    
    public func revoke(_ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try revoke(signer: nil, signKey: signKey, storePassword: storePassword, adapter: adapter)
    }
    
    public func revoke(_ signKey: DIDURL, _ storePassword: String) throws {
        try revoke(signer: nil, signKey: signKey, storePassword: storePassword, adapter: nil)
    }
    
    private func revoke(_ signer: DIDDocument?, _ signKey: String, _ storePassword: String, _ adapter: DIDTransactionAdapter?) throws {
        try revoke(signer: signer, signKey: DIDURL.valueOf(subject!.did, signKey), storePassword: storePassword, adapter: adapter)
    }
    
    public func revoke(_ signer: DIDDocument, _ signKey: String, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try revoke(signer, signKey, storePassword, adapter)
    }
    
    public func revoke(_ signer: DIDDocument, _ signKey: String, _ storePassword: String) throws {
        try revoke(signer, signKey, storePassword, nil)
    }
    
    public func revoke(_ signKey: String, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try revoke(nil, signKey, storePassword, adapter)
    }
    
    public func revoke(_ signKey: String, _ storePassword: String) throws {
        try revoke(nil, signKey, storePassword, nil)
    }
    
    public func revoke(_ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try revoke(signer: nil, signKey: nil, storePassword: storePassword, adapter: adapter)
    }
    
    public func revoke(_ storePassword: String) throws {
        try revoke(signer: nil, signKey: nil, storePassword: storePassword, adapter: nil)
    }
    
    private func revokeAsync(_ signer: DIDDocument?, _ signKey: DIDURL?, _ storePassword: String, _ adapter: DIDTransactionAdapter?) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try revoke(signer: signer, signKey: signKey, storePassword: storePassword, adapter: adapter) }
    }
    
    public func revokeAsync(_ signer: DIDDocument, _ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return revokeAsync(signer, signKey, storePassword, adapter)
    }
    
    public func revokeAsync(_ signer: DIDDocument, _ signKey: DIDURL, _ storePassword: String) -> Promise<Void> {
        return revokeAsync(signer, signKey, storePassword, nil)
    }
    
    public func revokeAsync(_ signer: DIDDocument, _ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return revokeAsync(signer, nil, storePassword, adapter)
    }
    
    public func revokeAsync(_ signer: DIDDocument, _ storePassword: String) -> Promise<Void> {
        return revokeAsync(signer, nil, storePassword, nil)
    }
    
    public func revokeAsync(_ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return revokeAsync(nil, signKey, storePassword, adapter)
    }
    
    public func revokeAsync(_ signKey: DIDURL, _ storePassword: String) -> Promise<Void> {
        return revokeAsync(nil, signKey, storePassword, nil)
    }
    
    private func revokeAsync(signer: DIDDocument?, signKey: String, storePassword: String, adapter: DIDTransactionAdapter?) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try revoke(signer: signer, signKey: DIDURL.valueOf(subject!.did, signKey), storePassword: storePassword, adapter: adapter) }
    }
    
    public func revokeAsync(_ signer: DIDDocument, _ signKey: String, _ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return revokeAsync(signer: signer, signKey: signKey, storePassword: storePassword, adapter: adapter)
    }
    
    public func revokeAsync(_ signer: DIDDocument, _ signKey: String, _ storePassword: String) -> Promise<Void> {
        return revokeAsync(signer: signer, signKey: signKey, storePassword: storePassword, adapter: nil)
    }
    
    public func revokeAsync(_ signKey: String, _ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return revokeAsync(signer: nil, signKey: signKey, storePassword: storePassword, adapter: adapter)
    }
    
    public func revokeAsync(_ signKey: String, _ storePassword: String) -> Promise<Void> {
        return revokeAsync(signer: nil, signKey: signKey, storePassword: storePassword, adapter: nil)
    }
    
    public func revokeAsync(_ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return revokeAsync(nil, nil, storePassword, adapter)
    }
    
    public func revokeAsync(_ storePassword: String) -> Promise<Void> {
        return revokeAsync(nil, nil, storePassword, nil)
    }
    
    private class func revoke(_ id: DIDURL, _ signer: DIDDocument, _ signKey: DIDURL?, _ storePassword: String, _ adapter: DIDTransactionAdapter?) throws {
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
                throw DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError("Not owner or issuer: \(signer.subject)")
            }
        }
        
        if signKey == nil && signer.defaultPublicKeyId() == nil {
            throw DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError("Unknown sign key")
        }
        var sk = signKey
        if signKey != nil {
            guard try signer.containsAuthenticationKey(forId: signKey!) else {
                throw DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError(signKey!.toString())
            }
        }
        else {
            sk = signer.defaultPublicKeyId()
        }
        try DIDBackend.sharedInstance().revokeCredential(id, signer, sk!, storePassword, adapter as? DIDAdapter)
    }
    
    public class func revoke(_ id: DIDURL, _ issuer: DIDDocument, _ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try revoke(id, issuer, signKey, storePassword, adapter)
    }
    
    public class func revoke(_ id: DIDURL, _ issuer: DIDDocument, _ signKey: DIDURL, _ storePassword: String) throws {
        try revoke(id, issuer, signKey, storePassword, nil)
    }
    
    public class func revoke(_ id: String, _ issuer: DIDDocument, _ signKey: String, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try revoke(DIDURL.valueOf(id), issuer, DIDURL.valueOf(issuer.subject, signKey), storePassword, adapter)
    }
   
    public class func revoke(_ id: String, _ issuer: DIDDocument, _ signKey: String, _ storePassword: String) throws {
        try revoke(DIDURL.valueOf(id), issuer, DIDURL.valueOf(issuer.subject, signKey), storePassword, nil)
    }
    
    public class func revoke(_ id: DIDURL, _ issuer: DIDDocument, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try revoke(id, issuer, nil, storePassword, adapter)
    }
    
    public class func revoke(_ id: DIDURL, _ issuer: DIDDocument, _ storePassword: String) throws {
        try revoke(id, issuer, nil, storePassword, nil)
    }
    
    public class func revoke(_ id: String, _ issuer: DIDDocument, _ storePassword: String, _ adapter: DIDTransactionAdapter) throws {
        try revoke(DIDURL.valueOf(id), issuer, nil, storePassword, adapter)
    }
   
    public class func revoke(_ id: String, _ issuer: DIDDocument, _ storePassword: String) throws {
        try revoke(DIDURL.valueOf(id), issuer, nil, storePassword, nil)
    }
    
    private class func revokeAsync(_ id: DIDURL, _ issuer: DIDDocument, _ signKey: DIDURL?, _ storePassword: String, _ adapter: DIDTransactionAdapter?) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try revoke(id, issuer, signKey, storePassword, adapter) }
    }
    
    public class func revokeAsync(_ id: DIDURL, _ issuer: DIDDocument, _ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return revokeAsync(id, issuer, signKey, storePassword, adapter)
    }
    
    public class func revokeAsync(_ id: DIDURL, _ issuer: DIDDocument, _ signKey: DIDURL, _ storePassword: String) -> Promise<Void> {
        return revokeAsync(id, issuer, signKey, storePassword, nil)
    }
    
    public class func revokeAsync(_ id: String, _ issuer: DIDDocument, _ signKey: String, _ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try revoke(id, issuer, signKey, storePassword, adapter) }
    }
    
    public class func revokeAsync(_ id: String, _ issuer: DIDDocument, _ signKey: String, _ storePassword: String) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try revoke(id, issuer, signKey, storePassword) }
    }

    public class func revokeAsync(_ id: String, _ issuer: DIDDocument, _ storePassword: String, _ adapter: DIDTransactionAdapter) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try revoke(id, issuer, storePassword, adapter) }
    }
    
    public class func revokeAsync(_ id: DIDURL, _ issuer: DIDDocument, _ storePassword: String) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try revoke(id, issuer, storePassword) }
    }
    
    public class func revokeAsync(_ id: String, _ issuer: DIDDocument, _ storePassword: String) -> Promise<Void> {
        return DispatchQueue.global().async(.promise){ [self] in try revoke(id, issuer, storePassword) }
    }
    
    private class func resolve(_ id: DIDURL, _ issuer: DID?, _ force: Bool) throws -> VerifiableCredential? {
        var vc: VerifiableCredential? = nil
        if let _ = issuer {
            vc = try DIDBackend.sharedInstance().resolveCredential(id, issuer!, force)
        }
        else {
            vc = try DIDBackend.sharedInstance().resolveCredential(id, force)
        }

        if vc != nil {
            id.setMetadata(vc!.getMetadata())
        }
        
        return vc
    }
    
    public class func resolve(_ id: DIDURL, _ issuer: DID, _ force: Bool) -> VerifiableCredential {
        return resolve(id, issuer, force)
    }
    
    private class func resolve(_ id: String, _ issuer: String?, _ force: Bool) throws -> VerifiableCredential? {
        return try resolve(DIDURL.valueOf(id), issuer != nil ? DID.valueOf(issuer!) : nil, force)
    }
    
    public class func resolve(_ id: String, _ issuer: String, _ force: Bool) throws -> VerifiableCredential? {
        return try resolve(DIDURL.valueOf(id), DID.valueOf(issuer), force)
    }
    
    public class func resolve(_ id: DIDURL, _ issuer: DID) -> VerifiableCredential {
        return resolve(id, issuer, false)
    }
    
    public class func resolve(_ id: String, _ issuer: String) throws -> VerifiableCredential? {
        return try resolve(DIDURL.valueOf(id), DID.valueOf(issuer), false)
    }
    
    public class func resolve(_ id: DIDURL, _ force: Bool) throws -> VerifiableCredential? {
        return try resolve(id, nil, force)
    }
    
    public class func resolve(_ id: String, _ force: Bool) throws -> VerifiableCredential? {
        return try resolve(DIDURL.valueOf(id), nil, force)
    }
    
    public class func resolve(_ id: DIDURL) throws -> VerifiableCredential? {
        return try resolve(id, nil, false)
    }
    
    public class func resolve(_ id: String) throws -> VerifiableCredential? {
        return try resolve(DIDURL.valueOf(id), nil, false)
    }
    
    private class func resolveAsync(_ id: DIDURL, _ issuer: DID?, _ force: Bool) -> Promise<VerifiableCredential?> {
        return DispatchQueue.global().async(.promise){ [self] in try resolve(id, issuer, force) }
    }
    
    public class func resolveAsync(_ id: DIDURL, _ issuer: DID, _ force: Bool) -> Promise<VerifiableCredential?> {
        return resolveAsync(id, issuer, force)
    }
    
    private class func resolveAsync(_ id: String, _ issuer: String?, _ force: Bool) -> Promise<VerifiableCredential?> {
        return DispatchQueue.global().async(.promise){ [self] in try resolve(id, issuer, force) }
    }
    
    public class func resolveAsync(_ id: String, _ issuer: String, _ force: Bool) -> Promise<VerifiableCredential?> {
        return resolveAsync(id, issuer, force)
    }
    
    public class func resolveAsync(_ id: DIDURL, _ issuer: DID) -> Promise<VerifiableCredential?> {
        return resolveAsync(id, issuer, false)
    }
    
    public class func resolveAsync(_ id: String, _ issuer: String) -> Promise<VerifiableCredential?> {
        return resolveAsync(id, issuer, false)
    }
    
    public class func resolveAsync(_ id: DIDURL, _ force: Bool) -> Promise<VerifiableCredential?> {
        return resolveAsync(id, force)
    }
    
    public class func resolveAsync(_ id: String, _ force: Bool) -> Promise<VerifiableCredential?> {
        return resolveAsync(id, nil, force)
    }
    
    public class func resolveAsync(_ id: DIDURL) -> Promise<VerifiableCredential?> {
        return resolveAsync(id, nil, false)
    }
    
    public class func resolveAsync(_ id: String) -> Promise<VerifiableCredential?> {
        return resolveAsync(id, nil, false)
    }
    
    public class func resolveBiography(_ id: DIDURL, _ issuer: DID) throws -> CredentialBiography? {
        return try DIDBackend.sharedInstance().resolveCredentialBiography(id, issuer)
    }
    
    public class func resolveBiography(_ id: DIDURL) throws -> CredentialBiography {
        return try DIDBackend.sharedInstance().resolveCredentialBiography(id)!
    }
    
    public class func resolveBiography(_ id: String, _ issuer: String) throws -> CredentialBiography? {
        return try DIDBackend.sharedInstance().resolveCredentialBiography(DIDURL.valueOf(id), DID.valueOf(issuer)!)
    }
    
    public class func resolveBiography(_ id: String) throws -> CredentialBiography? {
        return try DIDBackend.sharedInstance().resolveCredentialBiography(DIDURL.valueOf(id))
    }
    
    public class func resolveBiographyAsync(_ id: DIDURL, _ issuer: DID) -> Promise<CredentialBiography?> {
        return DispatchQueue.global().async(.promise){ [self] in try resolveBiography(id, issuer) }
    }
    
    public class func resolveBiographyAsync(_ id: DIDURL) -> Promise<CredentialBiography> {
        return DispatchQueue.global().async(.promise){ [self] in try resolveBiography(id) }
    }
    
    public class func resolveBiographyAsync(_ id: String, _ issuer: String) -> Promise<CredentialBiography?> {
        return DispatchQueue.global().async(.promise){ [self] in try resolveBiography(id, issuer) }
    }
    
    public class func resolveBiographyAsync(_ id: String) -> Promise<CredentialBiography?> {
        return DispatchQueue.global().async(.promise){ [self] in try resolveBiography(id) }
    }
    
    public class func list(_ did: DID, _ skip: Int, _ limit: Int) throws -> [DIDURL] {
        return try DIDBackend.sharedInstance().listCredentials(did, skip, limit)
    }
    
    public class func list(_ did: DID, _ limit: Int) throws -> [DIDURL] {
        return try list(did, 0, limit)
    }
    
    public class func list(_ did: DID) throws -> [DIDURL] {
        return try list(did, 0, 0)
    }
    
    public class func listAsync(_ did: DID, _ skip: Int, _ limit: Int) -> Promise<[DIDURL]> {
        return DispatchQueue.global().async(.promise){ [self] in try list(did, skip, limit) }
    }
    
    public class func listAsync(_ did: DID, _ limit: Int) -> Promise<[DIDURL]> {
        return listAsync(did, 0, limit)
    }
    
    public class func listAsync(_ did: DID) -> Promise<[DIDURL]> {
        return listAsync(did, 0, 0)
    }

    func checkIntegrity() -> Bool {
        return (!getTypes().isEmpty && _subject != nil)
    }

    func parse(_ node: JsonNode, _ ref: DID?) throws  {
        let error = { (des) -> DIDError in
            return DIDError.malformedCredential(des)
        }

        let serializer = JsonSerializer(node)
        var options: JsonSerializer.Options

        let arrayNode = node.get(forKey: Constants.TYPE)?.asArray()
        guard let _ = arrayNode else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedCredentialError("missing credential type")
        }
        for item in arrayNode! {
            appendType(item.toString())
        }

        options = JsonSerializer.Options()
            .withHint("credential expirationDate")
            .withError(error)

        let expirationDate = try serializer.getDate(Constants.EXPIRATION_DATE, options)

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
            .withHint("credential id")
            .withError(error)
        let id = try serializer.getDIDURL(Constants.ID, options)

        subNode = node.get(forKey: Constants.PROOF)
        guard let _ = subNode else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedCredentialError("missing credential proof")
        }

        options = JsonSerializer.Options()
            .withOptional()
            .withHint("credential issuer")
            .withError(error)
        if _ref != nil {
            options.withRef(_ref)
        }
        var issuer = try? serializer.getDID(Constants.ISSUER, options)
        options = JsonSerializer.Options()
            .withHint("credential issuanceDate")
            .withError(error)
        let issuanceDate = try serializer.getDate(Constants.ISSUANCE_DATE, options)

        if issuer == nil {
            issuer = subject.did
        }
        let proof = try VerifiableCredentialProof.fromJson(subNode!, issuer)

        setIssuer(issuer!)
        setIssuanceDate(issuanceDate)
        setExpirationDate(expirationDate)
        setSubject(subject)
        setId(id!)
        setProof(proof)

        guard let _ = getIssuer() else {
            setIssuer(self.subject!.did)
            return
        }
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
        try checkArgument(json.isEmpty, "Invalid json")

        let data: [String: Any]?
        do {
            data = try JSONSerialization.jsonObject(with: json, options: []) as? [String: Any]
        } catch {
            throw DIDError.didResolveError("Parse resolve result error")
        }
        guard let _  = data else {
            throw DIDError.didResolveError("Parse resolve result error")
        }
        return try fromJson(JsonNode(data!), nil)
    }

    /// Get one DID’s Credential from json context.
    /// - Parameter json: Json context about credential.
    /// - Throws: If error occurs, throw error.
    /// - Returns: VerifiableCredential instance.
    @objc(fromJsonWithJson:error:)
    public class func fromJson(_ json: String) throws -> VerifiableCredential {
        return try fromJson(json.data(using: .utf8)!)
    }
    
    @objc(fromJsonWithJsonfor:error:)
    public class func fromJson(for path: String) throws -> VerifiableCredential {
        //TODO: data from path
        return try fromJson(path.data(using: .utf8)!)
    }

    /// Get one DID’s Credential from json context.
    /// - Parameter json: Json context about credential.
    /// - Throws: If error occurs, throw error.
    /// - Returns: VerifiableCredential instance.
    @objc(fromJsonWithDict:error:)
    public class func fromJson(_ json: [String: Any]) throws -> VerifiableCredential {
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
}
