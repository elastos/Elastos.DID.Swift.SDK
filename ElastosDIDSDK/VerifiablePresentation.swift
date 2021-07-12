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

/// A Presentation object is used to combine and present credentials.
/// They can be packaged in such a way that the authorship of the data is
/// verifiable. The data in a presentation is often all about the same
/// subject, but there is no limit to the number of subjects or issuers
/// in the presentation.
///
/// This also helps prevent a verifier from reusing a verifiable presentation as
/// their own.
@objc(VerifiablePresentation)
public class VerifiablePresentation: NSObject {
    /// Default presentation type
    let DEFAULT_PRESENTATION_TYPE = "VerifiablePresentation"
    let ID = "id"
    let TYPE = "type"
    let HOLDER = "holder"
    let VERIFIABLE_CREDENTIAL = "verifiableCredential"
    let CREATED = "created"
    let PROOF = "proof"
    let NONCE = "nonce"
    let REALM = "realm"
    let VERIFICATION_METHOD = "verificationMethod"
    let SIGNATURE = "signature"

    var _id:DIDURL?
    var _types: [String] = []
    var _holder: DID?
    var _credentialsArray: [VerifiableCredential] = [ ]
    private var _createdDate: Date
    private var _verifiableCredentials: [DIDURL: VerifiableCredential] = [: ]
    private var _proof: VerifiablePresentationProof?
    
    /// Default constructor.
    override init() {
        self._createdDate = DateFormatter.currentDate()
    }
    
    /// Constructs a presentation object for given holder.
    /// - Parameter holder: the holder's DID of this presentation object
    init(_ holder: DID) {
        self._holder = holder
        self._createdDate = DateFormatter.currentDate()
    }
    
    /// Copy constructor.
    /// - Parameters:
    ///   - vp: the source VerifiablePresentation object
    init(_ vp: VerifiablePresentation, _ withProof: Bool) {
        self._id = vp.id
        self._types = vp.types
        self._holder = vp.holder
        self._createdDate = vp.createdDate
        self._credentialsArray = vp.credentials
        self._verifiableCredentials = vp._verifiableCredentials
        if (withProof) {
            self._proof = vp.proof
        }
    }

    /// Get the id of this presentation object.
    public var id: DIDURL? {
        return _id
    }
    
    func setId(_ id: DIDURL){
        _id = id
    }
    
    /// Get the types of this presentation object.
    public var types: [String] {
        return _types
    }
    
    public var credentialCount: Int {
        
        return credentials.count
    }
    
    /// Get the holder of this presentation object.
    public var holder: DID? {
        // NOTICE:
        //
        // DID 2 SDK should add the holder field as a mandatory field when
        // create the presentation, at the same time should treat the holder
        // field as an optional field when parse the presentation.
        //
        // This will ensure compatibility with the presentations that
        // created by the old SDK.
        let h = _holder != nil ? _holder : proof.verificationMethod.did
        return h
    }

    /// Get the time created this presentation object.
    @objc
    public var createdDate: Date {
        return _createdDate
    }

    func setCreatedDate(_ newDate: Date) {
        self._createdDate = newDate
    }

    /// Get the count of Credentials in this presentation object.
    @objc
    public var cedentialCount: Int {
        return _verifiableCredentials.count
    }

    /// Get all Credentials in this presentation object.
    @objc
    public var credentials: Array<VerifiableCredential> {
        return _credentialsArray
    }

    /// Add one credential to verifiable credential array.
    /// - Parameter credential: The handle to Credential.
    @objc
    public func appendCredential(_ credential: VerifiableCredential) {
        self._verifiableCredentials[credential.getId()!] = credential
    }

    /// Get the specified credential.
    /// - Parameter ofId: the specified credential id
    /// - Returns: the credential object
    public func credential(ofId: DIDURL) throws -> VerifiableCredential? {
        var id = ofId
        if id.did == nil {
            id = try DIDURL(holder!, id)
        }
        return self._verifiableCredentials[id]
    }

    /// Get the specified credential.
    /// - Parameter ofId: the specified credential id
    /// - Returns: the credential object
    public func credential(ofId: String) throws -> VerifiableCredential? {
        return self._verifiableCredentials[try DIDURL(self.holder!, ofId)]
    }

    /// Get the specified credential with Object-c
    /// - Parameter ofId: the specified credential id
    /// - Returns: the credential object
    @objc
    public func credential(ofId: String, error: NSErrorPointer) -> VerifiableCredential? {
        do {
            return self._verifiableCredentials[try DIDURL(self.holder!, ofId)]
        } catch let aError as NSError {
            error?.pointee = aError
            return nil
        }
    }

    /// Sanitize routine before sealing or after deserialization.
    func sanitize() throws {
        guard !types.isEmpty else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedPresentationError("Missing presentation type")
        }
        
        if _credentialsArray.count > 0 {
            for vc in _credentialsArray {
                do {
                    try vc.sanitize()
                } catch {
                    throw DIDError.CheckedError.DIDSyntaxError.MalformedPresentationError("Credential invalid: \(String(describing: vc.id))")
                }
                
                guard _verifiableCredentials[vc.id!] == nil else {
                    throw DIDError.CheckedError.DIDSyntaxError.MalformedPresentationError("Duplicated credential id: \(String(describing: vc.id))")
                }
                
                _verifiableCredentials[vc.id!] = vc
            }
        }
        
        guard proof.verificationMethod.did != nil else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedPresentationError("Invalid verification method")
        }
    }

    /// Check whether the presentation is genuine or not.
    /// - Throws: DIDResolveError if error occurs when resolving the DIDs
    /// - Returns: whether the credential object is genuine
    public func isGenuine() throws -> Bool {
        return try isGenuine(nil)
    }
    
    /// Check whether the presentation is genuine or not.
    /// - Parameter listener: the listener for the verification events and messages
    /// - Throws: DIDResolveError if error occurs when resolving the DIDs
    /// - Returns: whether the credential object is genuine
    public func isGenuine(listener: VerificationEventListener) throws -> Bool {
        return try isGenuine(listener)
    }
    
    /// Check whether the presentation is genuine or not.
    func isGenuine(_ listener: VerificationEventListener?) throws -> Bool {
        let holderDoc = try holder!.resolve()

        guard let _ = holderDoc else {
            listener?.failed(context: self, args: "VP \(String(describing: id)): can not resolve the holder's document")
            listener?.failed(context: self, args: "VP \(String(describing: id)): is not genuine")
            
            return false
        }
        
        // Check the integrity of signer's document.
        guard try holderDoc!.isGenuine(listener) else {
            listener?.failed(context: self, args: "VP \(String(describing: id)): holder's document is not genuine")
            listener?.failed(context: self, args: "VP \(String(describing: id)): is not genuine")
            
            return false
        }
        // Unsupported public key type
        guard proof.type == Constants.DEFAULT_PUBLICKEY_TYPE else {
            listener?.failed(context: self, args: "VP \(String(describing: id)): key type '\(proof.type)' for proof is not supported")
            listener?.failed(context: self, args: "VP \(String(describing: id)): is not genuine")
            
            return false
        }
        // Credential should be signed by authenticationKey.
        guard try holderDoc!.containsAuthenticationKey(forId: proof.verificationMethod) else {
            listener?.failed(context: self, args: "VP \(String(describing: id)): Key '\(proof.verificationMethod)' for proof is not an authencation key of '\(String(describing: proof.verificationMethod.did))'")
            listener?.failed(context: self, args: "VP \(String(describing: id)): is not genuine")
            
            return false
        }

        // All credentials should be owned by signer
        for credential in _verifiableCredentials.values {
            guard credential.subject!.did == holder else {
                listener?.failed(context: self, args: "VP \(String(describing: id)): credential '\(String(describing: credential.id))' not owned by the holder '\(String(describing: holder))'")
                listener?.failed(context: self, args: "VP \(String(describing: id)): is not genuine")
                
                return false
            }
            guard try credential.isGenuine(listener) else {
                listener?.failed(context: self, args: "VP \(String(describing: id)): credential '\(String(describing: credential.id))' is not genuine")
                listener?.failed(context: self, args: "VP \(String(describing: id)): is not genuine")
                
                return false
            }
        }

        var data: [Data] = []
        data.append(toJson(true))
        if let d = proof.realm.data(using: .utf8) {
            data.append(d)
        }
        if let d = proof.nonce.data(using: .utf8) {
            data.append(d)
        }

        let result = (try? holderDoc!.verify(proof.verificationMethod, proof.signature, data)) ?? false
        
        if (result) {
            listener?.succeeded(context: self, args: "VP \(String(describing: id)): is genuine")
        } else {
            listener?.failed(context: self, args: "VP \(String(describing: id)): proof is invalid, signature mismatch")
            listener?.failed(context: self, args: "VP \(String(describing: id)): is not genuine")
        }
        
        return result
    }

    /// Check whether the presentation is genuine or not in asynchronous mode.
    /// - Returns: flase if not genuine, true if genuine.
    public func isGenuineAsync() -> Promise<Bool> {
        return Promise<Bool> { $0.fulfill(try isGenuine()) }
    }

    /// Check whether the presentation is genuine or not in asynchronous mode.
    /// - Parameter listener: the listener for the verification events and messages
    /// - Returns: flase if not genuine, true if genuine.
    public func isGenuineAsync(listener: VerificationEventListener) -> Promise<Bool> {
        return Promise<Bool> { $0.fulfill(try isGenuine(listener)) }
    }

    /// Check whether the presentation is genuine or not in asynchronous mode with Object-C
    /// - Returns: flase if not genuine, true if genuine.
    @objc
    public func isGenuineAsyncUsingObjectC() -> AnyPromise {
        return AnyPromise(__resolverBlock: { [self] resolver in
            do {
                resolver(try isGenuine())
            }
            catch {
                resolver(error)
            }
        })
    }

    /// Check whether the presentation is genuine or not in asynchronous mode with Object-C
    /// - Parameter listener: the listener for the verification events and messages
    /// - Returns: flase if not genuine, true if genuine.
    @objc (isGenuineWithListenerAsyncUsingObjectC:)
    public func isGenuineAsyncUsingObjectC(listener: VerificationEventListener) -> AnyPromise {
        return AnyPromise(__resolverBlock: { [self] resolver in
            do {
                resolver(try isGenuine(listener))
            }
            catch {
                resolver(error)
            }
        })
    }
    
    /// Check whether the presentation is valid or not.
    /// - Throws: DIDResolveError if error occurs when resolve the DID
    /// - Returns: whether the credential object is valid
    public func isValid() throws -> Bool {
        return try isValid(nil)
    }
    
    /// Check whether the presentation is valid or not.
    /// - Parameter listener: the listener for the verification events and messages
    /// - Throws: DIDResolveError if error occurs when resolve the DID
    /// - Returns: whether the credential object is valid
    public func isValid(listener: VerificationEventListener) throws -> Bool {
        return try isValid(listener)
    }
    
    /// Check whether the presentation is valid or not.
    func isValid(_ listener: VerificationEventListener?) throws -> Bool {
        let doc: DIDDocument?
        do {
            doc = try holder!.resolve()
        } catch {
            doc = nil
        }
        if doc == nil {
            listener?.failed(context: self, args: "VP \(String(describing: id)): can not resolve the holder's document")
            listener?.failed(context: self, args: "VP \(String(describing: id)): is invalid")
        }
        // Check the validity of signer's document.
        guard try doc!.isValid(listener) else {
            listener?.failed(context: self, args: "VP \(String(describing: id)): holder's document is invalid")
            listener?.failed(context: self, args: "VP \(String(describing: id)): is invalid")
            
            return false
        }
        // Unsupported public key type.
        guard proof.type == Constants.DEFAULT_PUBLICKEY_TYPE else {
            listener?.failed(context: self, args: "VP \(String(describing: id)): Key type '\(proof.type)' for proof is not supported")
            listener?.failed(context: self, args: "VP \(String(describing: id)): is invalid")
            
            return false
        }
        // Credential should be signed by authenticationKey.
        guard try doc!.containsAuthenticationKey(forId: proof.verificationMethod) else {
            listener?.failed(context: self, args: "VP \(String(describing: id)): Key '\(proof.verificationMethod)' for proof is not an authencation key of '\(String(describing: proof.verificationMethod.did))'")
            listener?.failed(context: self, args: "VP \(String(describing: id)): is invalid")
            
            return false
        }

        // All credentials should be owned by signer.
        for credential in self._verifiableCredentials.values {
            guard credential.subject!.did == holder else {
                listener?.failed(context: self, args: "VP \(String(describing: id)): credential '\(String(describing: credential.id))' not owned by the holder '\(String(describing: holder))'")
                listener?.failed(context: self, args: "VP \(String(describing: id)): is not genuine")
                
                return false
            }
            guard try credential.isValid(listener) else {
                listener?.failed(context: self, args: "VP \(String(describing: id)): credential '\(String(describing: credential.id))' is invalid")
                listener?.failed(context: self, args: "VP \(String(describing: id)): is invalid")
                
                return false
            }
        }

        var data: [Data] = []
        data.append(toJson(true))
        if let d = proof.realm.data(using: .utf8)  {
            data.append(d)
        }
        if let d = proof.nonce.data(using: .utf8)  {
            data.append(d)
        }

        let result = (try? doc!.verify(proof.verificationMethod, proof.signature, data)) ?? false
        
        if (result) {
            listener?.succeeded(context: self, args: "VP \(String(describing: id)): is valid")
        } else {
            listener?.failed(context: self, args: "VP \(String(describing: id)): proof is invalid, signature mismatch")
            listener?.failed(context: self, args: "VP \(String(describing: id)): is invalid")
        }
        
        return result
    }

    /// Check whether the credential is valid in asynchronous mode.
    /// - Returns: flase if not valid, true if valid.
    public func isValidAsync() -> Promise<Bool> {
        return Promise<Bool> { $0.fulfill(try isValid()) }
    }

    /// Check whether the credential is valid in asynchronous mode.
    /// - Parameter listener: the listener for the verification events and messages
    /// - Returns: Returns: flase if not valid, true if valid.
    public func isValidAsync(listener: VerificationEventListener) -> Promise<Bool> {
        return Promise<Bool> { $0.fulfill(try isValid(listener)) }
    }
    
    /// Check whether the credential is valid in asynchronous mode with Object-C
    /// - Returns: flase if not valid, true if valid.
    @objc
    public func isValidAsyncUsingObjectC() -> AnyPromise {
        return AnyPromise(__resolverBlock: { [self] resolver in
            do {
                resolver(try isValid())
            }
            catch {
                resolver(error)
            }
        })
    }
    
    /// Check whether the credential is valid in asynchronous mode with Object-C
    /// - Returns: flase if not valid, true if valid.
    @objc (isValidWithListenerAsyncUsingObjectC:)
    public func isValidAsyncUsingObjectC(listener: VerificationEventListener) -> AnyPromise {
        return AnyPromise(__resolverBlock: { [self] resolver in
            do {
                resolver(try isValid(listener))
            }
            catch {
                resolver(error)
            }
        })
    }

    /// Get the proof object of this presentation.
    @objc
    public var proof: VerifiablePresentationProof {
        // Guaranteed that this field would not be nil becausesi the object
        // was generated by "builder".
        return _proof!
    }

    func setProof(_ proof: VerifiablePresentationProof) {
        self._proof = proof
    }

    private func parse(_ node: JsonNode) throws {

        let id = node.get(forKey: ID)?.asString()
        if let _ = id {
            _id = try DIDURL(id!)
        }

        let serializer = JsonSerializer(node)
        var options: JsonSerializer.Options
        // _holder
        let holder = node.get(forKey: HOLDER)?.asString()
        if holder != nil && holder! != "" {
            _holder = try DID(holder!)
        }

        let types = node.get(forKey: TYPE)?.asArray()
        if let _ = types {
            types?.forEach{ v in
                _types.append(v.asString()!)
            }
        }
        else {
            options = JsonSerializer.Options()
            guard let type = try serializer.getString(Constants.TYPE, options) else {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedPresentationError("Mssing presentation type")
            }
            guard type == Constants.DEFAULT_PRESENTATION_TYPE else {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedPresentationError("unkown presentation type:\(type)")
            }
            _types.append(type)
        }
        
        options = JsonSerializer.Options()
        guard let createdDate = try serializer.getDate(Constants.CREATED, options) else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedPresentationError("presentation created date")
        }
        setCreatedDate(createdDate)

        let arrayNode = node.get(forKey: Constants.VERIFIABLE_CREDENTIAL)?.asArray()
        guard let _ = arrayNode else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedPresentationError("missing credential")
        }

        for node in arrayNode! {
            _credentialsArray.append(try VerifiableCredential.fromJson(node, nil))
        }

        let subNode = node.get(forKey: Constants.PROOF)
        guard let _ = subNode else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedPresentationError("missing presentation proof")
        }

        let proof = try VerifiablePresentationProof.fromJson(subNode!, nil)
        setProof(proof)
        
        try sanitize()
    }

    /// Get Presentation from json context.
    /// - Parameter json: Json context about Presentation.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: The handle to Presentation
    @objc
    public static func fromJson(_ json: String) throws -> VerifiablePresentation {
        try checkArgument(!json.isEmpty, "Invalid json.")
        let data: [String: Any]?
        do {
            data = try JSONSerialization.jsonObject(with: json.data(using: .utf8)!, options: []) as? [String: Any]
        } catch {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedPresentationError("parse presentation json error")
        }
        guard let _ = data else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedPresentationError("parse presentation json error")
        }
        let vp = VerifiablePresentation()
        try vp.parse(JsonNode(data!))

        return vp
    }
    
    /*
     * Normalized serialization order:
     *
     * - type
     * - created
     * - verifiableCredential (ordered by name(case insensitive/ascending)
     * + proof
     *   - type
     *   - verificationMethod
     *   - realm
     *   - nonce
     *   - signature
     */
    func toJson(_ generator: JsonGenerator, _ forSign: Bool) {
        generator.writeStartObject()
        
        if let _ = id {
            generator.writeStringField(Constants.ID, id!.toString())
        }

        if types.count > 1 {
            generator.writeFieldName(TYPE)
            generator.writeStartArray()
            types.forEach { type in
                generator.writeString(type)
            }
            generator.writeEndArray()
        }
        else {
            if types.count == 1 {
                generator.writeStringField(Constants.TYPE, types[0])
            }
        }
        
        // holder
        if let _ = _holder {
            generator.writeStringField(HOLDER, holder!.toString())
        }

        // created
        generator.writeStringField(Constants.CREATED, DateFormatter.convertToUTCStringFromDate(self.createdDate))
        
        // verifiable credentials
        generator.writeFieldName(Constants.VERIFIABLE_CREDENTIAL)
        generator.writeStartArray()

        let sortedKeys = self._verifiableCredentials.keys.sorted { (a, b) -> Bool in
            let aStr = a.toString()
            let bStr = b.toString()
            return aStr.compare(bStr) == ComparisonResult.orderedAscending
        }

        for key in sortedKeys {
            let credential = self._verifiableCredentials[key]
            credential!.toJson(generator, nil, true)
        }
        generator.writeEndArray()

        // Proof
        if !forSign {
            generator.writeFieldName(Constants.PROOF)
            self._proof!.toJson(generator)
        }
        generator.writeEndObject()
    }

    func toJson(_ forSign: Bool) -> String {
        let generator = JsonGenerator()
        toJson(generator, forSign)
        return generator.toString()
    }

    func toJson(_ forSign: Bool) -> Data {
        let json: String = toJson(forSign)
        return json.data(using: .utf8)!
    }

    private class func editing(_ did: DID, _ signKey: DIDURL?,
                               _ store: DIDStore) throws -> VerifiablePresentationBuilder {

        let holder: DIDDocument?
        let useKey: DIDURL

        do {
            holder = try store.loadDid(did)
            if holder == nil {
                throw DIDError.CheckedError.DIDStoreError.DIDStorageError("Can not load DID.")
            }
        } catch {
            throw DIDError.CheckedError.DIDStoreError.DIDStorageError("Can not load DID")
        }

        // If no 'signKey' provided, use default public key. Otherwise,
        // need to check whether 'signKey' is authenticationKey or not.
        if signKey == nil {
            useKey = holder!.defaultPublicKeyId()!
        } else {
            guard try holder!.containsAuthenticationKey(forId: signKey!) else {
                throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("Not an authentication key.")
            }
            useKey = signKey!
        }

        guard try holder!.containsPrivateKey(forId: useKey) else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError(Errors.NO_PRIVATE_KEY_EXIST)
        }

        return VerifiablePresentationBuilder(holder!, useKey)
    }

    /// Get VerifiablePresentation Builder to modify VerifiableCredential.
    /// - Parameters:
    ///   - did: The handle to DID.
    ///   - signKey: The key id to sign.
    ///   - store: The handle to DIDStore.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiablePresentationBuilder instance.
    @objc
    public class func editingVerifiablePresentationFor(did: DID,
                                             using signKey: DIDURL,
                                                     store: DIDStore) throws
        -> VerifiablePresentationBuilder {
        return try editing(did, signKey, store)
    }

    /// Get VerifiablePresentation Builder to modify VerifiableCredential.
    /// - Parameters:
    ///   - did: The handle to DID.
    ///   - store: The handle to DIDStore.
    /// - Throws: if an error occurred, throw error.
    /// - Returns: VerifiablePresentationBuilder instance.
    @objc
    public class func editingVerifiablePresentation(for did: DID,
                                                using store: DIDStore) throws
        -> VerifiablePresentationBuilder {
        return try editing(did, nil, store)
    }
}

extension VerifiablePresentation {
    func toString() -> String {
        return toJson(false)
    }

    /// Get string context from Presentation.
    @objc
    public override var description: String {
        return toString()
    }
}
