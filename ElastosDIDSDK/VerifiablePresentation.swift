import Foundation

public class VerifiablePresentation {
    private var _type: String
    private var _createdDate: Date
    private var _verifiableCredentials: Dictionary<DIDURL, VerifiableCredential>
    private var _proof: VerifiablePresentationProof?
    
    init() {
        self._type = Constants.DEFAULT_PRESENTATION_TYPE
        self._createdDate = DateHelper.currentDate()
        self._verifiableCredentials = Dictionary<DIDURL, VerifiableCredential>()
    }

    public var type: String {
        return self._type
    }

    func setType(_ type: String) {
        self._type = type
    }

    public var createdDate: Date {
        return self._createdDate
    }

    func setCreatedDate(_ newDate: Date) {
        self._createdDate = newDate
    }

    public var cedentialCount: Int {
        return self._verifiableCredentials.count
    }
    
    public var credentials: Array<VerifiableCredential> {
        var credentials = Array<VerifiableCredential>()
        for credential in self._verifiableCredentials.values {
            credentials.append(credential)
        }
        return credentials
    }

    public func appendCredential(_ credential: VerifiableCredential) {
        self._verifiableCredentials[credential.getId()] = credential
    }

    public func credential(ofId: DIDURL) -> VerifiableCredential? {
        return self._verifiableCredentials[ofId]
    }

    public func credential(ofId: String) throws -> VerifiableCredential? {
        return self._verifiableCredentials[try DIDURL(self.signer, ofId)]
    }

    public var signer: DID {
        // Guaranteed that this field would not be nil because the object
        // was generated by "builder".
        return self._proof!.verificationMethod.did
    }

    func getSigner() -> DID? {
        return self._proof?.verificationMethod.did
    }

    public var isGenuine: Bool {
        let doc: DIDDocument? = (try? self.getSigner()?.resolve()) ?? nil
        guard let _ = doc else {
            return false
        }

        // Check the integrity of signer's document.
        guard doc!.isGenuine else {
            return false
        }
        // Unsupported public key type
        guard self.proof.type == Constants.DEFAULT_PUBLICKEY_TYPE else {
            return false
        }
        // Credential should be signed by authenticationKey.
        guard doc!.containsAuthenticationKey(forId: proof.verificationMethod) else {
            return false
        }

        // All credentials should be owned by signer
        for credential in self._verifiableCredentials.values {
            guard credential.subject.did == self.signer else {
                return false
            }
            guard credential.isGenuine else {
                return false
            }
        }

        var inputs: [Data] = []
        inputs.append(toJson(true).data(using: .utf8)!)
        inputs.append(self.proof.realm.data(using: .utf8)!)
        inputs.append(self.proof.nonce.data(using: .utf8)!)

        return (try? doc!.verifyEx(self.proof.verificationMethod,
                                   self.proof.signature, inputs)) ?? false
    }

    public var isValid: Bool {
        let doc: DIDDocument? = (try? self.getSigner()?.resolve()) ?? nil
        guard let _ = doc else {
            return false
        }

        // Check the validity of signer's document.
        guard doc!.isValid else {
            return false
        }
        // Unsupported public key type.
        guard self.proof.type == Constants.DEFAULT_PUBLICKEY_TYPE else {
            return false
        }
        // Credential should be signed by authenticationKey.
        guard doc!.containsAuthenticationKey(forId: proof.verificationMethod) else {
            return false
        }

        // All credentials should be owned by signer.
        for credential in self._verifiableCredentials.values {
            guard credential.subject.did == self.signer else {
                return false
            }
            guard credential.isValid else {
                return false
            }
        }

        var inputs: [Data] = []
        inputs.append(toJson(true).data(using: .utf8)!)
        inputs.append(self.proof.realm.data(using: .utf8)!)
        inputs.append(self.proof.nonce.data(using: .utf8)!)

        return (try? doc!.verifyEx(self.proof.verificationMethod,
                                   self.proof.signature, inputs)) ?? false
    }

    public var proof: VerifiablePresentationProof {
        // Guaranteed that this field would not be nil because the object
        // was generated by "builder".
        return self._proof!
    }

    func getProof() -> VerifiablePresentationProof? {
        return self._proof
    }

    func setProof(_ proof: VerifiablePresentationProof) {
        self._proof = proof
    }

    private func parse(_ json: String) throws {
        // TODO
    }

    public static func fromJson(_ json: String) throws -> VerifiablePresentation {
        guard !json.isEmpty else {
            throw DIDError.illegalArgument()
        }

        let vp = VerifiablePresentation()
        try vp.parse(json)

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
    func toJson(_ generator: JsonGenerator, _ forSign: Bool) throws {
        try generator.writeStartObject()
        try generator.writeStringField(Constants.TYPE, self.type)
        try generator.writeStringField(Constants.CREATED, JsonHelper.fromDate(self.createdDate)!) // TOOD:

        // verifiable credentials
        try generator.writeFieldName(Constants.VERIFIABLE_CREDENTIAL)
        try generator.writeStartArray()
        for credential in self._verifiableCredentials.values {
            try credential.toJson(generator, nil, true)
        }
        try generator.writeEndArray()

        // Proof
        if !forSign {
            try generator.writeFieldName(Constants.PROOF)
            try self._proof!.toJson(generator)
        }
        try generator.writeEndObject()
    }

    func toJson(_ forSign: Bool) -> String {
        // TODO
        return "TODO"
    }

    func toString() -> String {
        return toJson(false)
    }

    private class func createBuilderEx(_ did: DID, _ signKey: DIDURL?, _ store: DIDStore) throws
        -> VerifiablePresentationBuilder {

        let signer: DIDDocument
        let useKey: DIDURL

        do {
            signer = try store.loadDid(did)
        } catch {
            throw DIDError.unknownFailure("Can not load DID") // TODO:
        }

        // If no 'signKey' provided, use default public key. Otherwise,
        // need to check whether 'signKey' is authenticationKey or not.
        if signKey == nil {
            useKey = signer.defaultPublicKey
        } else {
            guard signer.containsAuthenticationKey(forId: signKey!) else {
                throw DIDError.illegalArgument("Invalid sign key Id")
            }
            useKey = signKey!
        }

        guard try signer.containsPrivateKey(forId: useKey) else {
            throw DIDError.unknownFailure(Errors.NO_PRIVATE_KEY_EXIST)
        }

        return VerifiablePresentationBuilder(signer, useKey)
    }

    public class func createBuilder(forDid: DID, using signKey: DIDURL, store: DIDStore) throws
        -> VerifiablePresentationBuilder {
        return try createBuilderEx(forDid, signKey, store)
    }

    public class func createBuilder(forDid: DID, using store: DIDStore) throws
        -> VerifiablePresentationBuilder {
        return try createBuilderEx(forDid, nil, store)
    }
}

extension VerifiablePresentation: CustomStringConvertible {
    public var description: String {
        return toString()
    }
}
