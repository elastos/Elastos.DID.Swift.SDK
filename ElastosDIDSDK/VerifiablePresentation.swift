import Foundation
import PromiseKit

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
        return _type
    }

    func setType(_ type: String) {
        self._type = type
    }

    public var createdDate: Date {
        return _createdDate
    }

    func setCreatedDate(_ newDate: Date) {
        self._createdDate = newDate
    }

    public var cedentialCount: Int {
        return _verifiableCredentials.count
    }
    
    public var credentials: Array<VerifiableCredential> {
        var credentials = Array<VerifiableCredential>()
        for credential in _verifiableCredentials.values {
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
        return proof.verificationMethod.did
    }

    func getSigner() -> DID? {
        return self._proof?.verificationMethod.did
    }

    public var isGenuine: Bool {
        let doc: DIDDocument?
        do {
            doc = try signer.resolve()
        } catch {
            doc = nil
        }

        // Check the integrity of signer's document.
        guard doc!.isGenuine else {
            return false
        }
        // Unsupported public key type
        guard proof.type == Constants.DEFAULT_PUBLICKEY_TYPE else {
            return false
        }
        // Credential should be signed by authenticationKey.
        guard doc!.containsAuthenticationKey(forId: proof.verificationMethod) else {
            return false
        }

        // All credentials should be owned by signer
        for credential in _verifiableCredentials.values {
            guard credential.subject.did == signer else {
                return false
            }
            guard credential.isGenuine else {
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

        return (try? doc!.verify(proof.verificationMethod, proof.signature, data)) ?? false
    }

    public func isGenuineAsync() -> Promise<Bool> {
        return Promise<Bool> { $0.fulfill(isGenuine) }
    }

    public var isValid: Bool {
        let doc: DIDDocument?
        do {
            doc = try signer.resolve()
        } catch {
            doc = nil
        }

        // Check the validity of signer's document.
        guard doc!.isValid else {
            return false
        }
        // Unsupported public key type.
        guard proof.type == Constants.DEFAULT_PUBLICKEY_TYPE else {
            return false
        }
        // Credential should be signed by authenticationKey.
        guard doc!.containsAuthenticationKey(forId: proof.verificationMethod) else {
            return false
        }

        // All credentials should be owned by signer.
        for credential in self._verifiableCredentials.values {
            guard credential.subject.did == signer else {
                return false
            }
            guard credential.isValid else {
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

        return (try? doc!.verify(proof.verificationMethod, proof.signature, data)) ?? false
    }

    public func isValidAsync() -> Promise<Bool> {
        return Promise<Bool> { $0.fulfill(isValid) }
    }

    public var proof: VerifiablePresentationProof {
        // Guaranteed that this field would not be nil becausesi the object
        // was generated by "builder".
        return _proof!
    }

    func getProof() -> VerifiablePresentationProof? {
        return _proof
    }

    func setProof(_ proof: VerifiablePresentationProof) {
        self._proof = proof
    }

    private func parse(_ node: JsonNode) throws {
        let error = { (des) -> DIDError in
            return DIDError.malformedPresentation(des)
        }

        let serializer = JsonSerializer(node)
        var options: JsonSerializer.Options

        options = JsonSerializer.Options()
                                .withHint("presentation type")
                                .withError(error)
        let type = try serializer.getString(Constants.TYPE, options)
        guard type == Constants.DEFAULT_PRESENTATION_TYPE else {
            throw DIDError.malformedPresentation("unkown presentation type:\(type)")
        }
        setType(type)

        options = JsonSerializer.Options()
                                .withHint("presentation created date")
                                .withError(error)
        let createdDate = try serializer.getDate(Constants.CREATED, options)
        setCreatedDate(createdDate)

        let arrayNode = node.get(forKey: Constants.VERIFIABLE_CREDENTIAL)?.asArray()
        guard let _ = arrayNode else {
            throw DIDError.malformedPresentation("missing credential")
        }

        for node in arrayNode! {
            appendCredential(try VerifiableCredential.fromJson(node, nil))
        }

        let subNode = node.get(forKey: Constants.PROOF)
        guard let _ = subNode else {
            throw DIDError.malformedPresentation("missing presentation proof")
        }

        let proof = try VerifiablePresentationProof.fromJson(subNode!, nil)
        setProof(proof)
    }

    public static func fromJson(_ json: String) throws -> VerifiablePresentation {
        guard !json.isEmpty else {
            throw DIDError.illegalArgument()
        }

        let data: [String: Any]?
        do {
            data = try JSONSerialization.jsonObject(with: json.data(using: .utf8)!, options: []) as? [String: Any]
        } catch {
            throw DIDError.malformedPresentation("parse presentation json error")
        }
        guard let _ = data else {
            throw DIDError.malformedPresentation("parse presentation json error")
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

        generator.writeStringField(Constants.TYPE, self.type)
        generator.writeStringField(Constants.CREATED, DateHelper.formateDate(self.createdDate))

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
        return toJson(forSign).data(using: .utf8)!
    }

    private class func editing(_ did: DID, _ signKey: DIDURL?,
                               _ store: DIDStore) throws -> VerifiablePresentationBuilder {

        let signer: DIDDocument
        let useKey: DIDURL

        do {
            signer = try store.loadDid(did)
        } catch {
            throw DIDError.unknownFailure("Can not load DID")
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

        guard signer.containsPrivateKey(forId: useKey) else {
            throw DIDError.unknownFailure(Errors.NO_PRIVATE_KEY_EXIST)
        }

        return VerifiablePresentationBuilder(signer, useKey)
    }

    public class func editingVerifiablePresentationFor(did: DID,
                                             using signKey: DIDURL,
                                                     store: DIDStore) throws
        -> VerifiablePresentationBuilder {
        return try editing(did, signKey, store)
    }

    public class func editingVerifiablePresentation(for did: DID,
                                                using store: DIDStore) throws
        -> VerifiablePresentationBuilder {
        return try editing(did, nil, store)
    }
}

extension VerifiablePresentation: CustomStringConvertible {
    func toString() -> String {
        return toJson(false)
    }

    public var description: String {
        return toString()
    }
}
