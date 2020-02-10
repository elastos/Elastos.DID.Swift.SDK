import Foundation

public class VerifiablePresentationProof {
    private let _type: String
    private let _verificationMethod: DIDURL
    private let _realm: String
    private let _nonce: String
    private let _signature: String
    
    init(_ type: String, _ method: DIDURL, _ realm: String,
        _ nonce: String, _ signature: String) {

        self._type = type
        self._verificationMethod = method
        self._realm = realm
        self._nonce = nonce
        self._signature = signature
    }
    
    convenience init(_ method: DIDURL, _ realm: String, _ nonce: String, _ signature: String) {
        self.init(Constants.DEFAULT_PUBLICKEY_TYPE, method, realm, nonce, signature)
    }

    public var type: String {
        return self._type
    }

    public var verificationMethod: DIDURL {
        return self._verificationMethod
    }

    public var realm: String {
        return self._realm
    }

    public var nonce: String {
        return self._nonce
    }

    public var signature: String {
        return self._signature
    }

    class func fromJson(_ node: JsonNode, _ ref: DID) throws -> VerifiablePresentationProof {
        let type: String?
        let method: DIDURL?
        let realm: String?
        let nonce: String?
        let signature: String?
        let errorGenerator = { (desc: String) -> DIDError in
            return DIDError.malformedDocument(desc)
        }

        type = try JsonHelper.getString(node, Constants.TYPE, true,
                                        Constants.DEFAULT_PUBLICKEY_TYPE,
                                        "presentation proof type",
                                        errorGenerator)
        method = try JsonHelper.getDidUrl(node, Constants.VERIFICATION_METHOD, ref,
                                        "presentation proof verificationMethod",
                                        errorGenerator)
        realm = try JsonHelper.getString(node, Constants.REALM, false, nil,
                                        "presentation proof realm",
                                        errorGenerator)
        nonce = try JsonHelper.getString(node, Constants.NONCE, false, nil,
                                        "presentation proof nonce",
                                        errorGenerator)
        signature = try JsonHelper.getString(node, Constants.SIGNATURE, false, nil,
                                        "presentation proof signature",
                                        errorGenerator)

        return VerifiablePresentationProof(type!, method!, realm!, nonce!, signature!)
    }

    func toJson(_ generator: JsonGenerator) throws {
        try generator.writeStartObject()
        try generator.writeStringField(Constants.TYPE, self.type)
        try generator.writeStringField(Constants.VERIFICATION_METHOD, self.verificationMethod.toString())
        try generator.writeStringField(Constants.REALM, self.realm)
        try generator.writeStringField(Constants.NONCE, self.nonce)
        try generator.writeStringField(Constants.SIGNATURE, self.signature)
        try generator.writeEndObject()
    }
}
