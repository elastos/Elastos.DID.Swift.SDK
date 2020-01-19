
import Foundation

public class VerifiablePresentation: NSObject{
   public var type: String!
   public var created: Date!
   public var credentials: OrderedDictionary<DIDURL, VerifiableCredential>!
   public var proof: PresentationProof?
    
    override init() {
        type = DEFAULT_PRESENTTATION_TYPE
        created = DateFormater.currentDate()
        credentials = OrderedDictionary()
    }
    
    public func getCredentials() -> Array<VerifiableCredential> {
        return credentials!.values
    }
    
    public func addCredential(_ credential: VerifiableCredential) {
        credentials![credential.id] = credential
    }
    
    public func getCredential(_ id: DIDURL) throws -> VerifiableCredential? {
        return credentials![id]
    }
    
    public func getCredential(_ id: String) throws -> VerifiableCredential? {
        return try getCredential(DIDURL(getSigner(), id))
    }
    
    public func getSigner() -> DID {
        return (proof?.verificationMethod.did)!
    }
    
    public func isGenuine() throws -> Bool {
        let signer: DID = getSigner()
        let signerDoc = try signer.resolve()
        if (signerDoc == nil) {
            return false
        }
        
        // Check the integrity of signer' document.
        if (try !signerDoc!.isGenuine()) {
            return false
        }
        // Unsupported public key type;
        if (proof?.type != (DEFAULT_PUBLICKEY_TYPE)) {
            return false
        }
        // Credential should signed by authentication key.
        if (try !signerDoc!.isAuthenticationKey(proof!.verificationMethod)) {
        return false
        }
        
        // All credentials should owned by signer
        for i in 0..<credentials.values.count {
            let vc = credentials.values[i]
            if vc.subject.id != signer {
                return false
            }
            
            if try !vc.isGenuine() {
                return false
            }
        }
        let dic = toJson(true)
        let json = JsonHelper.creatJsonString(dic: dic)
        var inputs: [CVarArg] = []
        if json.count > 0 {
            inputs.append(json)
            inputs.append(json.count)
        }
        if proof?.realm != nil && proof!.realm!.count > 0 {
            inputs.append(proof!.realm!)
            inputs.append(proof!.realm!.count)
        }
        if proof?.nonce != nil && proof!.nonce!.count > 0 {
            inputs.append(proof!.nonce!)
            inputs.append(proof!.nonce!.count)
        }
        let count = inputs.count / 2
        return try signerDoc!.verify(proof!.verificationMethod, proof!.signature, count, inputs)
    }
    
    public func isValid() throws -> Bool {
        let signer: DID = getSigner()
        let signerDoc = try signer.resolve()

        if signerDoc == nil {
            return false
        }
        
        // Check the validity of signer' document.
        if (try !signerDoc!.isValid()){
            return false
        }

        // Unsupported public key type;
        if (proof!.type != (DEFAULT_PUBLICKEY_TYPE)){
            return false
        }

        // Credential should signed by authentication key.
        if (try !signerDoc!.isAuthenticationKey(proof!.verificationMethod)){
            return false
        }

        // All credentials should owned by signer
        
        for _ in 0..<credentials.values.count {
            let vc = credentials.values[0]
            if (vc.subject.id != signer) {
                return false
            }
            if try !vc.isValid() {
                return false
            }
        }
        let dic = toJson(true)
        let json = JsonHelper.creatJsonString(dic: dic)
        var inputs: [CVarArg] = []
        if json.count > 0 {
            inputs.append(json)
            inputs.append(json.count)
        }
        
        if proof?.realm != nil && proof!.realm!.count > 0 {
            inputs.append(proof!.realm!)
            inputs.append(proof!.realm!.count)
        }
        if proof?.nonce != nil && proof!.nonce!.count > 0 {
            inputs.append(proof!.nonce!)
            inputs.append(proof!.nonce!.count)
        }
        let count = inputs.count / 2
        
        return try signerDoc!.verify(proof!.verificationMethod, proof!.signature, count, inputs)
    }
    
    public func getCredentialCount() -> Int {
        return credentials.count
    }
    
    public class func fromJson(_ jsonString: String) throws -> VerifiablePresentation {
        let vp: VerifiablePresentation = VerifiablePresentation()
        try vp.parse(jsonString)
        return vp
    }
    
    func parse(_ jsonString: String) throws {
        let string = JsonHelper.preHandleString(jsonString)
        let dic = JsonHelper.handleString(string) as! OrderedDictionary<String, Any>
        try parse(dic)
    }
    
    func parse(_ presentation: OrderedDictionary<String, Any>) throws {
        
        let type: String = try JsonHelper.getString(presentation, TYPE, false, nil, "presentation type")
        guard type == DEFAULT_PRESENTTATION_TYPE else {
            throw DIDError.malformedCredentialError(_desc: "Unknown presentation type: \(type)")
        }
        self.type = type
        let created: Date = try DateFormater.getDate(presentation, CREATED, false, nil, "presentation created date")!
        self.created = created
        
        var d = presentation[VERIFIABLE_CREDENTIAL]
        guard d != nil else {
            throw DIDError.malformedCredentialError(_desc: "Missing credentials.")
        }
        guard d is Array<Any> else {
            throw DIDError.malformedCredentialError(_desc: "Invalid verifiableCredentia, should be an array.")
        }
        try parseCredential(d as! Array<OrderedDictionary<String, Any>>)
        
        d = presentation[PROOF]
        guard d != nil else {
            throw DIDError.malformedCredentialError(_desc: "Missing credentials.")
        }
        let proof: PresentationProof = try PresentationProof.fromJson(d as! OrderedDictionary<String, Any>, nil)
        self.proof = proof
    }
    
    func parseCredential(_ jsonArry: Array<OrderedDictionary<String, Any>>) throws {
        guard jsonArry.count != 0 else {
            throw DIDError.malformedCredentialError(_desc: "Invalid verifiableCredentia, should not be an empty array.") 
        }
        try jsonArry.forEach { vc in
            let vc: VerifiableCredential = try VerifiableCredential.fromJson(vc)
            addCredential(vc)
        }
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
    public func toJson(_ forSign: Bool) -> OrderedDictionary<String, Any>  {
        var dic: OrderedDictionary<String, Any> = OrderedDictionary()

        // type
        dic[TYPE] = type

        // created
        dic[CREATED] = DateFormater.format(created)

        // credentials
        var arr: Array<OrderedDictionary<String, Any>> = []
        credentials = DIDURLComparator.DIDOrderedDictionaryComparatorByVerifiableCredential(credentials)
        credentials.values.forEach { vc in
           let dic = vc.toJson(true)
            arr.append(dic)
        }
        dic[VERIFIABLE_CREDENTIAL] = arr

        // proof
        if (!forSign ) {
            let d = proof?.toJson()
            dic[PROOF] = d
        }
        return dic
    }
    
    public func toJson() -> OrderedDictionary<String, Any> {
       return toJson(false)
    }

    func toJsonForSign(_ forSign: Bool) -> String {
        let dic = toJson(forSign)
        let jsonString: String = JsonHelper.creatJsonString(dic: dic)
        return jsonString
    }
    
    func toExternalForm() -> String {
        let dic = toJson()
        let jsonstring: String = JsonHelper.creatJsonString(dic: dic)
        return jsonstring
    }
    
    public override var description: String {
        return toExternalForm()
    }
    
    public class func createFor(_ did: DID, signKey: DIDURL? = nil, _ store: DIDStore) throws -> VerifiablePresentationBuilder {
        var sigK: DIDURL? = signKey
        let signer: DIDDocument? = try store.loadDid(did)
        guard signer != nil else {
            throw DIDError.illegalArgument("")
        }
        if sigK == nil {
            sigK = signer!.getDefaultPublicKey()
        }
        else {
            guard try signer!.isAuthenticationKey(sigK!) else {
                throw DIDError.didExpiredError(_desc: "Invalid sign key id.")
            }
        }
        guard try signer!.hasPrivateKey(sigK!) else {
            throw DIDError.didExpiredError(_desc: "No private key.")
        }
        return VerifiablePresentationBuilder(signer!, sigK!, store)
    }
}

public class VerifiablePresentationBuilder {
    var signer: DIDDocument
    var signKey: DIDURL
    var realm: String?
    var nonce: String?
    var presentation: VerifiablePresentation?
    
    init(_ signer: DIDDocument, _ signKey: DIDURL, _ store: DIDStore) {
        self.signer = signer
        self.signKey = signKey
        self.presentation = VerifiablePresentation()
    }
    
    
    public func credentials(_ credentials: Array<VerifiableCredential>) throws -> VerifiablePresentationBuilder {
        
        for vc in credentials {
            guard vc.subject.id == signer.subject else {
                throw DIDError.illegalArgument("Credential '\(vc.id!)' not match with requested did")
            }
            // TODO: integrity check?
            presentation!.addCredential(vc)
        }
        return self
    }
    
    public func realm(_ realm: String) -> VerifiablePresentationBuilder {
        self.realm = realm
        return self
    }
    
    public func nonce(_ nonce: String) -> VerifiablePresentationBuilder {
        self.nonce = nonce
        return self
    }
    
    public func seal(_ storepass: String) throws -> VerifiablePresentation {

        let dic = presentation!.toJson(true)
        let json = JsonHelper.creatJsonString(dic: dic)
        var inputs: [CVarArg] = []
        if json.count > 0 {
            inputs.append(json)
            inputs.append(json.count)
        }
        if realm != nil && !realm!.isEmpty {
            inputs.append(realm!)
            inputs.append(realm!.count)
        }
        if nonce != nil && !nonce!.isEmpty {
            inputs.append(nonce!)
            inputs.append(nonce!.count)
        }
        
        let count = inputs.count / 2
        let sig = try signer.sign(signKey, storepass, count, inputs)
        let proof = PresentationProof(signKey, realm!, nonce!, sig)
        presentation!.proof = proof
        let vp: VerifiablePresentation = presentation!
        presentation = nil
        
        return vp
    }
}

