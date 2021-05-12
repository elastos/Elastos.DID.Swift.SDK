
import Foundation
import Swifter

// For mini HTTP server
//let DEFAULT_PORT: Int = 9995
let DEFAULT_PORT: Int = 9123
public class SimulatedIDChain {
    
    let TAG = NSStringFromClass(SimulatedIDChain.self)
    let DEFAULT_HOST = "localhost"
//    let DEFAULT_PORT: Int = 9999
//    let DEFAULT_PORT: Int = 9123

    var host: String
    var port: Int
    public var httpServer: HttpServer = HttpServer()
//    var executor: ThreadPoolExecutor
    
    var idtxs: [DIDTransaction]
    var vctxs: [CredentialTransaction]
    var stat: Statistics
    
    /// Create a SimulatedIDChain instance at host:port.
    init(_ host: String, _ port: Int) {
        self.host = host
        self.port = port
        idtxs = []
        vctxs = []
        stat = Statistics()
    }
    
    init(_ port: Int) {
        self.host = DEFAULT_HOST
        self.port = port
        idtxs = []
        vctxs = []
        stat = Statistics()
    }
    
    init() {
        self.host = DEFAULT_HOST
        self.port = DEFAULT_PORT
        idtxs = []
        vctxs = []
        stat = Statistics()
    }
    
    func reset() {
        idtxs.removeAll()
        vctxs.removeAll()
        Log.i(TAG, "All transactions reseted.")
    }
    
    func resetIdtxs() {
        idtxs.removeAll()
        Log.i(TAG, "All id transactions reseted.")
    }
    
    func resetVctxs() {
        vctxs.removeAll()
        Log.i(TAG, "All credential transactions reseted.")
    }
    
    class func generateTxid() -> String {
        var str = ""
        while(str.count < 32){
            let re = Int.randomCustom(min: 0, max: 9)
            let r = Int.decTohex(number: re)
            str = "\(str)\(r)"
        }

        return str
    }
    
    func getLastDidTransaction(_ did: DID) -> DIDTransaction? {
        for tx in idtxs {
            if try! tx.did?.compareTo(did) == ComparisonResult.orderedSame {
                return tx
            }
        }

        return nil
    }
    
    func getLastDidDocument(_ did: DID) -> DIDDocument? {
        for tx in idtxs {
            if tx.did == did && tx.request.operation != IDChainRequestOperation.DEACTIVATE {
                return tx.request.document
            }
        }

        return nil
    }
    
    func createDidTransaction(_ request: DIDRequest) throws {
   
        Log.d(TAG, "ID Transaction[\(String(describing: request.operation))] - \(String(describing: request.did))")
        Log.i(TAG, "    payload: \(request.serialize(true))")

        if request.operation != IDChainRequestOperation.DEACTIVATE {
            Log.i(TAG, "    document: \(String(describing: request.document?.toString(true)))")
        }
        
        do {
            if (try !request.isValid()) {
                _ = stat.invalidDidRequest()
                throw DIDError.CheckedError.DIDBackendError.DIDTransactionError("Invalid DID transaction request.")
            }
        } catch {
            _ = stat.invalidDidRequest()
            Log.e(TAG, "INTERNAL - resolve failed when verify the did transaction")
            throw DIDError.CheckedError.DIDBackendError.DIDTransactionError("Resove DID error")
        }
        if request.operation != IDChainRequestOperation.DEACTIVATE {
            if (try !request.document!.isValid()) {
                _ = stat.invalidDidRequestWithInvalidDocument()
                throw DIDError.CheckedError.DIDBackendError.DIDTransactionError("Invalid DID Document.")
            }
        }

        var tx = getLastDidTransaction(request.did!)
        if (tx != nil) {
            if tx!.request.operation == IDChainRequestOperation.DEACTIVATE {
                _ = stat.invalidDidRequestOnDeactivatedDid()
                throw DIDError.CheckedError.DIDBackendError.DIDTransactionError("DID \(String(describing: request.did)) already deactivated")
            }
        }
        
        switch (request.operation) {
        case .CREATE:
            _ = stat.createDid()
            
            if (tx != nil) {
                _ = stat.createDidAlreadyExists()
            throw DIDError.CheckedError.DIDBackendError.DIDTransactionError("DID already exists.")
            }

            if request.document!.isCustomizedDid() {
                _ = stat.createCustomizedDid()

                if request.document!.controllerCount() == 1 {
                    _ = stat.createCustomizedDidWithSingleController()
                }
                else {
                    _ = stat.createCustomizedDidWithMultiController()
                }
                if (request.document!.multiSignature) != nil {
                    _ = stat.createCustomizedDidWithMultisig()
                }
                else {
                    _ = stat.createCustomizedDidWithSinglesig()
                }
            }

            break

        case .UPDATE:
            _ = stat.updateDid()

            if (tx == nil) {
                _ = stat.updateDidNotExists()
                throw DIDError.CheckedError.DIDBackendError.DIDTransactionError("DID not exists.")
            }

            if (request.document!.isCustomizedDid()) {
                _ = stat.updateCustomizedDid()

                if (request.document!.controllerCount() == 1) {
                    _ = stat.updateCustomizedDidWithSingleController()
                }
                else {
                    _ = stat.updateCustomizedDidWithMultiController()
                }

                if (request.document!.multiSignature != nil) {
                    _ = stat.updateCustomizedDidWithMultisig()
                }
                else {
                    _ = stat.updateCustomizedDidWithSinglesig()
                }
            }

            if request.previousTxid != tx?.transactionId {
                _ = stat.updateDidWithWrongTxid()
                throw DIDError.CheckedError.DIDBackendError.DIDTransactionError("Previous transaction id missmatch.")
            }

            if (tx!.request.document!.isCustomizedDid()) {
                let orgControllers = tx!.request.document!.controllers()
                let curControllers = request.document!.controllers()

                if (curControllers != orgControllers) {
                    _ = stat.updateCustomizedDidWithControllersChanged()
                    throw DIDError.CheckedError.DIDBackendError.DIDTransactionError("Document controllers changed.")
                }
            }
            break

        case .TRANSFER:
            _ = stat.transferDid()

            if (tx == nil) {
                _ = stat.transferDidNotExists();
                throw DIDError.CheckedError.DIDBackendError.DIDTransactionError("DID not exists.")
            }
            
            do {
                if (try !request.transferTicket!.isValid()) {
                    _ = stat.transferDidWithInvalidTicket()
                    throw DIDError.CheckedError.DIDBackendError.DIDTransactionError("Invalid transfer ticket.")
                }
            } catch  {
                throw DIDError.CheckedError.DIDBackendError.DIDTransactionError()
            }

            if request.transferTicket!.subject != request.did {
                _ = stat.transferDidWithInvalidTicketId()
                throw DIDError.CheckedError.DIDBackendError.DIDTransactionError("Ticket subject mismatched with target DID.")
            }

            if (!request.document!.hasController(request.transferTicket!.to)) {
                _ = stat.transferDidWithInvalidTicketTo();
                throw DIDError.CheckedError.DIDBackendError.DIDTransactionError("Ticket owner not a controller of target DID.")
            }

            var hasSignature = false
            for proof in request.document!.proofs() {
                if proof.creator?.did == request.transferTicket?.to {
                    hasSignature = true
                }
            }

            if (!hasSignature) {
                _ = stat.transferDidWithInvalidController();
                throw DIDError.CheckedError.DIDBackendError.DIDTransactionError("New document not include the ticket owner's signature.")
            }
            break

        case .DEACTIVATE:
            _ = stat.deactivateDid()

            if (tx == nil) {
                _ = stat.deactivateDidNotExists();
                throw DIDError.CheckedError.DIDBackendError.DIDTransactionError("DID not exist.")
            }

            if (try tx!.request.document!.containsAuthorizationKey(forId: request.proof!.verificationMethod)) {
                _ = stat.deactivateDidByAuthroization()
            }
            else {
                _ = stat.deactivateDidByOwner()
            }

            break

        default:
            throw DIDError.CheckedError.DIDBackendError.DIDTransactionError("Invalid opreation.")
        }

        tx = DIDTransaction(SimulatedIDChain.generateTxid(), DateFormatter.currentDate(), request)
        idtxs.insert(tx!, at: 0)
        Log.i(TAG, "ID Transaction[\(String(describing: request.operation))] - \(String(describing: request.did)) success")
    }
    
    func resolveDid(_ request: DIDResolveRequest) throws -> DIDResolveResponse {
        Log.d(TAG, "Resolveing DID \(String(describing: request.did)) ...")

        _ = stat.resolveDid()
        if (request.isResolveAll!) {
            _ = stat.resolveDidWithAll()
        }
        else {
            _ = stat.resolveDidNonAll()
        }

        let bio = DIDBiography(request.did!)
        let last = getLastDidTransaction(request.did!)
        if (last != nil) {
            var limit: Int
            if (last?.request.operation == IDChainRequestOperation.DEACTIVATE) {
                _ = stat.resolveDeactivatedDid()
                bio.setStatus(DIDBiographyStatus.STATUS_DEACTIVATED)
                limit = request.isResolveAll! ? -1 : 2
            } else {
                bio.setStatus(DIDBiographyStatus.STATUS_VALID)
                limit = request.isResolveAll! ? -1 : 1
            }

            print("idtxs.count = \(idtxs.count)")
            for tx in idtxs {
                if tx.did == request.did {
                    bio.appendTransaction(tx)
                    if limit < 0 {
                        continue
                    }
                    limit = limit - 1
                    if limit == 0 {
                        break
                    }
                }
            }
        } else {
            _ = stat.resolveNonExistsDid()
            bio.setStatus(DIDBiographyStatus.STATUS_NOT_FOUND)
        }

        Log.i(TAG, "Resolve DID \(String(describing: request.did)) \(bio.status)")
        return DIDResolveResponse(request.requestId, bio)
    }
    
    func getCredentialRevokeTransaction(_ id: DIDURL, _ signer: DID?) throws -> CredentialTransaction? {
        let ownerDoc = getLastDidDocument(id.did!)
        var signerDoc: DIDDocument?
        if (signer != nil && signer != id.did) {
            signerDoc = getLastDidDocument(signer!)
        }
        for tx in vctxs {
            if tx.id == id && tx.request.operation == IDChainRequestOperation.REVOKE {
                let did = tx.request.proof?.verificationMethod.did
                if did == id.did {
                    return tx
                }
                if signer != nil && did == signer {// issuer revoked
                    return tx
                }
                
                if ownerDoc != nil && ownerDoc!.hasController(did!) {// controller revoked
                    return tx
                }
                if signerDoc != nil && signerDoc!.hasController(did!) {// controller revoked
                    return tx
                }
            }
        }

        return nil
    }
    
    func getCredentialDeclareTransaction(_ id: DIDURL) throws -> CredentialTransaction? {
        for tx in vctxs {
            if tx.request.operation == IDChainRequestOperation.DECLARE {
                return tx
            }
        }

        return nil
    }
    
    func createCredentialTransaction(_ request: CredentialRequest) throws {
        Log.d(TAG, "VC Transaction[\(String(describing: request.operation))] - \(String(describing: request.credential)) ")
        Log.i(TAG,"    payload: \(request.serialize(true))")
        if (request.operation == IDChainRequestOperation.DECLARE) {
            Log.i(TAG, "    credential: \(request.credential!.toString(true))")
        }
        do {
            if (try !request.isValid()) {
                _ = stat.invalidCredentialRequest();
                throw DIDError.CheckedError.DIDBackendError.DIDTransactionError("Invalid ID transaction request.")
            }
        } catch {
            _ = stat.invalidCredentialRequest()
            Log.e(TAG, "INTERNAL - resolve failed when verify the id transaction")
            throw DIDError.CheckedError.DIDBackendError.DIDTransactionError("Resove DID error")
        }

        let declareTx = try getCredentialDeclareTransaction(request.credentialId!)
        let revokeTx:  CredentialTransaction?

        switch (request.operation) {
        case .DECLARE:
            _ = stat.declareCredential()

            if (declareTx != nil) { // Declared already
                _ = stat.declareCredentialAlreadyDeclared()
                throw DIDError.CheckedError.DIDBackendError.DIDTransactionError("Credential already exists.")
            }

            revokeTx = try getCredentialRevokeTransaction(
                request.credentialId!, request.credential?.issuer)
            if (revokeTx != nil) { // Revoked already
                _ = stat.declareCredentialAlreadyRevoked()
                throw DIDError.CheckedError.DIDBackendError.DIDTransactionError("Credential already revoked by \(String(describing: revokeTx?.request.proof?.verificationMethod.did))")
            }

            break;

        case .REVOKE:
            _ = stat.revokeCredential()
            
            let issuer = declareTx != nil ? declareTx?.request.credential?.issuer
                : request.proof?.verificationMethod.did
            
            if (declareTx != nil) {
                _ = stat.revokeCredentialNotDeclared()
            }
            else {
                _ = stat.revokeCredentialAlreadyDeclared()
            }
            revokeTx = try getCredentialRevokeTransaction(request.credentialId!, issuer)
            if (revokeTx != nil) {
                _ = stat.revokeCredentialAlreadyRevoked()
                throw  DIDError.CheckedError.DIDBackendError.DIDTransactionError("Credential already revoked by \(String(describing: revokeTx?.request.proof?.verificationMethod.did))")
            }
            
            break
            
        default:
            throw DIDError.CheckedError.DIDBackendError.DIDTransactionError("Invalid opreation.")
        }

        let tx = CredentialTransaction(SimulatedIDChain.generateTxid(),
                                       DateFormatter.currentDate(), request)
        vctxs.insert(tx, at: 0)
        Log.i(TAG, "VC Transaction[{}] - {} success \((request.operation, request.credentialId))")
        
    }
    
    func resolveCredential(_ request: CredentialResolveRequest) throws -> CredentialResolveResponse {
        Log.d(TAG, "Resolveing credential \(String(describing: request.id)) ...")

        _ = stat.resolveCredential()
        if (request.issuer != nil) {
            _ = stat.resolveCredentialWithIssuer()
        }
        else {
            _ = stat.resolveCredentialWithoutIssuer()
        }

        let declareTx = try getCredentialDeclareTransaction(request.id!)

        let issuer = declareTx != nil ? declareTx?.request.credential?.issuer
                : request.issuer
        let revokeTx = issuer != nil ? try getCredentialRevokeTransaction(
            request.id!, issuer) : nil

        let bio = CredentialBiography(request.id!)
        if (revokeTx != nil) {
            _ = stat.resolveRevokedCredential()
            bio.setStatus(CredentialBiographyStatus.STATUS_REVOKED)
            bio.appendTransaction(revokeTx!)
            if (declareTx != nil) {
                bio.appendTransaction(declareTx!)
            }
        } else {
            if (declareTx != nil) {
                bio.setStatus(CredentialBiographyStatus.STATUS_VALID)
                bio.appendTransaction(declareTx!)
            } else {
                _ = stat.resolveNonExistsCredential()
                bio.setStatus(CredentialBiographyStatus.STATUS_NOT_FOUND)
            }
        }

        Log.i(TAG, "Resolve VC \(String(describing: request.id)) \(bio.status)")
        
        return CredentialResolveResponse(request.requestId, bio)
    }
    
    func listCredentials(_ request: CredentialListRequest) throws -> CredentialListResponse {
        var skip = request.skip
        var limit = request.limit

        if (skip! < 0) {
            skip = 0
        }

        if (limit! <= 0) {
            limit = CredentialList.DEFAULT_SIZE
        }
        else if (limit! >= CredentialList.MAX_SIZE) {
            limit = CredentialList.MAX_SIZE
        }

        _ = stat.listCredentials()
        if (skip == 0) {
            _ = stat.listCredentialsWithoutSkip()
        }
        else {
            _ = stat.listCredentialsWithSkip()
        }

        if (limit == CredentialList.DEFAULT_SIZE) {
            _ = stat.listCredentialsWithDefaultLimit()
        }
        else if(limit == CredentialList.MAX_SIZE) {
            _ = stat.listCredentialsWithMaxLimit()
        }
        else {
            _ = stat.listCredentialsWithUserLimit()
        }

        Log.d(TAG, "Listing credentials \(String(describing: request.did)) \(String(describing: skip))/\(String(describing: limit))...")

        let cl = CredentialList(request.did!)
        for tx in vctxs {
            
            if (tx.request.operation == IDChainRequestOperation.REVOKE) {
                continue
            }

            if tx.request.credential?.subject?.did == request.did {
                if (skip! - 1 > 0) {
                    continue
                }

                if (limit! - 1 > 0) {
                    cl.appendCredentialId(tx.id!)
                }
                else {
                    break
                }
            }
        }

        Log.i(TAG, "List credentials \(String(describing: request.did)) total \(cl.count)")
        return CredentialListResponse(request.requestId, cl)
    }
    
    /**
     * Start the simulated ID chain begin to serve the HTTP requests.
     *
     * <p>
     * NOTICE: The start() method is a non-block call. the method will return
     * immediately, the HTTP server will run in background threads. if you want
     * to block current thread until the HTTP server shutdown graceful,
     * use run() instead of start().
     * </p>
     *
     * @throws IOException if there is a error when start the HTTP server
     */
    func start() {

        httpServer["/resolve"] = { [self] in
            
            do {
                let json: Dictionary = try JSONSerialization.jsonObject(with: Data($0.body), options: []) as! Dictionary<String, Any>
                let method: String = json["method"] as! String
                print(method)
                switch method {
                case DIDResolveRequest.METHOD_NAME:
                    let drr: DIDResolveRequest  = DIDResolveRequest(json["id"] as! String)
                    print("json[\"params\"] == \(json["params"])")
                    let params: [Dictionary] = json["params"] as! [Dictionary<String, Any>]
                    try! drr.setParameters(params[0]["did"] as! String, false)
                    let response = try! resolveDid(drr)
                    
                    var result: Dictionary<String, Any> = [:]
                    result["id"] = response.responseId
                    result["jsonrpc"] = "2.0"
                    let bio = response.result as! DIDBiography
                    var r1: Dictionary<String, Any> = [:]
                    r1 = bio.serialize().toDictionary()
                    result["result"] = r1
                    let data = try JSONSerialization.data(withJSONObject: result, options: JSONSerialization.WritingOptions.prettyPrinted)
                    return HttpResponse.ok(HttpResponseBody.data(data, contentType: "application/json"))
                    
                case CredentialResolveRequest.METHOD_NAME:
                    let crr = try CredentialResolveRequest.deserialize(json)
                    let response = try resolveCredential(crr)
                    var result: Dictionary<String, Any> = [:]
                    result["id"] = response.responseId
                    result["jsonrpc"] = "2.0"
                    let bio = response.result as! CredentialBiography

                    result["result"] = bio.serialize().toDictionary()
                    let data = try JSONSerialization.data(withJSONObject: result, options: JSONSerialization.WritingOptions.prettyPrinted)
                    return HttpResponse.ok(HttpResponseBody.data(data, contentType: "application/json"))
                default: break
                    
                }
            } catch {
                print("erroMsg")
            }
            
            return HttpResponse.ok(.htmlBody("You 111111 for"))
        }
        
        httpServer["/idtx"] = { [self] in
            do {
                
                let json: Dictionary = try JSONSerialization.jsonObject(with: Data($0.body), options: []) as! Dictionary<String, Any>
                print(json)
                let header: Dictionary = json["header"] as! Dictionary<String, Any>
                let specification: String = header["specification"]! as! String
                switch specification {
                case IDChainRequest.DID_SPECIFICATION:
                    let req: DIDRequest = try DIDRequest.deserialize(JsonNode(json))
                    try createDidTransaction(req)
                    return HttpResponse.accepted
                    
                case IDChainRequest.CREDENTIAL_SPECIFICATION:
                    let cr = try CredentialRequest.deserialize(json)
                    try createCredentialTransaction(cr)
                    return HttpResponse.accepted
                default: break
                    
                }
            } catch {
                print("erroMsg")
            }
            // TODO delete
            return HttpResponse.ok(.htmlBody("You 111111 for"))
        }
        
        httpServer["/reset"] = {
            .ok(.htmlBody("You 111111 for \($0)"))
        }
        
        httpServer["/shutdown"] = {
            .ok(.htmlBody("You 111111 for \($0)"))
        }
        
        try! httpServer.start(in_port_t(DEFAULT_PORT), forceIPv4: true)

    }
    
    func run() {
        self.start()
    }
    
    func stop() {
//        self.server.stop()
    }
    
    func getAdapter() -> DIDAdapter {
        return SimulatedIDChainAdapter("http://localhost:\(DEFAULT_PORT)/")
    }
}

class Statistics {
    // General
    var _invalidDidRequest = Int()
    var _invalidDidRequestWithInvalidDocument = Int()
    var _invalidDidRequestOnDeactivatedDid = Int()
    var _invalidCredentialRequest = Int()

    // DID transactions
    var _createDid = Int()
    var _createDidAlreadyExists = Int()
    var _createCustomizedDid = Int()
    var _createCustomizedDidWithSingleController = Int()
    var _createCustomizedDidWithMultiController = Int()
    var _createCustomizedDidWithMultisig = Int()
    var _createCustomizedDidWithSinglesig = Int()

    var _updateDid = Int()
    var _updateDidNotExists = Int()
    var _updateDidWithWrongTxid = Int()
    var _updateCustomizedDid = Int()
    var _updateCustomizedDidWithSingleController = Int()
    var _updateCustomizedDidWithMultiController = Int()
    var _updateCustomizedDidWithMultisig = Int()
    var _updateCustomizedDidWithSinglesig = Int()
    var _updateCustomizedDidWithControllersChanged = Int()

    var _transferDid = Int()
    var _transferDidNotExists = Int()
    var _transferDidWithInvalidTicket = Int()
    var _transferDidWithInvalidTicketId = Int()
    var _transferDidWithInvalidTicketTo = Int()
    var _transferDidWithInvalidController = Int()

    var _deactivateDid = Int()
    var _deactivateDidNotExists = Int()
    var _deactivateDidByOwner = Int()
    var _deactivateDidByAuthroization = Int()

    // Resolve DID
    var _resolveDid = Int()
    var _resolveDidWithAll = Int()
    var _resolveDidNonAll = Int()
    var _resolveNonExistsDid = Int()
    var _resolveDeactivatedDid = Int()

    // Credential transactions
    var _declareCredential = Int()
    var _declareCredentialAlreadyDeclared = Int()
    var _declareCredentialAlreadyRevoked = Int()
    var _revokeCredential = Int()
    var _revokeCredentialAlreadyDeclared = Int()
    var _revokeCredentialAlreadyRevoked = Int()
    var _revokeCredentialNotDeclared = Int()

    // Resolve credential
    var _resolveCredential = Int()
    var _resolveCredentialWithIssuer = Int()
    var _resolveCredentialWithoutIssuer = Int()
    var _resolveNonExistsCredential = Int()
    var _resolveRevokedCredential = Int()

    // List credential
    var _listCredentials = Int()
    var _listCredentialsWithoutSkip = Int()
    var _listCredentialsWithSkip = Int()
    var _listCredentialsWithDefaultLimit = Int()
    var _listCredentialsWithMaxLimit = Int()
    var _listCredentialsWithUserLimit = Int()
    
    func reset() {
        
    }
    
    func invalidDidRequest() -> Int {
        return _invalidDidRequest + 1
    }
    
    func invalidDidRequestWithInvalidDocument() -> Int {
        return _invalidDidRequestWithInvalidDocument + 1
    }
    
    func invalidDidRequestOnDeactivatedDid() -> Int {
        return _invalidDidRequestOnDeactivatedDid + 1
    }
    
    func invalidCredentialRequest() -> Int {
        return _invalidCredentialRequest + 1
    }
    
    func createDid() -> Int {
        return _createDid + 1
    }
    
    func createDidAlreadyExists() -> Int {
        return _createDidAlreadyExists + 1
    }
    
    func createCustomizedDid() -> Int {
        return _createCustomizedDid + 1
    }
    
    func createCustomizedDidWithSingleController() -> Int {
        return _createCustomizedDidWithSingleController + 1
    }
    
    func createCustomizedDidWithMultiController() -> Int {
        return _createCustomizedDidWithMultiController + 1
    }
    
    func createCustomizedDidWithMultisig() -> Int {
        return _createCustomizedDidWithMultisig + 1
    }
    
    func createCustomizedDidWithSinglesig() -> Int {
        return _createCustomizedDidWithSinglesig + 1
    }
    
    func updateDid() -> Int {
        return _updateDid + 1
    }
    
    func updateDidNotExists() -> Int {
        return _updateDidNotExists + 1
    }
    
    func updateDidWithWrongTxid() -> Int {
        return _updateDidWithWrongTxid + 1
    }
    
    func updateCustomizedDid() -> Int {
        return _updateCustomizedDid + 1
    }
    
    func updateCustomizedDidWithSingleController() -> Int {
        return _updateCustomizedDidWithSingleController + 1
    }
    
    func updateCustomizedDidWithMultiController() -> Int {
        return _updateCustomizedDidWithMultiController + 1
    }
    
    func updateCustomizedDidWithMultisig() -> Int {
        return _updateCustomizedDidWithMultisig + 1
    }
    
    func updateCustomizedDidWithSinglesig() -> Int {
        return _updateCustomizedDidWithSinglesig + 1
    }
    
    func updateCustomizedDidWithControllersChanged() -> Int {
        return _updateCustomizedDidWithControllersChanged + 1
    }
    
    func transferDid() -> Int {
        return _transferDid + 1
    }
    func transferDidNotExists() -> Int {
        return _transferDidNotExists + 1
    }
    func transferDidWithInvalidTicket() -> Int {
        return _transferDidWithInvalidTicket + 1
    }
    func transferDidWithInvalidTicketId() -> Int {
        return _transferDidWithInvalidTicketId + 1
    }
    func transferDidWithInvalidTicketTo() -> Int {
        return _transferDidWithInvalidTicketTo + 1
    }
    func transferDidWithInvalidController() -> Int {
        return _transferDidWithInvalidController + 1
    }
    func deactivateDid() -> Int {
        return _deactivateDid + 1
    }
    func deactivateDidNotExists() -> Int {
        return _deactivateDidNotExists + 1
    }
    func deactivateDidByOwner() -> Int {
        return _deactivateDidByOwner + 1
    }
    
    func deactivateDidByAuthroization() -> Int {
        return _deactivateDidByAuthroization + 1
    }
    func resolveDid() -> Int {
        return _resolveDid + 1
    }
    func resolveDidWithAll() -> Int {
        return _resolveDidWithAll + 1
    }
    func resolveDidNonAll() -> Int {
        return _resolveDidNonAll + 1
    }
    func resolveNonExistsDid() -> Int {
        return _resolveNonExistsDid + 1
    }
    func resolveDeactivatedDid() -> Int {
        return _resolveDeactivatedDid + 1
    }
    func declareCredential() -> Int {
        return _declareCredential + 1
    }
    func declareCredentialAlreadyRevoked() -> Int {
        return _declareCredentialAlreadyRevoked + 1
    }
    func declareCredentialAlreadyDeclared() -> Int {
        return _declareCredentialAlreadyDeclared + 1
    }
    func revokeCredential() -> Int {
        return _revokeCredential + 1
    }
    
    func revokeCredentialAlreadyRevoked() -> Int {
        return _revokeCredentialAlreadyRevoked + 1
    }
    func revokeCredentialAlreadyDeclared() -> Int {
        return _revokeCredentialAlreadyDeclared + 1
    }
    func revokeCredentialNotDeclared() -> Int {
        return _revokeCredentialNotDeclared + 1
    }
    func resolveCredential() -> Int {
        return _resolveCredential + 1
    }
    func resolveCredentialWithIssuer() -> Int {
        return _resolveCredentialWithIssuer + 1
    }
    func resolveCredentialWithoutIssuer() -> Int {
        return _resolveCredentialWithoutIssuer + 1
    }
    func resolveNonExistsCredential() -> Int {
        return _resolveNonExistsCredential + 1
    }
    func resolveRevokedCredential() -> Int {
        return _resolveRevokedCredential + 1
    }
    func listCredentials() -> Int {
        return _listCredentials + 1
    }
    func listCredentialsWithoutSkip() -> Int {
        return _listCredentialsWithoutSkip + 1
    }
    func listCredentialsWithSkip() -> Int {
        return _listCredentialsWithSkip + 1
    }
    
    func listCredentialsWithDefaultLimit() -> Int {
        return _listCredentialsWithDefaultLimit + 1
    }
    func listCredentialsWithMaxLimit() -> Int {
        return _listCredentialsWithMaxLimit + 1
    }
    func listCredentialsWithUserLimit() -> Int {
        return _listCredentialsWithUserLimit + 1
    }

    func toString() -> String {
        var str = ""
        str.append("========================================================\n")
        str.append("+ General: \n")
        str.append("  * Invalid DID request:")
        str.append("\(_invalidDidRequest)\n")
        str.append("  * Invalid DID request(invalid doc):")
        str.append("\(_invalidDidRequestWithInvalidDocument)\n")
        str.append("  * Invalid DID request(deactivated):")
        str.append("\(_invalidDidRequestOnDeactivatedDid)\n")
        str.append("  * Invalid Credential request:")
        str.append("\(_invalidCredentialRequest)\n")
        str.append("+ Create DID:")
        str.append("\(_createDid)\n")
        str.append("  * Create DID(already exists):")
        str.append("\(_createDidAlreadyExists)\n")
        str.append("  - Create customized DID:")
        str.append("\(_createCustomizedDid)\n")
        str.append("  - Create customized DID(SingleCtrl):")
        str.append("\(_createCustomizedDidWithSingleController)\n")
        str.append("  - Create customized DID(MultiCtrl):")
        str.append("\(_createCustomizedDidWithMultiController)\n")
        str.append("  - Create customized DID(SingleSig:")
        str.append("\(_createCustomizedDidWithSinglesig)\n")
        str.append("  - Create customized DID(MultiSig):")
        str.append("\(_createCustomizedDidWithMultisig)\n")
        str.append("+ Update DID: ")
        str.append("\(_updateDid)\n")
        str.append("  * Update DID(not exists):")
        str.append("\(_updateDidNotExists)\n")
        str.append("  * Update DID(wrong txid):")
        str.append("\(_updateDidWithWrongTxid)\n")
        str.append("  - Update customized DID:")
        str.append("\(_updateCustomizedDid)\n")
        str.append("  - Update customized DID(SingleCtrl):")
        str.append("\(_updateCustomizedDidWithSingleController)\n")
        str.append("  - Update customized DID(MultiCtrl):")
        str.append("\(_updateCustomizedDidWithMultiController)\n")
        str.append("  - Update customized DID(SingleSig:")
        str.append("\(_updateCustomizedDidWithSinglesig)\n")
        str.append("  - Update customized DID(MultiSig):")
        str.append("\(_updateCustomizedDidWithMultisig)\n")
        str.append("  * Update customized DID(controllers changed):")
        str.append("\(_updateCustomizedDidWithControllersChanged)\n")
        str.append("+ Transfer DID:")
        str.append("\(_transferDid)\n")
        str.append("  * Transfer DID(not exists):")
        str.append("\(_transferDidNotExists)\n")
        str.append("  * Transfer DID(invalid ticket):")
        str.append("\(_transferDidWithInvalidTicket)\n")
        str.append("  * Transfer DID(invalid ticket id:")
        str.append("\(_transferDidWithInvalidTicketId)\n")
        str.append("  * Transfer DID(invalid ticket to):")
        str.append("\(_transferDidWithInvalidTicketTo)\n")
        str.append("  * Transfer DID(invalid controller):")
        str.append("\(_transferDidWithInvalidController)\n")
        str.append("+ Deactivate DID:")
        str.append("\(_deactivateDid)\n")
        str.append("  * Deactivate DID(not exists):")
        str.append("\(_deactivateDidNotExists)\n")
        str.append("  - Deactivate DID(owner):")
        str.append("\(_deactivateDidByOwner)\n")
        str.append("  - Deactivate DID(authorization):")
        str.append("\(_deactivateDidByAuthroization)\n")
        
        str.append("+ Resolve DID:")
        str.append("\(_resolveDid)\n")
        
        str.append("  - Resolve DID(all=true):")
        str.append("\(_resolveDidWithAll)\n")
        str.append("  - Resolve DID(all=false):")
        str.append("\(_resolveDidNonAll)\n")
        str.append("  - Resolve non-exists DID:")
        str.append("\(_resolveNonExistsDid)\n")
        str.append("  - Resolve deactivated DID:")
        str.append("\(_resolveDeactivatedDid)\n")
        str.append("+ Declare credential:")
        str.append("\(_declareCredential)\n")
        str.append("  * Declare credential(declared):")
        str.append("\(_declareCredentialAlreadyDeclared)\n")
        str.append("  * Declare credential(revoked):")
        str.append("\(_declareCredentialAlreadyRevoked)\n")
        str.append("+ Revoke credential:")
        str.append("\(_revokeCredential)\n")
        str.append("  - Revoke credential(declared):")
        str.append("\(_revokeCredentialAlreadyDeclared)\n")
        str.append("  - Revoke credential(revoked):")
        str.append("\(_revokeCredentialAlreadyRevoked)\n")
        str.append("  - Revoke credential(not declared):")
        str.append("\(_revokeCredentialNotDeclared)\n")
        str.append("+ Resolve credential:")
        str.append("\(_resolveCredential)\n")
        str.append("  - Resolve credential(withIssuer):")
        str.append("\(_resolveCredentialWithIssuer)\n")
        str.append("  - Resolve credential(withoutIssuer):")
        str.append("\(_resolveCredentialWithoutIssuer)\n")
        str.append("  - Resolve non-exists credential:")
        str.append("\(_resolveNonExistsCredential)\n")
        str.append("  - Resolve revoked credential:")
        str.append("\(_resolveRevokedCredential)\n")
        str.append("+ List credentials:")
        str.append("\(_listCredentials)\n")
        str.append("  - List credential(withoutSkip):")
        str.append("\(_listCredentialsWithoutSkip)\n")
        str.append("  - list credential(withSkip):")
        str.append("\(_listCredentialsWithSkip)\n")
        str.append("  - list credential(withDefaultLimit):")
        str.append("\(_listCredentialsWithDefaultLimit)\n")
        str.append("  - list credential(withMaxLimit):")
        str.append("\(_listCredentialsWithMaxLimit)\n")
        str.append("  - list credential(withUserLimit):")
        str.append("\(_listCredentialsWithUserLimit)\n")
        str.append("========================================================\n")
        
        return str
    }
}
