import Foundation

public class DIDBackend: NSObject {
    
    private let ID: String = "id"
    private let RESULT: String = "result"
    private let ERROR: String = "error"
    private let ERROR_CODE: String = "code"
    private let ERROR_MESSAGE: String = "message"
    
    private let DEFAULT_TTL: Int = 24 * 60 * 60 * 1000
    private var ttl: Int // milliseconds
    private static var instance: DIDBackend?
    public var adapter: DIDAdapter!
    
    init(_ adapter: DIDAdapter){
        self.adapter = adapter
        self.ttl = DEFAULT_TTL
        super.init()
    }
    
    public static func creatInstance(_ adapter: DIDAdapter) {
        if instance != nil {
            return
        }
        instance = DIDBackend(adapter)
    }
    
    public static func shareInstance() -> DIDBackend {
        return instance!
    }
    
    // Time to live in minutes
    public func setTTL(_ ttl: Int) {
        self.ttl = ttl > 0 ? (ttl * 60 * 1000) : 0
    }
    
    public func getTTL() -> Int {
        return ttl != 0 ? (ttl / 60 / 1000) : 0
    }
    
    func generateRequestId() -> String {
        var str: String = ""
        while str.count < 16 {
            let random: Int = Int.randomCustom(min: 0, max: 16)
            let randomStr: String = Int.decTohex(number: random)
            str.append(randomStr)
        }
        return str
    }
    
    func resolveFromBackend(_ did: DID) throws -> ResolveResult {
        let requestId = generateRequestId()
        
        let json = try adapter.resolve(requestId, did.description, false)
        guard json != nil else {
            throw DIDResolveError.failue("Unknown error.")
        }
        var jsonString = json!.replacingOccurrences(of: " ", with: "")
        jsonString = jsonString.replacingOccurrences(of: "\n", with: "")
        let resultJson = JsonHelper.handleString(jsonString) as! OrderedDictionary<String, Any>
        let result: OrderedDictionary<String, Any> = resultJson[RESULT] as! OrderedDictionary<String, Any>

        guard result.count != 0 else {
            throw DIDResolveError.failue("Resolve DID error .")
        }
        // Check response id, should equals requestId
        let id = resultJson[ID] as? String
        if id == nil || id == "" || id != requestId {
            throw DIDResolveError.failue("Missmatched resolve result with request.")
        }
        let rr: ResolveResult = try ResolveResult.fromJson(result)
        if rr.status != ResolveResult.STATUS_NOT_FOUND {
            try ResolverCache.store(rr)
        }
        return rr
        /*
         // Check response id, should equals requestId
         JsonNode result = node.get(RESULT);
         if (result == null || result.isNull()) {
             JsonNode error = node.get(ERROR);
             throw new DIDResolveException("Resolve DID error("
                     + error.get(ERROR_CODE).longValue() + "): "
                     + error.get(ERROR_MESSAGE).textValue());
         }

         ResolveResult rr = ResolveResult.fromJson(result);

         if (rr.getStatus() != ResolveResult.STATUS_NOT_FOUND) {
             try {
                 ResolverCache.store(rr);
             } catch (IOException e) {
                 System.out.println("!!! Cache resolved resolved result error: "
                         + e.getMessage());
             }
         }

         return rr;
         */
    }
    
    func resolve(_ did: DID, _ force: Bool) throws -> DIDDocument? {
        var rr: ResolveResult?
        if !force {
            rr = try ResolverCache.load(did, ttl)
        }
        if (rr == nil) {
            rr = try resolveFromBackend(did)
        }
        switch rr!.status {
        case ResolveResult.STATUS_EXPIRED: do {
            throw DIDExpiredError.failue("")
            }
        case ResolveResult.STATUS_DEACTIVATED: do {
            throw DIDDeactivatedError.failue("")
            }
        case ResolveResult.STATUS_NOT_FOUND: do {
            return nil
            }
        default:
            
            let ti: IDTransactionInfo = rr!.getTransactionInfo(0)!
            let doc: DIDDocument = ti.request.doc!
            let meta: DIDMeta = DIDMeta()
            meta.transactionId = ti.transactionId
            meta.updated = ti.timestamp
            doc.meta = meta
            return doc;
        }
    }
    
    public func resolve(_ did: DID) throws -> DIDDocument? {
        return try resolve(did, false)
    }
    
    func create(_ doc: DIDDocument, _ signKey: DIDURL, _ storepass: String) throws -> String? {
        do {
            let request: IDChainRequest = try IDChainRequest.create(doc, signKey, storepass)
            let jsonString: String = request.toJson(true)
            
            return try adapter.createIdTransaction(jsonString, nil)
        } catch  {
            throw DIDError.failue("Create ID transaction error: \(error.localizedDescription).")
        }
    }
    
    func update(_ doc: DIDDocument, _ previousTxid: String, _ signKey: DIDURL, _ storepass: String) throws -> String? {
        do {
            let request: IDChainRequest = try IDChainRequest.update(doc, previousTxid, signKey, storepass)
            let jsonStr: String = request.toJson(true)
            return try adapter.createIdTransaction(jsonStr, nil)
        } catch {
            throw  DIDError.failue("Create ID transaction error.")
        }
    }
    
    public func deactivate(_ did: DID, _ signKey: DIDURL, _ storepass: String) throws -> String? {
        do {
            let request: IDChainRequest = try IDChainRequest.deactivate(did, signKey, storepass)
            let jsonStr: String = request.toJson(true)
            return try adapter.createIdTransaction(jsonStr, nil)
        } catch {
            throw  DIDError.failue("Deactivate ID transaction error: \(error.localizedDescription).")
        }
    }
    
    /*
     public func resolve(_ did: DID) throws -> DIDDocument? {
     do {
     let res = try adapter.resolve(did.methodSpecificId)
     guard res != nil else {
     return nil
     }
     var jsonString = res!.replacingOccurrences(of: " ", with: "")
     jsonString = jsonString.replacingOccurrences(of: "\n", with: "")
     let ordDic = JsonHelper.handleString(jsonString) as! OrderedDictionary<String, Any>
     let result = ordDic["result"] as! Array<Any>
     
     if (result.count == 0) {
     return nil
     }
     let re = result[0] as! OrderedDictionary<String, Any>
     let request: IDChainRequest = try IDChainRequest.fromJson(re)
     if try !request.isValid() {
     throw  DIDError.failue("Signature verify failed.")
     }
     return request.doc
     } catch {
     throw DIDError.failue("Resolve DID error: \(error.localizedDescription)")
     }
     }
     */
    
}