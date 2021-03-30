
import Foundation

public class DIDResolveRequest: ResolveRequest {
    private let PARAMETER_DID = "did"
    private let PARAMETER_ALL = "all"
    private let METHOD_NAME = "resolvedid"
    private var _params: DIDParameters?

    init(_ requestId: String) {
        super.init(requestId, METHOD_NAME)
    }
    
    public var params: DIDParameters? {
        return _params
    }
    
    public func setParameters(_ did: DID, _ all: Bool) {
        _params = DIDParameters(did, all)
    }
    
    public func setParameters(_ did: String, _ all: Bool) throws {
        _params = try DIDParameters(DID.valueOf(did)!, all)
    }
    
     public var did: DID? {
       return params?.did
    }
    
    public var isResolveAll: Bool? {
        return params?.all
    }
    
    public override var description: String {
        
        return "TODO:"
    }
}


public class DIDParameters: NSObject {
    private var _did: DID
    private var _all: Bool
    
    public init(_ did: DID, _ all: Bool) {
        self._did = did;
        self._all = all;
    }
    
    public init(_ did: DID) {
        self._did  = did
        self._all = false
    }
    
    public var did: DID {
        return _did
    }
    
    public var all: Bool {
        return _all
    }
    
    public override var hash: Int {
        return _did.hash + _all.hashValue
    }
    
    public func equalsTo(_ other: DIDParameters) -> Bool {
        return _did == other._did
    }
    
    public override func isEqual(_ object: Any?) -> Bool {
        if object is DIDParameters {
            return equalsTo(object as! DIDParameters)
        }
        else {
            return false
        }
    }
}

