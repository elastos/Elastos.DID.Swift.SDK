

import Foundation


public class ResolveRequest: NSObject {
  
    private let ID = "id"
    private let METHOD = "method"
    private let PARAMETERS = "params"

    private var _requestId: String
    private var _method: String
    private var _params: String?


    init(_ requestId: String, _ method: String) {
        self._requestId = requestId
        self._method = method
    }
    
    public var requestId: String {
        return _requestId
    }
    
    public var method: String {
        return _method
    }
    
    public override var hash: Int {
        return method.hash  + (_params != nil ? _params!.hash : 0)
    }
    
    public func equalsTo(_ other: ResolveRequest) -> Bool {
        return hash == other.hash
    }
    
    public override func isEqual(_ object: Any?) -> Bool {
        if object is ResolveRequest {
            return equalsTo(object as! ResolveRequest)
        }
        else {
            return false
        }
    }
    
    public class func parse(_ content: JsonNode) -> ResolveRequest {
        return ResolveRequest("TODO:", "TODO:")// TODO:
    }
}
