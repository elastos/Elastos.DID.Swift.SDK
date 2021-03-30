

import Foundation

public class CredentialResolveRequest: ResolveRequest{
    private let PARAMETER_ID = "id"
    private let PARAMETER_ISSUER = "issuer"
    private let METHOD_NAME = "resolvecredential"

    private var _params: CredentialParameters?
    
    init(_ requestId: String) {
        super.init(requestId, METHOD_NAME)
    }
    
    public var params: CredentialParameters? {
        return _params
    }
    
    public func setParameters(_ id: DIDURL, _ issuer: DID) {
        _params = CredentialParameters(id, issuer)
    }
    
    public func setParameters(_ id: DIDURL) {
        _params = CredentialParameters(id)
    }
    
    public func setParameters(_ id: String, _ issuer: String) throws {
        _params = try CredentialParameters(DIDURL.valueOf(id), DID.valueOf(issuer)!)
    }
    
    public func setParameters(_ id: String) throws {
        _params = try CredentialParameters(DIDURL.valueOf(id))
    }
    
    public var id: DIDURL? {
        return params?.id
    }
    
    public var issuer: DID? {
        return params?.issuer
    }
    
    public override var description: String {
        
        return "TODO:"
    }
}


public class CredentialParameters: NSObject {
    private var _id: DIDURL
    private var _issuer: DID?
    
    public init(_ id: DIDURL) {
        self._id = id
    }
    
    public init(_ id: DIDURL, _ issuer: DID) {
        self._id  = id
        self._issuer = issuer
    }
    
    public var id: DIDURL {
        return _id
    }
    
    public var issuer: DID? {
        return _issuer
    }
    
    public override var hash: Int {
        return _id.hash + (_issuer != nil ? _issuer!.hashValue : 0)
    }

    public func equalsTo(_ other: CredentialParameters) -> Bool {
        return _id == other._id
    }
    
    public override func isEqual(_ object: Any?) -> Bool {
        if object is CredentialParameters {
            return equalsTo(object as! CredentialParameters)
        }
        else {
            return false
        }
    }
}
