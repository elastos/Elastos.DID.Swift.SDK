
import Foundation

public class CredentialList: ResolveResult {
    private let DID = "did"
    private let CREDENTIALS = "credentials"

    private let DEFAULT_SIZE = 128
    private let MAX_SIZE = 512

    private var _did: DID
    private var _credentialIds: [DIDURL] = [ ]
    
    init(_ did: DID) {
        self._did = did
    }
    
    public var did: DID {
        return _did
    }
    
    public var count: Int {
        return credentialIds.count
    }
    
    public func getCredentialId(_ index: Int) -> DIDURL {
        return credentialIds[index]
    }
    
    public var credentialIds: [DIDURL] {
        return _credentialIds
    }
    
    public func appendCredentialId(_ id: DIDURL) {
        _credentialIds.append(id)
    }
    
    override func sanitize() throws {
        
    }
}
