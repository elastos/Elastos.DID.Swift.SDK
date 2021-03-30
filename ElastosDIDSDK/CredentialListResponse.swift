
import Foundation

public class CredentialListResponse: ResolveResponse{
    init() {}
    
    init(_ responseId: String, _ result: CredentialList) {
        super.init(responseId, result)
    }
    
    override init(_ responseId: String, _ code: Int, _ message: String) {
        super.init(responseId, code, message)
    }
}
