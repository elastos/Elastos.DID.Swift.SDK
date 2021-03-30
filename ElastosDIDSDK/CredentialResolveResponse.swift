
import Foundation

/// The credential resolve response object.
public class CredentialResolveResponse: ResolveResponse {
    init() {}
    
    init(_ responseId: String, _ result: CredentialBiography) {
        super.init(responseId, result)
    }
    
    override init(_ responseId: String, _ code: Int, _ message: String) {
        super.init(responseId, code, message)
    }
}
