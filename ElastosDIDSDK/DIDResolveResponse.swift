
import Foundation

public class DIDResolveResponse: ResolveResponse {
    
    init(_ responseId: String, _ result: DIDBiography) {
        super.init(responseId, result)
    }
    
    override init(_ responseId: String, _ code: Int, _ message: String) {
        super.init(responseId, code, message)
    }
}
