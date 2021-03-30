
import Foundation

public class CredentialTransaction: IDTransactionInfo {
    private var _request: CredentialRequest
    
    init(_ txid: String, _ timestamp: Date, _ request: CredentialRequest) {
        self._request = request
        super.init(txid, timestamp, request)
    }
    
    public override var request: CredentialRequest {
        return _request
    }
    
    public var id: DIDURL? {
        return request.id
    }
}

