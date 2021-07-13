

import Foundation

class SimulatedIDChainAdapter: DefaultDIDAdapter {
    private var idtxEndpoint: String = ""
    
    
    override init(_ endpoint: String) {
        super.init(endpoint + "resolve")
        idtxEndpoint = endpoint + "idtx"
    }
    
    override func createIdTransaction(_ payload: String, _ memo: String?) throws {
        let data = try performRequest(idtxEndpoint, payload)
        print("createIdTransaction: \(data)")
    }
}
