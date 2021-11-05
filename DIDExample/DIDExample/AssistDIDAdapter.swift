import UIKit
import ElastosDIDSDK

class AssistDIDAdapter: DefaultDIDAdapter {
    let MAINNET_RPC_ENDPOINT = "https://assist-restapi.tuum.tech/v2"
    let TESTNET_RPC_ENDPOINT = "https://assist-restapi-testnet.tuum.tech/v2"

    let API_KEY = "IdSFtQosmCwCB9NOLltkZrFy5VqtQn8QbxBKQoHPw7zp3w0hDOyOYjgL53DO3MDH"

    var assistRpcEndpoint: String

    init(network: String) {
        switch network.lowercased() {
        case "mainnet":
            assistRpcEndpoint = MAINNET_RPC_ENDPOINT
        default:
            assistRpcEndpoint = TESTNET_RPC_ENDPOINT
        }
        super.init(resolver: network)
    }
    
    override func createIdTransaction(_ payload: String, _ memo: String?) throws {
        
        if payload.isEmpty {
            throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalArgumentError("Invalid payload parameter")
        }
        let requestString = AssistDIDRequest(payload, memo).description()
        let url = URL(string: assistRpcEndpoint + "/didtx/create")
        var request = URLRequest.init(url: url!, cachePolicy: .useProtocolCachePolicy, timeoutInterval: 60)
        request.httpMethod = "POST"
        request.setValue(API_KEY, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let parameters = requestString.toDictionary()
        request.httpBody = try JSONSerialization.data(withJSONObject: parameters as Any, options: .prettyPrinted)
        
        let semaphore = DispatchSemaphore(value: 0)
        var errDes: String?
        var result: Data?
        
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            guard let _ = data,
                  let response = response as? HTTPURLResponse,
                  error == nil else { // check for fundamental networking error
                
                errDes = error.debugDescription
                semaphore.signal()
                return
            }
            guard (200 ... 299) ~= response.statusCode else { // check for http errors
                errDes = "Server eror (status code: \(response.statusCode)"
                semaphore.signal()
                return
            }
            
            result = data
            semaphore.signal()
        }
        
        task.resume()
        semaphore.wait()
        
        guard let _ = result else {
            throw DIDError.CheckedError.DIDBackendError.DIDResolveError(errDes ?? "Unknown error")
        }
        print("createIdTransaction result: ")
        print(String(data: result!, encoding: .utf8) as Any)
    }
    
}

extension String {
    func toDictionary() -> [String : Any] {
        
        var result = [String : Any]()
        guard !self.isEmpty else { return result }
        
        guard let dataSelf = self.data(using: .utf8) else {
            return result
        }
        
        if let dic = try? JSONSerialization.jsonObject(with: dataSelf,
                           options: []) as? [String : Any] {
            result = dic ?? [: ]
        }
        return result
    }
}
