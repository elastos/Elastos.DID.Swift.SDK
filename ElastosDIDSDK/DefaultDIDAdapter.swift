/*
* Copyright (c) 2021 Elastos Foundation
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

import Foundation

/// The default DIDAdapter implementation for the Elastos ID chain.
///
/// This adapter only provided resolve capability, it means you can not publish
/// ID transactions with this adapter. The sub class can implement the
/// createIdTransaction method to support publish capability.
open class DefaultDIDAdapter: DIDAdapter {
    private let TAG = NSStringFromClass(DefaultDIDAdapter.self)
    let MAINNET_RPC_ENDPOINTS = ["https://api.elastos.io/eid", "https://api.trinity-tech.io/eid"]
    let TESTNET_RPC_ENDPOINTS = ["https://api-testnet.elastos.io/eid", "https://api-testnet.trinity-tech.io/eid"]
    private var rpcEndpoint: String!
    private var endpoints: [String]?
    
    /// Create a DefaultDIDAdapter instance with given resolver endpoint.
    /// - Parameter resolver: the resolver url string
    public init(resolver: String) {
        var resolver = resolver
        switch resolver.lowercased() {
        case "mainnet":
            resolver = MAINNET_RPC_ENDPOINTS[0]
            endpoints = MAINNET_RPC_ENDPOINTS
            break
        case "testnet":
            resolver = TESTNET_RPC_ENDPOINTS[0]
            endpoints = TESTNET_RPC_ENDPOINTS
            break
        default:
            break
        }
        
        if (endpoints != nil) {
            checkNetwork(endpoints!)
        }
    }

    /// Create a DefaultDIDAdapter instance with given resolver endpoint.
    /// - Parameter resolver: resolver the resolver URL object
    public init(_ rpcEndpoint: String) {
        self.rpcEndpoint = rpcEndpoint
    }
    
    private func checkEndpoint(_ endpoint: String) throws -> CheckResult {
        Log.i(TAG, "Checking the resolver ", endpoint.description)
        let id = DateFormatter.getTimeStamp(Date())
        let json = ["id": id, "jsonrpc": "2.0", "method": "eth_blockNumber"] as [String : Any]
        do {
            let body = json.toJsonString()
            let start: Int = DateFormatter.getTimeStamp(Date())
            let resultData = try performRequest(endpoint, body!)
            let result: [String: Any] = try resultData!.dataToDictionary()
            let latency = DateFormatter.getTimeStamp(Date()) - start
            let resultId = result["id"] as! Int
            if resultId != id {
                throw DIDError.NetWorkError("Invalid JSON RPC id.")
            }
            
            var n = result["result"] as! String
            if (n.hasPrefix("0x")) {
                n = n[2..<n.count]
            }
            let blockNumber = String.changeToInt(num: n)
            
            Log.i(TAG, "Checking the resolver ", "\(endpoint)", "...latency: ", "\(latency)", "lastBlock: ", "\(n)")
            return CheckResult(endpoint, latency, blockNumber)
        } catch {
            Log.i(TAG, "Checking the resolver ", "\(endpoint)", "...error")
            
            return CheckResult(endpoint)
        }
    }
    
    private func checkNetwork(_ endpoints: [String]) {
        var results: [CheckResult] = [ ]
        endpoints.forEach { endPoint in
            do {
                let result = try checkEndpoint(endPoint)
                results.append(result)
            }
            catch {
            }
        }
        if (results.count > 0) {
            let best = results[0]
            if (best.available()) {
                self.rpcEndpoint = best.endpoint
                Log.i(TAG, "Update resolver to ", rpcEndpoint.description)
            }
        }
    }
    
    /// Perform a HTTP POST request with given request body to the url.
    /// - Parameters:
    ///   - urlString: the target HTTP endpoint
    ///   - body: the request body
    /// - Returns: an input data object of the response body
    public func performRequest(_ urlString: String, _ body: String) throws -> Data? {
        let url = URL(string: urlString)!
        var request = URLRequest.init(url: url, cachePolicy: .useProtocolCachePolicy, timeoutInterval: 60)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let parameters = body.toDictionary()
        request.httpBody = try JSONSerialization.data(withJSONObject: parameters as Any, options: .prettyPrinted)
        
        let semaphore = DispatchSemaphore(value: 0)
        var errDes: String?
        var result: Data?
        
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            guard let response = response as? HTTPURLResponse,
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
        
        return result
    }
    
    public func resolve(_ request: String) throws -> Data? {
        return try performRequest(rpcEndpoint, request)
    }
    
    open func createIdTransaction(_ payload: String, _ memo: String?) throws {
     
        throw DIDError.CheckedError.DIDBackendError.UnsupportedOperationError("Not implemented")
    }
}

class CheckResult: NSObject {
    private static let MAX_DIFF = 10

    public var endpoint: String
    public var latency: Int
    public var lastBlock: Int?

    public init(_ endpoint: String, _ latency: Int, _ lastBlock: Int) {
        self.endpoint = endpoint
        self.latency = latency
        self.lastBlock = lastBlock
    }

    public init(_ endpoint: String) {
        self.endpoint = endpoint
        self.latency = -1
    }

    public func compareTo(_ o: CheckResult) -> Int {
        if (o.latency < 0 && self.latency < 0) {
            return 0
        }
        if (o.latency < 0 || self.latency < 0) {
            return self.latency < 0 ? 1 : -1
        }
        let diff = (o.lastBlock != nil ? o.lastBlock! : 0) - (self.lastBlock != nil ? self.lastBlock! : 0)
        
        if abs(diff) > (CheckResult.MAX_DIFF) {
            return diff.signum()
        }
        if (self.latency == o.latency) {
            return diff.signum()
        } else {
            return self.latency - o.latency
        }
    }

    public func available() -> Bool {
        return self.latency >= 0
    }
}
