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

public class DefaultDIDAdapter: DIDAdapter {
    private let TAG = NSStringFromClass(DefaultDIDAdapter.self)
    let MAINNET_RESOLVER = "http://api.elastos.io:20606"
    let TESTNET_RESOLVER = "http://api.elastos.io:21606"
    private var resolver: String
    
    /// Set default resolver according to specified url.
    /// - Parameter resolver: the resolver url string
    public init(_ resolver: String) {
        switch resolver.lowercased() {
        case "mainnet":
            self.resolver = MAINNET_RESOLVER
            break
        case "testnet":
            self.resolver = TESTNET_RESOLVER
            break
        default:
            self.resolver = resolver
            break
        }
    }
    
    func performRequest(_ urlString: String, _ body: String) throws -> Data {
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
        
        return result!
    }
    
    public func resolve(_ request: String) throws -> Data {
        return try performRequest(resolver, request)
    }
    
    public func createIdTransaction(_ payload: String, _ memo: String?) throws {
     
        throw DIDError.CheckedError.DIDBackendError.UnsupportedOperationError("Not implemented")
    }
}
