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

public class ResolveRequest: NSObject {
  
    let ID = "id"
    let METHOD = "method"
    let PARAMETERS = "params"

    private var _requestId: String
    private var _method: String
    private var _params: String?


    init(_ requestId: String, _ method: String) {
        self._requestId = requestId
        self._method = method
    }
    
    public var requestId: String {
        return _requestId
    }
    
    public var method: String {
        return _method
    }
    
    public override var hash: Int {
        return method.hash  + (_params != nil ? _params!.hash : 0)
    }
    
    public func equalsTo(_ other: ResolveRequest) -> Bool {
        return hash == other.hash
    }
    
    public override func isEqual(_ object: Any?) -> Bool {
        if object is ResolveRequest {
            return equalsTo(object as! ResolveRequest)
        }
        else {
            return false
        }
    }
    
    public class func parse(_ content: JsonNode) -> ResolveRequest {
        return ResolveRequest("TODO:", "TODO:")// TODO:
    }
    
    func serialize(_ force: Bool) -> String {
        // TODO:
        
        return "TODO:"
    }
}
