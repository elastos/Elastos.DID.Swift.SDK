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

public class DIDResolveRequest: ResolveRequest {
    private let PARAMETER_DID = "did"
    private let PARAMETER_ALL = "all"
    public static let METHOD_NAME = "resolvedid"
    private var _params: DIDParameters?

    init(_ requestId: String) {
        super.init(requestId, DIDResolveRequest.METHOD_NAME)
    }
    
    public var params: DIDParameters? {
        return _params
    }
    
    public func setParameters(_ did: DID, _ all: Bool) {
        _params = DIDParameters(did, all)
    }
    
    public func setParameters(_ did: String, _ all: Bool) throws {
        _params = try DIDParameters(DID.valueOf(did)!, all)
    }
    
     public var did: DID? {
       return params?.did
    }
    
    public var isResolveAll: Bool? {
        return params?.all
    }
    
    public override var description: String {
        
        return "TODO:"
    }
    
    override func serialize(_ force: Bool) throws -> String {
        // TODO:
        return "todo"
    }
}


public class DIDParameters: NSObject {
    private var _did: DID
    private var _all: Bool
    
    public init(_ did: DID, _ all: Bool) {
        self._did = did;
        self._all = all;
    }
    
    public init(_ did: DID) {
        self._did  = did
        self._all = false
    }
    
    public var did: DID {
        return _did
    }
    
    public var all: Bool {
        return _all
    }
    
    public override var hash: Int {
        return _did.hash + _all.hashValue
    }
    
    public func equalsTo(_ other: DIDParameters) -> Bool {
        return _did == other._did
    }
    
    public override func isEqual(_ object: Any?) -> Bool {
        if object is DIDParameters {
            return equalsTo(object as! DIDParameters)
        }
        else {
            return false
        }
    }
}

