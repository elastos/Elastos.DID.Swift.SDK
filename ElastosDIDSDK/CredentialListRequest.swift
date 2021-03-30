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

public class CredentialListRequest: ResolveRequest {
    private let PARAMETER_DID = "did"
    private let PARAMETER_SKIP = "skip"
    private let PARAMETER_LIMIT = "limit"
    private let METHOD_NAME = "listcredentials"
    private var _params: CredentialListParameters?

    init(_ requestId: String) {
        super.init(requestId, METHOD_NAME)
    }
    
    public var params: CredentialListParameters? {
        return _params
    }
    
    public func setParameters(_ did: DID, _ skip: Int, _ limit: Int) {
        _params = CredentialListParameters(did, skip, limit)
    }
    
    public func setParameters(_ did: DID, _ limit: Int) {
        _params = CredentialListParameters(did, limit)
    }
    
    public func setParameters(_ did: DID) {
        _params = CredentialListParameters(did)
    }
    
    public func setParameters(_ did: String, _ skip: Int, _ limit: Int) throws {
        _params = try CredentialListParameters(DID.valueOf(did)!, skip, limit)
    }
    
    public func setParameters(_ did: String, _ limit: Int) throws {
        _params = try CredentialListParameters(DID.valueOf(did)!, limit)
    }
    
    public func setParameters(_ did: String) throws {
        _params = try CredentialListParameters(DID.valueOf(did)!)
    }

    public var did: DID? {
        return params?.did
    }
    
    public var skip: Int? {
        return params?.skip
    }
    
    public var limit: Int? {
        return params?.limit
    }
    
    public override var description: String {
        
        return "TODO:"
    }
}


public class CredentialListParameters: NSObject {
    private var _did: DID
    private var _skip: Int
    private var _limit: Int
    
    public init(_ did: DID, _ skip: Int, _ limit: Int) {
        self._did = did
        self._skip = skip
        self._limit = limit
    }

    public init(_ did: DID, _ limit: Int) {
        self._did = did
        self._skip = 0
        self._limit = limit
    }
    
    public init(_ did: DID) {
        self._did = did
        self._skip = 0
        self._limit = 0
    }
    
    public var did: DID {
        return _did
    }
    
    public var skip: Int {
        return _skip
    }
    
    public var limit: Int {
        return _limit
    }
    
    public override var hash: Int {
        return _did.hash + limit.hashValue + skip.hashValue
    }

    public func equalsTo(_ other: CredentialListParameters) -> Bool {
        if _did != other._did {
            return false
        }
        if skip != other.skip {
            return false
        }
        
        return limit == other.limit
    }
    
    public override func isEqual(_ object: Any?) -> Bool {
        if object is CredentialListParameters {
            return equalsTo(object as! CredentialListParameters)
        }
        else {
            return false
        }
    }
}
