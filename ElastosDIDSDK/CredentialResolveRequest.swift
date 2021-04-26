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

public class CredentialResolveRequest: ResolveRequest{
    private let PARAMETER_ID = "id"
    private let PARAMETER_ISSUER = "issuer"
    public static let METHOD_NAME = "did_resolveCredential"

    private var _params: CredentialParameters?
    
    init(_ requestId: String) {
        super.init(requestId, CredentialResolveRequest.METHOD_NAME)
    }
    
    public var params: CredentialParameters? {
        return _params
    }
    
    public func setParameters(_ id: DIDURL, _ issuer: DID) {
        _params = CredentialParameters(id, issuer)
    }
    
    public func setParameters(_ id: DIDURL) {
        _params = CredentialParameters(id)
    }
    
    public func setParameters(_ id: String, _ issuer: String) throws {
        _params = try CredentialParameters(DIDURL.valueOf(id), DID.valueOf(issuer)!)
    }
    
    public func setParameters(_ id: String) throws {
        _params = try CredentialParameters(DIDURL.valueOf(id))
    }
    
    public var id: DIDURL? {
        return params?.id
    }
    
    public var issuer: DID? {
        return params?.issuer
    }
    
    public override var description: String {
        
        return serialize(false)
    }
    
    override func serialize(_ force: Bool) -> String {
        let generator = JsonGenerator()
        serialize(generator)
        
        return generator.toString()
    }
    
    public override func serialize(_ generator: JsonGenerator) {
        generator.writeStartObject()
        generator.writeStringField(ID, requestId)
        generator.writeStringField(METHOD, method)
        if let _ = params {
            generator.writeFieldName(PARAMETERS)
            generator.writeStartArray()
            params!.serialize(generator)
            generator.writeEndArray()
        }
        
        generator.writeEndObject()
    }
    
    public class func deserialize(_ content: String) throws -> CredentialResolveRequest  {
        return try deserialize(content.toDictionary())
    }
    
    public class func deserialize(_ content: [String: Any]) throws -> CredentialResolveRequest {
        let id = content["id"] as? String
        let method = content["method"] as! String
        let param = content["params"] as? [[String: Any]]
        let cr = CredentialResolveRequest(id!)
        if let _ = param {
            let cp = try CredentialParameters.deserialize(param![0])
            cr._params = cp
        }
        
        return cr
    }
    
    public class func deserialize(_ content: JsonNode) throws -> CredentialResolveRequest {
        return try deserialize(content.toString().toDictionary())
    }
}


public class CredentialParameters: NSObject {
    private let ID = "id"
    private let ISSUER = "issuer"
    private var _id: DIDURL
    private var _issuer: DID?
    
    public init(_ id: DIDURL) {
        self._id = id
    }
    
    public init(_ id: DIDURL, _ issuer: DID) {
        self._id  = id
        self._issuer = issuer
    }
    
    public var id: DIDURL {
        return _id
    }
    
    public var issuer: DID? {
        return _issuer
    }
    
    public func serialize() -> String {
        let generator = JsonGenerator()
        serialize(generator)
        
        return generator.toString()
    }
    
    public func serialize(_ generator: JsonGenerator) {
        generator.writeStartObject()
        generator.writeStringField(ID, id.toString())
        if let _ = issuer {
            generator.writeStringField(ISSUER, issuer!.toString())
        }
        generator.writeEndObject()
    }
    
    public class func deserialize(_ content: [String: Any]) throws -> CredentialParameters {
        let id = content["id"] as! String
        let iss = content["issuer"] as? String
        if let _ = iss {
            return try CredentialParameters(DIDURL(id), DID(iss!))
        }
        
        return try CredentialParameters(DIDURL(id))
    }
    
    public override var hash: Int {
        return _id.hash + (_issuer != nil ? _issuer!.hashValue : 0)
    }

    public func equalsTo(_ other: CredentialParameters) -> Bool {
        return _id == other._id
    }
    
    public override func isEqual(_ object: Any?) -> Bool {
        if object is CredentialParameters {
            return equalsTo(object as! CredentialParameters)
        }
        else {
            return false
        }
    }
}
