/*
* Copyright (c) 2020 Elastos Foundation
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

/// The DID related chain request class for DID publishing.
public class DIDRequest: IDChainRequest {
    var _did: DID?
    var _doc: DIDDocument?
    
    override init() {
        super.init()
    }
    
    override init(_ operation: IDChainRequestOperation) {
        super.init(operation)
    }
    
    override init(_ operation: IDChainRequestOperation, _ previousTxid: String) {
        super.init(operation, previousTxid)
    }
    
    override init(_ operation: IDChainRequestOperation, _ ticket: TransferTicket) {
        super.init(operation, ticket)
    }
    
    /// Copy constructor.
    /// - Parameter request: another DID request object
    init(_ request: DIDRequest) {
        self._did = request.did
        self._doc = request.document
        super.init(request)
    }

    /// Constructs a DID 'create' Request.
    /// - Parameters:
    ///   - doc: the DID Document be publishing
    ///   - signKey: the key id to sign the request
    ///   - storePassword: the password for private key access from the DID store
    ///   - Returns: a DIDRequest object
    public class func create(_ doc: DIDDocument, _ signKey: DIDURL, _ storePassword: String) throws -> DIDRequest {
        let request = DIDRequest(IDChainRequestOperation.CREATE)
        request.setPayload(doc)
        do {
            try request.seal(signKey, storePassword)
        } catch {
            throw DIDError.UncheckedError.IllegalStateError.UnknownInternalError(DIDError.desription(error as! DIDError))
        }
        
        return request
    }

    /// Constructs a DID 'update' request.
    /// - Parameters:
    ///   - doc: the DID Document be publishing
    ///   - previousTxid: the previous transaction id string
    ///   - signKey: the key id to sign the request
    ///   - storePassword: the password for private key access from the DID store
    /// - Throws: DIDStoreError if an error occurred when access the private key
    /// - Returns: a DIDRequest object
    public class func update(_ doc: DIDDocument, _ previousTxid: String, _ signKey: DIDURL, _ storePassword: String) throws -> DIDRequest {
        let request = DIDRequest(IDChainRequestOperation.UPDATE, previousTxid)
        request.setPayload(doc)
        do {
            try request.seal(signKey, storePassword)
        } catch {
            throw DIDError.UncheckedError.IllegalStateError.UnknownInternalError(DIDError.desription(error as! DIDError))
        }
        
        return request
    }

    /// Constructs a DID 'transfer' request.
    /// - Parameters:
    ///   - doc: the DID Document be publishing
    ///   - ticket: the transfer ticket object
    ///   - signKey: the key id to sign the request
    ///   - storePassword: the password for private key access from the DID store
    /// - Throws: a DIDRequest object
    /// - Returns: DIDStoreError if an error occurred when access the private key
    public class func transfer(_ doc: DIDDocument, _ ticket: TransferTicket, _ signKey: DIDURL, _ storePassword: String) throws -> DIDRequest {
        let request = DIDRequest(IDChainRequestOperation.TRANSFER, ticket)
        request.setPayload(doc)
        do {
            try request.seal(signKey, storePassword)
        } catch {
            throw DIDError.UncheckedError.IllegalStateError.UnknownInternalError(DIDError.desription(error as! DIDError))
        }
        
        return request
    }
    
    /// Constructs a DID 'deactivate' request.
    /// - Parameters:
    ///   - doc: the DID Document be publishing
    ///   - signKey: the key id to sign the request
    ///   - storePassword: the password for private key access from the DID store
    /// - Throws: DIDStoreError if an error occurred when access the private key
    /// - Returns: a DIDRequest object
    public class func deactivate(_ doc: DIDDocument, _ signKey: DIDURL, _ storePassword: String) throws -> DIDRequest {
        let request = DIDRequest(IDChainRequestOperation.DEACTIVATE)
        request.setPayload(doc)
        do {
            try request.seal(signKey, storePassword)
        } catch {
            throw DIDError.UncheckedError.IllegalStateError.UnknownInternalError(DIDError.desription(error as! DIDError))
        }
        
        return request
    }
    
    /// Constructs a DID 'deactivate' request.
    /// - Parameters:
    ///   - target: target the DID to be deactivated
    ///   - targetSignKey: targetSignKey the authorization key id of target DID
    ///   - doc: the authorizer's document
    ///   - signKey: the real key is to sign request
    ///   - storePassword: the password for private key access from the DID store
    /// - Throws: DIDStoreError if an error occurred when access the private key
    /// - Returns: a DIDRequest object
    public class func deactivate(_ target: DIDDocument, _ targetSignKey: DIDURL, _ doc: DIDDocument, _ signKey: DIDURL, _ storePassword: String) throws -> DIDRequest {
        let request = DIDRequest(IDChainRequestOperation.DEACTIVATE)
        request.setPayload(target)
        do {
            try request.seal(targetSignKey, doc, signKey, storePassword)
        } catch {
            throw DIDError.UncheckedError.IllegalStateError.UnknownInternalError(DIDError.desription(error as! DIDError))
        }
        
        return request
    }
    
    /// Get previous transaction id string.
    public var previousTxid: String? {
        return header?.previousTxid
    }
    
    /// Get transfer ticket object.
    public var transferTicket: TransferTicket? {
        return header?.transferTicket
    }
    
    /// Get target DID of this request.
    public var did: DID? {
        return _did
    }
    
    /// Get the target DID Document of this request.
    public var document: DIDDocument? {
        return _doc
    }

    func setPayload(_ doc: DIDDocument) {
        self._did = doc.subject
        self._doc = doc
        
        if header?.operation != .DEACTIVATE {
            let json = doc.toString(true)
            let capacity = json.count * 3

            let cInput = json.toUnsafePointerUInt8()
            let cPayload = UnsafeMutablePointer<CChar>.allocate(capacity: capacity)
            let re = base64_url_encode(cPayload, cInput, json.lengthOfBytes(using: .utf8))
            cPayload[re] = 0
            self._payload = String(cString: cPayload)
        } else {
            self._payload = doc.subject.toString()
        }
    }
    
    /// Check the validity of the object and normalize the object after
    /// deserialized the DIDRequest object from JSON.
    /// - Throws: MalformedIDChainTransactionError if the object is invalid
    override func sanitize() throws {
        guard header?.specification != nil else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedIDChainRequestError("Missing specification")
        }
        guard header?.specification == IDChainRequest.DID_SPECIFICATION else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedIDChainRequestError("Unsupported specification")
        }
        
        switch header?.operation {
        case .CREATE:
            break
        case .UPDATE:
            if header?.previousTxid == nil || header!.previousTxid!.isEmpty {
                break
            }
            
        case .TRANSFER:
            if header?.ticket == nil || header!.ticket!.isEmpty {
                break
            }
        case .DEACTIVATE:
            break
        default:
            throw DIDError.CheckedError.DIDSyntaxError.MalformedIDChainRequestError("Invalid operation \(String(describing: header?.operation?.description))")
        }
        
        guard payload != nil, !payload!.isEmpty else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedIDChainRequestError("Missing payload")
        }
        guard proof != nil else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedIDChainRequestError("Missing proof")
        }
        
        do {
            if self.header?.operation != .DEACTIVATE {
                let capacity = payload!.count * 3
                let buffer: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
                let cp = payload!.toUnsafePointerInt8()
                let c = base64_url_decode(buffer, cp)
                buffer[c] = 0
                let json: String = String(cString: buffer)
                self._doc = try DIDDocument.convertToDIDDocument(fromJson: json)
                self._did = _doc!.subject
            } else {
                self._doc = nil
                self._did = try DID(payload!)
            }
        } catch {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedIDChainRequestError("Invalid payload \(DIDError.desription(error as! DIDError))")
        }
        proof?.qualifyVerificationMethod(_did!)
    }
    
    func seal(_ signKey: DIDURL, _ storePassword: String) throws {
        guard try _doc!.containsAuthenticationKey(forId: signKey) else {
            throw DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError("Not an authentication key.")
        }
        
        guard payload != nil, !payload!.isEmpty else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedIDChainRequestError("Missing payload")
        }
        let signature = try _doc!.sign(signKey, storePassword, getSigningInputs())
        setProof(IDChainProof(signKey, signature))
    }
    
    func seal(_ targetSignKey: DIDURL, _ doc: DIDDocument, _ signKey: DIDURL, _ storePassword: String) throws {
        guard try _doc!.containsAuthorizationKey(forId: targetSignKey) else {
            throw DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError("Not an authorization key: \(targetSignKey).")
        }
        guard try doc.containsAuthenticationKey(forId: signKey) else {
            throw DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError("Not an authentication key: \(signKey).")
        }
        guard payload != nil, !payload!.isEmpty else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedIDChainRequestError("Missing payload")
        }
        let signature = try _doc!.sign(signKey, storePassword, getSigningInputs())
        setProof(IDChainProof(targetSignKey, signature))
    }
    
    override func getSignerDocument() throws -> DIDDocument? {
        if document == nil {
            _doc = try did?.resolve()
        }
        
        return document
    }
    
    override class func deserialize(_ content: JsonNode) throws -> DIDRequest {

        let header = IDChainHeader.parse(content.get(forKey: "header")!)
        let payload = content.get(forKey: "payload")!.asString()
        let proof = try IDChainProof.parse(content.get(forKey: "proof")!)
        let request = DIDRequest()
        request.setHeader(header)
        request.setProof(proof)
        request.setPayload(payload!)
        try request.sanitize()
        
        return request
    }
    
    public override func serialize(_ generator: JsonGenerator) {
        generator.writeStartObject()
        generator.writeFieldName(HEADER)
        header?.serialize(generator)
        if let _ = payload {
            generator.writeFieldName(PAYLOAD)
            generator.writeString(payload!)
        }
        if let _ = proof {
            generator.writeFieldName(PROOF)
            proof?.serialize(generator)
        }
        generator.writeEndObject()
    }

}
