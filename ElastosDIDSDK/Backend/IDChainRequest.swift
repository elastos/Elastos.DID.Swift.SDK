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

/// The class records the information of IDChain Request.
@objc(IDChainRequest)
public class IDChainRequest: NSObject {

    /// The specification string of IDChain Request
    @objc public static let CURRENT_SPECIFICATION = "elastos/did/1.0"
    public static let DID_SPECIFICATION = "elastos/did/1.0"
    public static let CREDENTIAL_SPECIFICATION = "elastos/credential/1.0"

    var _header: IDChainHeader?
    var _payload: String?
    var _proof: IDChainProof?

    let HEADER = "header"
    let PAYLOAD = "payload"
    let PROOF = "proof"

    public let SPECIFICATION = "specification"
    private let OPERATION = "operation"
    private let PREVIOUS_TXID = "previousTxid"
    private let TICKET = "ticket"

    private let TYPE = "type"
    private let VERIFICATION_METHOD = "verificationMethod"
    private let SIGNATURE = "signature"

    override init() {
        
    }
    
    /// Create a ID chain request with given operation.
    /// - Parameter operation: the operation
    init(_ operation: IDChainRequestOperation) {
        self._header = IDChainHeader(operation)
    }
    
    /// Create a DID update request with given previous transaction id.
    /// - Parameters:
    ///   - operation: should be UPDATE operation
    ///   - previousTxid: the previous transaction id of target DID
    init(_ operation: IDChainRequestOperation, _ previousTxid: String) {
        self._header = IDChainHeader(operation, previousTxid)
    }
    
    /// Create a DID transfer request with given ticket.
    /// - Parameters:
    ///   - operation: should be TRANSFER operation
    ///   - ticket: the transfer ticket object
    init(_ operation: IDChainRequestOperation, _ ticket: TransferTicket) {
        self._header = IDChainHeader(operation, ticket)
    }
    
    /// Copy constructor.
    /// - Parameter request: another ID chain request object
    init(_ request: IDChainRequest) {
        self._header = request.header
        self._payload = request.payload
        self._proof = request.proof
    }
    
    /// Get the request header object.
    public var header: IDChainHeader? {
        return _header
    }

    /// Get the operation of this request.
    public var operation: IDChainRequestOperation? {
        return _header?.operation
    }
    
    /// Get the payload of this ID chain request.
    public var payload: String? {
        return _payload
    }
    
    /// Set the header for this ID chain request.
    /// - Parameter header: the IDChainHeader format payload
    func setHeader(_ header: IDChainHeader) {
        self._header = header
    }
    
    /// Set the payload for this ID chain request.
    /// - Parameter payload: the string format payload
    func setPayload(_ payload: String) {
        self._payload = payload
    }
    
    /// Get the proof object of this ID chain request.
    public var proof: IDChainProof? {
        return _proof
    }
    
    /// Set the proof object for the ID chain request.
    /// - Parameter proof: the proof object
    func setProof(_ proof: IDChainProof) {
        self._proof = proof
    }
    
    /// Get the signing inputs for generating the proof signature.
    /// - Returns: the array object of input Data arrays
    func getSigningInputs() -> [Data] {
        let prevTxid = operation == .UPDATE ? header?.previousTxid! : ""
        let ticket = operation == .TRANSFER ? header?.ticket! : ""

        var inputs: [Data] = []

        if let spec = header?.specification, let data = spec.data(using: .utf8) {
            inputs.append(data)
        }
        if let oper = operation, let data = oper.description.data(using: .utf8)  {
            inputs.append(data)
        }
        if let data = prevTxid?.data(using: .utf8)  {
            inputs.append(data)
        }
        if let data = ticket?.data(using: .utf8)  {
            inputs.append(data)
        }
        if let pay = _payload,let data = pay.data(using: .utf8)  {
            inputs.append(data)
        }

        return inputs
    }
    
    /// Abstract method to get the DIDDocument of the request signer.
    /// - Returns: the signer's DIDDocument object
    func getSignerDocument() throws -> DIDDocument? {
        return DIDDocument()
    }
    
    /// Return whether this ID chain request is valid or not.
    /// - Returns: true if valid, otherwise false
    public func isValid() throws -> Bool {
        let signKey = proof!.verificationMethod
        let doc = try getSignerDocument()
        guard doc != nil else {
            return false
        }
        
        // Here should not check the expiration and deactivated
        guard try doc!.isGenuine() else {
            return false
        }
        
        if operation != IDChainRequestOperation.DEACTIVATE {
            if try !doc!.containsAuthenticationKey(forId: signKey) {
                return false
            }
        }
        else {
            if (!doc!.isCustomizedDid()) {
                // the signKey should be default key or authorization key
                if try (doc!.defaultPublicKeyId() != signKey &&
                         doc!.authorizationKey(ofId: signKey) == nil) {
                    return false
                }
            } else {
                // the signKey should be controller's default key
                let controller = doc?.controllerDocument(signKey.did!)
                if (controller == nil || controller!.defaultPublicKeyId() != signKey) {
                    return false
                }
            }
        }
        
        return try doc!.verify(proof!.verificationMethod, proof!.signature, getSigningInputs())
    }
    
    func serialize(_ force: Bool) -> String {
        let generator = JsonGenerator()
        serialize(generator, force)
        return generator.toString()
    }
    
    func serialize(_ generator: JsonGenerator, _ force: Bool) {
        generator.writeStartObject()
        generator.writeFieldName(HEADER)
        header?.serialize(generator)
        
        if let _ = payload {
            generator.writeStringField(PAYLOAD, payload!)
        }
        generator.writeFieldName(PROOF)
        proof?.serialize(generator)
        generator.writeEndObject()
    }
    
    func sanitize() throws {
        print("TODO:")
    }
    
    class func deserialize(_ content: JsonNode) throws -> IDChainRequest {

        let header = IDChainHeader.parse(content.get(forKey: "header")!)
        let payload = content.get(forKey: "payload")!.asString()
        let proof = try IDChainProof.parse(content.get(forKey: "proof")!)
        let request = IDChainRequest()
        request.setHeader(header)
        request.setProof(proof)
        request.setPayload(payload!)
        
        return request
    }
}
