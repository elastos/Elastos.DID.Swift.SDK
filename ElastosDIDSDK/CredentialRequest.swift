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

/// The credential related chain request class for credential publishing.
public class CredentialRequest: IDChainRequest {
    var id: DIDURL?
    var vc: VerifiableCredential?
    var signer: DIDDocument?
    
    override init(_ operation: IDChainRequestOperation) {
        super.init(operation)
    }
    
    /// Copy constructor.
    /// - Parameter request: another credential request object
    init(_ request: CredentialRequest) {
        super.init(request)
        self.id = request.id
        self.vc = request.vc
        self.signer = request.signer
    }
    
    /// Constructs a credential 'declare' request.
    /// - Parameters:
    ///   - vc: the VerifiableCredential object that needs to be declare
    ///   - signer: the credential owner's DIDDocument object
    ///   - signKey: the key id to sign request
    ///   - storepass: the password for private key access from the DID store
    public class func declare(_ vc: VerifiableCredential, _ signer: DIDDocument, _ signKey: DIDURL, _ storepass: String) throws -> CredentialRequest {
        
        let request = CredentialRequest(IDChainRequestOperation.DECLARE)
        request.setPayload(vc)
        request.setSigner(signer)
        do {
            try request.seal(signer, signKey, storepass)
        } catch {
            throw DIDError.UncheckedError.IllegalStateError.UnknownInternalError("Invalid payload \(DIDError.desription(error as! DIDError))")
        }
        
        return request
    }
    
    /// Constructs a credential 'revoke' request.
    /// - Parameters:
    ///   - vc: the VerifiableCredential object that needs to be revoke
    ///   - signer: the credential owner's DIDDocument object
    ///   - signKey: the key id to sign request
    ///   - storepass: the password for private key access from the DID store
    /// - Returns: a CredentialRequest object
    public class func revoke(_ vc: VerifiableCredential, _ signer: DIDDocument, _ signKey: DIDURL, _ storepass: String) throws -> CredentialRequest {
        
        let request = CredentialRequest(IDChainRequestOperation.REVOKE)
        request.setPayload(vc)
        request.setSigner(signer)
        do {
            try request.seal(signer, signKey, storepass)
        } catch {
            throw DIDError.UncheckedError.IllegalStateError.UnknownInternalError("Invalid payload \(DIDError.desription(error as! DIDError))")
        }
        
        return request
    }
    
    /// Constructs a credential 'revoke' request.
    /// - Parameters:
    ///   - id: the id of the credential that needs to be revoke
    ///   - signer: the credential owner's DIDDocument object
    ///   - signKey: the key id to sign request
    ///   - storepass: the password for private key access from the DID store
    /// - Returns: a CredentialRequest object
    public class func revoke(_ id: DIDURL, _ signer: DIDDocument, _ signKey: DIDURL, _ storepass: String) throws -> CredentialRequest {
        
        let request = CredentialRequest(IDChainRequestOperation.REVOKE)
        request.setPayload(id)
        request.setSigner(signer)
        do {
            try request.seal(signer, signKey, storepass)
        } catch {
            throw DIDError.UncheckedError.IllegalStateError.UnknownInternalError("Invalid payload \(DIDError.desription(error as! DIDError))")
        }
        
        return request
    }
    
    func setSigner(_ initiator: DIDDocument) {
        self.signer = initiator
    }
    
    /// Get target credential id of this request.
    public var credentialId: DIDURL? {
        return id
    }
    
    /// Get the target VerifiableCredential object of this request.
    public var credential: VerifiableCredential? {
        return vc
    }
    
    func setPayload(_ vc: VerifiableCredential) {
        self.id = vc.getId()
        self.vc = vc
        if header?.operation == .DECLARE {
            let json = vc.toString()
            let capacity = json.count * 3

            let cInput = json.toUnsafePointerUInt8()
            let cPayload = UnsafeMutablePointer<CChar>.allocate(capacity: capacity)
            let re = base64_url_encode(cPayload, cInput, json.lengthOfBytes(using: .utf8))
            cPayload[re] = 0
            self._payload = String(cString: cPayload)
        } else {
            self._payload = vc.getId().toString()
        }
    }
    
    func setPayload(_ id: DIDURL) {
        self.id = id
        self.vc = nil
        setPayload(id.toString())
    }
    
    /// Check the validity of the object and normalize the object after
    /// deserialized the CredentialRequest object from JSON.
    override func sanitize() throws {
        guard header?.specification != nil else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedIDChainRequestError("Missing specification")
        }
        guard header?.specification == IDChainRequest.CREDENTIAL_SPECIFICATION else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedIDChainRequestError("Unsupported specification")
        }
        
        switch header?.operation {
        case .DECLARE:
            break
        case .REVOKE:
            break
        default:
            throw DIDError.CheckedError.DIDSyntaxError.MalformedIDChainRequestError("Invalid operation \(header?.operation?.description)")
        }
        
        guard payload == nil, payload!.isEmpty else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedIDChainRequestError("Missing payload")
        }
        guard proof == nil else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedIDChainRequestError("Missing proof")
        }
        
        do {
            if self.header?.operation == .DECLARE {
                let capacity = payload!.count * 3
                let buffer: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
                let cp = payload!.toUnsafePointerInt8()
                let c = base64_url_decode(buffer, cp)
                buffer[c] = 0
                let json: String = String(cString: buffer)
                self.vc = try VerifiableCredential.fromJson(json)
                self.id = vc?.getId()
            } else {
                self.vc = nil
                self.id = try DIDURL(payload!)
            }
        } catch {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedIDChainRequestError("Invalid payload \(DIDError.desription(error as! DIDError))")
        }
        proof?.qualifyVerificationMethod(id!.did!)
    }
    
    func seal(_ doc: DIDDocument, _ signKey: DIDURL, _ storepass: String) throws {
        guard doc.containsAuthenticationKey(forId: signKey) else {
            throw DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError("Not an authentication key.")
        }
        
        guard payload != nil, !payload!.isEmpty else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedIDChainRequestError("Missing payload")
        }
        let signature = try doc.sign(signKey, storepass, getSigningInputs())
        setProof(IDChainProof(signKey, signature))
    }
    
    /// Get the DIDDocument of the request signer.
    /// - Returns: the signer's DIDDocument object
    override func getSignerDocument() throws -> DIDDocument? {
        if signer != nil {
            return signer
        }
        
        if operation == IDChainRequestOperation.DECLARE {
            signer = try credential?.getSubject()?.did.resolve()
        }
        else {
           if credential != nil {
            signer = try credential?.getSubject()?.did.resolve()
            }
           else {
            signer = try proof?.verificationMethod.did?.resolve()
           }
        }
        
        return signer
    }
}
