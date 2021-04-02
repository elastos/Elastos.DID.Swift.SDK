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

/// Transfer ticket class.

/// When customized DID owner(s) transfer the DID ownership to the others,
/// they need create and sign a transfer ticket, it the DID document is mulisig
/// document, the ticket should also multi-signed according the DID document.
///
///The new owner(s) can use this ticket create a transfer transaction, get
///the subject DID's ownership.
public class TransferTicket: NSObject {
    let ID = "id"
    let TO = "to"
    let TXID = "txid"
    let PROOF = "proof"
    let TYPE = "type"
    let VERIFICATION_METHOD = "verificationMethod"
    let CREATED = "created"
    let SIGNATURE = "signature"
    
    var id: DID
    var doc: DIDDocument?
    
    var to: DID
    
    var txid: String
    var _proofs: [TransferTicketProof]?

    var proofs: [DID: TransferTicketProof]?
    
    /// Transfer ticket constructor.
    /// - Parameters:
    ///   - target: the subject did
    ///   - to: the new owner's DID
    init(_ target: DIDDocument, _ to: DID) throws {
        guard target.isCustomizedDid() else {
            throw DIDError.UncheckedError.IllegalStateError.NotCustomizedDIDError(target.subject.toString())
        }
        try target.getMetadata().setTransactionId(target.subject.resolve()!.getMetadata().transactionId!)
        self.id = target.subject
        self.doc = target
        self.to = to
        self.txid = target.getMetadata().transactionId!
        super.init()
    }

    init(_ did: DID, _ to: DID, _ txid: String) {
        self.id  = did
        self.to = to
        self.txid = txid
    }
    
    init(_ ticket: TransferTicket, _ withProof: Bool) {
        self.id = ticket.id
        self.to = ticket.to
        self.txid = ticket.txid
        self.doc = ticket.doc
        if withProof {
            self.proofs = ticket.proofs
            self._proofs = ticket._proofs
        }
    }
    
    /// Get the subject DID.
    public var subject: DID {
        return id
    }
    
    /// Get the new owner's DID.
    public var getTo: DID {
        return to
    }
    
    /// The reference transaction ID for this transfer operation.
    public var transactionId: String {
        return txid
    }
    
    /// Get first Proof object.
    public var proof: TransferTicketProof? {
        return _proofs?[0]
    }
  
    /// Get all Proof objects.
    public var getProofs: [TransferTicketProof]? {
        return _proofs
    }
    
    /// Get all Proof objects.
    func document() throws -> DIDDocument? {
        if doc == nil {
            doc = try id.resolve()
        }
        
        return doc
    }
    
      /// Check whether the ticket is tampered or not.
    /// - Returns: true is the ticket is genuine else false
    public func isGenuine() throws -> Bool {
        if doc == nil {
            return false
        }
        guard try doc!.isGenuine() else {
            return false
        }
        let tt = try TransferTicket(self, false)
        // Proofs count should match with multisig
        if ((doc!.controllerCount() > 1 && proofs?.count != doc!.multiSignature?.m) ||
                (doc!.controllerCount() <= 1 && proofs?.count != 1)) {
            
            return false
        }
        let json = tt.serialize(true)
//        byte[] digest = EcdsaSigner.sha256Digest(json.getBytes());
        var checkedControllers: [DID] = []
        for proof in _proofs! {
            if proof.type == Constants.DEFAULT_PUBLICKEY_TYPE {
                return false
            }
            let controllerDoc = doc!.controllerDocument(proof.verificationMethod.did!)
            if controllerDoc == nil {
                return false
            }
            
            guard try controllerDoc!.isValid() else {
                return false
            }
            // if already checked this controller
            if (checkedControllers.contains(proof.verificationMethod.did!)){
                return false
            }
            guard proof.verificationMethod == controllerDoc?.defaultPublicKeyId() else {
                return false
            }
            checkedControllers.append(proof.verificationMethod.did!)
        }
        return true
    }
    
    /// Check whether the ticket is genuine and still valid to use.
    /// - Returns: true is the ticket is valid else false
    public func isValid() throws -> Bool {
        let doc = try document()
        if doc == nil {
            return false
        }
        
        guard try doc!.isValid() else {
            return false
        }
        guard try isGenuine() else {
            return false
        }
        
        guard txid == doc!.getMetadata().transactionId else {
            return false
        }
        
        return true
    }
    
    /// Check whether the ticket is qualified.
    /// check will only check the number of signatures meet the requirement.
    /// - Returns: true is the ticket is qualified else false
    public func isQualified() throws -> Bool {
        if proofs == nil || proofs!.isEmpty {
            return false
        }
        let multisig = try document()?.multiSignature
        return proofs?.count == (multisig == nil ? 1 : multisig!.m)
    }
    
    /// Sanitize routine before sealing or after deserialization.
    func sanitize() throws {
        guard _proofs != nil , !_proofs!.isEmpty else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedTransferTicketError("Missing ticket proof")
        }
        // CAUTION: can not resolve the target document here!
        //          will cause recursive resolve.
        proofs = [: ]
        for proof in _proofs! {
            guard proof.verificationMethod != nil else {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedTransferTicketError("Missing verification method")
            }
            guard proof.verificationMethod.did != nil else {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedTransferTicketError("Invalid verification method")
            }
            
            guard proofs![proof.verificationMethod.did!] == nil else {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedTransferTicketError("Aleady exist proof from \(proof.verificationMethod.did!)")
            }
            proofs![proof.verificationMethod.did!] = proof
        }
        var ps: [TransferTicketProof] = [ ]
            _proofs?.forEach({ tp in
                ps.append(tp)
        })
        self._proofs = ps
//        Collections.sort(this._proofs); // TODO:
    }
    
    func seal(_ controller: DIDDocument, _ storePassword: String) throws {
        do {
            guard try !isQualified() else {
                return
            }
            
            if controller.isCustomizedDid() {
                guard controller.effectiveController != nil else {
                    throw DIDError.UncheckedError.IllegalStateError.NoEffectiveControllerError(controller.subject.toString())
                }
            }
            else {
                guard try document()!.hasController(controller.subject) else {
                    throw DIDError.UncheckedError.IllegalArgumentError.NotControllerError(controller.subject.toString())
                }
            }
        } catch {
            // TODO:
            throw DIDError.UncheckedError.IllegalStateError.UnknownInternalError(DIDError.desription(error as! DIDError))
        }
        
        let signKey = controller.defaultPublicKeyId()
        if proofs == nil {
            proofs = [: ]
        }
        else {
            guard proofs![signKey!.did!] == nil else {
                throw DIDError.UncheckedError.IllegalStateError.AlreadySignedError(signKey?.did?.toString())
            }
        }
        _proofs = nil
//        let json = serialize(true)
        let json = ""
        let sig = try controller.sign(using: storePassword, for: [json.data(using: .utf8)!])
        let proof = TransferTicketProof(signKey!, sig)
        proofs![proof.verificationMethod.did!] = proof
        proofs?.values.forEach({ tp in
            self._proofs?.append(tp)
        })
//        Collections.sort(this._proofs) //TODO:
    }
    
    public func serialize(_ force: Bool) -> String {
        
        return "TODO:"
    }
    
    /// Parse a TransferTicket object from from a string JSON representation.
    /// - Parameter content: the string JSON content for building the object
    /// - Returns: the TransferTicket object
    public class func fromJson(_ content: Dictionary<String, Any>) throws -> TransferTicket {
//        return try parse(content)
        return try TransferTicket(DIDDocument(), DID()) // TODO:
    }
}
