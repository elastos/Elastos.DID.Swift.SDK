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
    var _proofs: [TransferTicketProof] = []

    var proofs: [DID: TransferTicketProof] = [: ]
    
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
        return _proofs[0]
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
        let tt = TransferTicket(self, false)
        // Proofs count should match with multisig
        if ((doc!.controllerCount() > 1 && proofs.count != doc!.multiSignature?.m) ||
                (doc!.controllerCount() <= 1 && proofs.count != 1)) {
            
            return false
        }

        let json = tt.serialize()
        let digest = EcdsaSigner.sha256Digest([json.data(using: .utf8)!])

        var checkedControllers: [DID] = []
        for proof in _proofs {
            guard proof.type == Constants.DEFAULT_PUBLICKEY_TYPE else {
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
            
            guard try doc!.verifyDigest(withId: proof.verificationMethod, using: proof.signature, for: digest) else {
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
        if proofs.isEmpty {
            return false
        }
        let multisig = try document()?.multiSignature
        return proofs.count == (multisig == nil ? 1 : multisig!.m)
    }
    
    /// Sanitize routine before sealing or after deserialization.
    func sanitize() throws {
        guard !_proofs.isEmpty else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedTransferTicketError("Missing ticket proof")
        }
        // CAUTION: can not resolve the target document here!
        //          will cause recursive resolve.
        proofs = [: ]
        for proof in _proofs {
            guard proof.verificationMethod.did != nil else {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedTransferTicketError("Invalid verification method")
            }
            
            guard proofs[proof.verificationMethod.did!] == nil else {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedTransferTicketError("Aleady exist proof from \(proof.verificationMethod.did!)")
            }
            proofs[proof.verificationMethod.did!] = proof
        }
        // sort
        _proofs.sort { (proofA, proofB) -> Bool in
            let compareResult = DateFormatter.convertToUTCStringFromDate(proofA.created)
                .compare(DateFormatter.convertToUTCStringFromDate(proofB.created))
            if compareResult == ComparisonResult.orderedSame {

                return proofA.verificationMethod.compareTo(proofB.verificationMethod) == ComparisonResult.orderedAscending
            } else {
                return compareResult == ComparisonResult.orderedAscending
            }
        }
    }

    func seal(_ controller: DIDDocument, _ storePassword: String) throws {
        do {
            guard try !isQualified() else {
                return
            }
            
            if controller.isCustomizedDid() {
                guard let _ = controller.effectiveController else {
                    throw DIDError.UncheckedError.IllegalStateError.NoEffectiveControllerError(controller.subject.toString())
                }
            }
            else {
                guard try document()!.hasController(controller.subject) else {
                    throw DIDError.UncheckedError.IllegalArgumentErrors.NotControllerError(controller.subject.toString())
                }
            }
        } catch {
            throw DIDError.UncheckedError.IllegalStateError.UnknownInternalError(error.localizedDescription)
        }
        
        let signKey = controller.defaultPublicKeyId()
        
        guard proofs[signKey!.did!] == nil else {
            throw DIDError.UncheckedError.IllegalStateError.AlreadySignedError(signKey?.did?.toString())
        }
        _proofs = []
        let json = serialize()
        let sig = try controller.sign(using: storePassword, for: [json.data(using: .utf8)!])
        let proof = TransferTicketProof(signKey!, sig)
        proofs[proof.verificationMethod.did!] = proof
        proofs.values.forEach{ tp in
            self._proofs.append(tp)
        }
        
        _proofs.sort { (proofA, proofB) -> Bool in
            let compareResult = DateFormatter.convertToUTCStringFromDate(proofA.created)
                .compare(DateFormatter.convertToUTCStringFromDate(proofB.created))
            if compareResult == ComparisonResult.orderedSame {

                return proofA.verificationMethod.compareTo(proofB.verificationMethod) == ComparisonResult.orderedAscending
            } else {
                return compareResult == ComparisonResult.orderedAscending
            }
        }
    }
    
    public func serialize(_ generator: JsonGenerator) {
        generator.writeStartObject()
        generator.writeStringField(ID, id.toString())
        generator.writeStringField(TO, to.toString())
        generator.writeStringField(TXID, txid)
        // sort
        _proofs.sort { (proofA, proofB) -> Bool in
            let compareResult = DateFormatter.convertToUTCStringFromDate(proofA.created)
                .compare(DateFormatter.convertToUTCStringFromDate(proofB.created))
            if compareResult == ComparisonResult.orderedSame {

                return proofA.verificationMethod.compareTo(proofB.verificationMethod) == ComparisonResult.orderedAscending
            } else {
                return compareResult == ComparisonResult.orderedAscending
            }
        }
        if _proofs.count > 0 {
            generator.writeFieldName(PROOF)
            generator.writeStartArray()
            _proofs.forEach { tf in
                tf.serialize(generator)
            }
            generator.writeEndArray()
        }
        generator.writeEndObject()
    }
    
    public func serialize() -> String {
        let generator = JsonGenerator()
        serialize(generator)
        
        return generator.toString()
    }
    
    /// Parse a TransferTicket object from from a string JSON representation.
    /// - Parameter content: the string JSON content for building the object
    /// - Returns: the TransferTicket object
    public class func deserialize(_ content: String) throws -> TransferTicket {
        let capacity = content.count * 3
        let buffer: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
        let cp = content.toUnsafePointerInt8()
        let c = b64_url_decode(buffer, cp)
        buffer[c] = 0
        let jsonStr: String = String(cString: buffer)
        let json = jsonStr.toDictionary()
        let id = json["id"] as? String
        let to = json["to"] as? String
        let txid = json["txid"] as? String
        let proofs = json["proof"] as? [[String: Any]] ?? [ ]
        var ps: [TransferTicketProof] = [ ]
        if proofs.count > 0 {
            for pf in proofs {
                let tf = try TransferTicketProof.deserialize(pf)
                ps.append(tf)
            }
        }

        var transferTicket: TransferTicket?
        if id != nil && to != nil && txid != nil  {
            transferTicket = try TransferTicket(DID(id!), DID(to!), txid!)
            transferTicket?._proofs = ps
        }
        
        try transferTicket?.sanitize()
        return transferTicket!
    }
}
