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

public class CredentialBiography: ResolveResult{
    private let ID = "id"
    private let STATUS = "status"
    private let TRANSACTION = "transaction"

    private var _id: DIDURL
    private var _status: CredentialBiographyStatus
    private var _txs: [CredentialTransaction] = [ ]

    init(_ id: DIDURL, _ status: CredentialBiographyStatus) {
        self._id = id
        self._status = status
    }
    
    init(_ id: DIDURL) {
        self._id = id
        self._status = CredentialBiographyStatus.STATUS_VALID
    }
    
    public var id: DIDURL {
        return _id
    }
    
    func setStatus(_ status: CredentialBiographyStatus) {
        self._status = status
    }
    
    public var status: CredentialBiographyStatus {
        return _status
    }
    
    public var count: Int {
        return _txs.count
    }
    
    public func getTransaction(_ index: Int) -> CredentialTransaction {
        return _txs[index]
    }
    
    public func getAllTransactions() -> [CredentialTransaction] {
        return _txs
    }
    
    func removeTransaction(_ index: Int) -> CredentialTransaction? {
        return _txs.remove(at: index)
    }
    
    public func appendTransaction(_ tx: CredentialTransaction) {
        _txs.append(tx)
    }
    
    override func sanitize() throws {
        if (status != CredentialBiographyStatus.STATUS_NOT_FOUND) {
            guard  _txs.count != 0 else {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedResolveResultError("Missing transaction")
            }
            for tx in _txs {
                do {
                    try tx.sanitize()
                } catch {
                    throw DIDError.CheckedError.DIDSyntaxError.MalformedResolveResultError("Invalid transaction")
                }
            }
        } else {
            guard _txs.count == 0 else {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedResolveResultError("Should not include transaction")
            }
        }
    }
    
    public func serialize() -> String {
        let generator = JsonGenerator()
        serialize(generator)
        
        return generator.toString()
    }
    
    public func serialize(_ generator: JsonGenerator) {
        generator.writeStartObject()
        generator.writeStringField(ID, id.toString())
        generator.writeNumberField(STATUS, status.rawValue)
        if count > 0 {
            generator.writeFieldName(TRANSACTION)
            generator.writeStartArray()
            for tx in _txs {
                tx.serialize(generator)
            }
            generator.writeEndArray()
        }
        generator.writeEndObject()
    }

    public class func deserialize(_ content: [String: Any]) throws -> CredentialBiography {
        let id = content["id"] as! String
        let status = CredentialBiographyStatus(rawValue: content["status"] as! Int)
        let txs = content["transaction"] as? [[String: Any]]
        var _txs: [CredentialTransaction] = []
        if let _ = txs {
            for tx in txs! {
                let didtx = try CredentialTransaction.deserialize(tx)
                _txs.append(didtx)
            }
        }
        let bio = CredentialBiography(try DIDURL(id), status!)
        bio._txs = _txs
        
        return bio
    }
    
}

public enum CredentialBiographyStatus: Int, CustomStringConvertible {
    case STATUS_VALID = 0
    case STATUS_EXPIRED = 1
    case STATUS_REVOKED = 2
    case STATUS_NOT_FOUND = 3

    func toString() -> String {
        let desc: String
        switch self.rawValue {
        case 0:
            desc = "valid"
        case 1:
            desc = "expired"
        case 2:
            desc = "revoked"
        case 3:
            desc = "not_found"
        default:
            desc = "not_found"
        }
        return desc
    }

    /// ResolveResultStatus string.
    public var description: String {
        return toString()
    }
}
