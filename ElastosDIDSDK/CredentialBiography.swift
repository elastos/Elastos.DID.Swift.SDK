

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
    
    func getTransaction(_ index: Int) -> CredentialTransaction {
        return _txs[index]
    }
    
    func getAllTransactions() -> [CredentialTransaction] {
        return _txs
    }
    
    func appendTransaction(_ tx: CredentialTransaction) {
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
