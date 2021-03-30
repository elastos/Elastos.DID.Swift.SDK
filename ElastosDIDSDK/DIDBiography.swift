
import Foundation


public class DIDBiography: ResolveResult {
    private let DID = "did"
    private let STATUS = "status"
    private let TRANSACTION = "transaction"
    
    private var _did: DID
    private var _status: DIDBiographyStatus
    private var _txs: [DIDTransaction] = []

    init(_ did: DID, _ status: DIDBiographyStatus) {
        self._did = did
        self._status = status
    }
    
    init(_ did: DID) {
        self._did = did
        self._status = DIDBiographyStatus.STATUS_VALID
    }
    
    public var did: DID {
        return _did
    }
    
    func setStatus(_ newVaule: DIDBiographyStatus) {
        self._status = newVaule
    }
    
    public var status: DIDBiographyStatus {
        return _status
    }
    
    public var count: Int {
        return _txs.count
    }
    
    public func getTransaction(_ index: Int) -> DIDTransaction {
        return _txs[index]
    }
    
    public func getAllTransactions() -> [DIDTransaction] {
        return _txs
    }
    
    public func appendTransaction(_ newElement: DIDTransaction) {
        _txs.append(newElement)
    }
    
    override func sanitize() throws {
        if status != DIDBiographyStatus.STATUS_NOT_FOUND {
            guard _txs.count != 0 else {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedResolveResponseError("Missing transaction")
            }
            for tx in _txs {
                do {
                    try tx.sanitize()
                } catch {
                    throw DIDError.CheckedError.DIDSyntaxError.MalformedResolveResponseError("Invalid transaction")
                }
            }
        }
        else {
            guard _txs.count == 0 else {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedResolveResponseError("Should not include transaction")
            }
        }
    }
}
