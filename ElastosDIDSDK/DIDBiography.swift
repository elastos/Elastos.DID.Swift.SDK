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
