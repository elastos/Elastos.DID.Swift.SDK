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

/**
 * The interface to indicate how to get local did document, if this did is not published to chain.
 */
@objc(DIDBackend)
public class DIDBackend: NSObject {
    private let TAG = NSStringFromClass(DIDBackend.self)
    private static let DEFAULT_CACHE_INITIAL_CAPACITY = 16
    private static let DEFAULT_CACHE_MAX_CAPACITY = 64
    private static let DEFAULT_CACHE_TTL = 10 * 60 * 1000
    private var _random: String = ""
    
    private static let TAG = NSStringFromClass(DIDBackend.self)
//    private static var resolver: DIDResolver?
//    private static var _ttl: Int = Constants.DEFAULT_TTL // milliseconds
    private var _adapter: DIDAdapter
    public typealias ResolveHandle = (_ did: DID) -> DIDDocument?
    private var resolveHandle: ResolveHandle?
    private static var instance: DIDBackend?
    private var cache: LRUCache<ResolveRequest, ResolveResult>
    
    
    class TransactionResult: NSObject {
        private var _transactionId: String?
        private var _status: Int
        private var _message: String?
        private var _filled: Bool
        private let _semaphore: DispatchSemaphore

        override init() {
            self._status = 0
            self._filled = false
            self._semaphore = DispatchSemaphore(value: 0)
        }

        func update(_ transactionId: String, _ status: Int, _ message: String?) {
            self._transactionId = transactionId
            self._status = status
            self._message = message
            self._filled = true
            self._semaphore.signal()
        }

        func update(_ transactionId: String) {
            update(transactionId, 0, nil)
        }

        var transactionId: String {
            return _transactionId!
        }

        var status: Int {
            return _status
        }

        var message: String? {
            return _message
        }

        var isEmpty: Bool {
            return !_filled
        }

        override var description: String {
            var str = ""

            str.append("txid: ")
            str.append(transactionId)
            str.append("status: ")
            str.append(String(status))

            if status != 0 {
                str.append("message: ")
                str.append(message!)
            }

            return str
        }
    }

    class DefaultResolver: NSObject, DIDResolver {
        private var url: URL

        init(_ resolver: String) throws {
            guard !resolver.isEmpty else {
                throw DIDError.illegalArgument()
            }
            url = URL(string: resolver)!
        }

        func resolve(_ requestId: String, _ did: String, _ all: Bool) throws -> Data {
            Log.i(TAG, "Resolving {}...\(did.description)")

            var request = URLRequest.init(url: url, cachePolicy: .useProtocolCachePolicy, timeoutInterval: 60)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.setValue("application/json", forHTTPHeaderField: "Accept")

            let parameters: [String: Any] = [
                "jsonrpc": "2.0",
                "method": "resolvedid",
                "params": ["did":did, "all": all],
                "id": requestId
            ]

            do {
                request.httpBody = try JSONSerialization.data(withJSONObject: parameters, options: .prettyPrinted)
            } catch {
                throw DIDError.illegalArgument()
            }

            let semaphore = DispatchSemaphore(value: 0)
            var errDes: String?
            var result: Data?

            let task = URLSession.shared.dataTask(with: request) { data, response, error in
                guard let _ = data,
                    let response = response as? HTTPURLResponse,
                    error == nil else { // check for fundamental networking error

                        errDes = error.debugDescription
                        semaphore.signal()
                        return
                }
                guard (200 ... 299) ~= response.statusCode else { // check for http errors
                    errDes = "Server eror (status code: \(response.statusCode)"
                    semaphore.signal()
                    return
                }

                result = data
                semaphore.signal()
            }

            task.resume()
            semaphore.wait()

            guard let _ = result else {
                throw DIDError.didResolveError(errDes ?? "Unknown error")
            }

            return result!
        }
    }
    
    /// Create a DIDBackend with the adapter and the cache specification.
    /// - Parameters:
    ///   - adapter: the DIDAdapter object
    ///   - initialCacheCapacity: the initial cache size, 0 for default size
    ///   - maxCacheCapacity: the maximum cache capacity, 0 for default capacity
    ///   - cacheTtl: the live time for the cached entries, 0 for default
    init(_ adapter: DIDAdapter, _ initialCacheCapacity: Int, _ maxCacheCapacity: Int, _ cacheTtl: Int) {
        self._adapter = adapter
        cache = LRUCache<ResolveRequest, ResolveResult>(initialCacheCapacity, maxCacheCapacity)
    }

    /// Initialize the DIDBackend with the adapter and the cache specification.
    /// - Parameter adapter: the DIDAdapter object
    public class func initialize(_ adapter: DIDAdapter, _ initialCacheCapacity: Int, _ maxCacheCapacity: Int, _ cacheTtl: Int) throws {
        try checkArgument(initialCacheCapacity <= maxCacheCapacity, "Invalid cache capacity")
        let c = initialCacheCapacity < maxCacheCapacity ? initialCacheCapacity : maxCacheCapacity
        instance = DIDBackend(adapter, c, maxCacheCapacity, cacheTtl)
    }
    
    /// Initialize the DIDBackend with the adapter and the cache specification.
    /// - Parameters:
    ///   - adapter: the DIDAdapter object
    ///   - maxCacheCapacity: the maximum cache capacity, 0 for default capacity
    ///   - cacheTtl: the live time for the cached entries, 0 for default
    public class func initialize(_ adapter: DIDAdapter, _ maxCacheCapacity: Int, _ cacheTtl: Int) throws {
        instance = DIDBackend(adapter, DEFAULT_CACHE_INITIAL_CAPACITY, maxCacheCapacity, cacheTtl)
    }
    
    /// Initialize the DIDBackend with the adapter and the cache specification.
    /// - Parameters:
    ///   - adapter: the DIDAdapter object
    ///   - cacheTtl: the live time for the cached entries, 0 for default
    public class func initialize(_ adapter: DIDAdapter, _ cacheTtl: Int) throws {
        instance = DIDBackend(adapter, DEFAULT_CACHE_INITIAL_CAPACITY, DEFAULT_CACHE_MAX_CAPACITY, cacheTtl)
    }
    
    /// Initialize the DIDBackend with the adapter and the cache specification.
    /// - Parameters:
    ///   - adapter: the DIDAdapter object
    public class func initialize(_ adapter: DIDAdapter) throws {
        instance = DIDBackend(adapter, DEFAULT_CACHE_INITIAL_CAPACITY, DEFAULT_CACHE_MAX_CAPACITY, DEFAULT_CACHE_TTL)
    }
    
    /// Get DIDBackend instance.
    /// - Parameter adapter: A handle to DIDAdapter.
    /// - Returns: DIDBackend instance.
    @objc
    public class func sharedInstance() -> DIDBackend {
            return instance!
    }
    
    private func generateRequestId() -> String {
        var requestId = ""
        while requestId.count < 32 {
            let randomStr = Int.decTohex(number: Int.randomCustom(min: 0, max: 32))
            requestId.append(randomStr)
        }
        return requestId
    }

    var adapter: DIDAdapter {
        
        return _adapter
    }
    
    private func resolve(_ request: ResolveRequest) throws -> ResolveResult{
        Log.d(TAG, "Resolving request ", request, "...")
        
        let requestJson = request.serialize(true)
        let re = try adapter.resolve(requestJson)
        var response = ResolveResponse()
        switch request.method {
        case DIDResolveRequest.METHOD_NAME: do {
            response = try DIDResolveResponse.deserialize(re)
            break
        }
        case CredentialResolveRequest.METHOD_NAME: do {
            response = try CredentialResolveResponse.deserialize(re)
            break
        }
        case CredentialListRequest.METHOD_NAME: do {
            response = try CredentialListResponse.deserialize(re)
            break
        }
        default:
            Log.e(TAG, "INTERNAL - unknown resolve method ", request.method)
            throw DIDError.CheckedError.DIDBackendError.DIDResolveError("Unknown resolve method: \(request.method)")
        }
        //TODO:
//        if response.responseId != request.requestId {
//            throw DIDError.CheckedError.DIDBackendError.DIDResolveError("Mismatched resolve result with request.")
//        }
        
        if response.result != nil {
            return response.result!
        }
        else {
            throw DIDError.CheckedError.DIDBackendError.DIDResolveError("Server error: \(String(describing: response.errorCode)): \(String(describing: response.errorMessage))")
        }
    }

    private func resolveDidBiography(_ did: DID, _ all: Bool, _ force: Bool) throws -> DIDBiography {
        Log.i(TAG, "Resolving DID \(did.toString())", all, "=...")
        let request = DIDResolveRequest(generateRequestId())
        request.setParameters(did, all)
        if force {
            cache.removeValue(for: request)
        }
        let semaphore = DispatchSemaphore(value: 1)
        var bio = cache.getValue(for: request)
        if bio == nil {
            bio = try resolve(request)
            semaphore.signal()
        }
        semaphore.wait()
        return bio as! DIDBiography
    }
    
    ///  Resolve all DID transactions.
    /// - Parameter did: the specified DID object
    /// - Returns: the DIDBiography object
    func resolveDidBiography(_ did: DID) throws -> DIDBiography? {
        let biography = try resolveDidBiography(did, true, false)
        if biography.status == DIDBiographyStatus.STATUS_NOT_FOUND {
            return nil
        }
        return biography
    }
    
    /// Resolve DID content(DIDDocument).
    /// - Parameters:
    ///   - did: the DID object
    ///   - force: force = true, DID content must be from chain.
    ///            force = false, DID content could be from chain or local cache.
    /// - Returns: the DIDDocument object
    func
    resolveDid(_ did: DID, _ force: Bool) throws -> DIDDocument? {
        Log.d(TAG, "Resolving DID ", did.toString(), "...")
        if resolveHandle != nil {
            let doc = resolveHandle!(did)
            guard doc == nil else {
                return doc
            }
        }
        let bio = try resolveDidBiography(did, false, force)
        var tx: DIDTransaction?
        switch bio.status {
        case .STATUS_VALID:
            tx = bio.getTransaction(0)
            break
        case .STATUS_DEACTIVATED:
            guard bio.count == 2 else {
                throw DIDError.CheckedError.DIDBackendError.DIDResolveError("Invalid DID biography, wrong transaction count.")
            }
            tx = bio.getTransaction(0)
            guard tx?.request.operation == IDChainRequestOperation.DEACTIVATE else {
                throw DIDError.CheckedError.DIDBackendError.DIDResolveError("Invalid DID biography, wrong status.")
            }
            let doc = bio.getTransaction(1).request.document
            guard doc != nil else {
                throw DIDError.CheckedError.DIDBackendError.DIDResolveError("Invalid DID biography, invalid trancations.")
            }
            // Avoid resolve current DID recursively
            tx!.request._doc = tx!.request.document == nil ? doc : tx!.request.document!
            let request = DIDRequest(tx!.request)
            guard try request.isValid() else {
                throw DIDError.CheckedError.DIDBackendError.DIDResolveError("Invalid DID biography, transaction signature mismatch.")
            }
            tx = bio.getTransaction(1)
            break
        case .STATUS_NOT_FOUND:
            return nil
        
        default:
            return nil
        }
        
        if tx?.request.operation != IDChainRequestOperation.CREATE && tx?.request.operation != IDChainRequestOperation.UPDATE && tx?.request.operation != IDChainRequestOperation.TRANSFER {
            throw DIDError.CheckedError.DIDBackendError.DIDResolveError("Invalid ID transaction, unknown operation.")
        }
        
        if try (tx == nil || !tx!.request.isValid()) {
            throw DIDError.CheckedError.DIDBackendError.DIDResolveError("Invalid ID transaction, signature mismatch.")
        }
        let doc = tx!.request.document
        let metadata = DIDMetadata(doc!.subject)
        metadata.setTransactionId(tx!.getTransactionId())
        metadata.setSignature(doc!.proof.signature)
        metadata.setPublishTime(tx!.getTimestamp())
        if bio.status == DIDBiographyStatus.STATUS_DEACTIVATED {
            metadata.setDeactivated(true)
        }
        doc?.setMetadata(metadata)
        
        return doc
    }
    
    /// Resolve DID content(DIDDocument).
    /// - Parameter did: the DID object
    /// - Returns: the DIDDocument object
    func resolveDid(_ did: DID) throws -> DIDDocument? {
        return try resolveDid(did, false)
    }
    
    private func resolveCredentialBiography(_ id: DIDURL, _ issuer: DID?, _ force: Bool) throws -> CredentialBiography {
        Log.i(TAG, "Resolving credential ", id, ", issuer=\(String(describing: issuer))")
        let request = CredentialResolveRequest(generateRequestId())
        if issuer == nil {
            request.setParameters(id)
        }
        else {
            request.setParameters(id, issuer!)
        }
        if force {
            cache.removeValue(for: request)
        }
        return try cache.getValue(for: request) { () -> ResolveResult? in
            return try resolve(request)
        } as! CredentialBiography
    }
    
    func resolveCredentialBiography(_ id: DIDURL, _ issuer: DID) throws -> CredentialBiography? {
        return try resolveCredentialBiography(id, issuer, false)
    }
    
    func resolveCredentialBiography(_ id: DIDURL) throws -> CredentialBiography? {
        return try resolveCredentialBiography(id, nil, false)
    }
    
    private func resolveCredential(id: DIDURL, issuer: DID?, force: Bool) throws -> VerifiableCredential? {
        Log.d(TAG, "Resolving credential ", id)
        let bio = try resolveCredentialBiography(id, issuer, force)
        var tx: CredentialTransaction?
        switch bio.status {
        case .STATUS_VALID:
            tx = bio.getTransaction(0)
            break
        case .STATUS_REVOKED:
            tx = bio.getTransaction(0)
            guard tx?.request.operation == IDChainRequestOperation.REVOKE else {
                throw DIDError.CheckedError.DIDBackendError.DIDResolveError("Invalid credential biography, wrong status.")
            }
            if bio.count < 1, bio.count > 2 {
                throw DIDError.CheckedError.DIDBackendError.DIDResolveError("Invalid credential biography, transaction signature mismatch.")
            }
            guard bio.count != 1 else {
                guard try tx!.request.isValid() else {
                    throw DIDError.CheckedError.DIDBackendError.DIDResolveError("Invalid credential biography, transaction signature mismatch.")
                }
                return nil
            }
            let vc = bio.getTransaction(1).request.credential
            // Avoid resolve current credential recursively
            tx!.request.vc = tx!.request.credential == nil ? vc : tx!.request.credential!
            let request = CredentialRequest(tx!.request)
            guard try request.isValid() else {
                throw DIDError.CheckedError.DIDBackendError.DIDResolveError("Invalid credential biography, transaction signature mismatch.")
            }
            tx = bio.getTransaction(1)
            break
        case .STATUS_NOT_FOUND:
            return nil
        default:
            return nil
        }
        
        guard tx!.request.operation == IDChainRequestOperation.DECLARE else {
            throw DIDError.CheckedError.DIDBackendError.DIDResolveError("Invalid credential transaction, unknown operation.")
        }
        
        guard try (tx!.request.isValid()) else {
            throw DIDError.CheckedError.DIDBackendError.DIDResolveError("Invalid credential transaction, signature mismatch.")
        }
        let vc = tx!.request.credential
        let metadata = CredentialMetadata(vc!.id!)
        metadata.setTransactionId(tx!.getTransactionId())
        metadata.setPublishTime(tx!.getTimestamp())
        if (bio.status == CredentialBiographyStatus.STATUS_REVOKED) {
             metadata.setRevoked(true)
        }
        vc!.setMetadata(metadata)
        
        return vc
    }
    
    func resolveCredential(_ id: DIDURL, _ issuer: DID, _ force: Bool) throws -> VerifiableCredential? {
        try resolveCredential(id: id, issuer: issuer, force: force)
    }
    
    func resolveCredential(_ id: DIDURL, _ issuer: DID) throws -> VerifiableCredential? {
        
        return try resolveCredential(id: id, issuer: issuer, force: false)
    }
    
    func resolveCredential(_ id: DIDURL, _ force: Bool) throws -> VerifiableCredential? {
        
        return try resolveCredential(id: id, issuer: nil, force: force)
    }
    
    func resolveCredential(_ id: DIDURL) throws -> VerifiableCredential? {
        
        return try resolveCredential(id: id, issuer: nil, force: false)
    }
    
    func listCredentials(_ did: DID, _ skip: Int, _ limit: Int) throws -> [DIDURL] {
        Log.i(TAG, "List credentials for ", did)
        let request = CredentialListRequest(generateRequestId())
        request.setParameters(did, skip, limit)
        let list = try resolve(request) as? CredentialList
        guard let _ = list, list!.count != 0 else {
            return [ ]
        }
        
        return list!.credentialIds
    }
    
    private func createTransaction(_ request: IDChainRequest, _ adapter: DIDTransactionAdapter?) throws {
        Log.i(TAG, "Create ID transaction...")
        let payload = request.serialize(true)
        Log.i(TAG, "Transaction paload: '", payload, "', memo: ")
        var _adapter = adapter
        if _adapter == nil {
            _adapter = self.adapter
        }
        try _adapter!.createIdTransaction(payload, payload)
        Log.i(TAG, "ID transaction complete.")
    }
    
    private func invalidDidCache(_ did: DID) {
        let request = DIDResolveRequest(generateRequestId())
        request.setParameters(did, true)
        cache.removeValue(for: request)

        request.setParameters(did, false)
        cache.removeValue(for: request)
    }
    
    private func invalidCredentialCache(_ id: DIDURL, _ signer: DID?) {
        let request = CredentialResolveRequest(generateRequestId())
        if signer != nil {
            request.setParameters(id, signer!)
            cache.removeValue(for: request)
        }
        
        request.setParameters(id)
        cache.removeValue(for: request)
    }
    
    public func clearCache() {
        cache.clear()
    }
    
    /// Publish 'create' id transaction for the new did.
    /// - Parameters:
    ///   - doc: the DIDDocument object
    ///   - signKey: the key to sign
    ///   - storePassword: the password for DIDStore
    func createDid(_ doc: DIDDocument, _ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter?) throws {
        let request = try DIDRequest.create(doc, signKey, storePassword)
        try createTransaction(request, adapter)
        invalidDidCache(doc.subject)
    }
    
    /// Publish 'Update' id transaction for the existed did.
    /// - Parameters:
    ///   - doc: the DIDDocument object
    ///   - previousTxid: the previous transaction id string
    ///   - signKey: the key to sign
    ///   - storePassword: the password for DIDStore
    func updateDid(_ doc: DIDDocument, _ previousTxid: String, _ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter?) throws {
        let request = try DIDRequest.update(doc, previousTxid, signKey, storePassword)
        try createTransaction(request, adapter)
        invalidDidCache(doc.subject)
    }
    
    func transferDid(_ doc: DIDDocument, _ ticket: TransferTicket, _ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter?) throws {
        let request = try DIDRequest.transfer(doc, ticket, signKey, storePassword)
        try createTransaction(request, adapter)
        invalidDidCache(doc.subject)
    }
    
    /// Publish id transaction to deactivate the existed did.
    /// - Parameters:
    ///   - doc: the DIDDocument object
    ///   - signKey: the key to sign
    ///   - storePassword: the password for DIDStore
    func deactivateDid(_ doc: DIDDocument, _ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter?) throws {
        let request = try DIDRequest.deactivate(doc, signKey, storePassword)
        try createTransaction(request, adapter)
        invalidDidCache(doc.subject)
    }
    
    /// Publish id transaction to deactivate the existed did.
    /// - Parameters:
    ///   - target: the DID to be deactivated
    ///   - targetSignKey: the key to sign of specified DID
    ///   - signer: the signer's DIDDocument object
    ///   - signKey: the key to sign
    ///   - storePassword: the password for DIDStore
    func deactivateDid(_ target: DIDDocument, _ targetSignKey: DIDURL, _ signer: DIDDocument, _ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter?) throws {
        let request = try DIDRequest.deactivate(target, targetSignKey, signer, signKey, storePassword)
        try createTransaction(request, adapter)
        invalidDidCache(target.subject)
    }
    
    func declareCredential(_ vc: VerifiableCredential, _ signer: DIDDocument, _ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter?) throws {
        let request = try CredentialRequest.declare(vc, signer, signKey, storePassword)
        try createTransaction(request, adapter)
        invalidCredentialCache(vc.getId()!, nil)
        invalidCredentialCache(vc.getId()!, vc.getIssuer())
    }
    
    func revokeCredential(_ vc: VerifiableCredential, _ signer: DIDDocument, _ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter?) throws {
        let request = try CredentialRequest.revoke(vc, signer, signKey, storePassword)
        try createTransaction(request, adapter)
        invalidCredentialCache(vc.getId()!, nil)
        invalidCredentialCache(vc.getId()!, vc.getIssuer())
    }
    
    func revokeCredential(_ vc: DIDURL, _ signer: DIDDocument, _ signKey: DIDURL, _ storePassword: String, _ adapter: DIDTransactionAdapter?) throws {
        let request = try CredentialRequest.revoke(vc, signer, signKey, storePassword)
        try createTransaction(request, adapter)
        invalidCredentialCache(vc, nil)
        invalidCredentialCache(vc, signer.subject)
    }
}
