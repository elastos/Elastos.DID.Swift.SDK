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
import PromiseKit

/// DID is a globally unique identifier that does not require a centralized registration authority.
/// It includes method specific string. (elastos:id:ixxxxxxxxxx).
@objc(DID)
public class DID: NSObject {
    private static let TAG = "DID"

    private var _method: String?
    private var _methodSpecificId: String?
    private var _metadata: DIDMeta?

    @objc public static let METHOD: String = "elastos"

    override init() {}
    
    init(_ method: String, _ methodSpecificId: String) {
        self._method = method
        self._methodSpecificId = methodSpecificId
    }

    /// Create a new DID according to method specific string.
    /// - Parameter did: A pointer to specific string. The method-specific-id value should be globally unique by itself.
    /// - Throws: Language is empty or error occurs.
    @objc public init(_ did: String) throws {
        super.init()
        guard !did.isEmpty else {
            throw DIDError.illegalArgument("empty did string")
        }

        do {
            try ParserHelper.parse(did, true, DID.Listener(self))
        } catch {
            Log.e(DID.TAG, "Parsing did error: malformed did string \(did)")
            let didError = error as? DIDError
            var errmsg = "Parsing did error: malformed did string \(did)"
            if didError != nil {
                errmsg = DIDError.desription(didError!)
            }
            throw DIDError.malformedDID(errmsg)
        }
    }

    ///  Get method of DID.
    @objc public var method: String {
        return _method!
    }

    func setMethod(_ method: String) {
        self._method = method
    }

    /// Get method specific string of DID.
    @objc public var methodSpecificId: String {
        return _methodSpecificId!
    }

    func setMethodSpecificId(_ methodSpecificId: String) {
        self._methodSpecificId = methodSpecificId
    }

    /// Get DID MetaData from did.
    /// - Returns: Return the handle to DIDMetaData. Otherwise
    @objc public func getMetadata() -> DIDMeta {
        if  self._metadata == nil {
            self._metadata = DIDMeta()
        }
        return _metadata!
    }

    func setMetadata(_ newValue: DIDMeta) {
        self._metadata = newValue
    }

    /// Save DID MetaData.
    /// - Throws: If error occurs, throw error.
    @objc public func saveMetadata() throws {
        if (_metadata != nil && _metadata!.attachedStore) {
            try _metadata?.store?.storeDidMetadata(self, _metadata!)
        }
    }

    /// Check deactivated
    @objc public var isDeactivated: Bool {
        return getMetadata().isDeactivated
    }

    /// Get the newest DID Document from chain.
    /// - Parameter force: Indicate if load document from cache or not.
    ///  force = true, document gets only from chain. force = false, document can get from cache,
    ///   if no document is in the cache, resolve it from chain.
    /// - Throws: If error occurs, throw error.
    /// - Returns: Return the handle to DID Document.
    public func resolve(_ force: Bool) throws -> DIDDocument? {
        let doc = try DIDBackend.resolve(self, force)
        if doc != nil {
            setMetadata(doc!.getMetadata())
        }

        return doc
    }

    /// Get the newest DID Document from chain.
    /// - Parameter force: Indicate if load document from cache or not.
    ///  force = true, document gets only from chain. force = false, document can get from cache,
    ///   if no document is in the cache, resolve it from chain.
    /// - Throws: If error occurs, throw error.
    /// - Returns: Return the handle to DID Document.
    @objc public func resolve(_ force: Bool, error: NSErrorPointer) -> DIDDocument? {
        do {
            return try resolve(force)
        } catch let aError as NSError {
            error?.pointee = aError
            return nil
        }
    }

    /// Get the newest DID Document from chain.
    /// - Throws: If error occurs, throw error.
    /// - Returns: Return the handle to DID Document
    public func resolve() throws -> DIDDocument? {
        return try resolve(false)
    }

    /// Get the newest DID Document from chain.
    /// - Throws: If error occurs, throw error.
    /// - Returns: Return the handle to DID Document
    @objc public func resolve(error: NSErrorPointer) -> DIDDocument? {
        do {
            return try resolve(false)
        } catch let aError as NSError {
            error?.pointee = aError
            return nil
        }
    }

    /// Get the newest DID Document asynchronously from chain.
    /// - Parameter force: Indicate if load document from cache or not.
    ///  force = true, document gets only from chain. force = false, document can get from cache,
    ///   if no document is in the cache, resolve it from chain.
    /// - Returns: Return the handle to DID Document.
    public func resolveAsync(_ force: Bool) -> Promise<DIDDocument?> {
        return Promise<DIDDocument?> { resolver in
            do {
                resolver.fulfill(try resolve(force))
            } catch let error  {
                resolver.reject(error)
            }
        }
    }

    /// Get the newest DID Document asynchronously from chain.
    /// - Parameter force: Indicate if load document from cache or not.
    ///  force = true, document gets only from chain. force = false, document can get from cache,
    ///   if no document is in the cache, resolve it from chain.
    /// - Returns: Return the handle to DID Document.
    @objc public func resolveAsyncUsingObjectC(_ force: Bool) -> AnyPromise {
        return AnyPromise(__resolverBlock: { [self] resolver in
            do {
                resolver(try resolve(force))
            } catch let error  {
                resolver(error)
            }
        })
    }

    /// Get the newest DID Document asynchronously from chain.
    /// - Returns: Return the handle to DID Document.
    public func resolveAsync() -> Promise<DIDDocument?> {
        return resolveAsync(false)
    }

    /// Get the newest DID Document asynchronously from chain.
    /// - Returns: Return the handle to DID Document.
    @objc public func resolveAsyncUsingObjectC() -> AnyPromise {
        return resolveAsyncUsingObjectC(false)
    }

    /// Get all DID Documents from chain.
    /// - Throws: If error occurs, throw error.
    /// - Returns: return the handle to DID Document.
    @objc public func resolveHistory() throws -> DIDHistory {
        return try DIDBackend.resolveHistory(self)
    }

    /// Get all DID Documents from chain.
    /// - Returns: return the handle to DID Document asynchronously.
    public func resolveHistoryAsync() -> Promise<DIDHistory> {
        return Promise<DIDHistory> { resolver in
            do {
                resolver.fulfill(try resolveHistory())
            } catch let error  {
                resolver.reject(error)
            }
        }
    }

    /// Get all DID Documents from chain.
    /// - Returns: return the handle to DID Document asynchronously.
    @objc public func resolveHistoryAsyncUsingObjectC() -> AnyPromise {
        return AnyPromise(__resolverBlock: { [self] resolver in
            do {
                resolver(try resolveHistory())
            } catch let error  {
                resolver(error)
            }
        })
    }
}

extension DID {
    func toString() -> String {
        return String("did:\(_method!):\(_methodSpecificId!)")
    }

    /// Get id string from DID.
    @objc public override var description: String {
        return toString()
    }
}

extension DID {
    @objc public func equalsTo(_ other: DID) -> Bool {
        return methodSpecificId == other.methodSpecificId
    }

    @objc(equalsToOther:)
    public func equalsTo(_ other: String) -> Bool {
        return toString() == other
    }

    public static func == (lhs: DID, rhs: DID) -> Bool {
        return lhs.equalsTo(rhs)
    }

    public static func != (lhs: DID, rhs: DID) -> Bool {
        return !lhs.equalsTo(rhs)
    }
}

extension DID {
    //TODO:
//    public func hash(into hasher: inout Hasher) {
//        hasher.combine(self.toString())
//    }
}

// Parse Listener
extension DID {
    private class Listener: DIDURLBaseListener {
        private var did: DID

        init(_ did: DID) {
            self.did = did
            super.init()
        }
//  todo: OC
        public override func exitMethod(_ ctx: DIDURLParser.MethodContext) {
            let method = ctx.getText()
            if (method != Constants.METHOD){
                // can't throw , print...
                Log.e(DID.TAG, "unsupported method: \(method)")
            }
            self.did._method = Constants.METHOD
        }

        public override func exitMethodSpecificString(
                            _ ctx: DIDURLParser.MethodSpecificStringContext) {
            self.did._methodSpecificId = ctx.getText()
        }
    }
}
