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
import ObjectMapper

/**
 * DID is a globally unique identifier that does not require
 * a centralized registration authority.
 *
 * <p>
 * The generic DID scheme is a URI scheme conformant with
 * <a href="https://tools.ietf.org/html/rfc3986">RFC3986</a>
 * </p>
 */
@objc(DID)
public class DID: NSObject {
    private static let TAG = NSStringFromClass(DID.self)
    /// The default method name for Elastos DID method.
    @objc public static let METHOD: String = "elastos"

    private var _method: String?
    private var _methodSpecificId: String?
    private var _metadata: DIDMetadata?

    override init() {}
    
    /// Create a DID identifier with given method name and method specific id.
    /// - Parameters:
    ///   - method: a method name. e.g. "elastos"
    ///   - methodSpecificId: the method specific id string
    init(_ method: String, _ methodSpecificId: String) {
        self._method = method
        self._methodSpecificId = methodSpecificId
    }

    /// Create a new DID according to method specific string.
    /// - Parameter did: A pointer to specific string. The method-specific-id value should be globally unique by itself.
    /// - Throws: Language is empty or error occurs.
    @objc
    public init(_ did: String) throws {
        super.init()
        try checkArgument(!did.isEmpty, "did is empty")

        do {
            try ParserHelper.parse(did, true, DID.Listener(self))
        } catch {
            Log.e(DID.TAG, "Parsing did error: malformed did string \(did)")
            let didError: DIDError? = error as? DIDError
            var errmsg = "Parsing did error: malformed did string \(did)"
            if didError != nil {
                errmsg = didError!.localizedDescription
            }
            throw DIDError.UncheckedError.IllegalArgumentErrors.MalformedDIDError(errmsg)
        }
    }
    
    /// Create a DID object from the given string. The method will parse the
    /// DID method and the method specific id from the string if the string is
    /// not empty. Otherwise will return nil.
    /// - Parameter did: an identifier string.
    /// - Returns: the DID object if the did is not empty, otherwise nil
    public class func valueOf(_ did: String) throws -> DID? {
        return did.isEmpty ? nil : try DID(did)
    }

    /// Get the did method name.
    @objc
    public var method: String {
        return _method!
    }

    func setMethod(_ method: String) {
        self._method = method
    }

    /// Get the method specific id string.
    @objc
    public var methodSpecificId: String {
        return _methodSpecificId!
    }
    
    /// Set the method specific id string.
    /// - Parameter methodSpecificId: the method specific id string.
    func setMethodSpecificId(_ methodSpecificId: String) {
        self._methodSpecificId = methodSpecificId
    }

    /// Get the metadata object that associated with this DID.
    /// - Returns: the metadata object
    @objc
    public func getMetadata() -> DIDMetadata {
        if  self._metadata == nil {
            self._metadata = DIDMetadata()
        }
        return _metadata!
    }
    
    /// Set the metadata that related with this DID.
    /// - Parameter newValue: a metadata object
    func setMetadata(_ newValue: DIDMetadata) {
        self._metadata = newValue
    }
    
    /// Check the DID is deactivated or not.
    @objc
    public var isDeactivated: Bool {
        return getMetadata().isDeactivated
    }

    /// Resolve the DID document.
    /// - Parameter force: if true then ignore the local cache and resolve the DID
    ///                 from the ID chain directly; otherwise will try to load
    ///                 the document from the local cache, if the local cache
    ///                 not contains this DID, then resolve it from the ID chain
    /// - Throws: If error occurs, throw error.
    /// - Returns: the DIDDocument object
    public func resolve(_ force: Bool) throws -> DIDDocument? {
        let doc = try DIDBackend.sharedInstance().resolveDid(self, force)
        if doc != nil {
            setMetadata(doc!.getMetadata())
        }

        return doc
    }

    /// Resolve the DID document.
    /// - Parameter force: if true then ignore the local cache and resolve the DID
    ///                 from the ID chain directly; otherwise will try to load
    ///                 the document from the local cache, if the local cache
    ///                 not contains this DID, then resolve it from the ID chain
    /// - Throws: If error occurs, throw error.
    /// - Returns: the DIDDocument object
    @objc
    public func resolve(_ force: Bool, error: NSErrorPointer) -> DIDDocument? {
        do {
            return try resolve(force)
        } catch let aError as NSError {
            error?.pointee = aError
            return nil
        }
    }

    /// Resolve the DID document.
    /// - Throws: If error occurs, throw error.
    /// - Returns: the DIDDocument object
    public func resolve() throws -> DIDDocument? {
        return try resolve(false)
    }

    /// Resolve the DID document With Object-C
    /// - Throws: If error occurs, throw error.
    /// - Returns: the DIDDocument object
    @objc
    public func resolve(error: NSErrorPointer) -> DIDDocument? {
        do {
            return try resolve(false)
        } catch let aError as NSError {
            error?.pointee = aError
            return nil
        }
    }

    /// Resolve DID Document in asynchronous mode.
    /// - Parameter force: if true then ignore the local cache and resolve the DID
    ///                 from the ID chain directly; otherwise will try to load
    ///                 the document from the local cache, if the local cache
    ///                 not contains this DID, then resolve it from the ID chain
    /// - Returns: a new Promise, the result is the resolved DIDDocument
    public func resolveAsync(_ force: Bool) -> Promise<DIDDocument?> {
        return DispatchQueue.global().async(.promise){ [self] in try self.resolve(force) }
    }

    /// Resolve DID Document in asynchronous mode with Object-C
    /// - Parameter force: if true then ignore the local cache and resolve the DID
    ///                 from the ID chain directly; otherwise will try to load
    ///                 the document from the local cache, if the local cache
    ///                 not contains this DID, then resolve it from the ID chain
    /// - Returns: a new Promise, the result is the resolved DIDDocument
    @objc
    public func resolveAsyncUsingObjectC(_ force: Bool) -> AnyPromise {
        return AnyPromise(__resolverBlock: { [self] resolver in
            DispatchQueue.global().async{
                do {
                    resolver(try resolve(force))
                } catch let error  {
                    resolver(error)
                }
            }
        })
    }

    /// Resolve DID Document in asynchronous mode.
    /// - Returns: a new Promise, the result is the resolved DIDDocument
    public func resolveAsync() -> Promise<DIDDocument?> {
        return resolveAsync(false)
    }

    /// Resolve DID Document in asynchronous mode with Object-C.
    /// - Returns: a new Promise, the result is the resolved DIDDocument.
    @objc
    public func resolveAsyncUsingObjectC() -> AnyPromise {
        return resolveAsyncUsingObjectC(false)
    }

    /// Resolve all DID transactions.
    /// - Throws: If error occurs, throw error.
    /// - Returns: the DIDBiography object
    public func resolveBiography() throws -> DIDBiography? {
        return try DIDBackend.sharedInstance().resolveDidBiography(self)
    }
    
    /// Resolve all DID transactions in asynchronous mode.
    /// - Returns: a new Promise, the result is the resolved DIDBiography
    ///            object if success; nil otherwise
    public func resolveBiographyAsync() throws -> Promise<DIDBiography?> {
        
        return DispatchQueue.global().async(.promise){ [self] in try DIDBackend.sharedInstance().resolveDidBiography(self) }
    }

    /// Resolve all DID transactions in asynchronous mode with Object-C.
    /// - Returns: a new Promise, the result is the resolved DIDBiography
    ///            object if success; nil otherwise
    @objc
    public func resolveHistoryAsyncUsingObjectC() -> AnyPromise {
        return AnyPromise(__resolverBlock: { [self] resolver in
            DispatchQueue.global().async{
                do {
                    resolver(try resolveBiography())
                } catch let error  {
                    resolver(error)
                }
            }
        })
    }
}

extension DID {
    
    /// Return the string representation of this DID object.
    func toString() -> String {
        return String("did:\(_method!):\(_methodSpecificId!)")
    }

    /// Get id string from DID.
    @objc
    public override var description: String {
        return toString()
    }
}

extension DID {
    public func equalsTo(_ other: DID) -> Bool {
        return methodSpecificId == other.methodSpecificId
    }

    public func equalsTo(_ other: String) -> Bool {
        return toString() == other
    }

    public static func == (lhs: DID, rhs: DID) -> Bool {
        return try! lhs.compareTo(rhs) == ComparisonResult.orderedSame
    }

    public static func != (lhs: DID, rhs: DID) -> Bool {
        return !lhs.equalsTo(rhs)
    }

    @objc
    public override func isEqual(_ object: Any?) -> Bool {
        if object is DID {
            return equalsTo(object as! DID)
        }
        else {
            return equalsTo(object as! String)
        }
    }
}

extension DID {
    /// Returns a hash code for this DID object.
    @objc
    public override var hash: Int {
        return self.toString().hash
    }
}

// Parse Listener
extension DID {
    private class Listener: DIDURLBaseListener {
        private var did: DID

        init(_ did: DID) {
            self.did = did
            super.init()
        }

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

extension DID {
    
    /// Compares this DID with the specified DID.
    public func compareTo(_ did: DID) throws -> ComparisonResult {
        
        var result = self.method.compare(did.method)
        if result == ComparisonResult.orderedSame {
            result = self.methodSpecificId.compare(did.methodSpecificId)
        }
        return result
    }

}

