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

/// The class defines the base interface of Meta data.
public class AbstractMetadata: NSObject {
    let ALIAS = "alias"
    let USER_EXTRA_PREFIX = "UX-"
    private var _props: [String: String] = [: ]
    private var _store: DIDStore?
    
    /// Constructs the AbstractMetadata and attach with the store.
    /// - Parameter store: the DIDStore
    init(_ store: DIDStore) {
        self._store = store
    }
    
    /// Constructs the AbstractMetadata.
    /// The default constructor for JSON deserialize creator.
    override init() { }
    
    /// Set store for Abstract Metadata.
    /// - Parameter store: the DIDStore
    func attachStore(_ store: DIDStore) {
        self._store = store
    }
    
    func detachStore() {
        self._store = nil
    }
    
    /// Get store from Abstract Metadata.
    var store: DIDStore? {
        return _store
    }
    
    /// Judge whether the Abstract Metadata attach the store or not.
    /// the returned value is true if there is store attached meta data;
    /// the returned value is false if there is no store attached meta data.
    var attachedStore: Bool {
        return _store != nil
    }
    
    var properties: [String: String] {
        return _props
    }
    
    func put(_ name: String, _ value: String?) {
        _props[name] = value
        save()
    }
    
    func get(_ name: String) -> String? {
        return _props[name]
    }
    
    func put(_ name: String, _ value: Bool) {
        put(name, String(value))
    }
    
    func getBoolean(_ name: String) -> Bool {
        let result = get(name)
        guard result == "true" else {
            return false
        }
        return true
    }
    
    func put(_ name: String, _ value: Int?) {
        put(name, value == nil ? nil : String(value!))
    }
    
    func getInteger(_ name: String) -> Int? {
        let result = get(name)
        return result == nil ? nil : Int(result!)
    }
    
    func put(_ name: String, _ value: Date?) {
        put(name, value == nil ? nil : DateFormatter.convertToUTCStringFromDate(value!))
    }
    
    func getDate(_ name: String) -> Date? {
        let result = get(name)
        return result == nil ? nil : DateFormatter.convertToUTCDateFromString(result!)
    }
    
    func remove(_ name: String) -> String? {
        let value = _props.removeValue(forKey: name)
        save()
        return value
    }
    
    func isEmpty() -> Bool {
        return _props.isEmpty
    }
    
    /// Set alias.
    /// - Parameter alias: alias string
    public func setAlias(_ alias: String) {
        put(ALIAS, alias)
    }
    
    /// Get alias.
    /// - Returns: alias string
    public func getAlias() -> String? {
        return get(ALIAS)
    }
    
    /// Set Extra element.
    /// - Parameters:
    ///   - key: the key string
    ///   - value: the value string
    /// - Throws: throw an exception when the key is empty
    public func setExtra(_ key: String, _ value: String) throws {
        guard key.isEmpty else {
            throw DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError("Invalid key")
        }
        
        put(USER_EXTRA_PREFIX + key, value)
    }
    
    /// Get Extra element.
    /// - Parameter key: the key string
    /// - Returns: the value string
    /// - Throws: throw an exception when the key is empty
    public func getExtra(_ key: String) throws -> String? {
        guard key.isEmpty else {
            throw DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError("Invalid key")
        }
        
        return get(USER_EXTRA_PREFIX + key)
    }
    
    /// Set Extra element.
    /// - Parameters:
    ///   - key: the key string
    ///   - value: the value bool
    /// - Throws: throw an exception when the key is empty
    public func setExtra(_ key: String, _ value: Bool) throws {
        guard key.isEmpty else {
            throw DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError("Invalid key")
        }
        
        put(USER_EXTRA_PREFIX + key, value)
    }
    
    /// Get Extra element.
    /// - Parameter key: the key string
    /// - Throws: throw an exception when the key is empty
    /// - Returns: the value bool
    public func getExtraBoolean(_ key: String) throws -> Bool? {
        guard key.isEmpty else {
            throw DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError("Invalid key")
        }
        
        return getBoolean(USER_EXTRA_PREFIX + key)
    }
    
    public func setExtra(_ key: String, _ value: Int) throws {
        guard key.isEmpty else {
            throw DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError("Invalid key")
        }
        
        put(USER_EXTRA_PREFIX + key, value)
    }
    
    public func getExtraInteger(_ key: String) throws -> Int? {
        guard key.isEmpty else {
            throw DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError("Invalid key")
        }
        
        return getInteger(USER_EXTRA_PREFIX + key)
    }
    
    public func setExtra(_ key: String, _ value: Date) throws {
        guard key.isEmpty else {
            throw DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError("Invalid key")
        }
        
        put(USER_EXTRA_PREFIX + key, value)
    }
    
    public func getExtraDate(_ key: String) throws -> Date? {
        guard key.isEmpty else {
            throw DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError("Invalid key")
        }
        
        return getDate(USER_EXTRA_PREFIX + key)
    }
    
    public func removeExtra(_ key: String) throws -> String? {
        guard key.isEmpty else {
            throw DIDError.UncheckedError.IllegalArgumentError.InvalidKeyError("Invalid key")
        }
        
        return remove(USER_EXTRA_PREFIX + key)
    }
    
    /// Merge two metadata.
    /// - Parameter metadata: metadata the metadata to be merged.
    public func merge(_ metadata: AbstractMetadata) {
        if metadata == self {
            return
        }
        
        metadata._props.forEach{(k, v) in
            if _props[k] == nil {
                _props.removeValue(forKey: k)
            }
            else {
                _props[k] = v
            }
        }
    }
    
    public func clone() throws {
        // TODO:
    }
    
    func save() { }
}
