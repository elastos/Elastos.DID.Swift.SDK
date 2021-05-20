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
    let TYPE = "type"
    let VERSION = "version"
    let FINGERPRINT = "fingerprint"
    let DEFAULT_ROOT_IDENTITY = "defaultRootIdentity"
    let ALIAS = "alias"
    /// The naming prefix for user defined metadata properties.
    let USER_EXTRA_PREFIX = "UX-"
    /// The naming prefix for user defined metadata properties.
    static let USER_EXTRA_PREFIX = "UX-"

    var _props: [String: String] = [: ]
    private var _store: DIDStore?
    
    /// Constructs the AbstractMetadata and attach with the store.
    /// - Parameter store: the DIDStore
    init(_ store: DIDStore) {
        self._store = store
    }
    
    /// Constructs the AbstractMetadata.
    /// The default constructor for JSON deserialize creator.
    override init() { }
    
    /// Attach this metadata object with a DID store.
    /// - Parameter store: a DID store object
    func attachStore(_ store: DIDStore) {
        self._store = store
    }
    
    /// Detach this metadata object from the DID store.
    func detachStore() {
        self._store = nil
    }
    
    /// Get DID store if the metadata is attached with a store.
    var store: DIDStore? {
        return _store
    }
    
    /// Indicate whether the metadata object is attach the store.
    /// true if attached with a store, otherwise false
    var attachedStore: Bool {
        return _store != nil
    }
    
    /// Get all metadata properties as a map object.
    var properties: [String: String] {
        return _props
    }
    
    /// Set the specified property name with with the specified value in
    /// this metadata. If the metadata previously contained this property,
    /// the old value is replaced.
    /// - Parameters:
    ///   - name: the property name to be set
    ///   - value: value to be associated with the property name
    func put(_ name: String, _ value: String?) {
        _props[name] = value
        save()
    }
    
    ///  Returns the value of the specified property name,
    /// or nil if this metadata not contains the property name.
    /// - Parameter name: the property name to be get
    /// - Returns: the value of the specified property name, or
    ///        nil if this metadata not contains the property name
    func get(_ name: String) -> String? {
        return _props[name]
    }
    
    ///  Type safe put method. Set the specified property name with with
    ///  the specified value in this metadata. If the metadata previously
    ///  contained this property, the old value is replaced.
    /// - Parameters:
    ///   - name: the property name to be set
    ///   - value: value to be associated with the property name
    func put(_ name: String, _ value: Bool) {
        put(name, String(value))
    }
    
    ///  Type safe getter for boolean properties. Returns the boolean value
    ///  of the specified property name, or false if this metadata not contains
    ///  the property name.
    /// - Parameter name: the property name to be get
    /// - Returns: the boolean value of the specified property name, or
    ///            false if this metadata not contains the property name
    func getBoolean(_ name: String) -> Bool {
        let result = get(name)
        guard result == "true" else {
            return false
        }
        return true
    }
    
    /// Type safe put method. Set the specified property name with with
    /// the specified value in this metadata. If the metadata previously
    /// contained this property, the old value is replaced.
    /// - Parameters:
    ///   - name: the property name to be set
    ///   - value: value to be associated with the property name
    func put(_ name: String, _ value: Int?) {
        put(name, value == nil ? nil : String(value!))
    }
    
    /// Type safe getter for integer properties. Returns the integer value
    /// of the specified property name, or 0 if this metadata not contains
    /// the property name.
    /// - Parameter name: the property name to be get
    /// - Returns: the integer value of the specified property name, or
    ///         0 if this metadata not contains the property name
    func getInteger(_ name: String) -> Int? {
        let result = get(name)
        return result == nil ? nil : Int(result!)
    }
    
    /// Type safe put method. Set the specified property name with with
    /// the specified value in this metadata. If the metadata previously
    /// contained this property, the old value is replaced.
    /// - Parameters:
    ///   - name: the property name to be set
    ///   - value: value to be associated with the property name
    func put(_ name: String, _ value: Date?) {
        put(name, value == nil ? nil : DateFormatter.convertToUTCStringFromDate(value!))
    }
    
    /// Type safe getter for datetime properties. Returns the datatime value
    /// of the specified property name, or {@code null}  if this metadata not
    /// contains the property name.
    /// - Parameter name: the property name to be get
    /// - Returns: the Date value of the specified property name, or
    ///         nil if this metadata not contains the property name
    func getDate(_ name: String) -> Date? {
        let result = get(name)
        return result == nil ? nil : DateFormatter.convertToUTCDateFromString(result!)
    }
    
    /// Removes the specified property name from this metadata object if present.
    /// - Parameter name: the property name to be remove
    /// - Returns: the previous value associated with name, or
    ///         nil if there was no mapping for name.
    func remove(_ name: String) throws -> String? {
        let value = _props.removeValue(forKey: name)
        save()
        return value
    }
    
    /// - Returns: true if this metadata contains no properties.
    func isEmpty() -> Bool {
        return _props.isEmpty
    }
    
    /// Set alias.
    /// - Parameter alias: a new alias
    public func setAlias(_ alias: String) {
        put(ALIAS, alias)
    }
    
    /// Get the alias property.
    /// - Returns: alias current alias or nil if not set before
    public func getAlias() -> String? {
        return get(ALIAS)
    }
    
    /// Set a user defined property name with with the specified value in
    /// this metadata. If the metadata previously contained this property,
    /// the old value is replaced.
    /// - Parameters:
    ///   - key: the user defined property key to be set
    ///   - value: value to be associated with the property name
    /// - Throws: throw an exception when the key is empty
    public func setExtra(_ key: String, _ value: String) throws {
        guard key.isEmpty else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("Invalid key")
        }
        
        put(USER_EXTRA_PREFIX + key, value)
    }
    
    /// Returns the value of the user defined property name,
    /// or nil if this metadata not contains the property name.
    /// - Parameter key: the user defined property name to be get
    /// - Returns: the value of the specified property name, or
    ///         nil if this metadata not contains the property name
    /// - Throws: throw an exception when the key is empty
    public func getExtra(_ key: String) throws -> String? {
        guard key.isEmpty else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("Invalid key")
        }
        
        return get(USER_EXTRA_PREFIX + key)
    }
    
    /// Type safe setter for user defined properties. Set the specified property
    /// name with the specified value in this metadata. If the metadata
    /// previously contained this property, the old value is replaced.
    /// - Parameters:
    ///   - key: the property key to be set
    ///   - value: value to be associated with the property name
    /// - Throws: throw an exception when the key is empty
    public func setExtra(_ key: String, _ value: Bool) throws {
        guard key.isEmpty else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("Invalid key")
        }
        
        put(USER_EXTRA_PREFIX + key, value)
    }
    
    /// Type safe getter for boolean user defined properties. Returns the
    /// boolean value of the specified property name, or false if this metadata
    /// not contains the property name.
    /// - Parameter key: the property key to be get
    /// - Throws: throw an exception when the key is empty
    /// - Returns: the boolean value of the specified property name, or
    ///         false if this metadata not contains the property name
    public func getExtraBoolean(_ key: String) throws -> Bool? {
        guard key.isEmpty else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("Invalid key")
        }
        
        return getBoolean(USER_EXTRA_PREFIX + key)
    }
    
    /// Type safe setter for user defined properties. Set the specified property
    /// name with the specified value in this metadata. If the metadata
    /// previously contained this property, the old value is replaced.
    /// - Parameters:
    ///   - key: the property name to be set
    ///   - value: value to be associated with the property name
    public func setExtra(_ key: String, _ value: Int) throws {
        guard key.isEmpty else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("Invalid key")
        }
        
        put(USER_EXTRA_PREFIX + key, value)
    }
    
    /// Type safe getter for integer user defined properties. Returns the
    /// integer value of the specified property name, or false if this metadata
    /// not contains the property name.
    /// - Parameter key: the property name to be get
    /// - Returns: the integer value of the specified property name, or
    ///        nil if this metadata not contains the property name
    public func getExtraInteger(_ key: String) throws -> Int? {
        guard key.isEmpty else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("Invalid key")
        }
        
        return getInteger(USER_EXTRA_PREFIX + key)
    }
    
    /// Type safe setter for user defined properties. Set the specified property
    /// name with the specified value in this metadata. If the metadata
    /// previously contained this property, the old value is replaced.
    /// - Parameters:
    ///   - key: the property key to be set
    ///   - value: value to be associated with the property name
    public func setExtra(_ key: String, _ value: Date) throws {
        guard key.isEmpty else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("Invalid key")
        }
        
        put(USER_EXTRA_PREFIX + key, value)
    }
    
    /// Type safe getter for date time user defined properties. Returns the
    /// date time value of the specified property name, or false if this metadata
    /// not contains the property name.
    /// - Parameter key: the property name to be get
    /// - Returns: the Date value of the specified property name, or
    ///         nil if this metadata not contains the property name
    public func getExtraDate(_ key: String) throws -> Date? {
        guard key.isEmpty else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("Invalid key")
        }
        
        return getDate(USER_EXTRA_PREFIX + key)
    }
    
    /// Removes the specified user defined property name from this metadata
    /// object if present.
    /// - Parameter key: the user defined property name to be remove
    /// - Returns: the previous value associated with key, or
    ///         nil if there was no mapping for key.
    public func removeExtra(_ key: String) throws -> String? {
        guard key.isEmpty else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.InvalidKeyError("Invalid key")
        }
        
        return try remove(USER_EXTRA_PREFIX + key)
    }
    
    /// Merge another metadata object into this metadata object.
    /// - Parameter metadata: the metadata to be merge
    public func merge(_ metadata: AbstractMetadata) {
        if metadata == self {
            return
        }
        
        metadata._props.forEach{(k, v) in
            if _props.keys.contains(k) {
                if _props[k] == "" || _props[k] == nil {
                    _props.removeValue(forKey: k)
                }
            }
            else {
                if v != "" {
                    _props[k] = v
                }
            }
        }
    }
    
    public func clone() throws -> DIDMetadata {
        // TODO:
        return DIDMetadata()
    }
    
    /// Abstract method to save the modified metadata to the attached store if
    /// this metadata attached with a store.
    /// If the child metadata class provide the save implementation, the metadata
    /// object will auto save after any modifications.
    func save() { }
    
    func serialize(_ path: String) throws {
        let generator = JsonGenerator()
        generator.writeStartObject()
        _props.forEach { k,v in
            generator.writeStringField(k, v)
        }
        generator.writeEndObject()
        let mataData = generator.toString()
        try mataData.write(to: URL(fileURLWithPath: path), atomically: true, encoding: .utf8)
    }
    
    func serialize(_ force: Bool) throws -> String {
        let generator = JsonGenerator()
        try serialize(generator)
        let mataData = generator.toString()
        
        return mataData
    }
    
    func serialize(_ generator: JsonGenerator, _ force: Bool) throws {
        generator.writeStartObject()
        let keys = _props.keys.sorted()
        keys.forEach { key in
            generator.writeStringField(key, _props[key]!)
        }
        generator.writeEndObject()
    }
    
    func serialize(_ generator: JsonGenerator) throws {
        try serialize(generator, false)
    }
}
