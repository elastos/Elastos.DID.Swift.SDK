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

/// The class defines the implement of DID Metadata.
public class DIDStoreMetadata: AbstractMetadata {
    private let TAG = NSStringFromClass(DIDStoreMetadata.self)
    private let TYPE = "type"
    private let VERSION = "version"
    private let FINGERPRINT = "fingerprint"
    private let DEFAULT_ROOT_IDENTITY = "defaultRootIdentity"
    
    /// The default constructor for JSON deserialize creator.
    override init() { super.init() }
    
    /// Constructs the empty DIDMetadataImpl.
    override init(_ store: DIDStore) {
        super.init(store)
        put(TYPE, DIDStore.DID_STORE_TYPE)
        put(VERSION, 1)
    }
    
    public func getType() -> String {
        return get(TYPE)!
    }
    
    public func getVersion() -> Int {
        return getInteger(VERSION)!
    }
    
    func setFingerprint(_ fingerprint: String) throws {
        try checkArgument(!fingerprint.isEmpty, "Invalid fingerprint")
        try put(FINGERPRINT, fingerprint)
    }
    
    public func getFingerprint() -> String? {
       
        return get(FINGERPRINT)
    }
    
    func setDefaultRootIdentity(_ id: String?) throws {
        try put(DEFAULT_ROOT_IDENTITY, id)
    }
    
    public func getDefaultRootIdentity() -> String {
       
        return get(DEFAULT_ROOT_IDENTITY)!
    }
    
    override func save() {
       
        if attachedStore {
            do {
                try store!.storage!.storeMetadata(self)
            } catch {
                Log.e(TAG, "INTERNAL - error store metadata for DIDStore")
            }
        }
    }
    func serialize(_ path: String) {
        // TODO:
    }
    
    class func parse(_ path: String) -> DIDStoreMetadata {
        // TODO:
        return DIDStoreMetadata()
    }
}
/*
@objc(Metadata)
public class Metadata: NSObject {
    static let RESERVED_PREFIX = "DX-"
    static let LAST_MODIFIED = RESERVED_PREFIX + "lastModified"
    private var _store: DIDStore?
    private var _extra = Dictionary<String, Any>()

    @objc public required override init() {}

    init(store: DIDStore) {
        super.init()
        setStore(store)
    }

    /// Get store.
    @objc
    public var store: DIDStore? {
        return self._store
    }

    /// Check is attached store or not.
    @objc
    public var attachedStore: Bool {
        return self._store != nil
    }

    /// Set store for did.
    /// - Parameter store: The handle of DIDStore.
    @objc
    public func setStore(_ store: DIDStore) {
        self._store = store
    }

    /// Set last modify for metadata.
    /// - Parameter timestamp: The time of metadata modified.
    @objc
    public func setLastModified(_ timestamp: Date) {
        put(key: Metadata.LAST_MODIFIED, value: DateFormatter.convertToUTCStringFromDate(timestamp))
    }

    /// Get last modify for metadata.
    /// - Returns: The time of metadata modified.
    @objc
    public func getLastModified() -> Date? {
        if let date = get(key: Metadata.LAST_MODIFIED) as? String {
            let time = DateFormatter.convertToUTCDateFromString(date)
            return time
        }

        return nil
    }

    /// Clear last modified for metadata.
    @objc
    public func clearLastModified() {
        _extra.removeValue(forKey: Metadata.LAST_MODIFIED)
    }

    /// Set ‘string’ extra elemfor did.
    /// - Parameters:
    ///   - key: The key string.
    ///   - value: The value string.
    @objc
    public func setExtra(_ key: String, _ value: String?) {
        self._extra[key] = value
    }

    /// Get ‘string’ extra elem from DID.
    /// - Parameter key: The key string.
    /// - Returns: The elem string
    @objc
    public func getExtra(_ key: String) -> String? {
        return self._extra[key] as? String
    }

    /// Merge meta.
    /// - Parameter meta: The metadata foe merge.
    /// - Throws: If error occurs, throw error.
    @objc
    public func merge(_ meta: Metadata) throws {
        meta._extra.forEach{ (key, value) in
            if _extra.keys.contains(key) {
                if _extra[key] == nil {
                    _extra.removeValue(forKey: key)
                }
            }
            else {
                if case Optional<Any>.none = value {
                    return
                }
                _extra[key] = value
            }
        }
    }

    /// Load metadata.
    /// - Parameter reader: The FileHandle of metadata data.
    /// - Throws: If error occurs, throw error.
    @objc
    public func load(reader: FileHandle) throws {
        let data = reader.readDataToEndOfFile()
        defer {
            reader.closeFile()
        }
        var node = JsonNode()
        do {
            let json = try JSONSerialization.jsonObject(with: data, options: .mutableContainers)
            let dic = json as! Dictionary<String, Any>
            node = JsonNode(dic)
        } catch {
            throw DIDError.didMetaDateLocalFormatError("Loading metadata format error.")
        }

        try load(node)
    }

    /// Load metadata.
    /// - Parameter node: The JsonNode of metadata data.
    /// - Throws: If error occurs, throw error.
    @objc
    public func load(_ node: JsonNode) throws {
        let dic = node.asDictionary()
        try dic?.forEach{ (key, value) in
            switch value.getNodeType() {

            case .BOOLEAN:
                _extra[key] = value.asBool()
                break;
            case .NIL:
                break
            case .NUMBER:
                _extra[key] = value.asNumber()
                break;
            case .STRING:
                _extra[key] = value.asString()
                break;
            default:
                throw DIDError.malformedMeta("Unsupported field: \(key)")
            }
        }
    }

    /// Add key-value for metadata.
    /// - Parameters:
    ///   - key: The key string.
    ///   - value: The value string.
    @objc
    public func put(key: String, value: Any) {
        _extra[key] = value
    }

    /// Get metadata value by key.
    /// - Parameter key: The key string.
    /// - Returns: If error occurs, throw error.
    @objc
    public func get(key: String) -> Any {
        return _extra[key] as Any
    }

    private func save(_ generator: JsonGenerator) throws {
        generator.writeStartObject()

        let sortedKeys = _extra.keys.sorted()
        for key in sortedKeys {
            let value = _extra[key] as Any
            if case Optional<Any>.none = value {
                // Continue
            } else if value is Int {
                generator.writeNumberField(key, value as! Int)
            } else if value is Bool {
                generator.writeBoolField(key, value as! Bool)
            } else if value is String {
                generator.writeStringField(key, value as! String)
            } else if value is Date {
                generator.writeStringField(key, DateFormatter.convertToUTCStringFromDate(value as! Date))
            } else {
                throw DIDError.malformedMeta("Can not serialize attribute: \(key)")
            }
        }
        generator.writeEndObject()
    }

    /// Save metada.
    /// - Parameter path: The path to save metada.
    /// - Throws: If error occurs, throw error.
    @objc
    public func save(path: FileHandle) throws {
        defer {
            path.closeFile()
        }

        let generator = JsonGenerator()
        try save(generator)
        path.write(generator.toString().data(using: .utf8)!)
    }

    /// Get string of metadata.
    /// - Throws: If error occurs, throw error.
    /// - Returns: Metadata string.
    @objc
    public func toJson() throws -> String {
        let generator = JsonGenerator()
        try save(generator)

        return generator.toString()
    }

    /// Check metadata is empty or not.
    /// - Returns: true if metadata is empty, otherwise false.
    @objc
    public func isEmpty() -> Bool {
        return _extra.isEmpty
    }
}

extension Metadata {

    /// Get string of metadata.
    /// - Throws: If error occurs, throw error.
    /// - Returns: Metadata string.
    @objc
    public func toString() throws -> String {
        return try toJson()
    }
}
*/