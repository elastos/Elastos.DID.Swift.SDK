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
    override init() {
        super.init()
        put(TYPE, DIDStore.DID_STORE_TYPE)
        put(VERSION, DIDStore.DID_STORE_VERSION)
    }
    
    /// Constructs the empty DIDMetadataImpl.
    override init(_ store: DIDStore) {
        super.init(store)
        put(TYPE, DIDStore.DID_STORE_TYPE)
        put(VERSION, 1)
    }
    
    public var type: String {
        return get(TYPE)!
    }
    
    public var version: Int {
        return getInteger(VERSION)!
    }
    
    func setFingerprint(_ fingerprint: String) throws {
        try checkArgument(!fingerprint.isEmpty, "Invalid fingerprint")
        put(FINGERPRINT, fingerprint)
    }
    
    public var fingerprint: String? {
       
        return get(FINGERPRINT)
    }
    
    func setDefaultRootIdentity(_ id: String?) throws {
        put(DEFAULT_ROOT_IDENTITY, id)
    }
    
    public var defaultRootIdentity: String {
       
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
    
    func serialize(_ path: String) throws {
        let generator = JsonGenerator()
        generator.writeStartObject()
        generator.writeStringField(TYPE, _props[TYPE]!)
        generator.writeStringField(VERSION, _props[VERSION]!)
        _props.forEach { k,v in
            guard k != TYPE, k != VERSION else {
                return
            }
            generator.writeStringField(k, v)
        }
        generator.writeEndObject()
        try generator.toString().write(to: URL(fileURLWithPath: path), atomically: true, encoding: .utf8)
    }
    
    class func parse(_ path: String) throws -> DIDStoreMetadata {
        let data: Data = try path.forReading()
        let dic: [String: String] = try data.dataToDictionary()
        let metadata = DIDStoreMetadata()
        metadata._props = dic
        
        return metadata
    }
}
