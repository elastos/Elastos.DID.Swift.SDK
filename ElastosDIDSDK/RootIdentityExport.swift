

import Foundation

public class RootIdentityExport: NSObject {
    let DID_EXPORT = "did.elastos.export/2.0"
    let TYPE = "type"
    let MNEMONIC = "mnemonic"
    let PRIVATEKEY = "privateKey"
    let PUBLICKEY = "publicKey"
    let INDEX = "index"
    let DEFAULT = "default"
    let CREATED = "created"
    let FINGERPRINT = "fingerprint"
    
    var _type: String
    var _mnemonic: String?
    var _privateKey: String?
    var _publicKey: String?
    var _index: Int?
    var _default: Bool = false
    var _created: Date?
    var _fingerprint: String?
    
    init(_ type: String) {
        self._type = type
        super.init()
    }
    
    public func getMnemonic(_ exportpass: String, _ storepass: String) throws -> String? {
        return try _mnemonic == nil ? nil : DIDStore.reEncrypt(_mnemonic!, exportpass, storepass)
    }
    
    public func setMnemonic(_ mnemonic: String, _ storepass: String, _ exportpass: String) throws {
        self._mnemonic = try DIDStore.reEncrypt(mnemonic, storepass, exportpass)
    }
    
    public func getPrivateKey(_ exportpass: String, _ storepass: String) throws -> String {
        return try DIDStore.reEncrypt(_privateKey!, exportpass, storepass)
    }
    
    public func setPrivateKey(_ privateKey: String, _ storepass: String, _ exportpass: String) throws {
        self._privateKey = try DIDStore.reEncrypt(privateKey, storepass, exportpass)
    }
    
    public var publicKey: String {
        return _publicKey!
    }
    
    public func setPubkey(_ publicKey:  String) {
        self._publicKey = publicKey
    }
    
    public var index: Int {
        return _index!
    }
    
    public func setIndex(_ index:  Int) {
        self._index = index
    }
    
    public var isDefault: Bool {
        return _default
    }
    
    public func setDefault() {
        self._default = true
    }
    
    func calculateFingerprint(_ exportpass: String) throws -> String {
        let sha256 = SHA256Helper()
        var bytes = [UInt8](exportpass.data(using: .utf8)!)
        sha256.update(&bytes)
        
        bytes = [UInt8](_type.data(using: .utf8)!)
        sha256.update(&bytes)
        
        if let _ = _mnemonic {
            bytes = [UInt8](_mnemonic!.data(using: .utf8)!)
            sha256.update(&bytes)
        }
        
        bytes = [UInt8](_privateKey!.data(using: .utf8)!)
        sha256.update(&bytes)
        
        bytes = [UInt8](_publicKey!.data(using: .utf8)!)
        sha256.update(&bytes)
        
        bytes = [UInt8]("\(_index!)".data(using: .utf8)!)
        sha256.update(&bytes)
        
        bytes = [UInt8]("\(_default)".data(using: .utf8)!)
        sha256.update(&bytes)
        
        bytes = [UInt8](DateFormatter.convertToUTCStringFromDate(_created!).data(using: .utf8)!)
        sha256.update(&bytes)
        
        // Fingerprint
        let result = sha256.finalize()

        let capacity = result.count * 3
        let cFing = UnsafeMutablePointer<CChar>.allocate(capacity: capacity)
        let dateFing = Data(bytes: result, count: result.count)
        let cFingerprint = dateFing.withUnsafeBytes { fing -> UnsafePointer<UInt8> in
            return fing
        }
        let re = b64_url_encode(cFing, cFingerprint, dateFing.count)
        cFing[re] = 0
        let fingerprint = String(cString: cFing)
        
        return fingerprint
    }
    
    public func sealed(using exportpass: String) throws -> RootIdentityExport {
        self._created = DateFormatter.currentDate()
        self._fingerprint = try calculateFingerprint(exportpass)
        
        return self
    }
    
    public func verify(_ exportpass: String) throws {
        if try _fingerprint != calculateFingerprint(exportpass) {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedExportDataError("Invalid export data, fingerprint mismatch.")
        }
    }
    
    func sanitize() throws {
        guard _type == DID_EXPORT else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedExportDataError("Invalid export data, unknown type.")
        }
        guard let _ = _created else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedExportDataError("Invalid export data, missing created time.")
        }
        
        guard let _ = _privateKey else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedExportDataError("Invalid export data, missing key.")
        }
        
        if _fingerprint == nil || _fingerprint!.isEmpty {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedExportDataError("Invalid export data, missing fingerprint.")
        }
    }
    
    func serialize(_ force: Bool) throws -> String {
        try sanitize()
        let generator = JsonGenerator()
        generator.writeStartObject()
        generator.writeStringField(TYPE, _type)
        generator.writeStringField(MNEMONIC, _mnemonic!)
        generator.writeStringField(PRIVATEKEY, _privateKey!)
        if let _ = _publicKey {
            generator.writeStringField(PUBLICKEY, _publicKey!)
        }
        if let _ = _index {
            generator.writeNumberField(INDEX, _index!)
        }
        
        generator.writeBoolField(DEFAULT, _default)
        generator.writeStringField(CREATED, DateFormatter.convertToUTCStringFromDate(_created!))
        generator.writeStringField(FINGERPRINT, _fingerprint!)

        generator.writeEndObject()
        return generator.toString()
    }
    
    public class func deserialize(_ content: [String: Any]) throws -> RootIdentityExport {
        let type = content["type"] as! String
        let mnemonic = content["mnemonic"] as? String
        let re = RootIdentityExport(type)
        re._mnemonic = mnemonic
        
        let privateKey = content["privateKey"] as? String
        re._privateKey = privateKey
        
        let publicKey = content["publicKey"] as? String
        re._publicKey = publicKey
        
        let index = content["index"] as? Int
        re._index = index
        
        let _default = content["default"] as? Bool
        re._default = _default == nil ? false : _default!
       
        let created = content["created"] as? String
        if let _ = created {
            re._created = DateFormatter.convertToUTCDateFromString(created!)
        }
        
        let fingerprint = content["fingerprint"] as? String
        if let _ = fingerprint {
            re._fingerprint = fingerprint
        }
        
        return re
    }
}

