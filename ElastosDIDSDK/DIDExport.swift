
import Foundation

public class DIDExport: NSObject {
    let DID_EXPORT = "did.elastos.export/2.0"
    var type: String
    var id: DID
    var _document: DIDExportDocument?
    var _credentials: [DIDExportCredential] = []
    var _privatekeys: [DIDExportPrivateKey] = []
    var created: Date?
    var fingerprint: String?
    
    init(_ type: String, _ id: DID) {
        self.type = type
        self.id = id
        super.init()
    }
    
    public var document: DIDDocument? {
        return _document?.content
    }
    
    public func setDocument(_ doc: DIDDocument) {
        self._document = DIDExportDocument(doc, doc.getMetadata())
    }
    
    public var credentials: [VerifiableCredential] {
        
        var vcs: [VerifiableCredential] = []
        _credentials.forEach { cre in
            vcs.append(cre.content)
        }
        
        return vcs
    }
    public func appendCredential(_ credential: VerifiableCredential) {
        self._credentials.append(DIDExportCredential(credential, credential.getMetadata()))
    }
    
    public var privateKeys: [DIDExportPrivateKey] {
        return _privatekeys
    }
    
    public func appendPrivatekey(_ id: DIDURL, _ privatekey: String, _ storepass: String, _ exportpass: String) throws {
        
        let sk = DIDExportPrivateKey(id)
        try sk.setKey(privatekey, storepass, exportpass)
        self._privatekeys.append(sk)
    }
    
    func calculateFingerprint(_ exportpass: String) throws -> String {
        let sha256 = SHA256Helper()
        var bytes = [UInt8](exportpass.data(using: .utf8)!)
        sha256.update(&bytes)
        
        bytes = [UInt8](type.data(using: .utf8)!)
        sha256.update(&bytes)
        
        bytes = [UInt8](id.toString().data(using: .utf8)!)
        sha256.update(&bytes)
        
        bytes = [UInt8](_document!.content.toString(true).data(using: .utf8)!)
        sha256.update(&bytes)
        
        if _document!.metadata != nil {
            bytes = [UInt8](try _document!.metadata!.serialize(true).data(using: .utf8)!)
            sha256.update(&bytes)
        }
        
        if _credentials.count > 0 {
            for cred in _credentials {
                bytes = [UInt8](cred.content.toString(true).data(using: .utf8)!)
                sha256.update(&bytes)

                if try cred.metadata != nil && cred.metadata!.serialize(true) != "{}" {
                    bytes = [UInt8](try cred.metadata!.serialize(true).data(using: .utf8)!)
                    sha256.update(&bytes)
                }
            }
        }
        
        if _privatekeys.count > 0 {
            for sk in _privatekeys {
                bytes = [UInt8](sk.id.toString().data(using: .utf8)!)
                sha256.update(&bytes)
                
                bytes = [UInt8](sk.key!.data(using: .utf8)!)
                sha256.update(&bytes)
            }
        }
        
        bytes = [UInt8](DateFormatter.convertToUTCStringFromDate(created!).data(using: .utf8)!)
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
    
    public func sealed(using exportpass: String) throws -> DIDExport {
        self.created = DateFormatter.currentDate()
        self.fingerprint = try calculateFingerprint(exportpass)
        
        return self
    }
    
    public func verify(_ exportpass: String) throws {
        if try fingerprint != calculateFingerprint(exportpass) {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedExportDataError("Invalid export data, fingerprint mismatch.")
        }
    }
    
    func sanitize() throws {
        guard type == DID_EXPORT else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedExportDataError("Invalid export data, unknown type.")
        }
        guard let _ = created else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedExportDataError("Invalid export data, missing created time.")
        }
        
        guard let _ = _document else {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedExportDataError("Invalid export data, missing document.")
        }
        
        if _document!.metadata != nil {
            _document!.content.setMetadata(_document!.metadata!)
        }

        for cre in _credentials {
            if cre.metadata != nil {
                cre.content.setMetadata(cre.metadata!)
            }
        }
        
        for sk in _privatekeys {
            if sk.key == nil || sk.key!.isEmpty {
                throw DIDError.CheckedError.DIDSyntaxError.MalformedExportDataError("Invalid export data, invalid privatekey.")
            }
        }
        
        if fingerprint == nil || fingerprint!.isEmpty {
            throw DIDError.CheckedError.DIDSyntaxError.MalformedExportDataError("Invalid export data, missing fingerprint.")
        }
    }
    
    func serialize(_ force: Bool) throws -> String {
        try sanitize()
        let generator = JsonGenerator()
        generator.writeStartObject()
        generator.writeStringField("type", type)
        generator.writeStringField("id", id.toString())
        
        if let _ = _document {
            generator.writeFieldName("document")
            try _document!.serialize(generator)
        }
        
        if _credentials.count > 0 {
            generator.writeFieldName("credential")
            generator.writeStartArray()
            for cre in _credentials {
                try cre.serialize(generator)
            }
            generator.writeEndArray()
        }
        
        if privateKeys.count > 0 {
            generator.writeFieldName("privateKey")
            generator.writeStartArray()
            for sk in privateKeys {
                try sk.serialize(generator)
            }
            generator.writeEndArray()
        }
        if let _ = created {
            generator.writeStringField("created", DateFormatter.convertToUTCStringFromDate(created!))
        }
        if let _ = fingerprint {
            generator.writeStringField("fingerprint", fingerprint!)
        }
        generator.writeEndObject()
        
        return generator.toString()
    }
    
    public class func deserialize(_ content: [String: Any]) throws -> DIDExport{
        let type = content["type"] as! String
        let id = content["id"] as! String
        let didex = try DIDExport(type, DID(id))
        
        let document = content["document"] as? [String: Any]
        if let _ = document {
            didex._document = try DIDExportDocument.deserialize(document!)
        }
        
        let credential = content["credential"] as? [[String: Any]]
        if let _ = credential {
            for cre in credential! {
                didex._credentials.append(try DIDExportCredential.deserialize(cre))
            }
        }
        
        let privatekey = content["privateKey"] as? [[String: Any]]
        if let _ = privatekey {
            for sk in privatekey! {
                didex._privatekeys.append(try DIDExportPrivateKey.deserialize(sk))
            }
        }
        
        let created = content["created"] as? String
        if let _ = created {
            didex.created = DateFormatter.convertToUTCDateFromString(created!)
        }
        
        let fingerprint = content["fingerprint"] as? String
        if let _ = fingerprint {
            didex.fingerprint = fingerprint
        }
        
        return didex
    }
}

class DIDExportDocument: NSObject {
    let CONTENT = "content"
    let METADATA = "metadata"
    var content: DIDDocument
    var metadata: DIDMetadata?
    
    init(_ content: DIDDocument, _ metadata: DIDMetadata?) {
        self.content = content
        self.metadata = metadata
        super.init()
    }
    
    func serialize(_ generator: JsonGenerator) throws {
        generator.writeStartObject()
        generator.writeFieldName("content")
        try content.serialize(generator, true)
        
        if let _ = metadata {
            generator.writeFieldName("metadata")
            try metadata!.serialize(generator)
        }
        generator.writeEndObject()
    }
    
    public class func deserialize(_ content: [String: Any]) throws -> DIDExportDocument {
        let document = content["content"] as! [String: Any]
        let metadata = content["metadata"] as? [String: Any]

        if let _ = metadata {
            return try DIDExportDocument(DIDDocument.convertToDIDDocument(fromDictionary: document), DIDMetadata.deserialize(metadata!.toJsonString()!))
        }
        
        return try DIDExportDocument(DIDDocument.convertToDIDDocument(fromDictionary: content), nil)
    }
}

class DIDExportCredential: NSObject {
    let CONTENT = "content"
    let METADATA = "metadata"
    var content: VerifiableCredential
    var metadata: CredentialMetadata?
    
    init(_ content: VerifiableCredential, _ metadata: CredentialMetadata?) {
        self.content = content
        self.metadata = metadata
        super.init()
    }
    
    func serialize(_ generator: JsonGenerator) throws {
        generator.writeStartObject()
        generator.writeFieldName("content")
        content.serialize(generator, true)
        
        if let _ = metadata {
            generator.writeFieldName("metadata")
            try metadata!.serialize(generator)
        }
        generator.writeEndObject()
    }
    
    public class func deserialize(_ content: [String: Any]) throws -> DIDExportCredential {
        let document = content["content"] as! [String: Any]
        let metadata = content["metadata"] as? [String: Any]
        
        if metadata != nil && metadata!.toJsonString() != "{}"  {
            return try DIDExportCredential(VerifiableCredential.fromJson(for: document), CredentialMetadata.deserialize(content: metadata!.toJsonString()!))
        }
        
        return try DIDExportCredential(VerifiableCredential.fromJson(for: document), nil)
    }
}

public class DIDExportPrivateKey: NSObject {
    let ID = "id"
    let KEY = "key"
    var id: DIDURL
    var key: String?
    
    init(_ id: DIDURL) {
        self.id = id
        super.init()
    }
    
    func getKey(_ exportpass: String, _ storepass: String) throws -> String {
        return try DIDStore.reEncrypt(key!, exportpass, storepass)
    }
    
    func setKey(_ key: String, _ storepass: String, _ exportpass: String) throws {
        self.key = try DIDStore.reEncrypt(key, storepass, exportpass)
    }
    
    func serialize(_ generator: JsonGenerator) throws {
        generator.writeStartObject()
        generator.writeStringField("id", id.toString())
        if  let _ = key {
            generator.writeStringField("key", key!)
        }
        generator.writeEndObject()
    }
    
    public class func deserialize(_ content: [String: Any]) throws -> DIDExportPrivateKey {
        let id = content["id"] as! String
        let key = content["key"] as! String
        
        let sk = try DIDExportPrivateKey(DIDURL(id))
        sk.key = key
        
        return sk
    }
}

