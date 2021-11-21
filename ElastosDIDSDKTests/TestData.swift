
import XCTest
@testable import ElastosDIDSDK

class TestData {
    static var rootKey: DIDHDKey?
    static var index: Int?
    
    var store: DIDStore?
    var mnemonic: String = ""
    var identity: RootIdentity?
    
    var v1: CompatibleData?
    var v2: CompatibleData?
    var v3: CompatibleData?

    var instantData: InstantData?
    init() {
        do {
            TestData.deleteFile(storeRoot)
            store = try DIDStore.open(atPath: storeRoot)
            v1 = CompatibleData(1, store!)
            v2 = CompatibleData(2, store!)
            v3 = CompatibleData(3, store!)

        } catch {
            print(error)
        }
    }

    func cleanup() {
        if store != nil {
            store!.close()
        }
        try? DIDBackend.sharedInstance().clearCache()
    }
    
    func reset() {
        let urlStr = "http://localhost:\(DEFAULT_PORT)" + "/reset"
        let url = URL(string: urlStr)!
        var request = URLRequest.init(url: url, cachePolicy: .useProtocolCachePolicy, timeoutInterval: 60)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
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
        
        print(result)
    }
    
    public class func generateKeypair() throws -> DIDHDKey {
        if TestData.rootKey == nil {
            let mnemonic: String = try Mnemonic.generate(Mnemonic.DID_ENGLISH)
            TestData.rootKey = DIDHDKey(mnemonic, "", Mnemonic.DID_ENGLISH)
            TestData.index = 0
        }
        let path: String = DIDHDKey.DID_DERIVE_PATH_PREFIX + "\(TestData.index!)"
        TestData.index = TestData.index! + 1

        return try TestData.rootKey!.derive(path)
    }

    public func getRootIdentity() throws -> RootIdentity {
        if identity == nil {
            mnemonic = try Mnemonic.generate(Mnemonic.DID_ENGLISH)
            identity = try RootIdentity.create(mnemonic, passphrase, true, store!, storePassword)
        }
        
        return identity!
    }
    
    public func getCompatibleData(_ version: Int) throws -> CompatibleData {
        switch (version) {
        case 1:
            if (v1 == nil) {
                v1 = CompatibleData(version, store!)
            }
            return v1!
        case 2:
            if (v2 == nil) {
                v2 = CompatibleData(version, store!)
            }
            return v2!
        case 3:
            if (v3 == nil) {
                v3 = CompatibleData(version, store!)
            }
            return v3!
            
        default:
            throw TestError.failue("Unsupported version")
        }
    }
    
    func sharedInstantData() -> InstantData {
        if (instantData == nil) {
            instantData = InstantData(self)
        }
        
        return instantData!
    }
    
//    func wait(interval: Double) {

//        let lock = XCTestExpectation(description: "")

//        DispatchQueue.main.asyncAfter(deadline: DispatchTime.now() + interval) {
//            lock.fulfill()
//        }
//        wait(for: [lock], timeout: interval + 10)
//    }

    class func getResolverCacheDir() -> String {
        return "\(NSHomeDirectory())/Library/Caches/.cache.did.elastos"
    }
  
   class func deleteFile(_ path: String) {
        do {
            let filemanager: FileManager = FileManager.default
            var isdir = ObjCBool.init(false)
            let fileExists = filemanager.fileExists(atPath: path, isDirectory: &isdir)
            if fileExists && isdir.boolValue {
                if let dircontents = filemanager.enumerator(atPath: path) {
                    for case let url as URL in dircontents {
                        deleteFile(url.absoluteString)
                    }
                }
            }
            guard fileExists else {
                return
            }
            try filemanager.removeItem(atPath: path)
        } catch {
            print("deleteFile error: \(error)")
        }
    }
    
    func exists(_ dirPath: String) -> Bool {
        let fileManager = FileManager.default
        var isDir : ObjCBool = false
        if fileManager.fileExists(atPath: dirPath, isDirectory:&isDir) {
            if isDir.boolValue {
                return true
            }
        }
        return false
    }
    
    func existsFile(_ path: String) -> Bool {
        let fileManager = FileManager.default
        var isDir : ObjCBool = false
        fileManager.fileExists(atPath: path, isDirectory:&isDir)
        let readhandle = FileHandle.init(forReadingAtPath: path)
        let data: Data = (readhandle?.readDataToEndOfFile()) ?? Data()
        let str: String = String(data: data, encoding: .utf8) ?? ""
        return str.count > 0 ? true : false
    }
    
    func currentDateToWantDate(_ year: Int)-> Date {
        let current = Date()
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(abbreviation: "UTC")!
        var comps:DateComponents?
        
        comps = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: current)
        comps?.year = 5 // TODO:
        comps?.month = 0
        comps?.day = 0
        comps?.hour = 0
        comps?.minute = 0
        comps?.second = 0
        comps?.nanosecond = 0
        let realDate = calendar.date(byAdding: comps!, to: current) ?? Date()
        let hour = calendar.component(.hour, from: realDate)
        let useDate = calendar.date(bySettingHour: hour, minute: 00, second: 00, of: realDate) ?? Date()
        
        return useDate
    }
}

extension String {
    var asciiArray: [UInt32] {
        return unicodeScalars.filter{$0.isASCII}.map{$0.value}
    }

    /*
    func toUnsafePointerUInt8() -> UnsafePointer<UInt8>? {
        guard let data: Data = self.data(using: .utf8) else {
            return nil
        }
        
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
        let stream = OutputStream(toBuffer: buffer, capacity: data.count)
        stream.open()
        let value = data.withUnsafeBytes {
            $0.baseAddress?.assumingMemoryBound(to: UInt8.self)
        }
        guard let val = value else {
            return nil
        }
        stream.write(val, maxLength: data.count)
        stream.close()
        
        return UnsafePointer<UInt8>(buffer)
    }
    */
    
    func toUnsafePointerInt8() -> UnsafePointer<Int8>? {
        let str: NSString = self as NSString
        let strUnsafe = str.utf8String
        return strUnsafe
    }
    
    func toUnsafeMutablePointerInt8() -> UnsafeMutablePointer<Int8>? {
        return strdup(self)
    }
}

public class CompatibleData {
    var dataPath: String = "resources/v1/testdata/"
    var storePath: String = "resources/v1/teststore/"
    var data: [String: Any] = [: ]
    var version: Int = 1
    var store: DIDStore?
    
    init(_ version: Int, _ store: DIDStore) {
        self.version = version
        self.dataPath = "resources/v\(version)/testdata/"
        self.storePath = "resources/v\(version)/teststore/"
        self.store = store
    }
    
    func test1() {
        print("123")
       let re = listFiles(dataPath, "sk")
        let kfs = re.filter(re, dataPath, "user1.id.", ".sk")
        kfs.forEach { kf in
            let start = kf.count - "user1".count - 4
            var fragment = kf.suffix(start)
            let end = fragment.count - 3
            fragment = fragment.prefix(end)
        }
        
        print("kfs == \(kfs)")
    }
    
    var isLatestVersion: Bool {
        return version == 3
    }
    
    func getDidFile(_ name: String, _ type: String?) -> String {
        var str = dataPath
        str.append(name)
        str.append(".id")
        if let _ = type {
            str.append(".\(type!)")
        }
        str.append(".json")
        print("path = \(str)")
        
        return str
    }
    
    func getCredentialFile(_ did: String, _ vc: String, _ type: String?) -> String {
        var str = dataPath
        str.append(did)
        str.append(".vc.")
        str.append(vc)
        if let _ = type {
            str.append(".\(type!)")
        }
        str.append(".json")

        return str
    }
    
    func getTransferTicketFile(_ name: String) -> String {
        if (version == 1) {
            return ""
        }
        
        return dataPath + "/" + name + ".tt.json"
    }
    
    func getPresentationFile(_ did: String, _ vp: String, _ type: String?) -> String {
        var str = dataPath
        str.append(did)
        str.append(".vp.")
        str.append(vp)
        if let _ = type {
            str.append(".\(type!)")
        }
        str.append(".json")

        return str
    }
    
    func getTransferTicket(_ did: String) throws -> TransferTicket{
        if (version == 1) {
            throw TestError.failue("Not exists")
        }
        
        let key = "res:tt:" + did
        if data.keys.contains(key) {
            return data[key] as! TransferTicket
        }
        // load the presentation
        var text = try loadText(getTransferTicketFile(did))
        text = text.replacingOccurrences(of: "\n", with: "")
        text = text.replacingOccurrences(of: " ", with: "")
        let transferTicket = try TransferTicket.deserialize(text)
        data[key] = transferTicket
        
        return transferTicket
    }
    
    public func loadText(_ path: String) throws -> String {
        let bl = Bundle(for: type(of: self))
        let paths = path.replacingOccurrences(of: bl.bundlePath, with: "").slip()
        let filepath = bl.path(forResource: paths[0], ofType: paths[1])
        let json = try String(contentsOf: URL(fileURLWithPath: filepath!), encoding: .utf8)
        
        print("loadText ---> path=: \(path): json = \(json)")
        return json
    }

    func listFiles(_ path: String, _ ofType: String) -> [String] {
        let bl = Bundle(for: type(of: self))
        print("path == \(path)")
        let files = bl.paths(forResourcesOfType: ofType, inDirectory: path)
//        print("filepath == \(filepath)")
        
        return files
    }
    
    func getDocument(_ did: String, _ type: String?) throws -> DIDDocument {
        let baseKey = "res:did:" + did
        let key = type != nil ? baseKey + ":" + type! : baseKey
        if data.keys.contains(key) {
            return data[key] as! DIDDocument
        }

        // load the document
        let path = getDidFile(did, type)
        let doc = try DIDDocument.convertToDIDDocument(fromJson: loadText(path))
        
        if !data.keys.contains(baseKey) {
            // If not stored before, store it and load private keys
            try store?.storeDid(using: doc)
//            let kfs = dataPath.
            let re = listFiles(dataPath, ".sk")
            let kfs: [String] = re.filter(re, dataPath, did + ".id.", ".sk")
            
            try kfs.forEach { kf in
                let kfName = kf.components(separatedBy: "/").last!
                
                let start = kfName.index(kfName.startIndex, offsetBy: did.count + 4)
                let end = kfName.index(kfName.startIndex, offsetBy: kfName.count - 4)

                let fragment = kfName[start...end]
                let id = try DIDURL(doc.subject, "#" + fragment)

                let sk = try DIDHDKey.deserializeBase58(loadText(kf)).serialize()
                try store!.storePrivateKey(for: id, privateKey: sk, using: storePassword)
            }
        }
        
        switch did {
        case "foobar", "foo", "bar", "baz":
            try doc.publish(with: getDocument("user1").defaultPublicKeyId()!, using: storePassword)
            break
        default:
            print("09090909090909")
            try doc.publish(using: storePassword)
            break
        }
        data[key] = doc
        
        return doc
    }
    
    func getDocument(_ did: String) throws -> DIDDocument {
        return try getDocument(did, nil)
    }
    
    func getDocumentJson(_ did: String, _ type: String?) throws -> String {
        let path = getDidFile(did, type)
        let key = "res:json:" + path
        if (data.keys.contains(key)) {
            return data[key] as! String
        }
        // load the document
        let text = try loadText(path)
        data[key] = text
        
        return text
    }
    
    func getCredential(_ did: String, _ vc: String, _ type: String?) throws -> VerifiableCredential {
        // Load DID document first for verification
        _ = try getDocument(did)
        let baseKey = "res:vc:" + did + ":" + vc
        let key = type != nil ? baseKey + ":" + type! : baseKey
        if (data.keys.contains(key)) {
            return data[key] as! VerifiableCredential
        }
        // load the credential
        let path = getCredentialFile(did, vc, type)
        let credential = try VerifiableCredential.fromJson(loadText(path))
        // If not stored before, store it
        
        if (!data.keys.contains(baseKey)) {
            try store!.storeCredential(using: credential)
        }
        data[key] = credential
        
        return credential
    }
    
    func getCredential(_ did: String, _ vc: String) throws -> VerifiableCredential {
        return try getCredential(did, vc, nil)
    }
    
    func getCredentialJson(_ did: String, _ vc: String, _ type: String?) throws -> String {
        let path = getCredentialFile(did, vc, type)
        let key = "res:json:" + path
        if (data.keys.contains(key)) {
            return data[key] as! String
        }
        
        // load the document
        let text = try loadText(path)
        data[key] = text
        
        return text
    }
    
    func getPresentation(_ did: String, _ vp: String, _ type: String?) throws -> VerifiablePresentation {
        // Load DID document first for verification
        _ = try getDocument(did)

        let baseKey = "res:vp:" + did + ":" + vp
        let key = type != nil ? baseKey + ":" + type! : baseKey
        if (data.keys.contains(key)) {
            return data[key] as! VerifiablePresentation
        }

        // load the presentation
        let json = try loadText(getPresentationFile(did, vp, type))
        let presentation = try VerifiablePresentation.fromJson(json)

        data[key] = presentation
        
        return presentation
    }
    
    func getPresentation(_ did: String, _ vp: String) throws -> VerifiablePresentation {
        return try getPresentation(did, vp, nil)
    }
    
    func getPresentationJson(_ did: String, _ vp: String, _ type: String?) throws -> String {
        let path = getPresentationFile(did, vp, type)
        let key = "res:json:" + path
        if (data.keys.contains(key)) {
            return data[key] as! String
        }
        // load the document
        let text = try loadText(path)
        data[key] = text
        
        return text
    }
    
    func loadAll() throws {
        _ = try getDocument("issuer")
        _ = try getDocument("user1")
        _ = try getDocument("user2")
        _ = try getDocument("user3")

        if (version >= 2) {
            _ = try getDocument("user4")
            _ = try getDocument("examplecorp")
            _ = try getDocument("foobar")
            _ = try getDocument("foo")
            _ = try getDocument("bar")
            _ = try getDocument("baz")
        }
    }
}

class InstantData {
    var idIssuer: DIDDocument?
    var idUser1: DIDDocument?
    var idUser2: DIDDocument?
    var idUser3: DIDDocument?
    var idUser4: DIDDocument?

    var vcUser1Passport: VerifiableCredential?    // Issued by idIssuer
    var vcUser1Twitter: VerifiableCredential?    // Self-proclaimed
    var vcUser1Json: VerifiableCredential?      // Issued by idIssuer with complex JSON subject
    var vpUser1Nonempty: VerifiablePresentation?
    var vpUser1Empty: VerifiablePresentation?

    var idExampleCorp: DIDDocument?     // Controlled by idIssuer
    var idFooBar: DIDDocument?         // Controlled by User1, User2, User3 (2/3)
    var idFoo: DIDDocument?           // Controlled by User1, User2 (2/2)
    var idBar: DIDDocument?          // Controlled by User1, User2, User3 (3/3)
    var idBaz: DIDDocument?         // Controlled by User1, User2, User3 (1/3)

    var vcFooBarServices: VerifiableCredential?    // Self-proclaimed
    var vcFooBarLicense: VerifiableCredential?    // Issued by idExampleCorp
    var vcFooEmail: VerifiableCredential?        // Issued by idIssuer

    var vpFooBarNonempty: VerifiablePresentation?
    var vpFooBarEmpty: VerifiablePresentation?

    var vcUser1JobPosition: VerifiableCredential? // Issued by idExampleCorp

    var ttFooBar: TransferTicket?
    var ttBaz: TransferTicket?
    
//    var identity: RootIdentity
//    var store: DIDStore
    var testData: TestData


    init(_ testData: TestData) {
        self.testData = testData
    }
    
    func getIssuerDocument() throws -> DIDDocument {
        if idIssuer == nil {
            _ = try testData.getRootIdentity()
            
            var doc = try testData.identity!.newDid(storePassword)
            doc.getMetadata().setAlias("Issuer")
            
            let selfIssuer = try VerifiableCredentialIssuer(doc)
            let cb = try selfIssuer.editingVerifiableCredentialFor(did: doc.subject)
            var props = ["name": "Test Issuer"]
            props["nationality"] = "Singapore"
            props["language"] = "English"
            props["email"] = "issuer@example.com"
            let vc = try cb.withId("#profile")
                .withType("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
                .withType("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
                .withProperties(props)
                .seal(using: storePassword)
            
            let db = try doc.editing()
            _ = try db.appendCredential(with: vc)
            
            var key = try TestData.generateKeypair()
            var id = try DIDURL(doc.subject, "#key2")
            _ = try db.appendAuthenticationKey(with: id, keyBase58: key.getPublicKeyBase58())
            try testData.store!.storePrivateKey(for: id, privateKey: key.serialize(), using: storePassword)
            
            // No private key for testKey
            key = try TestData.generateKeypair()
            id = try DIDURL(doc.subject, "#testKey")
            _ = try db.appendAuthenticationKey(with: id, keyBase58: key.getPublicKeyBase58())
            
            // No private key for recovery
            key = try TestData.generateKeypair()
            id = try DIDURL(doc.subject, "#recovery")
            _ = try db.appendAuthorizationKey(id, DID("did:elastos:\(key.getAddress())"), key.getPublicKeyBase58())
            
            doc = try db.seal(using: storePassword)
            try testData.store!.storeDid(using: doc)
            try doc.publish(using: storePassword)
            
            idIssuer = doc
        }
        return idIssuer!
    }
    
    func getUser1Document() throws -> DIDDocument {
        if idUser1 == nil {
            _ = try getIssuerDocument()
            
            var doc = try testData.identity!.newDid(storePassword)
            doc.getMetadata().setAlias("User1")

            // Test document with two embedded credentials
            let db = try doc.editing()

            var temp = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key2", keyBase58: temp.getPublicKeyBase58())
            try testData.store!.storePrivateKey(for: DIDURL(doc.subject, "#key2"),
                                            privateKey: temp.serialize(),
                                            using: storePassword)
            
            temp = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key3", keyBase58: temp.getPublicKeyBase58())
            try testData.store!.storePrivateKey(for: DIDURL(doc.subject, "#key3"),
                                            privateKey: temp.serialize(),
                                            using: storePassword)

            temp = try TestData.generateKeypair()
            _ = try db.appendAuthorizationKey(with: "#recovery", controller: "did:elastos:\(temp.getAddress())", keyBase58: temp.getPublicKeyBase58())
            
            _ = try db.appendService(with: "#openid", type: "OpenIdConnectVersion1.0Service", endpoint: "https://openid.example.com/")
            _ = try db.appendService(with: "#vcr", type: "CredentialRepositoryService",
                             endpoint: "https://did.example.com/credentials")

            let map = ["abc": "helloworld",
                       "foo": 123,
                       "bar": "foobar",
                       "foobar": "lalala...",
                       "date": DateFormatter.currentDate(),
                       "ABC": "Helloworld",
                       "FOO": 678,
                       "BAR": "Foobar",
                       "DATE": DateFormatter.currentDate()] as [String : Any]
            let props = ["abc": "helloworld",
                         "foo": 123,
                         "bar": "foobar",
                         "foobar": "lalala...",
                         "date": DateFormatter.currentDate(),
                         "map": map,
                         "ABC": "Helloworld",
                         "FOO": 678,
                         "BAR": "Foobar",
                         "FOOBAR": "Lalala...",
                         "DATE": DateFormatter.currentDate(),
                         "MAP": map] as [String : Any]
            _ = try db.appendService(with: "#carrier", type: "CarrierAddress", endpoint: "carrier://X2tDd1ZTErwnHNot8pTdhp7C7Y9FxMPGD8ppiasUT4UsHH2BpF1d", properties: map)
            let selfIssuer = try VerifiableCredentialIssuer(doc)
            var cb = try selfIssuer.editingVerifiableCredentialFor(did: doc.subject)
            var prop: [String: String] = [: ]
            prop["name"] = "John"
            prop["gender"] = "Male"
            prop["nationality"] = "Singapore"
            prop["language"] = "English"
            prop["email"] = "john@example.com"
            prop["twitter"] = "@john"
            let vcProfile = try cb.withId("#profile")
                .withType("https://ns.elastos.org/credentials/v1#SelfProclaimedCredential")
                .withType("https://ns.elastos.org/credentials/profile/v1#ProfileCredential")
                .withType("EmailCredential", "https://ns.elastos.org/credentials/email/v1")
                .withType("SocialCredential", "https://ns.elastos.org/credentials/social/v1")
                .withProperties(prop)
                .seal(using: storePassword)
            
            let kycIssuer = try VerifiableCredentialIssuer(idIssuer!)
            cb = try kycIssuer.editingVerifiableCredentialFor(did: doc.subject)

            prop.removeAll()
            prop["email"] = "john@example.com"

            let vcEmail = try cb.withId("#email")
                .withType("EmailCredential", "https://ns.elastos.org/credentials/email/v1")
                .withProperties(prop)
                .seal(using: storePassword)

            _ = try db.appendCredential(with: vcProfile)
            _ = try db.appendCredential(with: vcEmail)
            doc = try db.seal(using: storePassword)
            try testData.store!.storeDid(using: doc)
            try doc.publish(using: storePassword)

            idUser1 = doc
        }
        
        return idUser1!
    }
    
    func getUser1PassportCredential() throws -> VerifiableCredential {
        if (vcUser1Passport == nil) {
            let doc = try getUser1Document()
            
            let id = try DIDURL(doc.subject, "#passport")
            
            let selfIssuer = try VerifiableCredentialIssuer(doc)
            let cb = try selfIssuer.editingVerifiableCredentialFor(did: doc.subject)
            
            let props: [String: String] = ["nationality": "Singapore", "passport": "S653258Z07"]
            
            let vcPassport = try cb.withId(id)
                .withType("https://elastos.org/credentials/v1#SelfProclaimedCredential")
                .withProperties(props)
                .seal(using: storePassword)
            vcPassport.getMetadata().setAlias("Passport")
            try testData.store!.storeCredential(using: vcPassport)
            
            vcUser1Passport = vcPassport
        }
        
        return vcUser1Passport!
    }
    
    func getUser1TwitterCredential() throws -> VerifiableCredential {
        if (vcUser1Twitter == nil) {
            let doc = try getUser1Document()
            
            let id = try DIDURL(doc.subject, "#twitter")
            
            let kycIssuer = try VerifiableCredentialIssuer(idIssuer!)
            let cb = try kycIssuer.editingVerifiableCredentialFor(did: doc.subject)
            
            let props = ["twitter": "@john"]
            
            let vcTwitter = try cb.withId(id)
                .withType("SocialCredential", "https://ns.elastos.org/credentials/social/v1")
                .withProperties(props)
                .seal(using: storePassword)
            vcTwitter.getMetadata().setAlias("Twitter")
            try testData.store!.storeCredential(using: vcTwitter)
            
            vcUser1Twitter = vcTwitter
        }
        
        return vcUser1Twitter!
    }
    
    func getUser1JsonCredential() throws -> VerifiableCredential {
        if (vcUser1Json == nil) {
            let doc = try  getUser1Document()

            let id = try DIDURL(doc.subject, "#json")

            let kycIssuer = try VerifiableCredentialIssuer(idIssuer!)
            let cb = try kycIssuer.editingVerifiableCredentialFor(did: doc.subject)

            let jsonProps = "{\"name\":\"Jay Holtslander\",\"alternateName\":\"Jason Holtslander\",\"booleanValue\":true,\"numberValue\":1234,\"doubleValue\":9.5,\"nationality\":\"Canadian\",\"birthPlace\":{\"type\":\"Place\",\"address\":{\"type\":\"PostalAddress\",\"addressLocality\":\"Vancouver\",\"addressRegion\":\"BC\",\"addressCountry\":\"Canada\"}},\"affiliation\":[{\"type\":\"Organization\",\"name\":\"Futurpreneur\",\"sameAs\":[\"https://twitter.com/futurpreneur\",\"https://www.facebook.com/futurpreneur/\",\"https://www.linkedin.com/company-beta/100369/\",\"https://www.youtube.com/user/CYBF\"]}],\"alumniOf\":[{\"type\":\"CollegeOrUniversity\",\"name\":\"Vancouver Film School\",\"sameAs\":\"https://en.wikipedia.org/wiki/Vancouver_Film_School\",\"year\":2000},{\"type\":\"CollegeOrUniversity\",\"name\":\"CodeCore Bootcamp\"}],\"gender\":\"Male\",\"Description\":\"Technologist\",\"disambiguatingDescription\":\"Co-founder of CodeCore Bootcamp\",\"jobTitle\":\"Technical Director\",\"worksFor\":[{\"type\":\"Organization\",\"name\":\"Skunkworks Creative Group Inc.\",\"sameAs\":[\"https://twitter.com/skunkworks_ca\",\"https://www.facebook.com/skunkworks.ca\",\"https://www.linkedin.com/company/skunkworks-creative-group-inc-\",\"https://plus.google.com/+SkunkworksCa\"]}],\"url\":\"https://jay.holtslander.ca\",\"image\":\"https://s.gravatar.com/avatar/961997eb7fd5c22b3e12fb3c8ca14e11?s=512&r=g\",\"address\":{\"type\":\"PostalAddress\",\"addressLocality\":\"Vancouver\",\"addressRegion\":\"BC\",\"addressCountry\":\"Canada\"},\"sameAs\":[\"https://twitter.com/j_holtslander\",\"https://pinterest.com/j_holtslander\",\"https://instagram.com/j_holtslander\",\"https://www.facebook.com/jay.holtslander\",\"https://ca.linkedin.com/in/holtslander/en\",\"https://plus.google.com/+JayHoltslander\",\"https://www.youtube.com/user/jasonh1234\",\"https://github.com/JayHoltslander\",\"https://profiles.wordpress.org/jasonh1234\",\"https://angel.co/j_holtslander\",\"https://www.foursquare.com/user/184843\",\"https://jholtslander.yelp.ca\",\"https://codepen.io/j_holtslander/\",\"https://stackoverflow.com/users/751570/jay\",\"https://dribbble.com/j_holtslander\",\"http://jasonh1234.deviantart.com/\",\"https://www.behance.net/j_holtslander\",\"https://www.flickr.com/people/jasonh1234/\",\"https://medium.com/@j_holtslander\"]}";

            let vcJson = try cb.withId(id)
                    .withTypes("TestCredential", "JsonCredential")
                    .withProperties(jsonProps)
                    .seal(using: storePassword)
            vcJson.getMetadata().setAlias("json")
            try testData.store!.storeCredential(using: vcJson)

            vcUser1Json = vcJson
        }

        return vcUser1Json!
    }
    
    func getUser1JobPositionCredential() throws -> VerifiableCredential {
        if (vcUser1JobPosition == nil) {
            _ = try getExampleCorpDocument()
            
            let doc = try getUser1Document()
            
            let id = try DIDURL(doc.subject, "#email")
            
            let kycIssuer = try VerifiableCredentialIssuer(idExampleCorp!)
            let cb = try kycIssuer.editingVerifiableCredentialFor(did: doc.subject)
            
            let props = ["title": "CEO"]
            
            let vc = try cb.withId(id)
                .withType("JobPositionCredential", "https://example.com/credentials/v1")
                .withProperties(props)
                .seal(using: storePassword)
            try testData.store!.storeCredential(using: vc)
            
            vcUser1JobPosition = vc
        }
        
        return vcUser1JobPosition!
    }
    
    func getUser1NonemptyPresentation() throws -> VerifiablePresentation {
        if (vpUser1Nonempty == nil) {
            let doc = try getUser1Document()

            let pb = try VerifiablePresentation.editingVerifiablePresentation(for: doc.subject, using: testData.store!)

            let vp = try pb
                .withCredentials(doc.credential(ofId: "#profile")!,
                                 doc.credential(ofId: "#email")!,
                                 getUser1PassportCredential(),
                                 getUser1TwitterCredential(),
                                 getUser1JobPositionCredential())
                    .withRealm("https://example.com/")
                    .withNonce("873172f58701a9ee686f0630204fee59")
                    .seal(using: storePassword)

            vpUser1Nonempty = vp
        }

        return vpUser1Nonempty!
    }
    
    func getUser1EmptyPresentation() throws -> VerifiablePresentation {
        if (vpUser1Empty == nil) {
            let doc = try getUser1Document()
            
            let pb = try VerifiablePresentation.editingVerifiablePresentation(for: doc.subject, using: testData.store!)
            
            let vp = try pb.withRealm("https://example.com/")
                .withNonce("873172f58701a9ee686f0630204fee59")
                .seal(using: storePassword)
            
            vpUser1Empty = vp
        }
        
        return vpUser1Empty!
    }
    
    func getUser2Document() throws -> DIDDocument {
        if (idUser2 == nil) {
            var doc = try testData.identity!.newDid(storePassword)
            doc.getMetadata().setAlias("User2")

            let db = try doc.editing()

            let props = ["name": "John", "gender": "Male", "nationality": "Singapore", "language": "English", "email": "john@example.com", "twitter": "@john"]
            let types = [
                "https://ns.elastos.org/credentials/v1#SelfProclaimedCredential",
                "https://ns.elastos.org/credentials/profile/v1#ProfileCredential",
                "https://ns.elastos.org/credentials/email/v1#EmailCredential",
                "https://ns.elastos.org/credentials/social/v1#SocialCredential"
            ]
            _ = try db.appendCredential(with: "#profile", types: types, json: props.toJsonString()!, using: storePassword)
            doc = try db.seal(using: storePassword)
            try testData.store!.storeDid(using: doc)
            try doc.publish(using: storePassword)

            idUser2 = doc
        }

        return idUser2!
    }
    
    func getUser3Document() throws -> DIDDocument {
        if (idUser3 == nil) {
            let doc = try testData.identity!.newDid(storePassword)
            doc.getMetadata().setAlias("User3")
            try doc.publish(using: storePassword)

            idUser3 = doc
        }

        return idUser3!
    }
    
    func getUser4Document() throws -> DIDDocument {
        if (idUser4 == nil) {
            let doc = try testData.identity!.newDid(storePassword)
            doc.getMetadata().setAlias("User4")
            try doc.publish(using: storePassword)
            
            idUser4 = doc
        }

        return idUser4!
    }
    
    func getExampleCorpDocument() throws -> DIDDocument {
        if (idExampleCorp == nil) {
            _ = try getIssuerDocument()
            
            let did = try DID("did:elastos:example")
            var doc = try idIssuer!.newCustomizedDid(withId: did, storePassword)
            
            let selfIssuer = try VerifiableCredentialIssuer(doc)
            let cb = try selfIssuer.editingVerifiableCredentialFor(did: doc.subject)
            let props = ["name": "Example LLC", "url": "https://example.com/", "email": "contact@example.com"]
            
            let vc = try cb.withId("#profile")
                .withType("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
                .withType("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
                .withType("EmailCredential", "https://ns.elastos.org/credentials/email/v1")
                .withProperties(props)
                .seal(using: storePassword)
            
            let db = try doc.editing()
            _ = try db.appendCredential(with: vc)
            
            var key = try TestData.generateKeypair()
            var id = try DIDURL(doc.subject, "#key2")
            _ = try db.appendAuthenticationKey(with: id, keyBase58: key.getPublicKeyBase58())
            try testData.store!.storePrivateKey(for: id, privateKey: key.serialize(), using: storePassword)
            
            // No private key for testKey
            key = try TestData.generateKeypair()
            id = try DIDURL(doc.subject, "#testKey")
            _ = try db.appendAuthenticationKey(with: id, keyBase58: key.getPublicKeyBase58())
            
            doc = try db.seal(using: storePassword)
            try testData.store!.storeDid(using: doc)
            try doc.publish(using: storePassword)
            
            idExampleCorp = doc
        }
        
        return idExampleCorp!
    }
    
    func getFooBarDocument() throws -> DIDDocument {
        if (idFooBar == nil) {
            _ = try getExampleCorpDocument()
            _ = try getUser1Document()
            _ = try getUser2Document()
            _ = try getUser3Document()
            
            let controllers = [idUser1!.subject, idUser2!.subject, idUser3!.subject]
            let did = try DID("did:elastos:foobar")
            var doc = try idUser1!.newCustomizedDid(withId: did, controllers, 2, storePassword)
            let signKey = idUser1!.defaultPublicKeyId()
            
            // Add public keys embedded credentials
            let db = try doc.editing(idUser1!)
            
            var temp = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key2", keyBase58: temp.getPublicKeyBase58())
            try testData.store!.storePrivateKey(for: DIDURL(doc.subject, "#key2"),
                                                privateKey: temp.serialize(), using: storePassword)
            
            temp = try TestData.generateKeypair()
            _ = try db.appendAuthenticationKey(with: "#key3", keyBase58: temp.getPublicKeyBase58())
            try testData.store!.storePrivateKey(for: DIDURL(doc.subject, "#key3"),
                                                privateKey: try temp.serialize(), using: storePassword)
            
            _ = try db.appendService(with: "#vault", type: "Hive.Vault.Service",
                                 endpoint: "https://foobar.com/vault")
            
            let map = ["abc": "helloworld", "foo": 123, "bar": "foobar", "foobar": "lalala...", "date": DateFormatter.currentDate(), "ABC": "Helloworld", "FOO": 678, "BAR": "Foobar", "DATE": DateFormatter.currentDate()] as [String : Any]
            
            let props = ["abc": "helloworld", "foo": 123, "bar": "foobar", "foobar": "lalala...", "date": DateFormatter.currentDate(),"map": map, "ABC": "Helloworld", "FOO": 678, "BAR": "Foobar", "DATE": DateFormatter.currentDate(), "MAP": map] as [String : Any]
            
            _ = try db.appendService(with: "#vcr", type: "CredentialRepositoryService",
                                 endpoint: "https://foobar.com/credentials", properties: props)
            
            let selfIssuer = try VerifiableCredentialIssuer(doc, signKey!)
            var cb = try selfIssuer.editingVerifiableCredentialFor(did: doc.subject)
            
            var pr = ["name": "Foo Bar Inc", "language": "Chinese", "email": "contact@foobar.com"]
            
            let vcProfile = try cb.withId("#profile")
                .withType("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
                .withType("ProfileCredential", "https://ns.elastos.org/credentials/profile/v1")
                .withType("EmailCredential", "https://ns.elastos.org/credentials/email/v1")
                .withProperties(pr)
                .seal(using: storePassword)
            
            let kycIssuer = try VerifiableCredentialIssuer(idExampleCorp!)
            cb = try kycIssuer.editingVerifiableCredentialFor(did: doc.subject)
            
            pr.removeAll()
            pr["email"] = "foobar@example.com"
            
            let vcEmail = try cb.withId("#email")
                .withType("EmailCredential", "https://ns.elastos.org/credentials/email/v1")
                .withProperties(pr)
                .seal(using: storePassword)
            
            _ = try db.appendCredential(with: vcProfile)
            _ = try db.appendCredential(with: vcEmail)
            doc = try db.seal(using: storePassword)
            doc = try idUser3!.sign(with: doc, using: storePassword)
            try testData.store!.storeDid(using: doc)
            try doc.publish(with: signKey!, using: storePassword)
            
            idFooBar = doc
        }
        
        return idFooBar!
    }
    
    func getFooBarServiceCredential() throws -> VerifiableCredential {
        if (vcFooBarServices == nil) {
            let doc = try getFooBarDocument()
            
            let id = try DIDURL(doc.subject, "#services")
            
            let selfIssuer = try VerifiableCredentialIssuer(doc, idUser1!.defaultPublicKeyId()!)
            let cb = try selfIssuer.editingVerifiableCredentialFor(did: doc.subject)
            
            let props = ["consultation": "https://foobar.com/consultation", "Outsourceing": "https://foobar.com/outsourcing"]
            
            let vc = try cb.withId(id)
                .withType("SelfProclaimedCredential", "https://ns.elastos.org/credentials/v1")
                .withProperties(props)
                .seal(using: storePassword)
            try testData.store!.storeCredential(using: vc)
            
            vcFooBarServices = vc
        }
        
        return vcFooBarServices!
    }
    
    func getFooBarLicenseCredential() throws -> VerifiableCredential {
        if (vcFooBarLicense == nil) {
            _ = try getExampleCorpDocument()
            _ = try getUser1Document()
            _ = try getUser2Document()
            _ = try getUser3Document()
            
            let doc = try getFooBarDocument()
            
            let id = try DIDURL(doc.subject, "#license")
            
            let kycIssuer = try VerifiableCredentialIssuer(idExampleCorp!)
            let cb = try kycIssuer.editingVerifiableCredentialFor(did: doc.subject)
            
            let props = ["license-id": "20201021C889", "scope": "Consulting"]
            
            let vc = try cb.withId(id)
                .withType("LicenseCredential", "https://example.com/credentials/license/v1")
                .withProperties(props)
                .seal(using: storePassword)
            try testData.store!.storeCredential(using: vc)
            
            vcFooBarLicense = vc
        }
        
        return vcFooBarLicense!
    }
    
    func getFooBarNonemptyPresentation() throws -> VerifiablePresentation {
        if (vpFooBarNonempty == nil) {
            let doc = try getFooBarDocument()
            
            let pb = try VerifiablePresentation.editingVerifiablePresentation(for: doc.subject, using: testData.store!)
            
            let vp = try pb
                .withCredentials(doc.credential(ofId: "#profile")!,
                                 doc.credential(ofId: "#email")!)
                .withCredentials(getFooBarServiceCredential())
                .withCredentials(getFooBarLicenseCredential())
                .withRealm("https://example.com/")
                .withNonce("873172f58701a9ee686f0630204fee59")
                .seal(using: storePassword)
            
            vpFooBarNonempty = vp
        }
        
        return vpFooBarNonempty!
    }
    
    func getFooBarEmptyPresentation() throws -> VerifiablePresentation {
        if (vpFooBarEmpty == nil) {
            let doc = try getFooBarDocument()

            let pb = try VerifiablePresentation.editingVerifiablePresentation(for: doc.subject, using: testData.store!)

            let vp = try pb.withRealm("https://example.com/")
                    .withNonce("873172f58701a9ee686f0630204fee59")
                    .seal(using: storePassword)

            vpFooBarEmpty = vp
        }

        return vpFooBarEmpty!
    }
    
    func getFooBarTransferTicket() throws -> TransferTicket {
        if (ttFooBar == nil) {
            let doc = try getFooBarDocument()
            let user4 = try getUser4Document()

            var tt = try idUser1!.createTransferTicket(withId: doc.subject, to: user4.subject, using: storePassword)
            tt = try idUser3!.sign(with: tt, using: storePassword)

            ttFooBar = tt
        }

        return ttFooBar!
    }
    
    func getFooDocument() throws -> DIDDocument {
        if (idFoo == nil) {
            _ = try getUser1Document()
            _ = try getUser2Document()

            let controllers = [idUser2!.subject]
            let did = try DID("did:elastos:foo")
            var doc = try idUser1!.newCustomizedDid(withId: did, controllers, 2, storePassword)
            doc = try idUser2!.sign(with: doc, using: storePassword)
            try testData.store!.storeDid(using: doc)

            try doc.setEffectiveController(idUser2!.subject)
            try doc.publish(using: storePassword)
            try doc.setEffectiveController(nil)

            idFoo = doc
        }

        return idFoo!
    }
    
    func getFooEmailCredential() throws -> VerifiableCredential {
        if (vcFooEmail == nil) {
            _ = try getIssuerDocument()
            
            let doc = try getFooDocument()
            
            let id = try DIDURL(doc.subject, "#email")
            
            let kycIssuer = try VerifiableCredentialIssuer(idIssuer!)
            let cb = try kycIssuer.editingVerifiableCredentialFor(did: doc.subject)
            
            let props = ["email": "foo@example.com"]
            
            let vc = try cb.withId(id)
                .withType("EmailCredential", "https://ns.elastos.org/credentials/email/v1")
                .withProperties(props)
                .seal(using: storePassword)
            try testData.store!.storeCredential(using: vc)
            
            vcFooEmail = vc
        }
        
        return vcFooEmail!
    }
    
    func getBarDocument() throws -> DIDDocument {
        if (idBar == nil) {
            _ = try getUser1Document()
            _ = try getUser2Document()
            _ = try getUser3Document()
            
            let controllers = [idUser2!.subject, idUser3!.subject]
            let did = try DID("did:elastos:bar")
            var doc = try idUser1!.newCustomizedDid(withId: did, controllers, 3, storePassword)
            doc = try idUser2!.sign(with: doc, using: storePassword)
            doc = try idUser3!.sign(with: doc, using: storePassword)
            try testData.store!.storeDid(using: doc)
            try doc.publish(with: idUser3!.defaultPublicKeyId()!, using: storePassword)
            
            idBar = doc
        }
        
        return idBar!
    }
    
    func getBazDocument() throws -> DIDDocument {
        if (idBaz == nil) {
            _ = try getUser1Document()
            _ = try getUser2Document()
            _ = try getUser3Document()

            let controllers = [idUser2!.subject, idUser3!.subject]
            let did = try DID("did:elastos:baz")
            let doc = try idUser1!.newCustomizedDid(withId: did, controllers, 1, storePassword)
            try testData.store!.storeDid(using: doc)
            try doc.publish(with: idUser1!.defaultPublicKeyId()!, using: storePassword)

            idBaz = doc
        }

        return idBaz!
    }
    
    func getBazTransferTicket() throws -> TransferTicket {
        if (ttBaz == nil) {
            let doc = try getBazDocument()
            let user4 = try getUser4Document()

            let tt = try idUser2!.createTransferTicket(withId: doc.subject, to: user4.subject, using: storePassword)

            ttBaz = tt
        }

        return ttBaz!
    }
    
    func getDocument(_ did: String) throws -> DIDDocument? {
        switch (did) {
        case "issuer":
            return try getIssuerDocument()

        case "user1":
            return try getUser1Document()

        case "user2":
            return try getUser1Document()

        case "user3":
            return try getUser1Document()

        case "user4":
            return try getUser1Document()

        case "examplecorp":
            return try getExampleCorpDocument()

        case "foobar":
            return try getFooBarDocument()

        case "foo":
            return try getFooDocument()

        case "bar":
            return try getBarDocument()

        case "baz":
            return try getBazDocument()

        default:
            return nil
        }
    }
    
    func getCredential(_ did: String, _ vc: String) throws -> VerifiableCredential? {
        switch (did) {
        case "user1":
            switch (vc) {
            case "passport":
                return try getUser1PassportCredential()

            case "twitter":
                return try getUser1TwitterCredential()

            case "json":
                return try getUser1JsonCredential()

            case "jobposition":
                return try getUser1JobPositionCredential()

            default:
                return nil
            }

        case "foobar":
            switch (vc) {
            case "services":
                return try getFooBarServiceCredential()

            case "license":
                return try getFooBarLicenseCredential()

            default:
                return nil
            }

        case "foo":
            switch (vc) {
            case "email":
                return try getFooEmailCredential()

            default:
                return nil
            }

        default:
            return nil
        }
    }
    
    func getPresentation(_ did: String, _ vp: String) throws -> VerifiablePresentation? {
        switch (did) {
        case "user1":
            switch (vp) {
            case "nonempty":
                return try getUser1NonemptyPresentation()

            case "empty":
                return try getUser1EmptyPresentation()

            default:
                return nil
            }

        case "foobar":
            switch (vp) {
            case "nonempty":
                return try getFooBarNonemptyPresentation()

            case "empty":
                return try getFooBarEmptyPresentation()

            default:
                return nil
            }

        default:
            return nil
        }
    }
}
