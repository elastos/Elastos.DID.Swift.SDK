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

/*
 * FileSystem DID Store: storage layout
 *
 *  + DIDStore root
 *    + data                             [Current data root folder]
 *      - .metadata                        [DIDStore metadata]
 *      + roots                            [Root identities folder]
 *        + xxxxxxx0                    [Root identity folder named by id]
 *          - .metadata                    [RootIdentity metadata]
 *          - mnemonic                    [Encrypted mnemonic file, OPTIONAL]
 *          - private                    [Encrypted root private key file]
 *          - public                    [Pre-derived public key file]
 *          - index                        [Last derive index]
 *        + ...
 *        + xxxxxxxN
 *      + ids                            [DIDs folder]
 *        + ixxxxxxxxxxxxxxx0             [DID root, named by id specific string]
 *          - .metadata                    [Meta for DID, json format, OPTIONAL]
 *          - document                    [DID document, json format]
 *          + credentials                [Credentials root, OPTIONAL]
 *            + credential-id-0         [Credential root, named by id' fragment]
 *              - .metadata                [Meta for credential, json format, OPTONAL]
 *              - credential            [Credential, json format]
 *            + ...
 *            + credential-id-N
 *          + privatekeys                [Private keys root, OPTIONAL]
 *            - privatekey-id-0            [Encrypted private key, named by pk' id]
 *            - ...
 *            - privatekey-id-N
 *        + ...
 *        + ixxxxxxxxxxxxxxxN
 */
typealias ReEncryptor = (String) throws -> String
public class FileSystemStorage: DIDStorage {
    private let TAG = NSStringFromClass(FileSystemStorage.self)
    let DATA_DIR = "data"
    let ROOT_IDENTITIES_DIR = "roots"
    let ROOT_IDENTITY_MNEMONIC_FILE = "mnemonic"
    let ROOT_IDENTITY_PRIVATEKEY_FILE = "private"
    let ROOT_IDENTITY_PUBLICKEY_FILE = "public"
    let ROOT_IDENTITY_INDEX_FILE = "index"
    let DID_DIR = "ids"
    let DOCUMENT_FILE = "document"
    let CREDENTIALS_DIR = "credentials"
    let CREDENTIAL_FILE = "credential"
    let PRIVATEKEYS_DIR = "privatekeys"
    let METADATA = ".metadata"
    let JOURNAL_SUFFIX = ".journal"
    private var storeRoot: String
    private var currentDataDir: String
    private let MAGIC: [UInt8] = [0x00, 0x0D, 0x01, 0x0D]
    
    
    init(_ dir: String) throws {
        self.storeRoot = dir
        currentDataDir = DATA_DIR
        try checkArgument(dir.isEmpty, "Invalid DIDStore root directory.")
    
        if FileManager.default.fileExists(atPath: storeRoot) {
            try checkStore()
        } else {
            try initializeStore()
        }
    }

    private func initializeStore() throws {
        do {
            Log.d(TAG, "Initializing DID store at ", storeRoot)
            try FileManager.default.createDirectory(atPath: self.storeRoot,
                                                    withIntermediateDirectories: true,
                                                    attributes: nil)
            let path = try getFile(true, currentDataDir + "/" + METADATA)
            let metadata = DIDStoreMetadata()
            try metadata.serialize(path)
        } catch {
            Log.i(TAG, "Initialize DID store error ", storeRoot)
            throw DIDError.didStoreError("Initialize DIDStore \(storeRoot) error.")
        }
    }

    private func checkStore() throws {
        var isDir: ObjCBool = false
        Log.d(TAG, "Checking DID store at ", storeRoot)

        // Further to check the '_rootPath' is not a file path.
        guard FileManager.default.fileExists(atPath: storeRoot, isDirectory: &isDir) && isDir.boolValue else {
            Log.i(TAG, "Path ", storeRoot, " not a directory")
            throw DIDError.didStoreError("Invalid DIDStore ' \(storeRoot) '.")
        }
        try postOperations()
        let path = try getFile(true, currentDataDir + "/" + METADATA)
        if !FileManager.default.fileExists(atPath: path) {
            let oldMetadata = try getFile(".meta")
            if FileManager.default.fileExists(atPath: oldMetadata!) {
               
                try upgradeFromV2()
            }
            else {
               let list = try? FileManager.default.contentsOfDirectory(atPath: storeRoot)
                if list == nil || list!.count == 0 {
                    // if an empty folder
                    try initializeStore()
                    return
                }
                else {
                    Log.e(TAG, "Path ", storeRoot, "not a DID store")
                    throw DIDError.didStoreError("Invalid DIDStore ' \(storeRoot) '.")
                }
            }
        }
        
        do {
            let metadata = try DIDStoreMetadata.parse(path)
            guard metadata.type == DIDStore.DID_STORE_TYPE else {
                throw DIDError.CheckedError.DIDStoreError.DIDStoreError("Unknown DIDStore type")
            }
            
            guard metadata.version == DIDStore.DID_STORE_VERSION else {
                throw DIDError.CheckedError.DIDStoreError.DIDStoreError("Unsupported DIDStore version")
            }
        } catch {
            Log.e(TAG, "Check DID store error, failed load store metadata")
            throw  DIDError.CheckedError.DIDStoreError.DIDStorageError.DIDStorageError("Can not check the store metadata")
        }
    }
    
    private class func toPath(_ id: DIDURL) -> String {
        var path = ""
        if id.did != nil {
            path = id.toString(id.did!)
        }
        else {
            path = id.toString()
        }
        return path.replacingOccurrences(of: ";", with: ".").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "?", with: "-")
    }
    
    private class func toDIDURL(_ did: DID, _ path: String) throws -> DIDURL {
       let p = path.replacingOccurrences(of: ".", with: ";").replacingOccurrences(of: "_", with: "/").replacingOccurrences(of: "-", with: "?")
        return try DIDURL(did, path)
    }
    
    private class func copyFile(_ src: String, _ dest: String) throws {
        if isDirectory(src) {
            try createDir(true, dest) // dest create if not
            
            let fileManager = FileManager.default
            let enumerator = try fileManager.contentsOfDirectory(atPath: src)
            for element: String in enumerator  {
                // if !element.hasSuffix(".meta")
                let srcFile = src + "/" + element
                let destFile = dest + "/" + element
                try copyFile(srcFile, destFile)
            }
        }
        else {
            let fileManager = FileManager.default
            try fileManager.copyItem(atPath: src, toPath: dest)
        }
    }
    
    private func dirExists(_ dirPath: String) throws -> Bool {
        let fileManager = FileManager.default
        var isDir : ObjCBool = false
        let re = fileManager.fileExists(atPath: dirPath, isDirectory:&isDir)
        return re && isDir.boolValue
    }
    
    private func fileExists(_ dirPath: String) throws -> Bool {
        let fileManager = FileManager.default
        var isDir : ObjCBool = false
        return fileManager.fileExists(atPath: dirPath)
    }
    
    private func fileExistsWithContent(_ dirPath: String) throws -> Bool {
        let fileManager = FileManager.default
        var isDir : ObjCBool = false
        fileManager.fileExists(atPath: dirPath, isDirectory:&isDir)
        let readhandle = FileHandle.init(forReadingAtPath: dirPath)
        let data = (readhandle?.readDataToEndOfFile()) ?? Data()
        let str = String(data: data, encoding: .utf8) ?? ""
        return str.count > 0 ? true : false
    }
    
    private func deleteFile(_ path: String) throws -> Bool {
        let fileManager = FileManager.default
        var isDir = ObjCBool.init(false)
        let fileExists = fileManager.fileExists(atPath: path, isDirectory: &isDir)
        // If path is a folder, traverse the subfiles under the folder and delete them
        let re: Bool = false
        guard fileExists else {
            return re
        }
        try fileManager.removeItem(atPath: path)
        return true
    }

    private func filePath( _ pathArgs: String...) -> String {
        var path: String = storeRoot
        for item in pathArgs {
            path.append("/")
            path.append(item)
        }
        return path
    }

    private func openFileHandle(_ forWrite: Bool, _ pathArgs: String...) throws -> FileHandle {
        var path: String = storeRoot
        for item in pathArgs {
            path.append("/")
            path.append(item)
        }

        if forWrite {
            // Delete before writing
            _ = try deleteFile(path)
        }
        if !FileManager.default.fileExists(atPath: path) && forWrite {
            let dirPath: String = PathExtracter(path).dirname()
            let fileM = FileManager.default
            let re = fileM.fileExists(atPath: dirPath)
            if !re {
                try fileM.createDirectory(atPath: dirPath, withIntermediateDirectories: true, attributes: nil)
            }
            FileManager.default.createFile(atPath: path, contents: nil, attributes: nil)
        }

        let handle: FileHandle?
        if forWrite {
            handle = FileHandle(forWritingAtPath: path)
        } else {
            handle = FileHandle(forReadingAtPath: path)
        }

        guard let _ = handle else {
            throw DIDError.unknownFailure("opening file at \(path) error")
        }

        return handle!
    }

//    private func openPrivateIdentityFile(_ forWrite: Bool) throws -> FileHandle {
//        return try openFileHandle(forWrite, Constants.PRIVATE_DIR, Constants.HDKEY_FILE)
//    }
//
//    private func openPublicIdentityFile() throws -> FileHandle {
//        return try openPublicIdentityFile(false)
//    }
//
//    private func openMnemonicFile() throws -> FileHandle {
//        return try openMnemonicFile(false)
//    }
//
//    private func openMnemonicFile(_ forWrite: Bool) throws -> FileHandle {
//        return try openFileHandle(forWrite, Constants.PRIVATE_DIR, Constants.MNEMONIC_FILE)
//    }
//
//    private func openPublicIdentityFile(_ forWrite: Bool) throws -> FileHandle {
//        return try openFileHandle(forWrite, Constants.PRIVATE_DIR, Constants.HDPUBKEY_FILE)
//    }
//
//    private func openPrivateIdentityFile() throws -> FileHandle {
//        return try openPrivateIdentityFile(false)
//    }

    func getLocation() -> String {
        
        return storeRoot
    }

    func storeMetadata(_ metadata: DIDStoreMetadata) throws {
        let path = try getFile(true, currentDataDir + "/" + METADATA)
        if metadata.isEmpty() {
            try deleteFile(path)
        }
        else {
            try metadata.serialize(path)
        }
    }

    func loadMetadata() throws -> DIDStoreMetadata? {
        let path = try getFile(currentDataDir + "/" + METADATA)
        var metadata: DIDStoreMetadata?
        if try fileExists(path!) {
            metadata = try DIDStoreMetadata.parse(path!)
        }
        
        return metadata
    }

    private func getRootIdentityFile(_ id: String, _ file: String, _ create: Bool) throws -> String {
        return try getFile(create, currentDataDir + "/" + ROOT_IDENTITIES_DIR + "/" + id + "/" + file)
    }

    private func getRootIdentityDir(_ id: String) throws -> String {
        return try getFile(currentDataDir + "/" + ROOT_IDENTITIES_DIR + "/" + id)!
    }

    func storeRootIdentityMetadata(_ id: String, _ metadata: RootIdentityMetadata) throws {
        do {
            let file = try getRootIdentityFile(id, METADATA, true)
            if metadata.isEmpty() {
                try deleteFile(file)
            }
            else {
                metadata.serialize(file)
            }
        } catch {
            throw DIDError.didStoreError("Store root identity metadata error: \(id)")
        }
    }

    func loadRootIdentityMetadata(_ id: String) throws -> RootIdentityMetadata? {
        do {
            let file = try getRootIdentityFile(id, METADATA, false)
            var metadata: RootIdentityMetadata?
            if try fileExists(file) {
                metadata = RootIdentityMetadata.parse(file)
            }

            return metadata
        } catch {
            throw DIDError.didStoreError("Load root identity metadata error: \(id)")
        }
    }

    func storeRootIdentity(_ id: String, _ mnemonic: String?, _ privateKey: String?, _ publicKey: String?, _ index: Int) throws {
        if mnemonic != nil {
            let file = try getRootIdentityFile(id, ROOT_IDENTITY_MNEMONIC_FILE, true)
            try writeTextToPath(file, mnemonic!)
        }
        if privateKey != nil {
            let file = try! getRootIdentityFile(id, ROOT_IDENTITY_PRIVATEKEY_FILE, true)
            try writeTextToPath(file, privateKey!)
        }
        
        if publicKey != nil {
            let file = try getRootIdentityFile(id, ROOT_IDENTITY_PUBLICKEY_FILE, true)
            try writeTextToPath(file, publicKey!)
        }
    }
    
    func loadRootIdentity(_ id: String) throws -> RootIdentity? {
        var file = try getRootIdentityFile(id, ROOT_IDENTITY_PUBLICKEY_FILE, false)
        if try !fileExists(file) {
            return nil
        }
        let publicKey = try readTextFromPath(file)
        file = try getRootIdentityFile(id, ROOT_IDENTITY_INDEX_FILE, false)
        let index = try Int(value: readTextFromPath(file))
        
        return try RootIdentity.create(publicKey, index)
    }
    
    func updateRootIdentityIndex(_ id: String, _ index: Int) throws {
        let file = try getRootIdentityFile(id, ROOT_IDENTITY_INDEX_FILE, false)
        try writeTextToPath(file, "\(index)")
    }
    
    func loadRootIdentityPrivateKey(_ id: String) throws -> String? {
        let file = try getRootIdentityFile(id, ROOT_IDENTITY_PRIVATEKEY_FILE, false)
        if try !fileExists(file) {
            return nil
        }
        
        return try readTextFromPath(file)
    }
    
    func deleteRootIdentity(_ id: String) throws -> Bool {
        let dir = try getRootIdentityDir(id)
        if try dirExists(dir) {
            try deleteFile(dir)
            return true
        }
        else {
            return false
        }
    }
    
    func listRootIdentities() throws -> [RootIdentity] {
        let dir = try getFile(currentDataDir + "/" + ROOT_IDENTITIES_DIR)
        
        if try !dirExists(dir!) {
            return [ ]
        }
        
        var ids: [RootIdentity] = []
        let fileManager = FileManager.default
        let enumerator = try fileManager.contentsOfDirectory(atPath: dir!)
        for element: String in enumerator {
            let identity = try loadRootIdentity(element)
            ids.append(identity!)
        }
        
        return ids
    }
    
    func containsRootIdenities() throws -> Bool {
        let dir = try getFile(currentDataDir + "/" + ROOT_IDENTITIES_DIR)
        if try !dirExists(dir!) {
            return false
        }
        var ids: [String] = []
        let fileManager = FileManager.default
        let enumerator = try fileManager.contentsOfDirectory(atPath: dir!)
        for element: String in enumerator {
            ids.append(element)
        }
        
        return ids.count > 0
    }
    
    func loadRootIdentityMnemonic(_ id: String) throws -> String {
        let file = try getRootIdentityFile(id, ROOT_IDENTITY_MNEMONIC_FILE, false)
        return try readTextFromPath(file)
    }
    
    private func getDidFile(_ did: DID, _ create: Bool) throws -> String {
        let path = currentDataDir + "/" + DID_DIR + "/" + did.methodSpecificId + "/" + DOCUMENT_FILE
        return try getFile(create, path)
    }
    
    private func getDidMetadataFile(_ did: DID, _ create: Bool) throws -> String {
        let path = currentDataDir + "/" + DID_DIR + "/" + did.methodSpecificId + "/" + METADATA
        return try getFile(create, path)
    }
    
    private func getDidDir(_ did: DID) throws -> String {
        storeRoot + "/" + Constants.DID_DIR + "/" + did.methodSpecificId
        return try getFile(currentDataDir + "/" + DID_DIR + "/" + did.methodSpecificId)!
    }
    
    func storeDidMetadata(_ did: DID, _ metadata: DIDMetadata) throws {
        do {
            let file = try getDidMetadataFile(did, true)

            if metadata.isEmpty() {
                var path: String = storeRoot
                path.append("/")
                path.append(currentDataDir)
                path.append("/")
                path.append(did.methodSpecificId)
                path.append("/")
                path.append(Constants.META_FILE)
                
                if FileManager.default.fileExists(atPath: path) {
                    try FileManager.default.removeItem(atPath: path)
                }

            } else {
                try metadata.serialize(file)
            }
        } catch {
            throw DIDError.didStoreError("store DID metadata error")
        }
    }
    
    func loadDidMetadata(_ did: DID) throws -> DIDMetadata? {
    let file = try getDidMetadataFile(did, false)
        var metadata: DIDMetadata?
        if try dirExists(file) {
            metadata = DIDMetadata.parse(file)
        }

        return metadata
    }

    func storeDid(_ doc: DIDDocument) throws {
        let path = try getDidFile(doc.subject, true)
        try doc.convertFromDIDDocument(true, asFileAtPath: path)
    }

    func loadDid(_ did: DID) throws -> DIDDocument? {
        do {
            var data: Data
            do {
                let handle = try openDocumentFile(did)
                defer {
                    handle.closeFile()
                }
                data = handle.readDataToEndOfFile()
            } catch {
                return nil
            }
            return try DIDDocument.convertToDIDDocument(fromData: data)
        } catch {
            throw DIDError.didStoreError("load DIDDocument error")
        }
    }

    func deleteDid(_ did: DID) -> Bool {
        do {
            let path = storeRoot + "/" + Constants.DID_DIR + "/" + did.methodSpecificId
            try FileManager.default.removeItem(atPath: path)
            return true
        } catch {
            return false
        }
    }

    func listDids() throws -> Array<DID> {
        var dids: Array<DID> = []
//        let path = storeRoot + "/" + FileSystemStorage.DID_DIR
        let path = try getFile(currentDataDir + "/" + DID_DIR)
        let re = try dirExists(path!)
        guard re else {
            return []
        }

        let fileManager = FileManager.default
        let enumerator = try fileManager.contentsOfDirectory(atPath: path!)
        for element: String in enumerator {
            let did = DID(DID.METHOD, element)
            dids.append(did)
        }
        return dids
    }

    private func getCredentialFile(_ id: DIDURL, _ create: Bool) throws -> String {
        
        return try getFile(create, currentDataDir + "/" + DID_DIR + "/" + id.did!.methodSpecificId + "/" +
                            CREDENTIALS_DIR + "/" + FileSystemStorage.toPath(id) + "/" + CREDENTIAL_FILE)
    }
    
    private func getCredentialMetadataFile(_ id: DIDURL, _ create: Bool) throws -> String {
        
        return try getFile(create, currentDataDir + "/" + DID_DIR + "/" + id.did!.methodSpecificId + "/" +
                            CREDENTIALS_DIR + "/" + FileSystemStorage.toPath(id) + "/" + METADATA)
    }

    private func getCredentialDir(_ id: DIDURL) throws -> String {
        
        return try getFile(currentDataDir + "/" + DID_DIR + "/" + id.did!.methodSpecificId + "/" +
                            CREDENTIALS_DIR + "/" + FileSystemStorage.toPath(id))!
    }
    
    private func getCredentialsDir(_ id: DID) throws -> String {
        let path = currentDataDir + "/" + DID_DIR + "/" + id.methodSpecificId + "/" + CREDENTIALS_DIR
            
        return try getFile(path)!
    }
    
    func storeCredentialMetadata(_ id: DIDURL, _ metadata: CredentialMetadata) throws {
        do {
            let file = try getCredentialMetadataFile(id, true)
//            let handle = try openCredentialMetaFile(did, id, true)
            if metadata.isEmpty() {
                try FileManager.default.removeItem(atPath: file)
            } else {
                metadata.serialize(file)
            }
        } catch {
            throw DIDError.didStoreError("store credential meta error")
        }
    }

    func loadCredentialMetadata(_ id: DIDURL) throws -> CredentialMetadata? {
        let file = try getCredentialMetadataFile(id, false)
        if try !fileExists(file) {
            return nil
        }
        return CredentialMetadata.parse(file)
    }

    func storeCredential(_ credential: VerifiableCredential) throws {
        let path = try getCredentialFile(credential.getId()!, true)
        let fileHandle = FileHandle(forWritingAtPath: path)
        let generator = JsonGenerator()
        credential.toJson(generator, true)

        fileHandle!.write(generator.toString().data(using: .utf8)!)
    }

    func loadCredential(_ id: DIDURL) throws -> VerifiableCredential? {
        do {
            let path = try getCredentialFile(id, false)
            if try !fileExists(path) {
                return nil
            }
            
            return try VerifiableCredential.fromJson(for: path)
        } catch {
            throw DIDError.didStoreError("load credential error")
        }
    }

    func containsCredentials(_ did: DID) -> Bool {
        do {
            let dir = try getCredentialsDir(did)
            let exit = try dirExists(dir)
            guard exit else {
                return false
            }
            let arr = try listCredentials(did)
            guard arr.count > 0 else {
                return false
            }
            return true
        } catch  {
            return false
        }
    }

    func deleteCredential(_ id: DIDURL) -> Bool {
        do {
            var dir = try getCredentialDir(id)
            if try dirExists(dir) {
                try FileManager.default.removeItem(atPath: dir)
                dir = try getCredentialsDir(id.did!)
                
                let fileManager = FileManager.default
                let enumerator = try fileManager.contentsOfDirectory(atPath: dir)
                if enumerator.count == 0 {
                    try fileManager.removeItem(atPath: dir)
                }
                return true
            }
            return false
        } catch {
            return false
        }
    }
    
    func listCredentials(_ did: DID) throws -> Array<DIDURL> {
        let dir = try getCredentialsDir(did)
        guard try dirExists(dir) else {
            return []
        }
        
        let fileManager = FileManager.default
        let enumerator = try fileManager.contentsOfDirectory(atPath: dir)
        var didurls: Array<DIDURL> = []
        for element: String in enumerator  {
            // if !element.hasSuffix(".meta")
            let didUrl: DIDURL = try DIDURL(did, element)
            didurls.append(didUrl)
        }
        return didurls
    }
    
    private func getPrivateKeyFile(_ id: DIDURL, _ create: Bool) throws -> String {
        let path = currentDataDir + "/" + DID_DIR + "/" + id.did!.methodSpecificId + "/" +
            PRIVATEKEYS_DIR + "/" + FileSystemStorage.toPath(id)
        return try getFile(create, path)
    }

    private func getPrivateKeysDir(_ did: DID) throws -> String {
        
        return try getFile(currentDataDir + "/" + DID_DIR + "/" + did.methodSpecificId + "/" + PRIVATEKEYS_DIR)!
    }

    func storePrivateKey(_ id: DIDURL, _ privateKey: String) throws {
        do {
            let file = try getPrivateKeyFile(id, true)
            try writeTextToPath(file, privateKey)
        } catch {
            throw DIDError.didStoreError("store private key error.")
        }
    }

    func loadPrivateKey(_ id: DIDURL) throws -> String {
        do {
            let file = try getPrivateKeyFile(id, false)
            return try readTextFromPath(file)
        } catch {
            throw DIDError.didStoreError("load private key error.")
        }
    }

    func containsPrivateKeys(_ did: DID) throws -> Bool {
        let dir = try getPrivateKeysDir(did)
        if try !dirExists(dir) {
            return false
        }
        let fileManager: FileManager = FileManager.default
        var isDir = ObjCBool.init(false)
        _ = fileManager.fileExists(atPath: dir, isDirectory: &isDir)
        guard isDir.boolValue else {
            return false
        }
        
        var keys: [String] = []
        if let dirContents = fileManager.enumerator(atPath: dir) {
            // determine whether files are hidden or not
            while let url = dirContents.nextObject() as? String  {
                // Not hiding files
                if url.first!.description != "." {
                    keys.append(url)
                }
            }
        }
        return keys.count > 0
    }
    
    func deletePrivateKey(_ id: DIDURL) -> Bool {
        do {
            let file = try getPrivateKeyFile(id, false)
            if try fileExists(file) {
                _ = try deleteFile(file)
                
                // Remove the privatekeys directory is no privatekey exists.
                let dir = try getPrivateKeysDir(id.did!)
                let fileManager = FileManager.default
                let enumerator = try fileManager.contentsOfDirectory(atPath: dir)
                if enumerator.count == 0 {
                    try fileManager.removeItem(atPath: dir)
                }
            }
            return false
        } catch {
            return false
        }
    }
    
    func listPrivateKeys(_ did: DID) throws -> Array<DIDURL> {
        let dir = try getPrivateKeysDir(did)
        if try !dirExists(dir) {
            return []
        }
        let fileManager = FileManager.default
        let enumerator = try fileManager.contentsOfDirectory(atPath: dir)
        if  enumerator.isEmpty {
            return []
        }
        var sks: [DIDURL] = []
        for key in enumerator {
            try sks.append(FileSystemStorage.toDIDURL(did, key))
        }

        return sks
    }
    
    private func needReencrypt(_ path: String) throws -> Bool {
        let patterns: Array<String> = [
            "(.+)\\" + "/" + DATA_DIR + "\\" + "/" + ROOT_IDENTITIES_DIR + "\\" + "/" + "(.+)\\" + "/" + "ROOT_IDENTITY_PRIVATEKEY_FILE",
            "(.+)\\" + "/" + DATA_DIR + "\\" + "/" + ROOT_IDENTITIES_DIR + "\\" + "/" + "(.+)\\" + "/" + "ROOT_IDENTITY_MNEMONIC_FILE",
            "(.+)\\" + "/" + DATA_DIR + "\\" + "/" + DID_DIR + "\\" + "/" + "(.+)" + "\\" + "/" + PRIVATEKEYS_DIR + "\\" + "/" + "(.+)"]
        for pattern in patterns {
            let matcher: RegexHelper = try RegexHelper(pattern)
            
            if matcher.match(input: path)  { // if (path.matches(pattern))
                return true
            }
        }
        return false
    }
    
    private func copy(_ src: String, _ dest: String, _ callback: ReEncryptor) throws {
        if isDirectory(src) {
            try createDir(true, dest) // dest create if not
            
            let fileManager = FileManager.default
            let enumerator = try fileManager.contentsOfDirectory(atPath: src)
            for element: String in enumerator  {
                // if !element.hasSuffix(".meta")
                let srcFile = src + "/" + element
                let destFile = dest + "/" + element
                try copy(srcFile, destFile, callback)
            }
        }
        else {
            if try needReencrypt(src) {
                let org = try readTextFromPath(src)
                try writeTextToPath(dest, callback(org))
            }
            else {
                let fileManager = FileManager.default
                try fileManager.copyItem(atPath: src, toPath: dest)
            }
        }
    }
    
    private func postChangePassword() throws {
        let dataDir = try getFile(DATA_DIR)
        let dataJournal = try getFile(DATA_DIR + "/" + JOURNAL_SUFFIX)
        let timestamp = DateFormatter.getTimeStampForString(DateFormatter.currentDate())
        let dataDeprecated = try getFile(DATA_DIR + "_" + timestamp)
        let stageFile = try getFile("postChangePassword")
        
        let fileManager = FileManager.default
        if fileManager.fileExists(atPath: stageFile!) {
            if try dirExists(dataJournal!) {
                if try dirExists(dataDir!) {
                    try fileManager.moveItem(atPath: dataDir!, toPath: dataDeprecated!)
                }
                try fileManager.moveItem(atPath: dataJournal!, toPath: dataDir!)
            }
            _ = try deleteFile(stageFile!)
        }
        else {
            if try dirExists(dataJournal!) {
                _ = try deleteFile(dataJournal!)
            }
        }
    }
    
    func changePassword(_ reEncryptor: ReEncryptor) throws {
        let dataDir = try getFile(DATA_DIR)
        let dataJournal = try getFile(DATA_DIR + "/" + JOURNAL_SUFFIX)

        do {
            try copy(dataDir!, dataJournal!, reEncryptor)
        }
        catch {
            throw DIDError.didStoreError("Change store password failed.")
        }
        let stageFile = try getFile(true, "postChangePassword")
        // create new file ?
        try postChangePassword()
    }
    
    // Dirty upgrade implementation
    /* V2 store layout:
     *  + DIDStore root
     *    - .meta                            [Store meta file, include magic and version]
     *    + private                            [Personal root private key for HD identity]
     *      - key                            [HD root private key]
     *      - index                            [Last derive index]
     *    + ids
     *      + ixxxxxxxxxxxxxxx0             [DID root, named by id specific string]
     *        - .meta                        [Meta for DID, json format, OPTIONAL]
     *        - document                    [DID document, json format]
     *        + credentials                    [Credentials root, OPTIONAL]
     *          + credential-id-0           [Credential root, named by id' fragment]
     *            - .meta                    [Meta for credential, json format, OPTONAL]
     *            - credential                [Credential, json format]
     *          + ...
     *          + credential-id-N
     *            - .meta
     *            - credential
     *        + privatekeys                    [Private keys root, OPTIONAL]
     *          - privatekey-id-0            [Encrypted private key, named by pk' id]
     *          - ...
     *          - privatekey-id-N
     *
     *      ......
     *
     *      + ixxxxxxxxxxxxxxxN
     */
    
    func upgradeFromV2() throws {
        Log.i(TAG, "Try to upgrading DID store to the latest version...")
        var path = try getFile(".meta")
        if try !fileExists(path!) {
            Log.e(TAG, "Abort upgrade DID store, invalid DID store metadata file")
            throw DIDError.didStoreError("Directory '\(storeRoot)' is not a DIDStore.")
        }
        let data = FileHandle(forReadingAtPath: path!)!.readDataToEndOfFile()
        guard data.count == 8 else {
            throw DIDError.didStoreError("Directory \(storeRoot) is not DIDStore directory")
        }
        let versionArray : [UInt8] = [UInt8](data[4...7])
        var version : UInt32 = 0
        let storeVersion = NSData(bytes: versionArray, length: 4)
        storeVersion.getBytes(&version, length: 4)
        version = UInt32(bigEndian: version)
        
        let magicArray : [UInt8] = [UInt8](data[0...3])
        var magic : UInt32 = 0
        let storeMagic = NSData(bytes: magicArray, length: 4)
        storeMagic.getBytes(&magic, length: 4)
        magic = UInt32(bigEndian: magic)
        
        guard data[0...3].elementsEqual(MAGIC) else {
            Log.e(TAG, "Abort upgrade DID store, failed load DID store metadata file")
            throw DIDError.didStoreError("Check DIDStore '\(storeRoot)' error.")
        }
        guard version == 2 else {
            Log.e(TAG, "Abort upgrade DID store, invalid DID store version")
            throw DIDError.CheckedError.DIDStoreError.DIDStorageError.DIDStoreVersionMismatchError("Version: \(version)")
        }
            // upgrade to data journal directory
            currentDataDir = DATA_DIR + JOURNAL_SUFFIX
            var dir = try getFile(currentDataDir)
            if try dirExists(dir!) {
                try deleteFile(dir!)
            }
            try createDir(true, dir!)
            var id: String
            dir = try getFile("private")
            if try !dirExists(dir!) {
                Log.e(TAG, "Abort upgrade DID store, invalid root identity folder")
                throw DIDError.didStoreError("Invalid root identity folder")
            }
            // Root identity
        path = try getFile("private" + "/" + "key")
            var privateKey: String?
            if try fileExists(path!) {
                privateKey = try readTextFromPath(path!)
            }
            if privateKey == nil || privateKey!.isEmpty {
                Log.e(TAG, "Abort upgrade DID store, invalid root private key")
                throw DIDError.didStoreError("Invalid root private key")
            }
        path = try getFile("private" + "/" + "key.pub")
            var publicKey: String?
            if try fileExists(path!) {
                publicKey = try readTextFromPath(path!)
            }
            if publicKey == nil || publicKey!.isEmpty {
                Log.e(TAG, "Abort upgrade DID store, invalid root public key")
                throw DIDError.didStoreError("Invalid root public key")
            }
        path = try getFile("private" + "/" + "mnemonic")
            var mnemonic: String?
            if try fileExists(path!) {
                mnemonic = try readTextFromPath(path!)
            }
        path = try getFile("private" + "/" + "index")
            var index = 0
            if try fileExists(path!) {
                index = try Int(value: readTextFromPath(path!))
            }
            let pk = DIDHDKey.deserializeBase58(publicKey!)
            id = try RootIdentity.getId(pk.serializePublicKey())
            try storeRootIdentity(id, mnemonic, privateKey, publicKey, index)
            
        // Create store metadata with default root identity
        var metadata = DIDStoreMetadata()
        try metadata.setDefaultRootIdentity(id)
        try storeMetadata(metadata)
        
        // DIDs
        dir = try getFile("ids")
        if try !dirExists(dir!) {
            return
        }
        var ids: [DID] = []
        let fileManager = FileManager.default
        let enumerator = try fileManager.contentsOfDirectory(atPath: dir!)
        if enumerator.count == 0 {
            return
        }
        for element: String in enumerator  {
            let did = DID(DID.METHOD, element)
            // DID document and metadata
            path = try getFile("\(element)/document")
            if try !fileExists(path!) {
                Log.e(TAG, "Abort upgrade DID store, invalid DID document: \(element)")
                throw DIDError.didStoreError("Invalid DID document: \(element)")
            }
//            let doc = DIDDocument.parse(file)
            let doc = try DIDDocument.convertToDIDDocument(fromFileAtPath: path!)
            try storeDid(doc)
            path = try getFile("\(element)/.meta")
            if try fileExists(path!) {
                let dm = upgradeMetadataV2(path!, DIDMetadata.self) as! DIDMetadata
                try storeDidMetadata(doc.subject, dm)
            }
            
            // Credentials
            dir = try getFile(element + "/" + "credentials")
            guard try dirExists(dir!) else {
                Log.e(TAG, "Abort upgrade DID store, invalid credential directory: \(element)")
                throw DIDError.didStoreError("Invalid credential directory: \(element)")
            }
            let fileManager = FileManager.default
            let vcs = try fileManager.contentsOfDirectory(atPath: dir!)
            if vcs.count == 0 {
                return
            }
            for vcDir in vcs {
                path = try getFile("ids" + "/" + element + "/" + "credentials" + "/" +
                                vcDir + "/" + "credential")
                if try !fileExists(path!) {
                    continue
                }
//               let vc = VerifiableCredential.parse(file)
                let vc = try VerifiableCredential.fromJson(for: path!)
                try storeCredential(vc)
                path = try getFile("ids" + "/" + element + "/" + "credentials" + "/" +
                        vcDir + "/" + ".meta")
                let cm = upgradeMetadataV2(path!, CredentialMetadata.self) as! CredentialMetadata
                try storeCredentialMetadata(vc.getId()!, cm)
            }
   
            // Private keys
            dir = try getFile("ids" + "/" + element + "/" + "privatekeys")
            guard try dirExists(dir!) else {
                Log.e(TAG, "Abort upgrade DID store, invalid private keys directory: \(element)")
                throw DIDError.didStoreError("Invalid private keys directory:  \(element)")
            }
            let sks = try fileManager.contentsOfDirectory(atPath: dir!)
            if sks.count == 0 {
                return
            }
            if sks == nil || sks.isEmpty {
                break
            }
        // For each credential
            for skFile in sks {
                // Credential and metadata
                let sk = try readTextFromPath(skFile)
                if sk == nil || sk.isEmpty {
                    continue
                }
                let keyId = try DIDURL(did, "#" + skFile)
                try storePrivateKey(keyId, sk)
            }
        }
        
        currentDataDir = DATA_DIR
        let stageFile = try getFile("postUpgrade")
        let timestamp = DateFormatter.getTimeStampForString(DateFormatter.currentDate())
        try writeTextToPath(stageFile!, DATA_DIR + "_" + timestamp)
        try postUpgrade()
    }
    
    private func postUpgrade() throws {
        let dataDir = try getFile(DATA_DIR)
        let dataJournal = try getFile(DATA_DIR + "/" + JOURNAL_SUFFIX)
        let stageFile = try getFile("postUpgrade")
        // The fail-back file name
        let timestamp = DateFormatter.getTimeStampForString(DateFormatter.currentDate())
        var fileName = DATA_DIR + "_" + timestamp
        fileName = try readTextFromPath(stageFile!)
        let dataDeprecated = try getFile(fileName)
        if try fileExists(stageFile!) {
            if try fileExists(dataJournal!) {
                if try dirExists(dataDir!) {
                    throw DIDError.didStoreError("Data conflict when upgrade")
                }
                try createDir(true, dataDir!)
                try FileManager.default.moveItem(atPath: dataJournal!, toPath: dataDir!)
                _ = try deleteFile(dataJournal!)
            }
            try createDir(true, dataDeprecated!)
            let file = try getFile(".meta")
            if try fileExists(file!) {
                try FileManager.default.moveItem(atPath: file!, toPath: dataDeprecated! + ".meta")
            }
            //TODO: private ids
        }
    }
    
    private func upgradeMetadataV2<T>(_ filePath: String, _ class: T) -> T.Type{
        // TODO:
        return T.Type.self as! T.Type
    }
    
    private func postOperations(){
        // TODO:
    }
    /*
     private void postOperations() throws DIDStorageException {
         File stageFile = getFile("postUpgrade");
         if (stageFile.exists()) {
             postUpgrade();
             return;
         }

         stageFile = getFile("postChangePassword");
         if (stageFile.exists()) {
             postChangePassword();
             return;
         }
     }
     */
    
    private func openPrivateIdentityIndexFile(_ forWrite: Bool) throws -> FileHandle {
        return try openFileHandle(forWrite, Constants.PRIVATE_DIR, Constants.INDEX_FILE)
    }

    private func openPrivateIdentityIndexFile() throws -> FileHandle {
        return try openPrivateIdentityIndexFile(false)
    }

    private func openDidMetaFile(_ did: DID, _ forWrite: Bool) throws -> FileHandle {
        return try openFileHandle(forWrite, Constants.DID_DIR, did.methodSpecificId, Constants.META_FILE)
    }

    private func openDidMetaFile(_ did: DID) throws -> FileHandle {
        return try openDidMetaFile(did, false)
    }

    private func openDocumentFile(_ did: DID, _ forWrite: Bool) throws -> FileHandle {
        return try openFileHandle(forWrite, Constants.DID_DIR, did.methodSpecificId, Constants.DOCUMENT_FILE)
    }

    private func openDocumentFile(_ did: DID) throws -> FileHandle {
        return try openDocumentFile(did, false)
    }

    private func getLastModificationDate(_ path: String) throws -> Date {
        let fileAttributes = try FileManager.default.attributesOfItem(atPath: path)
        let modificationDate = fileAttributes[FileAttributeKey.modificationDate] as! Date
        return modificationDate
    }
    
    private func openCredentialMetaFile(_ did: DID, _ id: DIDURL, _ forWrite: Bool) throws -> FileHandle {
        return try openFileHandle(forWrite, Constants.DID_DIR, did.methodSpecificId,
                                  Constants.CREDENTIALS_DIR, id.fragment!, Constants.META_FILE)
    }

    private func openCredentialMetaFile(_ did: DID, _ id: DIDURL) throws -> FileHandle {
        return try openCredentialMetaFile(did, id, false)
    }
    
    private func openCredentialFile(_ did: DID, _ id: DIDURL, _ forWrite: Bool) throws -> FileHandle {
        return try openFileHandle(forWrite, Constants.DID_DIR, did.methodSpecificId,
                                  Constants.CREDENTIALS_DIR, id.fragment!, Constants.CREDENTIAL_FILE)
    }

    private func openCredentialFile(_ did: DID, _ id: DIDURL) throws -> FileHandle {
        return try openCredentialFile(did, id, false)
    }
    
    private func getFile(_ create: Bool, _ path: String) throws -> String {
        let relPath = storeRoot + "/" + path
        let fileManager = FileManager.default
        if create {
            var isDirectory = ObjCBool.init(false)
            let fileExists = FileManager.default.fileExists(atPath: relPath, isDirectory: &isDirectory)
            if !isDirectory.boolValue && fileExists {
                _ = try deleteFile(relPath)
            }
        }
        if create {
            let dirPath: String = PathExtracter(relPath).dirname()
            if try !dirExists(dirPath) {
                try fileManager.createDirectory(atPath: dirPath, withIntermediateDirectories: true, attributes: nil)
            }
            fileManager.createFile(atPath: relPath, contents: nil, attributes: nil)
        }
        return relPath
    }
    
    private func getFile(_ path: String) throws -> String? {
        return try getFile(false, path)
    }

    private func openPrivateKeyFile(_ did: DID, _ id: DIDURL, _ forWrite: Bool) throws -> FileHandle {
        return try openFileHandle(forWrite, Constants.DID_DIR, did.methodSpecificId,
                                  Constants.PRIVATEKEYS_DIR, id.fragment!)
    }

    private func openPrivateKeyFile(_ did: DID, _ id: DIDURL) throws -> FileHandle {
        return try openPrivateKeyFile(did, id, false)
    }

    private func isDirectory(_ path: String) -> Bool {
        let fileManager = FileManager.default
        var isDir : ObjCBool = false
        _ = fileManager.fileExists(atPath: path, isDirectory:&isDir)
        return isDir.boolValue
    }
    
    private class func isDirectory(_ path: String) -> Bool {
        let fileManager = FileManager.default
        var isDir : ObjCBool = false
        _ = fileManager.fileExists(atPath: path, isDirectory:&isDir)
        return isDir.boolValue
    }
    
    private func createDir(_ create: Bool, _ path: String) throws {
        let fileManager = FileManager.default
        if create {
            var isDirectory = ObjCBool.init(false)
            let fileExists = FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory)
            if !fileExists {
                try fileManager.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: nil)
            }
        }
    }
    
    private class func createDir(_ create: Bool, _ path: String) throws {
        let fileManager = FileManager.default
        if create {
            var isDirectory = ObjCBool.init(false)
            let fileExists = FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory)
            if !fileExists {
                try fileManager.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: nil)
            }
        }
    }
    
    private func readTextFromPath(_ path: String) throws -> String {
        guard try fileExists(path) else {
            return ""
        }
        return try String(contentsOfFile:path, encoding: String.Encoding.utf8)
    }
    
    private func writeTextToPath(_ path: String, _ text: String) throws {
        let writePath = try getFile(path)
        let fileManager = FileManager.default
        // Delete before writing
        _ = try deleteFile(writePath!)
        fileManager.createFile(atPath: path, contents:nil, attributes:nil)
        let handle = FileHandle(forWritingAtPath:path)
        handle?.write(text.data(using: String.Encoding.utf8)!)
    }
    
    func intToByteArray(i : Int) -> [UInt8] {
        var result: [UInt8] = []
        result.append(UInt8((i >> 24) & 0xFF))
        result.append(UInt8((i >> 16) & 0xFF))
        result.append(UInt8((i >> 8) & 0xFF))
        result.append(UInt8(i & 0xFF))
        return result
    }
}
