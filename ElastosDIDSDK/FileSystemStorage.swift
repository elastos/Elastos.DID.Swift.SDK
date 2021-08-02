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
        try checkArgument(!dir.isEmpty, "Invalid DIDStore root directory.")
    
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
            let path = try fullPath(true, currentDataDir, METADATA)
            let metadata = DIDStoreMetadata()
            try metadata.serialize(path)
        } catch {
            Log.i(TAG, "Initialize DID store error ", storeRoot)
            throw DIDError.CheckedError.DIDStoreError.DIDStorageError("Initialize DIDStore \(storeRoot) error.")
        }
    }

    private func checkStore() throws {
        var isDir: ObjCBool = false
        Log.d(TAG, "Checking DID store at ", storeRoot)

        // Further to check the '_rootPath' is not a file path.
        guard FileManager.default.fileExists(atPath: storeRoot, isDirectory: &isDir) && isDir.boolValue else {
            Log.i(TAG, "Path ", storeRoot, " not a directory")
            throw DIDError.CheckedError.DIDStoreError.DIDStorageError("Invalid DIDStore ' \(storeRoot) '.")
        }
        try postOperations()
        let path = try fullPath(false, currentDataDir, METADATA)
        if try !path.fileExists() {
            let oldMetadata = try fullPath(".meta")
            if try oldMetadata.exists() {
               
                try upgradeFromV2()
            }
            else {
                let list = try storeRoot.files()
//               let list = try? FileManager.default.contentsOfDirectory(atPath: storeRoot)
                if list.count == 0 {
                    // if an empty folder
                    try initializeStore()
                    return
                }
                else {
                    Log.e(TAG, "Path ", storeRoot, "not a DID store")
                    throw DIDError.CheckedError.DIDStoreError.DIDStorageError("Invalid DIDStore ' \(storeRoot) '.")
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
            throw  DIDError.CheckedError.DIDStoreError.DIDStorageError("Can not check the store metadata")
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
        return path.replacingOccurrences(of: ";", with: "+").replacingOccurrences(of: "/", with: "~").replacingOccurrences(of: "?", with: "!")
    }
    
    private class func toDIDURL(_ did: DID, _ path: String) throws -> DIDURL {
       let p = path.replacingOccurrences(of: "+", with: ";").replacingOccurrences(of: "~", with: "/").replacingOccurrences(of: "!", with: "?")
        return try DIDURL(did, p)
    }
    
    private class func copyFile(_ src: String, _ dest: String) throws {
        if src.isDirectory() {
            try dest.createDir(true) // dest create if not
            
            let fileManager = FileManager.default
            let enumerator = try fileManager.contentsOfDirectory(atPath: src)
            for element: String in enumerator  {
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

    private func openFileHandle(_ forWrite: Bool, _ pathArgs: String...) throws -> FileHandle {
        var path: String = storeRoot + "/" + DATA_DIR
        for item in pathArgs {
            path.append("/")
            path.append(item)
        }

        if forWrite {
            // Delete before writing
            _ = try path.deleteFile()
        }
        if try !path.fileExists() && forWrite {
            let dirPath: String = path.dirname()
            if try !dirPath.fileExists() {
                try dirPath.createDir(true)
            }
            try path.create(forWrite: true)
        }

        let handle: FileHandle?
        if forWrite {
            handle = FileHandle(forWritingAtPath: path)
        } else {
            handle = FileHandle(forReadingAtPath: path)
        }

        guard let _ = handle else {
            throw DIDError.UncheckedError.IllegalArgumentErrors.IllegalArgumentError("opening file at \(path) error")
        }

        return handle!
    }

    func getLocation() -> String {
        return storeRoot
    }

    func storeMetadata(_ metadata: DIDStoreMetadata) throws {
        let path = try fullPath(true, currentDataDir, METADATA)
        if metadata.isEmpty() {
            _ = try path.deleteFile()
        }
        else {
            try metadata.serialize(path)
        }
    }

    func loadMetadata() throws -> DIDStoreMetadata? {
        let path = try fullPath(currentDataDir, METADATA)
        var metadata: DIDStoreMetadata?
        if try path.fileExists() {
            metadata = try DIDStoreMetadata.parse(path)
        }
        
        return metadata
    }

    private func getRootIdentityFile(_ id: String, _ file: String, _ create: Bool) throws -> String {
        return try fullPath(create, currentDataDir, ROOT_IDENTITIES_DIR, id, file)
    }

    private func getRootIdentityDir(_ id: String) throws -> String {
        return try fullPath(currentDataDir, ROOT_IDENTITIES_DIR, id)
    }

    func storeRootIdentityMetadata(_ id: String, _ metadata: RootIdentityMetadata) throws {
        do {
            let file = try getRootIdentityFile(id, METADATA, true)
            if metadata.isEmpty() {
                _ = try file.deleteFile()
            }
            else {
                try metadata.serialize(file)
            }
        } catch {
            throw DIDError.CheckedError.DIDStoreError.DIDStorageError("Store root identity metadata error: \(id)")
        }
    }

    func loadRootIdentityMetadata(_ id: String) throws -> RootIdentityMetadata? {
        do {
            let file = try getRootIdentityFile(id, METADATA, false)
            var metadata: RootIdentityMetadata?
            if try file.fileExists() {
                metadata = try RootIdentityMetadata.parse(file)
            }

            return metadata
        } catch {
            throw DIDError.CheckedError.DIDStoreError.DIDStorageError("Load root identity metadata error: \(id)")
        }
    }

    func storeRootIdentity(_ id: String, _ mnemonic: String?, _ privateKey: String?, _ publicKey: String?, _ index: Int) throws {
        if mnemonic != nil {
            let file = try getRootIdentityFile(id, ROOT_IDENTITY_MNEMONIC_FILE, true)
            try file.writeTextToPath(mnemonic!)
        }
        if privateKey != nil {
            let file = try! getRootIdentityFile(id, ROOT_IDENTITY_PRIVATEKEY_FILE, true)
            try file.writeTextToPath(privateKey!)
        }
        
        if publicKey != nil {
            let file = try getRootIdentityFile(id, ROOT_IDENTITY_PUBLICKEY_FILE, true)
            try file.writeTextToPath(publicKey!)
        }
        
        let file = try getRootIdentityFile(id, ROOT_IDENTITY_INDEX_FILE, true)
        try file.writeTextToPath("\(index)")
    }
    
    func loadRootIdentity(_ id: String) throws -> RootIdentity? {
        var file = try getRootIdentityFile(id, ROOT_IDENTITY_PUBLICKEY_FILE, false)
        if try !file.fileExists() {
            return nil
        }
        let publicKey = try file.readTextFromPath()
        file = try getRootIdentityFile(id, ROOT_IDENTITY_INDEX_FILE, false)
        let index = try Int(value: file.readTextFromPath())
        
        return try RootIdentity.create(publicKey, index)
    }
    
    func updateRootIdentityIndex(_ id: String, _ index: Int) throws {
        let file = try getRootIdentityFile(id, ROOT_IDENTITY_INDEX_FILE, false)
        try file.writeTextToPath("\(index)")
    }
    
    func loadRootIdentityPrivateKey(_ id: String) throws -> String? {
        let file = try getRootIdentityFile(id, ROOT_IDENTITY_PRIVATEKEY_FILE, false)
        if try !file.fileExists() {
            return nil
        }
        
        return try file.readTextFromPath()
    }
    
    func deleteRootIdentity(_ id: String) throws -> Bool {
        let dir = try getRootIdentityDir(id)
        if try dir.dirExists() {
            return try dir.deleteFile()
        }
        else {
            return false
        }
    }
    
    func listRootIdentities() throws -> [RootIdentity] {
        let dir = try fullPath(currentDataDir, ROOT_IDENTITIES_DIR)
        
        if try !dir.dirExists() {
            return [ ]
        }
        
        var ids: [RootIdentity] = []
        let enumerator = try dir.files()
        for element: String in enumerator {
            let identity = try loadRootIdentity(element)
            ids.append(identity!)
        }
        
        return ids
    }
    
    func containsRootIdenities() throws -> Bool {
        let dir = try fullPath(currentDataDir, ROOT_IDENTITIES_DIR)
        if try !dir.dirExists() {
            return false
        }
        var ids: [String] = []
        let enumerator = try dir.files()
        for element: String in enumerator {
            ids.append(element)
        }
        
        return ids.count > 0
    }
    
    func loadRootIdentityMnemonic(_ id: String) throws -> String {
        let file = try getRootIdentityFile(id, ROOT_IDENTITY_MNEMONIC_FILE, false)
        return try file.readTextFromPath()
    }
    
    private func getDidFile(_ did: DID, _ create: Bool) throws -> String {
        return try fullPath(create, currentDataDir, DID_DIR, did.methodSpecificId, DOCUMENT_FILE)
    }
    
    private func getDidMetadataFile(_ did: DID, _ create: Bool) throws -> String {
        return try fullPath(create, currentDataDir, DID_DIR, did.methodSpecificId, METADATA)
    }
    
    private func getDidDir(_ did: DID) throws -> String {
        return try fullPath(currentDataDir, DID_DIR, did.methodSpecificId)
    }
    
    public func storeDidMetadata(_ did: DID, _ metadata: DIDMetadata) throws {
        do {
            let file = try getDidMetadataFile(did, true)

            if metadata.isEmpty() {
               try FileManager.default.removeItem(atPath: file)
            } else {
                try metadata.serialize(file)
            }
        } catch {
            throw DIDError.CheckedError.DIDStoreError.DIDStorageError("store DID metadata error")
        }
    }
    
    func loadDidMetadata(_ did: DID) throws -> DIDMetadata? {
        let file = try getDidMetadataFile(did, false)
        var metadata: DIDMetadata?
        if try file.exists() {
            metadata = try DIDMetadata.parse(file)
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
            throw DIDError.CheckedError.DIDStoreError.DIDStorageError("load DIDDocument error")
        }
    }

    func deleteDid(_ did: DID) -> Bool {
        do {
            let path = try fullPath(DATA_DIR, Constants.DID_DIR, did.methodSpecificId)
            try path.deleteDir()
            return true
        } catch {
            return false
        }
    }
    
    func listDids() throws -> Array<DID> {
        var dids: Array<DID> = []
        let path = try fullPath(currentDataDir, DID_DIR)
        let re = try path.dirExists()
        guard re else {
            return []
        }

        let enumerator = try path.files()
        for element in enumerator {
            let did = DID(DID.METHOD, element)
            dids.append(did)
        }
        return dids
    }

    private func getCredentialFile(_ id: DIDURL, _ create: Bool) throws -> String {
        return try fullPath(create, currentDataDir, DID_DIR, id.did!.methodSpecificId,
                            CREDENTIALS_DIR, FileSystemStorage.toPath(id), CREDENTIAL_FILE)
    }
    
    private func getCredentialMetadataFile(_ id: DIDURL, _ create: Bool) throws -> String {
        return try fullPath(create, currentDataDir, DID_DIR, id.did!.methodSpecificId,
                            CREDENTIALS_DIR, FileSystemStorage.toPath(id), METADATA)
    }

    private func getCredentialDir(_ id: DIDURL) throws -> String {
        return try fullPath(currentDataDir, DID_DIR, id.did!.methodSpecificId,
                            CREDENTIALS_DIR, FileSystemStorage.toPath(id))
    }
    
    private func getCredentialsDir(_ id: DID) throws -> String {
        return try fullPath(currentDataDir, DID_DIR, id.methodSpecificId, CREDENTIALS_DIR)
    }
    
    func storeCredentialMetadata(_ id: DIDURL, _ metadata: CredentialMetadata) throws {
        do {
            let file = try getCredentialMetadataFile(id, true)
            if metadata.isEmpty() {
                try FileManager.default.removeItem(atPath: file)
            } else {
                try metadata.serialize(file)
            }
        } catch {
            throw DIDError.CheckedError.DIDStoreError.DIDStorageError("store credential meta error")
        }
    }

    func loadCredentialMetadata(_ id: DIDURL) throws -> CredentialMetadata? {
        let file = try getCredentialMetadataFile(id, false)
        if try !file.fileExists() {
            return nil
        }
        return try CredentialMetadata.parse(file)
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
            if try !path.fileExists() {
                return nil
            }
            
            return try VerifiableCredential.fromJson(for: path)
        } catch {
            throw DIDError.CheckedError.DIDStoreError.DIDStorageError("load credential error")
        }
    }

    func containsCredentials(_ did: DID) -> Bool {
        do {
            let dir = try getCredentialsDir(did)
            let exit = try dir.dirExists()
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
            if try dir.dirExists() {
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
        guard try dir.dirExists() else {
            return []
        }
        
        var didurls: Array<DIDURL> = []
        let enumerator = try dir.files()
        for element: String in enumerator  {
            let didUrl: DIDURL = try DIDURL(did, element)
            didurls.append(didUrl)
        }
        return didurls
    }
    
    private func getPrivateKeyFile(_ id: DIDURL, _ create: Bool) throws -> String {

        return try fullPath(create, currentDataDir, DID_DIR, id.did!.methodSpecificId, PRIVATEKEYS_DIR, FileSystemStorage.toPath(id))
    }

    private func getPrivateKeysDir(_ did: DID) throws -> String {
        
        return try fullPath(currentDataDir, DID_DIR, did.methodSpecificId, PRIVATEKEYS_DIR)
    }

    func storePrivateKey(_ id: DIDURL, _ privateKey: String) throws {
        do {
            let file = try getPrivateKeyFile(id, true)
            try file.writeTextToPath(privateKey)
        } catch {
            throw DIDError.CheckedError.DIDStoreError.DIDStorageError("store private key error.")
        }
    }

    func loadPrivateKey(_ id: DIDURL) throws -> String {
        do {
            let file = try getPrivateKeyFile(id, false)
            return try file.readTextFromPath()
        } catch {
            throw DIDError.CheckedError.DIDStoreError.DIDStorageError("load private key error.")
        }
    }

    func containsPrivateKeys(_ did: DID) throws -> Bool {
        let dir = try getPrivateKeysDir(did)
        if try !dir.dirExists() {
            return false
        }
        guard try dir.dirExists() else {
            return false
        }
        
        var keys: [String] = []
        let fileManager: FileManager = FileManager.default
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
            if try file.fileExists() {
                _ = try file.deleteFile()
                
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
        if try !dir.dirExists() {
            return []
        }
        let enumerator = try dir.files()
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
            "(.+)\\" + "/" + DATA_DIR + "\\" + "/" + ROOT_IDENTITIES_DIR + "\\" + "/" + "(.+)\\" + "/" + ROOT_IDENTITY_PRIVATEKEY_FILE,
            "(.+)\\" + "/" + DATA_DIR + "\\" + "/" + ROOT_IDENTITIES_DIR + "\\" + "/" + "(.+)\\" + "/" + ROOT_IDENTITY_MNEMONIC_FILE,
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
        if src.isDirectory() {
            try dest.createDir(true) // dest create if not
            
            let enumerator = try src.files()
            for element: String in enumerator  {
                // if !element.hasSuffix(".meta")
                if !element.hasSuffix(JOURNAL_SUFFIX) {
                    let srcFile = src + "/" + element
                    let destFile = dest + "/" + element
                    try copy(srcFile, destFile, callback)
                }
            }
        }
        else {
            if try needReencrypt(src) {
                let org = try src.readTextFromPath()
                try dest.writeTextToPath(callback(org))
            }
            else {
                let fileManager = FileManager.default
                try fileManager.copyItem(atPath: src, toPath: dest)
            }
        }
    }
    
    private func postChangePassword() throws {
        let dataDir = try fullPath(DATA_DIR)
        let dataJournal = try fullPath(JOURNAL_SUFFIX)
        let timestamp = DateFormatter.getTimeStampForString(DateFormatter.currentDate())
        let dataDeprecated = try fullPath(DATA_DIR + "_" + timestamp)
        let stageFile = try fullPath("postChangePassword")
        
        let fileManager = FileManager.default
        if fileManager.fileExists(atPath: stageFile) {
            if try dataJournal.dirExists() {
                if try dataDir.dirExists() {
                    try fileManager.moveItem(atPath: dataDir, toPath: dataDeprecated)
                }
                try fileManager.moveItem(atPath: dataJournal, toPath: dataDir)
            }
            _ = try stageFile.deleteFile()
        }
        else {
            if try dataJournal.dirExists() {
                _ = try dataJournal.deleteFile()
            }
        }
    }
    
    func changePassword(_ reEncryptor: ReEncryptor) throws {
        let dataDir = try fullPath(DATA_DIR)
        let dataJournal = try fullPath(JOURNAL_SUFFIX)

        do {
            try copy(dataDir, dataJournal, reEncryptor)
        }
        catch {
            throw DIDError.CheckedError.DIDStoreError.DIDStoreError("Change store password failed.")
        }
        _ = try fullPath(true, "postChangePassword")
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
        var path = try fullPath(".meta")
        if try !path.fileExists() {
            Log.e(TAG, "Abort upgrade DID store, invalid DID store metadata file")
            throw DIDError.CheckedError.DIDStoreError.DIDStorageError("Directory '\(storeRoot)' is not a DIDStore.")
        }
        let data = FileHandle(forReadingAtPath: path)!.readDataToEndOfFile()
        guard data.count == 8 else {
            throw DIDError.CheckedError.DIDStoreError.DIDStorageError("Directory \(storeRoot) is not DIDStore directory")
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
            throw DIDError.CheckedError.DIDStoreError.DIDStorageError("Check DIDStore '\(storeRoot)' error.")
        }
        guard version == 2 else {
            Log.e(TAG, "Abort upgrade DID store, invalid DID store version")
            throw DIDError.CheckedError.DIDStoreError.DIDStorageErrors.DIDStoreVersionMismatchError("Version: \(version)")
        }
        // upgrade to data journal directory
        currentDataDir = DATA_DIR + JOURNAL_SUFFIX
        var dir = try fullPath(currentDataDir)
        if try dir.dirExists() {
            _ = try dir.deleteFile()
        }
        try dir.createDir(true)
        var id: String
        dir = try fullPath("private")
        if try !dir.dirExists() {
            Log.e(TAG, "Abort upgrade DID store, invalid root identity folder")
            throw DIDError.CheckedError.DIDStoreError.DIDStorageError("Invalid root identity folder")
        }
        // Root identity
        path = try fullPath("private" + "/" + "key")
        var privateKey: String?
        if try path.fileExists() {
            privateKey = try path.readTextFromPath()
        }
        if privateKey == nil || privateKey!.isEmpty {
            Log.e(TAG, "Abort upgrade DID store, invalid root private key")
            throw DIDError.CheckedError.DIDStoreError.DIDStorageError("Invalid root private key")
        }
        path = try fullPath("private" + "/" + "key.pub")
        var publicKey: String?
        if try path.fileExists() {
            publicKey = try path.readTextFromPath()
        }
        if publicKey == nil || publicKey!.isEmpty {
            Log.e(TAG, "Abort upgrade DID store, invalid root public key")
            throw DIDError.CheckedError.DIDStoreError.DIDStorageError("Invalid root public key")
        }
        path = try fullPath("private" + "/" + "mnemonic")
        var mnemonic: String?
        if try path.fileExists() {
            mnemonic = try path.readTextFromPath()
        }
        path = try fullPath("private" + "/" + "index")
        var index = 0
        if try path.fileExists() {
            index = try path.readIndexFromPath()
        }
        let pk = DIDHDKey.deserializeBase58(publicKey!)
        id = try RootIdentity.getId(pk.serializePublicKey())
        try storeRootIdentity(id, mnemonic, privateKey, publicKey, index)
        
        // Create store metadata with default root identity
        let metadata = DIDStoreMetadata()
        try metadata.setDefaultRootIdentity(id)
        try storeMetadata(metadata)
        
        // DIDs
        dir = try fullPath("ids")
        if try !dir.dirExists() {
            return
        }
        let fileManager = FileManager.default
        let enumerator = try fileManager.contentsOfDirectory(atPath: dir)
        if enumerator.count == 0 {
            return
        }
        
        for element: String in enumerator  {
            let did = DID(DID.METHOD, element)
            // DID document and metadata
            path = dir + "/" + "\(element)/document"
            if element == ".DS_Store" {
                continue
            }
            if try !path.fileExists() {
                Log.e(TAG, "Abort upgrade DID store, invalid DID document: \(element)")
                throw DIDError.CheckedError.DIDStoreError.DIDStorageError("Invalid DID document: \(element)")
            }
            let doc = try DIDDocument.convertToDIDDocument(fromFileAtPath: path)
            try storeDid(doc)
            path = dir + "/" + "\(element)/.meta"
            if try path.fileExists() {
                let dm = try upgradeMetadataV2(path, DIDMetadata.self)
                try storeDidMetadata(doc.subject, dm)
            }
            
            // Credentials
            path = dir + "/" + element + "/" + "credentials"
            var subPath = path
            if try path.dirExists() {
                let fileManager = FileManager.default
                let vcs = try fileManager.contentsOfDirectory(atPath: path)
                if vcs.count == 0 {
                    return
                }
                for vcDir in vcs {
                    if vcDir == ".DS_Store" {
                        continue
                    }
                    path = subPath + "/" + vcDir + "/" + "credential"
                    if try !path.fileExists() {
                        continue
                    }
                    let vc = try VerifiableCredential.fromJson(for: path)
                    try storeCredential(vc)
                    path = try fullPath("ids", element, "credentials", vcDir, ".meta")
                    let cm = try upgradeMetadataV2(path, CredentialMetadata.self)
                    try storeCredentialMetadata(vc.getId()!, cm)
                }
            }
            // Private keys
            path = try fullPath("ids", element, "privatekeys")
            if try path.dirExists() {
                let sks = try fileManager.contentsOfDirectory(atPath: path)
                if sks.count == 0 {
                    return
                }
                if sks.isEmpty {
                    break
                }
                // For each credential
                subPath = path
                for skFile in sks {
                    if skFile == ".DS_Store" {
                        continue
                    }
                    // Credential and metadata
                    path = subPath + "/" + skFile
                    let sk = try path.readTextFromPath()
                    if sk.isEmpty {
                        continue
                    }
                    let keyId = try DIDURL(did, "#" + skFile)
                    try storePrivateKey(keyId, sk)
                }
            }
        }
        
        currentDataDir = DATA_DIR
        let stageFile = try fullPath("postUpgrade")
        let timestamp = DateFormatter.getTimeStampForString(DateFormatter.currentDate())
        
        try stageFile.writeTextToPath(DATA_DIR + "_" + timestamp)
        try postUpgrade()
    }
    
    private func postUpgrade() throws {
        let dataDir = try fullPath(DATA_DIR)
        let dataJournal = try fullPath(DATA_DIR + JOURNAL_SUFFIX)
        let stageFile = try fullPath("postUpgrade")
        // The fail-back file name
        let timestamp = DateFormatter.getTimeStampForString(DateFormatter.currentDate())
        var fileName = DATA_DIR + "_" + timestamp
        fileName = try stageFile.readTextFromPath()
        let dataDeprecated = try fullPath(fileName)
        if try stageFile.fileExists() {
            if try dataJournal.fileExists() {
                if try dataDir.dirExists() {
                    throw DIDError.CheckedError.DIDStoreError.DIDStorageError("Data conflict when upgrade")
                }
                try dataDir.createDir(true)
                try rename(dataJournal, dataDir)
                _ = try dataJournal.deleteFile()
            }
            try dataDeprecated.createDir(true)
            var file = try fullPath(".meta")
            if try file.fileExists() {
                let meta = dataDeprecated + "/.meta"
              try FileManager.default.moveItem(atPath: file, toPath: meta)
            }
            //private ids
            file = try fullPath("ids")
            if try file.fileExists() {
                let ids = dataDeprecated + "/ids"
                try rename(file, ids)
                _ = try file.deleteFile()
            }
            
            file = try fullPath("private")
            if try file.fileExists() {
                let pv = dataDeprecated + "/private"
                try rename(file, pv)
                _ = try file.deleteFile()
            }
            
            _ = try stageFile.deleteFile()
            Log.d(TAG, "v1 update to v2 is ok.")
        }
    }
    
    private func upgradeMetadataV2<T: AbstractMetadata>(_ filePath: String, _ cls: T.Type) throws -> T {
        let oldData = try filePath.readTextFromPath().toStringDictionary()
        var newData: [String: String] = [: ]
        oldData.forEach { k, v in
            var key = k
            if key.hasPrefix("DX-") {
                if key != "DX-lastModified" {
                    key = String(key.suffix(key.count - 3))
                    newData[key] = v as String
                }
            }
            else {
                key = AbstractMetadata.USER_EXTRA_PREFIX + key
                newData[key] = v as String
            }
        }
        
        if cls.self == DIDMetadata.self {
            let instance = DIDMetadata()
            instance._props = newData
            
            return instance as! T
        }
        else if cls.self == DIDStoreMetadata.self {
            let instance = DIDStoreMetadata()
            instance._props = newData
            
            return instance as! T
        }
        else if cls.self == CredentialMetadata.self {
            let instance = CredentialMetadata()
            instance._props = newData
            
            return instance as! T
        }
        else if cls.self == RootIdentityMetadata.self {
            let instance = RootIdentityMetadata()
            instance._props = newData
            
            return instance as! T
        }
        
        throw DIDError.CheckedError.DIDStoreError.DIDStorageError("TODO:")
    }
    
    private func postOperations() throws {
        var stageFile = try fullPath("postUpgrade")
        if try stageFile.exists() {
            try postUpgrade()
            return
        }
        stageFile = try fullPath("postChangePassword")
        if try stageFile.exists() {
            try postChangePassword()
            return
        }
    }
    
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

    private func openPrivateKeyFile(_ did: DID, _ id: DIDURL, _ forWrite: Bool) throws -> FileHandle {
        return try openFileHandle(forWrite, Constants.DID_DIR, did.methodSpecificId,
                                  Constants.PRIVATEKEYS_DIR, id.fragment!)
    }

    private func openPrivateKeyFile(_ did: DID, _ id: DIDURL) throws -> FileHandle {
        return try openPrivateKeyFile(did, id, false)
    }

    func intToByteArray(i : Int) -> [UInt8] {
        var result: [UInt8] = []
        result.append(UInt8((i >> 24) & 0xFF))
        result.append(UInt8((i >> 16) & 0xFF))
        result.append(UInt8((i >> 8) & 0xFF))
        result.append(UInt8(i & 0xFF))
        return result
    }
    
    func fullPath(_ create: Bool, _ pathArgs: String...) throws -> String {
        return try fullPath(create, pathArgs)
    }
    
    func fullPath(_ pathArgs: String...) throws -> String {
        return try fullPath(false, pathArgs)
    }

    static var pathSeparator = "/"
    private func fullPath(_ create: Bool, _ pathArgs: [String]) throws -> String {
        var fullPath = storeRoot
        for subPath in pathArgs {
            fullPath += FileSystemStorage.pathSeparator + subPath
        }

        let fileManager = FileManager.default
        if create {
            var isDirectory = ObjCBool.init(false)
            let fileExists = FileManager.default.fileExists(atPath: fullPath, isDirectory: &isDirectory)
            if !isDirectory.boolValue && fileExists {
                _ = try fullPath.deleteFile()
            }
        }
        if create {
            let dirPath: String = fullPath.dirname()
            if try !dirPath.dirExists() {
                try fileManager.createDirectory(atPath: dirPath, withIntermediateDirectories: true, attributes: nil)
            }
            fileManager.createFile(atPath: fullPath, contents: nil, attributes: nil)
        }
        
        return fullPath
    }
    
    private func rename(_ src: String, _ dest: String) throws {
        if src.isDirectory() {
            try dest.createDir(true) // dest create if not
            
            let enumerator = try src.files()
            for element: String in enumerator  {
                if !element.hasSuffix(JOURNAL_SUFFIX) {
                    let srcFile = src + "/" + element
                    let destFile = dest + "/" + element
                    try rename(srcFile, destFile)
                }
            }
        }
        else {
            let fileManager = FileManager.default
            try fileManager.copyItem(atPath: src, toPath: dest)
        }
    }
}
