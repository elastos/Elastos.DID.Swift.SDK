import Foundation

public struct KeyPair {
    var publicKey: Data?
    var privatekey: Data?
}

public class HDKey: NSObject {
    public static let PUBLICKEY_BYTES : Int = 33
    public static let PRIVATEKEY_BYTES: Int = 32
    public static let SEED_BYTES: Int = 64
    public static let EXTENDED_KEY_BYTES = 82
    public static let EXTENDED_PRIVATEKEY_BYTES = EXTENDED_KEY_BYTES
    public static let EXTENDED_PUBLICKEY_BYTES = EXTENDED_KEY_BYTES

    private static let PADDING_IDENTITY = 0x67
    private static let PADDING_STANDARD = 0xAD
    
    private var key: UnsafePointer<CHDKey>

    // Derive path: m/44'/0'/0'/0/index
    public static let DERIVE_PATH_PREFIX = "44H/0H/0H/0/"

    // Pre-derive publickey path: m/44'/0'/0'
    public static let PRE_DERIVED_PUBLICKEY_PATH = "44H/0H/0H"

    let PUBLICKEY_BASE58_BYTES = 64

    required init(_ key: UnsafePointer<CHDKey>) {
        self.key = key
    }

    public convenience init(_ mnemonic: String, _ passPhrase: String, _ language: String) {
        let cmnemonic = mnemonic.toUnsafePointerInt8()!
        let cpassphrase = passPhrase.toUnsafePointerInt8()!
        let chdKey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 66)
        let key = HDKey_FromMnemonic(cmnemonic, cpassphrase, language.toUnsafePointerInt8()!, chdKey)
        self.init(key)
    }

    public convenience init(_ seed: Data) {
        let cseed: UnsafePointer<UInt8> = seed.withUnsafeBytes { bytes -> UnsafePointer<UInt8> in
            return bytes
        }

        let chdKey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 66)
        let chdkey = HDKey_FromSeed(cseed, Int32(seed.count), chdKey)
        self.init(chdkey)
    }

    public func getPrivateKeyBytes() -> [UInt8] {
        let privatekeyPointer = HDKey_GetPrivateKey(key)
        let privatekeyPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: privatekeyPointer, count: HDKey.PRIVATEKEY_BYTES)
        let privatekeyData: Data = Data(buffer: privatekeyPointerToArry)

        return [UInt8](privatekeyData)
    }

    public func getPrivateKeyData() -> Data {
        let privatekeyPointer = HDKey_GetPrivateKey(key)
        let privatekeyPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: privatekeyPointer, count: HDKey.PRIVATEKEY_BYTES)

        return Data(buffer: privatekeyPointerToArry)
    }

//    public func getPrivateKeyBase58() -> String {
//
//    }

    public func getPublicKeyBytes() ->[UInt8] {
        let cpublicKeyPointer = HDKey_GetPublicKey(key)
        let publicKeyPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: cpublicKeyPointer, count: HDKey.PUBLICKEY_BYTES)
        let publicKeyData: Data = Data(buffer: publicKeyPointerToArry)

        return [UInt8](publicKeyData)
    }

    public func getPublicKeyData() -> Data {
        let cpublicKeyPointer = HDKey_GetPublicKey(key)
        let publicKeyPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: cpublicKeyPointer, count: HDKey.PUBLICKEY_BYTES)

        return Data(buffer: publicKeyPointerToArry)
    }

    public func getPublicKeyBase58() -> String {
        let basePointer: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: HDKey.PUBLICKEY_BYTES)
        let cpublickeybase58 = HDKey_GetPublicKeyBase58(key, basePointer, Int32(PUBLICKEY_BASE58_BYTES))
        print(String(cString: cpublickeybase58))
        return String(cString: cpublickeybase58)
    }

    public func serialize() -> Data {
        let data = Base58.bytesFromBase58(serializeBase58())
        return Data(bytes: data, count: data.count)
    }

    public func serializeBase58() -> String {
        let extendedkeyPointer: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: 512)
        let cextendedkey = HDKey_SerializePrvBase58(key, extendedkeyPointer, 512)
        
        return String(cString: cextendedkey!)
    }

    public func serializePublicKey() throws -> [UInt8] {
        return try Base58.bytesFromBase58(serializePublicKeyBase58())
    }

    public func serializePublicKeyBase58() throws -> String {

        let extendedkeyPointer: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: 256)
        let cextendedkey = HDKey_SerializePubBase58(key, extendedkeyPointer,Int32(256))
        guard let _ = cextendedkey else {
            throw DIDError.notFoundError("HDKey_SerializePubBase58 error.")
        }

        return String(cString: cextendedkey!)
    }

    public class func deserialize(_ keyData: [UInt8]) -> HDKey {
        let chdKey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 66)
        let cdata: UnsafePointer<UInt8> = Data(bytes: keyData, count: keyData.count).withUnsafeBytes { bytes -> UnsafePointer<UInt8> in
            return bytes
        }
        let k = HDKey_Deserialize(chdKey, cdata, Int32(keyData.count))
        return self.init(k)
    }

    public class func deserialize(_ keyData: Data) -> HDKey {
        let chdKey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 66)
        let cdata: UnsafePointer<UInt8> = keyData.withUnsafeBytes { bytes -> UnsafePointer<UInt8> in
            return bytes
        }
        let k = HDKey_Deserialize(chdKey, cdata, Int32(keyData.count))
        return self.init(k)
    }

    public class func deserializeBase58(_ keyData: String) -> HDKey {
        let chdKey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 66)
        let hdkey = HDKey_DeserializeBase58(chdKey, keyData.toUnsafePointerInt8()!, Int32(keyData.count))
        return self.init(hdkey)
    }

    public class func paddingToExtendedPrivateKey(_ privateKeyBytes: Data) -> Data {
        var pkData: Data = privateKeyBytes
        let cpks: UnsafeMutablePointer<UInt8> = pkData.withUnsafeMutableBytes { (bytes) -> UnsafeMutablePointer<UInt8> in
            return bytes
        }
        let cextenedkey: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.allocate(capacity: EXTENDED_PRIVATEKEY_BYTES)

        _ = HDKey_PaddingToExtendedPrivateKey(cpks, 32, cextenedkey, UInt32(EXTENDED_PRIVATEKEY_BYTES))
        let extenedToArrary: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: cextenedkey, count: EXTENDED_PRIVATEKEY_BYTES)
        let extenedData: Data = Data(buffer: extenedToArrary)

        return extenedData
//        return [UInt8](extenedData)
    }

    public func derive(_ path: String) throws -> HDKey {
        let cderivedkey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 256)
        let childNum = try childList(path)
        let hkey = HDKey_GetvDerivedKey(key, cderivedkey, Int32(childNum.count), getVaList(childNum))

        return HDKey(hkey)
    }

    // "44H/0H/0H"
    private func childList(_ path: String) throws -> [CVarArg] {
        var childNum: [CVarArg] = []
        let arraySubstrings: [Substring] = path.split(separator: "/")
        try arraySubstrings.forEach { str in
            if (str.suffix(1) == "H") {
                let v = String(str.prefix(str.count - 1))
                let iV: UInt32 = try UInt32(value: v)
                let value = iV | 0x80000000
                childNum.append(value)
            }
            else {
                let iV: UInt32 = try UInt32(value: String(str))
                childNum.append(UInt32(iV))
            }
        }

        return childNum
    }

    public func derive(_ index: Int, _ hardened: Bool) -> HDKey {
        // TODO: TODO
        return HDKey(key)
    }

    public func derive(_ index: Int) -> HDKey {

        return derive(index, false)
    }

    public func getAddress() -> String {
        let cid = HDKey_GetAddress(self.key)
        return (String(cString: cid!))
    }

    public class func toAddress(_ pk: [UInt8]) -> String {
        var pkData: Data = Data(bytes: pk, count: pk.count)
        let cpks: UnsafeMutablePointer<UInt8> = pkData.withUnsafeMutableBytes { (bytes) -> UnsafeMutablePointer<UInt8> in
            return bytes
        }
        let address: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: 48)
        let cid = HDKey_PublicKey2Address(cpks, address, 48)

        return (String(cString: cid!))
    }

    class func PEM_ReadPublicKey(_ publicKey: Data) -> String {
        let cpub: UnsafePointer<UInt8> = publicKey.withUnsafeBytes { (bytes) -> UnsafePointer<UInt8> in
            return bytes
        }
        let cprivateKey: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: 512)
        var size: Int32 = 512
        let re = PEM_WritePublicKey(cpub, cprivateKey, &size)
        if re < 0 {
            //TODO: throws
        }
        let cstr = String(cString: cprivateKey)
        return cstr
    }

    class func PEM_ReadPrivateKey(_ publicKey: Data, _ privatekey: Data) throws -> String {
        let cpub: UnsafePointer<UInt8> = publicKey.withUnsafeBytes { bytes -> UnsafePointer<UInt8> in
            return bytes
        }
        let cpri: UnsafePointer<UInt8> = privatekey.withUnsafeBytes { bytes -> UnsafePointer<UInt8> in
            return bytes
        }
        let cPEM_privateKey: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.allocate(capacity: 512)
        var count = 512
        let re = PEM_WritePrivateKey(cpub, cpri, cPEM_privateKey, &count)
        if re < 0 {
            //TODO: throws
        }
        let cstr = String(cString: cPEM_privateKey)
        return cstr
    }

    func wipe() {
        HDKey_Wipe(UnsafeMutablePointer<CHDKey>(mutating: key))
    }

//    public func sign() -> Data {
//
//    }

    /*
    class DerivedKey {
        private var cderivedKey: UnsafePointer<CDerivedKey>

        init(_ chdkey: UnsafePointer<CHDKey>, _ index: Int) {
            let cderivedKey: UnsafeMutablePointer<CDerivedKey> = UnsafeMutablePointer<CDerivedKey>.allocate(capacity: 66)
            self.cderivedKey = HDKey_GetDerivedKey(chdkey, Int32(index), cderivedKey)
        }

        class func getAddress(_ pk: [UInt8]) -> String  {
            var pkData: Data = Data(bytes: pk, count: pk.count)
            let cpks: UnsafeMutablePointer<UInt8> = pkData.withUnsafeMutableBytes { (bytes) -> UnsafeMutablePointer<UInt8> in
                return bytes
            }
            let address: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: 48)
            let cid = HDKey_PublicKey2Address(cpks, address, 48)

            return (String(cString: cid!))
        }

        func getAddress() -> String {
            let cid = DerivedKey_GetAddress(self.cderivedKey)
            return (String(cString: cid!))
        }

        func getPublicKeyData() -> Data {
            let cpublicKeyPointer = DerivedKey_GetPublicKey(self.cderivedKey)
            let publicKeyPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: cpublicKeyPointer, count: PUBLICKEY_BYTES)
            let publicKeyData: Data = Data(buffer: publicKeyPointerToArry)
            return publicKeyData
        }

        func getPublicKeyBytes() -> [UInt8] {
            let cpublicKeyPointer = DerivedKey_GetPublicKey(self.cderivedKey)
            let publicKeyPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: cpublicKeyPointer, count: PUBLICKEY_BYTES)
            let publicKeyData: Data = Data(buffer: publicKeyPointerToArry)
            return [UInt8](publicKeyData)
        }

        func getPublicKeyBase58() -> String {
            let publickeyPointer: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: PUBLICKEY_BYTES)
            let cpublickeybase58 = DerivedKey_GetPublicKeyBase58(self.cderivedKey, publickeyPointer, Int32(PUBLICKEY_BASE58_BYTES))
            return String(cString: cpublickeybase58)
        }

        func getPrivateKeyData() -> Data {
            let privatekeyPointer = DerivedKey_GetPrivateKey(self.cderivedKey)
            let privatekeyPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: privatekeyPointer, count: PRIVATEKEY_BYTES)
            let privatekeyData: Data = Data(buffer: privatekeyPointerToArry)
            return privatekeyData
        }

        func getPrivateKeyBytes() -> [UInt8] {
            let privatekeyPointer = DerivedKey_GetPrivateKey(self.cderivedKey)
            let privatekeyPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: privatekeyPointer, count: PRIVATEKEY_BYTES)
            let privatekeyData: Data = Data(buffer: privatekeyPointerToArry)
            return [UInt8](privatekeyData)
        }

        func serialize() -> Data {
            // TODO:
            return getPrivateKeyData()
        }

        class func PEM_ReadPublicKey(_ publicKey: Data) -> String {
            let cpub: UnsafePointer<UInt8> = publicKey.withUnsafeBytes { (bytes) -> UnsafePointer<UInt8> in
                return bytes
            }
            let cprivateKey: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: 512)
            var size: Int32 = 512
            let re = PEM_WritePublicKey(cpub, cprivateKey, &size)
            if re < 0 {
                //TODO: throws
            }
            let cstr = String(cString: cprivateKey)
            return cstr
        }

        class func PEM_ReadPrivateKey(_ publicKey: Data, _ privatekey: Data) throws -> String {
            let cpub: UnsafePointer<UInt8> = publicKey.withUnsafeBytes { bytes -> UnsafePointer<UInt8> in
                return bytes
            }
            let cpri: UnsafePointer<UInt8> = privatekey.withUnsafeBytes { bytes -> UnsafePointer<UInt8> in
                return bytes
            }
            let cPEM_privateKey: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.allocate(capacity: 512)
            var count = 512
            let re = PEM_WritePrivateKey(cpub, cpri, cPEM_privateKey, &count)
            if re < 0 {
                //TODO: throws
            }
            let cstr = String(cString: cPEM_privateKey)
            return cstr
        }

        func wipe() {
            DerivedKey_Wipe(self.cderivedKey)
        }
    }
    */

    /*
     class func getAddress(_ pk: [UInt8]) -> String  {
         var pkData: Data = Data(bytes: pk, count: pk.count)
         let cpks: UnsafeMutablePointer<UInt8> = pkData.withUnsafeMutableBytes { (bytes) -> UnsafeMutablePointer<UInt8> in
             return bytes
         }
         let address: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: 48)
         let cid = HDKey_PublicKey2Address(cpks, address, 48)

         return (String(cString: cid!))
     }

     public byte[] getBinAddress() {
         return getBinAddress(getPublicKeyBytes());
     }

     public String getAddress() {
         return Base58.encode(getBinAddress());
     }

     public static String toAddress(byte[] pk) {
         return Base58.encode(getBinAddress(pk));
     }



     public HDKey derive(String path) {
         HDPath derivePath = HDPath.parsePath(path);

         DeterministicKey child = key;
         for (ChildNumber childNumber: derivePath)
             child = HDKeyDerivation.deriveChildKey(child, childNumber);

         return new HDKey(child);
     }

     public HDKey derive(int index, boolean hardened) {
         ChildNumber childNumber = new ChildNumber(index, hardened);
         return new HDKey(HDKeyDerivation.deriveChildKey(key, childNumber));
     }

     public HDKey derive(int index) {
         return derive(index, false);
     }

     public static byte[] paddingToExtendedPrivateKey(byte[] privateKeyBytes) {
         byte[] extendedPrivateKeyBytes = new byte[EXTENDED_PRIVATEKEY_BYTES];

         int version = MainNetParams.get().getBip32HeaderP2PKHpriv();
         extendedPrivateKeyBytes[0] = (byte)((version >> 24) & 0xFF);
         extendedPrivateKeyBytes[1] = (byte)((version >> 16) & 0xFF);
         extendedPrivateKeyBytes[2] = (byte)((version >> 8) & 0xFF);
         extendedPrivateKeyBytes[3] = (byte)(version & 0xFF);

         System.arraycopy(privateKeyBytes, 0,
                 extendedPrivateKeyBytes, 46, 32);

         byte[] hash = Sha256Hash.hashTwice(extendedPrivateKeyBytes, 0, 78);
         System.arraycopy(hash, 0, extendedPrivateKeyBytes, 78, 4);

         return extendedPrivateKeyBytes;
     }

     public static byte[] paddingToExtendedPublicKey(byte[] publicKeyBytes) {
         byte[] extendedPublicKeyBytes = new byte[EXTENDED_PUBLICKEY_BYTES];

         int version = MainNetParams.get().getBip32HeaderP2PKHpub();
         extendedPublicKeyBytes[0] = (byte)((version >> 24) & 0xFF);
         extendedPublicKeyBytes[1] = (byte)((version >> 16) & 0xFF);
         extendedPublicKeyBytes[2] = (byte)((version >> 8) & 0xFF);
         extendedPublicKeyBytes[3] = (byte)(version & 0xFF);

         System.arraycopy(publicKeyBytes, 0,
                 extendedPublicKeyBytes, 45, 33);

         byte[] hash = Sha256Hash.hashTwice(extendedPublicKeyBytes, 0, 78);
         System.arraycopy(hash, 0, extendedPublicKeyBytes, 78, 4);

         return extendedPublicKeyBytes;
     }


     public static HDKey deserialize(byte[] keyData) {
         /*
         DeterministicKey k = DeterministicKey.deserialize(
                 MainNetParams.get(), keyData);
         return new HDKey(k);
         */
         return deserializeBase58(Base58.encode(keyData));
     }

     public static HDKey deserializeBase58(String keyData) {
         DeterministicKey k = DeterministicKey.deserializeB58(
                 keyData, MainNetParams.get());
         return new HDKey(k);
     }
     public byte[] serialize() {
         return Base58.decode(serializeBase58());
     }

     public String serializeBase58() {
         return key.serializePrivB58(MainNetParams.get());
     }

     public byte[] serializePublicKey() {
         return Base58.decode(serializePublicKeyBase58());
     }

     public String serializePublicKeyBase58() {
         return key.serializePubB58(MainNetParams.get());
     }
     func getPrivateKeyBytes() -> [UInt8] {
         let privatekeyPointer = DerivedKey_GetPrivateKey(self.cderivedKey)
         let privatekeyPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: privatekeyPointer, count: PRIVATEKEY_BYTES)
         let privatekeyData: Data = Data(buffer: privatekeyPointerToArry)
         return [UInt8](privatekeyData)
     }
     func getPrivateKeyData() -> Data {
         let privatekeyPointer = DerivedKey_GetPrivateKey(self.cderivedKey)
         let privatekeyPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: privatekeyPointer, count: PRIVATEKEY_BYTES)
         let privatekeyData: Data = Data(buffer: privatekeyPointerToArry)
         return privatekeyData
     }
     public String getPrivateKeyBase58() {
         return Base58.encode(getPrivateKeyBytes());
     }
     public byte[] getPublicKeyBytes() {
         return key.getPubKey();
     }

     public String getPublicKeyBase58() {
         return Base58.encode(getPublicKeyBytes());
     }
     */
/*
     public HDKey(String mnemonic, String passphrase) {
         this(Mnemonic.toSeed(mnemonic, passphrase));
     }
     public HDKey(byte[] seed) {
         this(HDKeyDerivation.createMasterPrivateKey(seed));
     }
     public byte[] getPrivateKeyBytes() {
         return key.getPrivKeyBytes();
     }
     */
/*
    class func fromMnemonic(_ mnemonic: String, _ passPhrase: String, _ language: String) -> HDKey {
        let cmnemonic = mnemonic.toUnsafePointerInt8()!
        let cpassphrase = passPhrase.toUnsafePointerInt8()!
        let chdKey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 66)
        let chdkey = HDKey_FromMnemonic(cmnemonic, cpassphrase, language.toUnsafePointerInt8()!, chdKey)
        return HDKey(chdkey)
    }

    class func fromSeed(_ seed: Data) -> HDKey {
        let cseed: UnsafePointer<UInt8> = seed.withUnsafeBytes { bytes -> UnsafePointer<UInt8> in
            return bytes
        }
        
        let chdKey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 66)
        let chdkey = HDKey_FromSeed(cseed, Int32(seed.count), chdKey)
        return HDKey(chdkey)
    }

    class func fromExtendedKey(_ extendedKey: Data) -> HDKey {
        var extendedkeyData = extendedKey
        let cextendedkey = extendedkeyData.withUnsafeMutableBytes { re -> UnsafeMutablePointer<UInt8> in
            return re
        }
        let chdKey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 66)
        let chdkey = HDKey_FromExtendedKey(cextendedkey, Int32(extendedKey.count), chdKey)
        return HDKey(chdkey)
    }
    
    func derivedKey(_ index: Int) -> HDKey.DerivedKey {
        return DerivedKey(self.chdKey, index)
    }

    func serializePrv() throws -> Data {
        let cextendedkey = UnsafeMutablePointer<UInt8>.allocate(capacity: HDKey.EXTENDED_PRIVATE_BYTES)
        let csize = HDKey_SerializePrv(self.chdKey, cextendedkey, Int32(HDKey.EXTENDED_PRIVATE_BYTES))
        if csize <= -1 {
            throw DIDError.didStoreError("HDKey_Serialize error.")
        }
        let extendedkeyPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: cextendedkey, count: HDKey.EXTENDED_PRIVATE_BYTES)
        return Data(buffer: extendedkeyPointerToArry)
    }

    func serializePub() throws -> Data {
        let cextendedkey = UnsafeMutablePointer<UInt8>.allocate(capacity: HDKey.EXTENDED_PRIVATE_BYTES)
        let csize = HDKey_SerializePub(self.chdKey, cextendedkey, Int32(HDKey.EXTENDED_PRIVATE_BYTES))
        if csize <= -1 {
            throw DIDError.didStoreError("HDKey_Serialize error.")
        }
        let extendedkeyPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: cextendedkey, count: HDKey.EXTENDED_PRIVATE_BYTES)
        return Data(buffer: extendedkeyPointerToArry)
    }
    
    class func deserialize(_ keyData: Data) throws -> HDKey {
        if keyData.count == SEED_BYTES {
            return HDKey.fromSeed(keyData)
        }
        else if (keyData.count == EXTENDED_PRIVATE_BYTES) {
            return HDKey.fromExtendedKey(keyData)
        }
        else {
            // TODO:
            throw DIDError.unknownFailure("deserialize error.")
        }
    }
    
    class func deserialize(_ keyData: [UInt8]) throws -> HDKey {
        let keyData = Data(bytes: keyData, count: keyData.count)
        return try deserialize(keyData)
    }

    func wipe() {
        HDKey_Wipe(UnsafeMutablePointer<CHDKey>(mutating: key))
    }
 */
}
