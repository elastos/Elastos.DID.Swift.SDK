import Foundation

public let PUBLICKEY_BYTES: Int = 33
public let PRIVATEKEY_BYTES: Int = 32
public let CHAINCODE_BYTES: Int = 32
public let EXTENDEDKEY_BYTES: Int = 82
public let SEED_BYTES: Int = 64
public class HDKey: NSObject {
    private var chdkey: UnsafeMutablePointer<CHDKey>
    
    // HDKey_FromMnemonic
    public init(mnemonic: String, passphrase: String, language: Int) {
        let cmnemonic = mnemonic.toUnsafePointerInt8()!
        let cpassphrase = passphrase.toUnsafePointerInt8()!
        let chdKey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 66)
        self.chdkey = HDKey_FromMnemonic(cmnemonic, cpassphrase, Int32(language), chdKey)
    }
    
    //  HDKey *HDKey_FromExtendedKey(const uint8_t *extendedkey, size_t size, HDKey *hdkey);
    public init(extendedkey: Data, size: Int) {
//        let cextendedkey = extendedkey.toUnsafePointerUInt8()!
        var extendedkeyData = extendedkey
        let cextendedkey = extendedkeyData.withUnsafeMutableBytes { re -> UnsafeMutablePointer<UInt8> in
            return re
        }
        let chdKey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 66)
        self.chdkey = HDKey_FromExtendedKey(cextendedkey, Int32(size), chdKey)
    }
    
    // HDKey *HDKey_FromSeed(const uint8_t *seed, size_t size, HDKey *hdkey);
    public init(seed: Data, size: Int) {
//        let cseed = seed.toUnsafePointerUInt8()!
        //        let pks: UnsafeMutablePointer<Int8> = pkData.withUnsafeMutableBytes { (bytes) -> UnsafeMutablePointer<Int8> in
        //            return bytes
        //        }
        let cseed: UnsafePointer<UInt8> = seed.withUnsafeBytes { bytes -> UnsafePointer<UInt8> in
            return bytes
        }
        
        let chdKey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 66)
        self.chdkey = HDKey_FromSeed(cseed, Int32(size), chdKey)
        super.init()
    }
    
    // DerivedKey *HDKey_GetDerivedKey(HDKey* hdkey, int index, DerivedKey *derivedkey);
    public func derivedKey(index: Int) -> DerivedKey {
        return DerivedKey(self.chdkey, index)
    }
    
    // ssize_t HDKey_Serialize(HDKey *hdkey, uint8_t *extendedkey, size_t size);
    public func hdKeySerialize(_ size: Int) throws -> Data {
        let cextendedkey = UnsafeMutablePointer<UInt8>.allocate(capacity: EXTENDEDKEY_BYTES)
        let csize = HDKey_Serialize(self.chdkey, cextendedkey, Int32(size))
        if csize <= -1 {
            throw DIDError.didStoreError(_desc: "HDKey_Serialize error.")
        }
        let extendedkeyPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: cextendedkey, count: EXTENDEDKEY_BYTES)
        let extendedkeyData: Data = Data(buffer: extendedkeyPointerToArry)
        return extendedkeyData
    }
    
    // void HDKey_Wipe(HDKey *hdkey);
    public func hdKeyWipe() {
        HDKey_Wipe(self.chdkey)
    }
    
    
    
//    public func getPrivateKeyBase58() throws -> String {
//        let data8: [UInt8] = try getPrivateKeyBytes()
//        return Base58.base58FromBytes(data8)
//    }
    
    // uint8_t *DerivedKey_GetPublicKey(DerivedKey *derivedkey);
//    public class func publickFromeDerivedKey(_ derivedkey: )
    
    //    public class func getIdString(_ pk: [UInt8]) -> String {
    //        var pkData: Data = Data(bytes: pk, count: pk.count)
    //        let pks: UnsafeMutablePointer<Int8> = pkData.withUnsafeMutableBytes { (bytes) -> UnsafeMutablePointer<Int8> in
    //            return bytes
    //        }
    //        let address: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: 48)
    //        let idstring = HDKey_GetAddress(pks, address, 48)
    //        return (String(cString: idstring))
    //    }
    
    
//    private var seed: Data!
//    init(_ seed: Data) {
//        self.seed = seed
//    }

//    public class func fromMnemonic(_ mnemonic: String, _ passphrase: String) throws -> HDKey {
//        let mnem: String = mnemonic
//        let passph: String = passphrase
//        let mpointer: UnsafePointer<Int8> = mnem.toUnsafePointerInt8()!
//        let passphrasebase58Pointer = passph.toUnsafePointerInt8()
//
//        var seedPinter: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: 64)
//        seedPinter = HDKey_GetSeedFromMnemonic(mpointer, passphrasebase58Pointer!, 0, seedPinter)
//        let seedPointToArry: UnsafeBufferPointer<Int8> = UnsafeBufferPointer(start: seedPinter, count: 64)
//        let seedData: Data = Data(buffer: seedPointToArry)
//        print(seedData.hexEncodedString())
//        return HDKey(seedData)
//    }
//
//    public func getSeed() -> Data {
//        return seed
//    }
//
//    public class func fromSeed(_ seed: Data) -> HDKey {
//        return HDKey(seed)
//    }
//
//    public func derive(_ index: Int) throws -> DerivedKey {
//        return DerivedKey(seed, Int32(index))
//    }
}
