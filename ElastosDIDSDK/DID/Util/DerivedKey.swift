import Foundation

public class DerivedKey: NSObject {
    private var chdkey: UnsafeMutablePointer<CHDKey>
    private var index: Int
    private var cderivedKey: UnsafeMutablePointer<CDerivedKey>
    
    public init(_ chdkey: UnsafeMutablePointer<CHDKey>, _ index: Int) {
        self.chdkey = chdkey
        self.index = index
        let cderivedKey: UnsafeMutablePointer<CDerivedKey> = UnsafeMutablePointer<CDerivedKey>.allocate(capacity: 66)
        self.cderivedKey = HDKey_GetDerivedKey(chdkey, Int32(index), cderivedKey)
    }
    
    // DerivedKey_GetAddress
    public func getIdString() -> String {
        let cid = DerivedKey_GetAddress(self.cderivedKey)
        return (String(cString: cid!))
    }
    
    // getIdString(pks)
    public class func getIdString(pks: [UInt8]) -> String {
        var pkData: Data = Data(bytes: pks, count: pks.count)
        let cpks: UnsafeMutablePointer<UInt8> = pkData.withUnsafeMutableBytes { (bytes) -> UnsafeMutablePointer<UInt8> in
            return bytes
        }
        let address: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: 48)
        let cid = HDKey_PublicKey2Address(cpks, address, 48)
        
        return (String(cString: cid!))
    }
    
    // uint8_t *DerivedKey_GetPublicKey(DerivedKey *derivedkey);
    public func getPublicKeyData() -> Data {
        let cpublicKeyPointer = DerivedKey_GetPublicKey(self.cderivedKey)
        let publicKeyPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: cpublicKeyPointer, count: PUBLICKEY_BYTES)
        let publicKeyData: Data = Data(buffer: publicKeyPointerToArry)
        return publicKeyData
    }
    
    // uint8_t *DerivedKey_GetPublicKey(DerivedKey *derivedkey);
    public func getPublicKeyBytes() -> [UInt8] {
        let cpublicKeyPointer = DerivedKey_GetPublicKey(self.cderivedKey)
        let publicKeyPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: cpublicKeyPointer, count: PUBLICKEY_BYTES)
        let publicKeyData: Data = Data(buffer: publicKeyPointerToArry)
        return [UInt8](publicKeyData)
    }
    
    // const char *DerivedKey_GetPublicKeyBase58(DerivedKey *derivedkey, char *base, size_t size);
    public func getPublicKeyBase58() -> String {
        let publickeyPointer: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: PUBLICKEY_BYTES)
        let cpublickeybase58 = DerivedKey_GetPublicKeyBase58(self.cderivedKey, publickeyPointer, Int32(PUBLICKEY_BYTES))
        // TODO:
        let pkpointToarry: UnsafeBufferPointer<Int8> = UnsafeBufferPointer(start: publickeyPointer, count: 33)
        var pkData: Data = Data(buffer: pkpointToarry)
        let re = pkData.hexEncodedString()
//        let re2 = String(cString: cpublickeybase58)
        let base58: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: 2048)
        let d = pkData.withUnsafeMutableBytes { re -> UnsafeMutablePointer<UInt8> in
            return re
        }
        _ = base58_encode(base58, d, pkData.count)
        let base58Str = String(cString: base58)
        return re
//        return String(cString: cpublickeybase58)
    }
    
    // uint8_t *DerivedKey_GetPrivateKey(DerivedKey *derivedkey);
    public func getPrivateKeyData() -> Data {
        let privatekeyPointer = DerivedKey_GetPrivateKey(self.cderivedKey)
        let privatekeyPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: privatekeyPointer, count: PRIVATEKEY_BYTES)
        let privatekeyData: Data = Data(buffer: privatekeyPointerToArry)
        return privatekeyData
    }
    
    public func getPrivateKeyBytes() -> [UInt8] {
        let privatekeyPointer = DerivedKey_GetPrivateKey(self.cderivedKey)
        let privatekeyPointerToArry: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: privatekeyPointer, count: PRIVATEKEY_BYTES)
        let privatekeyData: Data = Data(buffer: privatekeyPointerToArry)
        return [UInt8](privatekeyData)
    }
    
    // void DerivedKey_Wipe(DerivedKey *derivedkey);
    public func derivedKeyWipe() {
        DerivedKey_Wipe(self.cderivedKey)
    }
    
    
    //
    //    public func getPublicKeyBytes() throws -> [UInt8] {
    //        return seed.withUnsafeMutableBytes { (seeds: UnsafeMutablePointer<Int8>) -> [UInt8] in
    //            let pukey: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: 66)
    //            let chdKey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 66)
    //            let hdKey: UnsafePointer<CHDKey> = HDKey_GetPrivateIdentity(seeds, 0, chdKey)
    //            let pk: UnsafeMutablePointer<Int8> = HDKey_GetSubPublicKey(hdKey, 0, index, pukey)
    //            let pkpointToarry: UnsafeBufferPointer<Int8> = UnsafeBufferPointer(start: pk, count: 33)
    //            let pkData: Data = Data(buffer: pkpointToarry)
    //            return [UInt8](pkData)
    //        }
    //    }
    //
    //    public func getPublicKeyData() throws -> Data {
    //        return seed.withUnsafeMutableBytes { (seeds: UnsafeMutablePointer<Int8>) -> Data in
    //            let pukey: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: 66)
    //            let chdKey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 66)
    //            let hdKey: UnsafePointer<CHDKey> = HDKey_GetPrivateIdentity(seeds, 0, chdKey)
    //            let pk: UnsafeMutablePointer<Int8> = HDKey_GetSubPublicKey(hdKey, 0, index, pukey)
//            let pkpointToarry: UnsafeBufferPointer<Int8> = UnsafeBufferPointer(start: pk, count: 33)
//            let pkData: Data = Data(buffer: pkpointToarry)
//            return pkData
//        }
//    }
//
//    public func getPrivateKeyBytes() throws -> [UInt8] {
//        return seed.withUnsafeMutableBytes { (seeds: UnsafeMutablePointer<Int8>) -> [UInt8] in
//            let privateKey: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: 64)
//            let chdKey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 66)
//            let hdKey: UnsafePointer<CHDKey> = HDKey_GetPrivateIdentity(seeds, 0, chdKey)
//            let pk: UnsafeMutablePointer<Int8> = HDKey_GetSubPrivateKey(hdKey, 0, 0, index, privateKey)
//            let privateKeyPointToarry: UnsafeBufferPointer<Int8> = UnsafeBufferPointer(start: pk, count: 33)
//            let pkData: Data = Data(buffer: privateKeyPointToarry)
//            return [UInt8](pkData)
//        }
//    }
//
//    public func getPrivateKeyData() throws -> Data {
//        return seed.withUnsafeMutableBytes { (seeds: UnsafeMutablePointer<Int8>) -> Data in
//            let privateKey: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: 64)
//            let chdKey: UnsafeMutablePointer<CHDKey> = UnsafeMutablePointer<CHDKey>.allocate(capacity: 66)
//            let hdKey: UnsafePointer<CHDKey> = HDKey_GetPrivateIdentity(seeds, 0, chdKey)
//            _ = HDKey_GetSubPrivateKey(hdKey, 0, 0, index, privateKey)
//            let privateKeyPointToarry: UnsafeBufferPointer<Int8> = UnsafeBufferPointer(start: privateKey, count: 33)
//            let pkData: Data = Data(buffer: privateKeyPointToarry)
//            return pkData
//        }
//    }
//
//    public func getPrivateKeyBase58() throws -> String {
//        let data8: [UInt8] = try getPrivateKeyBytes()
//        return Base58.base58FromBytes(data8)
//    }
//
//    public func getPublicKeyBase58() throws -> String {
//        var pkData: Data = try getPublicKeyData()
//        let base58: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: 2048)
//        let d = pkData.withUnsafeMutableBytes { re -> UnsafeMutablePointer<UInt8> in
//            return re
//        }
//        _ = base58_encode(base58, d, pkData.count)
//        let base58Str = String(cString: base58)
//        return base58Str
//    }
//
//    public class func getIdString(_ pk: [UInt8]) -> String {
//        var pkData: Data = Data(bytes: pk, count: pk.count)
//        let pks: UnsafeMutablePointer<Int8> = pkData.withUnsafeMutableBytes { (bytes) -> UnsafeMutablePointer<Int8> in
//            return bytes
//        }
//        let address: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: 48)
//        let idstring = HDKey_GetAddress(pks, address, 48)
//        return (String(cString: idstring))
//    }
}
