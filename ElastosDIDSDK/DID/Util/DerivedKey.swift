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
        let cpublickeybase58 = DerivedKey_GetPublicKeyBase58(self.cderivedKey, publickeyPointer, Int32(PUBLICKEY_BASE58_COUNT))
        let re = String(cString: cpublickeybase58)
        return re
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
}
